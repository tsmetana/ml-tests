from flask import Flask, render_template, request, redirect, url_for, flash
import os
import requests
import torch
import torch.nn as nn
import sqlite3
import re
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'log', 'txt', '0'}  # Allow files without extension (like journal files)
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB max file size

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# LogFile class from the notebook
class LogFile:
    __path = None
    __hostname_pattern = re.compile('^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')
    __id_suffix_pattern = re.compile('^([a-z]+-)+[a-f0-9]+-.{5}$')
    __id_prefix_pattern1 = re.compile('^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}-(.*)$')
    __id_prefix_pattern2 = re.compile('^[a-f0-9]{32}-(.*)$')
    __id_suffix_pattern3 = re.compile('^([a-z]+-)+[a-f0-9]{5}$')
    __id_suffix_pattern4 = re.compile('^([a-z]+-)+[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')
    __id_token_pattern1 = re.compile('^[a-z-]+')
    __id_token_pattern2 = re.compile('^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')
    __numeric_token_pattern = re.compile('^[+]?[0-9]+[.]*[0-9]*[mug]*i*[sb]*$')
    __hex_num_pattern = re.compile('[a-z0-9]+')
    __ttable = str.maketrans('{}[]()=:/\\,&?_', '              ', '"\'')
    __db = None
    __dbc = None
    
    def __init__(self, path = None, db_path = None, clear = True):
        if db_path is None:
            self.__db = sqlite3.connect(":memory:")
        else:
            self.__db = sqlite3.connect(db_path)
        self.__dbc = self.__db.cursor()
        self.__dbc.execute("create table if not exists log_lines(ID integer primary key, line text not NULL)")
        self.__dbc.execute("create table if not exists tokens(ID integer primary key, token text unique not NULL, freq integer not null default 1)")
        self.__dbc.execute("create table if not exists identifiers(ID integer primary key, identifier text unique not NULL)")
        self.__dbc.execute("create table if not exists log_line_tokens(line_ID integer not null, token_ID integer not null, primary key (line_ID, token_ID))")
        self.__dbc.execute("create table if not exists log_line_identifiers(line_ID integer not null, identifier_ID integer not null, primary key (line_ID, identifier_ID))")
        if clear:
            self.__dbc.execute("delete from log_lines")
        self.set_path(path)

    def __is_hostname(self, s):
        return s.count('.') > 0 and self.__hostname_pattern.match(s)

    def __is_hash(self, s):
        if (len(s) == 32 or len(s) == 64) and self.__hex_num_pattern.match(s):
            return True
        if self.__id_token_pattern2.match(s):
            return True
        return False

    def __is_numberlike(self, s):
        if s.isnumeric() or self.__numeric_token_pattern.match(s):
            return True
        return False

    def __replace_id_suffix(self, s):
        m = None
        if s.startswith("--"):
            return(s, False)
        if self.__id_suffix_pattern.match(s):
            m = self.__id_token_pattern1.match(s)
        if m != None:
            return (m.group() + 'id_suffix', True)
        m = self.__id_suffix_pattern4.match(s)
        if m is not None:
            return (m.group(1) + 'id_suffix', True)
        return (s, False)

    def __replace_id_prefix(self, s):
        m = self.__id_prefix_pattern1.match(s)
        if m is not None:
            return ('id-prefix-' + m.group(1), True)
        m = self.__id_prefix_pattern2.match(s)
        if m is not None:
            return ('id-prefix-' + m.group(1), True)
        return (s, False)
        
    def __log_line_tokenize(self, line):
        ret = []
        tokens = line.split(" ", 8)
        if not (tokens[4].startswith("kubenswrapper") and (tokens[5].startswith("i") or tokens[5].startswith("w") or tokens[5].startswith("e"))):
             raise IndexError
        identifiers = []
        log_text = tokens.pop(-1)
        log_text = log_text.translate(self.__ttable)
        log_text_tokens = log_text.split()
        i = 0
        for t in log_text_tokens:
            log_text_tokens[i] = t.strip(". ?!*#,+")
            i = i + 1
        tokens = [tokens[5]]
        tokens[0] = tokens[0][0] + '000'
        tokens = tokens + log_text_tokens
        for t in tokens:
            tr = t
            if self.__is_numberlike(t):
                continue
            if self.__is_hostname(t):
                tr = "_hostname_token"
            elif self.__is_hash(t):
                if not t in identifiers:
                    identifiers.append(t)
                tr = "_hash_token"
            else:
                (tr, found) = self.__replace_id_prefix(t)
                if found and not t in identifiers:
                    identifiers.append(t)
                (tr, found) = self.__replace_id_suffix(tr)
                if found and not t in identifiers:
                    identifiers.append(t)
            ret.append(tr)
        return (ret, identifiers)
    
    def set_path(self, path):
        self.__path = path

    def parse_log(self, limit = 0):
        logfile = open(self.__path, "r")
        line = logfile.readline().casefold()
        line_num = 1
        while (len(line) > 0 and limit == 0) or (len(line) > 0 and limit != 0 and line_num <= limit):
            try:
                tokens, identifiers = self.__log_line_tokenize(line)
                self.__dbc.execute("insert into log_lines (ID, line) values (?, ?)", (line_num, line))
                l_id = self.__dbc.lastrowid
                for t in tokens:
                    if t.isspace():
                        continue
                    self.__dbc.execute("insert into tokens (token) values (?) on conflict do update set freq = freq + 1", (t,))
                    t_id = self.__dbc.execute("select id from tokens where (token = ?)", (t,)).fetchone()[0]
                    self.__dbc.execute("insert or ignore into log_line_tokens (line_ID, token_ID) values (?,?)", (l_id, t_id))
                for t in identifiers:
                    self.__dbc.execute("insert or ignore into identifiers (identifier) values (?)", (t,))
                    i_id = self.__dbc.execute("select id from identifiers where (identifier = ?)", (t,)).fetchone()[0]
                    self.__dbc.execute("insert or ignore into log_line_identifiers (line_ID, identifier_ID) values (?,?)", (l_id, i_id))
            except IndexError:
                pass
            line = logfile.readline().casefold()
            line_num = line_num + 1
        self.__db.commit()
        logfile.close()

    def import_words_table(self, filename):
        r = self.__dbc.execute("create table if not exists words (id integer primary key, word text unique not null)")
        self.__dbc.execute("delete from words")
        with open(filename, "r") as fr:
            for line in fr:
                self.__dbc.execute("insert or ignore into words (word) values (?)",(line.rstrip(),))
        self.__db.commit()

    def get_words_count(self):
        r = self.__dbc.execute("select count(*) from words")
        return r.fetchone()[0]

    def db_handle(self):
        return self.__db

# LSTM Model class
class LogLSTM(nn.Module):
    def __init__(self, input_dim=1171, hidden_dim=256, num_layers=2, dropout=0.2):
        super(LogLSTM, self).__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0
        )
        
        self.output_layer = nn.Linear(hidden_dim, input_dim)
        self.sigmoid = nn.Sigmoid()
        
    def forward(self, x):
        lstm_out, (hidden, cell) = self.lstm(x)
        last_output = lstm_out[:, -1, :]
        prediction = self.output_layer(last_output)
        prediction = self.sigmoid(prediction)
        return prediction

# Global variables for model and device
model = None
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

def load_model(model_path='log_check/log_lstm_model.pth'):
    """Load the trained LSTM model"""
    global model
    try:
        checkpoint = torch.load(model_path, map_location=device)
        config = checkpoint['model_config']
        model = LogLSTM(**config)
        model.load_state_dict(checkpoint['model_state_dict'])
        model.to(device)
        model.eval()
        return True
    except Exception as e:
        print(f"Error loading model: {e}")
        return False

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS or '.' not in filename

def download_file(url, local_path):
    """Download file from URL"""
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except Exception as e:
        print(f"Error downloading file: {e}")
        return False

def create_training_vectors(logfile_obj):
    """Create training vectors from parsed log data"""
    con = logfile_obj.db_handle()
    cur = con.cursor()
    
    words_num = logfile_obj.get_words_count()
    if words_num == 0:
        return None
    
    prev_line_id = 0
    raw_dataset = []
    line_words = torch.zeros(words_num)
    
    for r in cur.execute("""
        select words.id as word_id, log_line_identifiers.identifier_ID, log_line_identifiers.line_ID 
        from words 
        join tokens on tokens.token = words.word 
        join log_line_tokens on log_line_tokens.token_ID = tokens.ID 
        join log_line_identifiers on log_line_identifiers.line_ID = log_line_tokens.line_ID 
        order by log_line_identifiers.identifier_ID, log_line_identifiers.line_ID, word_id
    """):
        (word_id, identifier_id, line_id) = r
        if line_id != prev_line_id:
            raw_dataset.append(line_words.clone())
            line_words = torch.zeros(words_num)
            prev_line_id = line_id
        line_words[word_id - 1] = 1.0
    
    if len(raw_dataset) > 0:
        return torch.stack(raw_dataset)
    return None

def predict_next_vector(model, input_sequence):
    """Predict next vector given input sequence"""
    model.eval()
    with torch.no_grad():
        input_batch = input_sequence.unsqueeze(0).to(device)
        prediction = model(input_batch)
        return prediction.squeeze(0).cpu()

def analyze_log_predictions(training_vectors, sequence_length=50):
    """Analyze log by comparing predictions with actual vectors"""
    if model is None or training_vectors is None or len(training_vectors) <= sequence_length:
        return None
    
    results = []
    total_vectors = len(training_vectors)
    
    for i in range(sequence_length, min(total_vectors, sequence_length + 100)):  # Limit to first 100 predictions
        input_sequence = training_vectors[i-sequence_length:i]
        true_next = training_vectors[i]
        predicted_next = predict_next_vector(model, input_sequence)
        
        # Calculate similarity metrics
        mse = torch.mean((predicted_next - true_next) ** 2).item()
        mae = torch.mean(torch.abs(predicted_next - true_next)).item()
        
        # Binary accuracy (using 0.5 threshold)
        predicted_binary = (predicted_next > 0.5).float()
        binary_accuracy = (predicted_binary == true_next).float().mean().item()
        
        # Top-k accuracy (check if true positives are in top-k predictions)
        true_indices = torch.where(true_next == 1)[0]
        if len(true_indices) > 0:
            _, top_k_indices = torch.topk(predicted_next, k=min(10, len(predicted_next)))
            top_k_accuracy = len(set(true_indices.numpy()) & set(top_k_indices.numpy())) / len(true_indices)
        else:
            top_k_accuracy = 0.0
        
        results.append({
            'line_number': i + 1,
            'mse': mse,
            'mae': mae,
            'binary_accuracy': binary_accuracy,
            'top_k_accuracy': top_k_accuracy,
            'true_word_count': int(true_next.sum().item()),
            'predicted_word_count': int((predicted_next > 0.5).sum().item())
        })
    
    return results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_log():
    try:
        # Check if model is loaded
        if model is None:
            if not load_model():
                flash('Error: Could not load the trained model. Please ensure log_lstm_model.pth exists in log_check/.', 'error')
                return redirect(url_for('index'))
        
        log_source = request.form.get('log_source')
        temp_file_path = None
        
        if log_source == 'upload':
            # Handle file upload
            if 'file' not in request.files:
                flash('No file selected', 'error')
                return redirect(url_for('index'))
            
            file = request.files['file']
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(url_for('index'))
            
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                temp_file_path = file_path
            else:
                flash('Invalid file type', 'error')
                return redirect(url_for('index'))
        
        elif log_source == 'url':
            # Handle URL download
            url = request.form.get('url')
            if not url:
                flash('Please provide a URL', 'error')
                return redirect(url_for('index'))
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"downloaded_{timestamp}.log"
            temp_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            if not download_file(url, temp_file_path):
                flash('Error downloading file from URL', 'error')
                return redirect(url_for('index'))
        
        elif log_source == 'path':
            # Handle local file path
            file_path = request.form.get('file_path')
            if not file_path or not os.path.exists(file_path):
                flash('File path does not exist', 'error')
                return redirect(url_for('index'))
            temp_file_path = file_path
        
        # Create temporary database
        db_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db")
        
        # Parse log file
        logfile = LogFile(temp_file_path, db_path)
        
        # Import words dictionary (assuming it exists)
        words_file = 'log_check/words.csv'
        if not os.path.exists(words_file):
            flash('Error: words.csv dictionary file not found. Please ensure it exists in log_check/.', 'error')
            return redirect(url_for('index'))
        
        logfile.import_words_table(words_file)
        logfile.parse_log()
        
        # Create training vectors
        training_vectors = create_training_vectors(logfile)
        if training_vectors is None:
            flash('Error: Could not create training vectors from log file', 'error')
            return redirect(url_for('index'))
        
        # Analyze predictions
        results = analyze_log_predictions(training_vectors)
        if results is None:
            flash('Error: Could not analyze log predictions', 'error')
            return redirect(url_for('index'))
        
        # Clean up temporary files
        if log_source in ['upload', 'url']:
            try:
                os.remove(temp_file_path)
            except:
                pass
        
        try:
            os.remove(db_path)
        except:
            pass
        
        # Calculate summary statistics
        avg_mse = sum(r['mse'] for r in results) / len(results)
        avg_mae = sum(r['mae'] for r in results) / len(results)
        avg_binary_accuracy = sum(r['binary_accuracy'] for r in results) / len(results)
        avg_top_k_accuracy = sum(r['top_k_accuracy'] for r in results) / len(results)
        
        summary = {
            'total_predictions': len(results),
            'avg_mse': avg_mse,
            'avg_mae': avg_mae,
            'avg_binary_accuracy': avg_binary_accuracy,
            'avg_top_k_accuracy': avg_top_k_accuracy,
            'vectors_analyzed': len(training_vectors)
        }
        
        return render_template('results.html', results=results, summary=summary)
        
    except Exception as e:
        flash(f'Error processing log file: {str(e)}', 'error')
        return redirect(url_for('index'))

if __name__ == '__main__':
    # Try to load model on startup
    load_model()
    app.run(debug=True, host='0.0.0.0', port=5000) 
#!/usr/bin/python

import sys
from datetime import datetime

class LogFile(object):
    def __init__(self, path):
        self._path = path
        self._fr = open(self._path, "r")
        self._current_line = None
    
    def __fini__(self):
        self.close()

    def close(self):
        self._fr.close()

    def current_line(self):
        return self._current_line

    def readline(self):
        done = False
        retval = False
        while not done:
            line = self._fr.readline()
            if len(line) > 0:
                tokens = line.split()
                try:
                    month = datetime.strptime(tokens[0], "%b").month
                    new_date = f"{month:02} {tokens[1]:02}"
                    self._current_line = new_date + " " + " ".join(tokens[3:])
                    done = True
                    retval = True
                except Exception as e:
                    pass
            else:
                done = True
        return retval
    

if __name__ == '__main__':
    paths = sys.argv[1:]

    if len(paths) == 0:
        print("No file(s) to merge given")
        sys.exit(1)

    files = []
    for p in paths:
        files.append(LogFile(p))
        if not files[-1].readline():
            files.pop(-1).close()
    
    while len(files) > 0:
        files.sort(key=lambda f: f.current_line())
        print(files[0].current_line())
        if not files[0].readline():
            files.pop(0).close()

import subprocess

FLOSS_PATH = "/home/ryan/Downloads/MalwareTools/Floss/floss"

class FlossData:
    '''Data object that houses output from FLOSS'''

    def __init__ (self, path, file):
        args = ["--no-static-strings", "--no-stack-strings", "--no-decoded-strings"]
        self.static = subprocess.getoutput(f"{path} {file} -q {args[1]} {args[2]}").split('\n')
        self.decoded = subprocess.getoutput(f"{path} {file} -q {args[0]} {args[1]}").split('\n')
        self.stack = subprocess.getoutput(f"{path} {file} -q {args[0]} {args[2]}").split('\n')

    def staticStrings (self):
        return self.static

    def decodedStrings (self):
        return self.decoded

    def stackStrings (self):
        return self.stack

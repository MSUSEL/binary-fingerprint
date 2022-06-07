import subprocess

FILE_PATH = "Modules/oledump/oledump.py"

def OleFindStreams (name):
    cmd = "python3"
    args = name
    oleProc = subprocess.Popen([cmd, FILE_PATH, args], stdout = subprocess.PIPE)
    output = str(oleProc.communicate())
    output = output.split('\\n')

    streams = []
    for i in output:
        if i.split()[1] == "M":
            streams.append(i.split()[0][:-1])

    return streams

def OleOpenStreams (name, streams):
    cmd = "python3"

    allVBA = []
    for i in streams:
        arg1 = "-s" + i
        arg2 = "-v"
        oleProc = subprocess.Popen([cmd, FILE_PATH, name, arg1, arg2], stdout = subprocess.PIPE)
        output = str(oleProc.communicate()).split('\\n')[:-1]
        output[0] = output[0][3:]
        allVBA += output
    return allVBA

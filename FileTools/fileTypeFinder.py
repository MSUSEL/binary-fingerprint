import subprocess
import os

def runFileCommand (name, find):
    cmd = 'file'
    temp = subprocess.Popen([cmd, name], stdout = subprocess.PIPE)
    output = str(temp.communicate())
    output = output.split(":")[1].strip()
    output = output.split(",")[0].strip()
    if output[-3:] == "\\n'":
        output = output[0:-3]
    return output == find

def main ():
    fileRoot = input("Enter root directory: ")
    fileType = input("Enter file type: ")
    for directory, subdirlist, filelist in os.walk(fileRoot):
        for f in filelist:
            ret = runFileCommand (directory + "/" + f, fileType)
            if ret:
                print (f)

if __name__ == "__main__":
    main()

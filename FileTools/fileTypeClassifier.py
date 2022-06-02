import subprocess
import os

def runFileCommand (name):
    cmd = 'file'
    temp = subprocess.Popen([cmd, name], stdout = subprocess.PIPE)
    output = str(temp.communicate())
    output = output.split(":")[1].strip()
    output = output.split(",")[0].strip()
    if (output[-3:] == "\\n'"):
        output = output[0:-3]
    return output

def main ():
    myDict = {}
    fileRoot = input("Enter root directory: ")
    for directory, subdirlist, filelist in os.walk(fileRoot):
        print(directory)
        for f in filelist:
            fileType = runFileCommand (directory + "/" + f)
            # print (fileType)
            if (fileType in myDict):
                myDict[fileType] += 1
            else:
                myDict[fileType] = 1

    return myDict

if __name__ == "__main__":
    res = main()
    for i in res:
        print ("{:5}".format(res[i]), ":", i)

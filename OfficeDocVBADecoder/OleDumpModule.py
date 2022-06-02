import subprocess
import os
import sys
from os.path import exists

def oleFindStreams (name):
    cmd = "python3"
    ole = "oledump/oledump.py"
    args = name
    oleProc = subprocess.Popen([cmd, ole, args], stdout = subprocess.PIPE)
    output = str(oleProc.communicate())
    output = output.split('\\n')

    streams = []
    for i in output:
        if i.split()[1] == "M":
            streams.append(i.split()[0][:-1])

    return streams

def oleOpenStreams (name, streams):
    cmd = "python3"
    ole = "oledump/oledump.py"

    allVBA = []
    for i in streams:
        arg1 = "-s" + i
        arg2 = "-v"
        oleProc = subprocess.Popen([cmd, ole, name, arg1, arg2], stdout = subprocess.PIPE)
        output = str(oleProc.communicate()).split('\\n')[:-1]
        output[0] = output[0][3:]
        allVBA += output
    return allVBA

def functionalizeVBA (vbaArray):
    functions = {"null": []}
    inFunc = 0

    currBuffer = []
    currName = ""
    for line in vbaArray:
        i = line.lower()
        if ("end" in i and ("sub" in i or "function" in i)):
            inFunc -= 1
            if (inFunc == 0):
                currBuffer.append(i)
                functions[currName] = currBuffer
                currBuffer = []
                currName = ""
        elif (("function" in i or "sub" in i) and inFunc == 0):
            currName = i
            inFunc += 1
        else:
            if (len(i.strip()) == 0):
                continue
            if (inFunc > 0):
                currBuffer.append(i.strip())
            else:
                functions["null"].append(i.strip())

    return functions


def determineFileType (name):
    cmd = 'file'
    fileProc = subprocess.Popen([cmd, name], stdout = subprocess.PIPE)
    output = str(fileProc.communicate())
    output = output.split(":")[1].strip()
    output = output.split(",")[0].strip()

    return output

def main ():
    fileName = input("Enter OfficeDoc File Name: ")
    fileExists = exists(fileName)
    if not fileExists:
        print ("Unable to find file, exiting...")
        sys.exit (1)

    fileType = determineFileType (fileName)
    if "Excel" in fileType:
        streams = oleFindStreams (fileName)
        print (streams)
        if (len(streams) > 0):
            vbas = oleOpenStreams (fileName, streams)
            functions = functionalizeVBA (vbas)
            for i in functions:
                print (i)
                for j in functions[i]:
                    print (j)
                print ()

if __name__ == "__main__":
    main ()

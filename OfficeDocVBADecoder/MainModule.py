import subprocess
import sys
import re
from os.path import exists

#import modules
import Modules.OleDumpModule as Ole
import Modules.VBAModule as VBA

indents = ["#if", "if", "for", "while"]
unindents = ["#end", "end", "next"]

def DetermineFileType (name):
    cmd = 'file'
    fileProc = subprocess.Popen([cmd, name], stdout = subprocess.PIPE)
    output = str(fileProc.communicate())
    output = output.split(":")[1].strip()
    output = output.split(",")[0].strip()

    return output

def PrintFunctions (funcs):
    for i in funcs:
        print (i)
        indent = 1
        for j in funcs[i]:
            splitLine = [x for x in re.split (r'[\(\),\s]', j) if x != '']

            if splitLine[0] in unindents:
                indent -= 1

            if splitLine[0] == "#else":
                print (" "*(indent-1)*4 + j)
            else:
                print (" "*indent*4 + j)

            if splitLine[0] in indents:
                indent += 1
        print ()

def Main ():
    # fileName = input("Enter OfficeDoc File Name: ")
    fileName = "/home/ryan/MalFiles/Invoice_yahoo.bin"

    fileExists = exists(fileName)

    if not fileExists:
        print ("Unable to find file, exiting...")
        sys.exit (1)

    # Check File Type
    fileType = DetermineFileType (fileName)
    print ("\nFile Type: " + fileType + "\n")

    # Attempt OLE Dump
    print ("Attempting OLE Dump...\n")

    streams = Ole.OleFindStreams (fileName)
    if streams == "Error: OleDumpModule.py is not a valid OLE file.":
        print ("Not Valid OLE File...\n")
    elif len(streams) > 0:
        print ("OLE Streams Found...")
        vbas = Ole.OleOpenStreams (fileName, streams)
        functions = VBA.FunctionalizeVBA (vbas)
        functions = VBA.CleanFunctions (functions)
        PrintFunctions (functions)
    else:
        print ("No OLE Streams Found...\n")

    # Attempt Other

if __name__ == "__main__":
    Main ()

import hashlib
import subprocess
import json
import pefile
import magic
import ssdeep
import InfoDicts as dic

FLOSS_PATH = "/home/ryan/Downloads/MalwareTools/Floss/floss"
MANALYZER_PATH = "/home/ryan/Downloads/MalwareTools/Manalyze/bin/manalyze"
FILE = "/home/ryan/MalFiles/PEFiles/ShinoLocker.bin"

class MetaDataObject:
    '''Data object that houses all meta data pulled from the PE file'''

    def __init__ (self, file):
        pe = pefile.PE(file)
        raw = pe.write()

        self.fileName = file
        self.fileType = magic.from_file(file)
        self.mimeType = magic.from_file(file, mime=True)
        self.size = len(raw)
        self.entropy = pe.sections[0].entropy_H(raw)
        self.md5 = hashlib.md5(raw).hexdigest()
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.ssdeep = ssdeep.hash_from_file(file)
        self.sections = pe.sections
        self.imports = pe.DIRECTORY_ENTRY_IMPORT
        self.bits = 32 if hex(pe.OPTIONAL_HEADER.Magic) == '0x10b' else 64

        self.manalyzer = ManalyzerData(MANALYZER_PATH, file)
        # self.floss = FlossData(FLOSS_PATH, file)

    def printFileInfo (self):
        print(f"{self.fileName:~^100}\n"
        f"   File Type: {self.fileType}\n"
        f"   MIME Type: {self.mimeType}\n"
        f"   Size:      {self.size}\n"
        f"   Entropy:   {round(self.entropy,3)}\n\n"

        f"   MD5:       {self.md5}\n"
        f"   SHA-256:   {self.sha256}\n"
        f"   SSDEEP:    {self.ssdeep}\n")

    def printPEInfo (self):
        print(f"{'PE Information':~^100}\n"
        f"   {self.bits}-bit program")
        for i in self.manalyzer.summary() :
            print (f"   {i+':':<20} {self.manalyzer.summary()[i]}")
        print()

    def printSectionInfo (self):
        print(f"{'Sections':~^100}")
        for section in self.sections:
            x = section.Name.decode().rstrip(chr(0))
            print(f"   {x:<10}{dic.dSections.get(x, 'Unknown')}\n"
            f"        Virtual Size - {section.Misc_VirtualSize}\n"
            f"        Rawdata Size - {section.SizeOfRawData}\n"
            )

    def printImportInfo (self):
        print(f"{'Imports':~^100}")
        for entry in self.imports:
            print (f"   {entry.dll.decode().strip()}")


class ManalyzerData:
    '''Data object that houses output from Manalyzer '''

    def __init__ (self, path, file):
        x = subprocess.getoutput(f"{path} {file} --plugins=all -o json").split('\n')
        self.jsonArr = json.loads("{" + "".join(x[x.index("{")+2:-1]))

    def summary (self):
        return self.jsonArr["Summary"]

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

def main ():
    dataObj = MetaDataObject (FILE)

    # Print out file information
    dataObj.printFileInfo()

    # Print out PE information
    dataObj.printPEInfo()

    # Print out section information from pecheck
    dataObj.printSectionInfo()

    # Print out imported dlls
    dataObj.printImportInfo()

if __name__ == "__main__":
    main ()

# for entry in pe.DIRECTORY_ENTRY_IMPORT:
    # print(str(entry.dll)[2:-1])
    # dictInfo["imports"].append(entry.dll.decode().strip())
    # for imp in entry.imports:
        # dictInfo["apis"].append(imp.name.decode().strip())

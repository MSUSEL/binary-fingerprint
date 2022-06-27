import math
import os
import hashlib
import subprocess
import json
import string
import imagehash
import pefile
import magic
import ssdeep
import numpy as np
import InfoDicts as dic
from PIL import Image as im

ALPHABET = string.ascii_letters
FLOSS_PATH = "/home/ryan/Downloads/MalwareTools/Floss/floss"
MANALYZER_PATH = "/home/ryan/Downloads/MalwareTools/Manalyze/bin/manalyze"
FILE = "/home/ryan/MalFiles/PEFiles/lokibot"
SAVE_IMAGE = True
SAVE_PATH = "./images/lokibot/"
WIDTH_TABLE=[(10,32), (30,64), (60,128), (100,256), (200,384), (500,512), (1000,768), (1001,1024)]

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
        self.images = ImageData(file, self.size, SAVE_IMAGE)
        # self.floss = FlossData(FLOSS_PATH, file)

    def printFileInfo (self):
        print(f"{self.fileName:~^100}\n"
        f"   File Type: {self.fileType}\n"
        f"   MIME Type: {self.mimeType}\n"
        f"   Size:      {self.size}\n"
        f"   Entropy:   {round(self.entropy,3)}\n\n"

        f"   MD5:       {self.md5}\n"
        f"   SHA-256:   {self.sha256}\n"
        f"   SSDEEP:    {self.ssdeep}\n"
        f"   IMAGE:     {self.images.returnHash('full')}\n")

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
            f"        Image Hash   - {self.images.returnHash(x)}\n"
            f"        Entropy      - {section.get_entropy()}\n"
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

class ImageData:
    '''Data object that houses information about images'''

    def __init__ (self, file, size, save=False):
        pe = pefile.PE(file)
        self.file = file
        self.pe = pe
        self.hashes = self.partImage(save)
        self.hashes.update(self.fullImage(size, save))

    def returnHash (self, name):
        return self.hashes[name]

    def fullImage (self, size, save):
        if size/1024 > 20000:
            return {"full": 0}

        width = 1
        for x in WIDTH_TABLE:
            if x[0] < size:
                width = x[1]

        array = []
        with open(self.file, "rb") as f:
            while byte := f.read(width):
                array.append(list(byte))
        while (len(array[-1]) < width):
            array[-1].append(0)

        np_array = np.array(array)
        data = im.fromarray((np_array * 255).astype(np.uint8))
        if save:
            data.save(f"{SAVE_PATH}full.png")

        return {"full":imagehash.average_hash(data)}

    def partImage (self, save):
        hashes = {}
        for i in self.pe.sections:
            name = i.Name.decode().rstrip(chr(0))
            bincode = self.pe.get_data(i.PointerToRawData, i.SizeOfRawData)

            if len(bincode) == 0:
                hashes[name] = 0
                continue

            width = math.ceil(math.sqrt(len(bincode)))
            bincode += b"\x00"*(width**2 - len(bincode))

            array = [[bincode[x] for x in range(y*width, (y+1)*width)] for y in range(width)]
            np_array = np.array(array)
            data = im.fromarray((np_array * 255).astype(np.uint8))

            if save:
                data.save(f"{SAVE_PATH}{name}.png")

            hashes[name] = imagehash.average_hash(data)
        return hashes

    def importImage (self, save):
        return False

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
    if SAVE_IMAGE:
        try:
            os.stat(SAVE_PATH)
        except:
            os.makedirs(SAVE_PATH)
    main ()

# for entry in pe.DIRECTORY_ENTRY_IMPORT:
    # print(str(entry.dll)[2:-1])
    # dictInfo["imports"].append(entry.dll.decode().strip())
    # for imp in entry.imports:
        # dictInfo["apis"].append(imp.name.decode().strip())

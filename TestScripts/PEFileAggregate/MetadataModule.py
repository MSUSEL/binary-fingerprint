import subprocess
import json
import hashlib
import pefile
import magic
import ssdeep
import InfoDicts as dic
import ImageModule as im

MANALYZER_PATH = "/home/ryan/Downloads/MalwareTools/Manalyze/bin/manalyze"
SAVE_IMAGE = True

class MetaDataObject:
    '''Data object that houses all meta data pulled from the PE file'''

    saveData = {}

    def __init__ (self, file):
        pe = pefile.PE(file)
        raw = pe.write()

        self.manalyzer = ManalyzerData(MANALYZER_PATH, file)
        self.images = im.ImageData(file, len(raw), SAVE_IMAGE)
        # self.floss = FlossData(FLOSS_PATH, file)

        self.saveData["fileName"] = file
        self.saveData["fileType"] = magic.from_file(file)
        self.saveData["mimeType"] = magic.from_file(file, mime=True)
        self.saveData["size"] = len(raw)
        self.saveData["entropy"] = pe.sections[0].entropy_H(raw)
        self.saveData["md5"] = hashlib.md5(raw).hexdigest()
        self.saveData["sha256"] = hashlib.sha256(raw).hexdigest()
        self.saveData["ssdeep"] = ssdeep.hash_from_file(file)
        print(pe.dump_info())
        print(pe.dump_dict()['Version Information'][0][2])
        self.saveData.update(self.manalyzer.summary())
        print (self.saveData)

        self.sections = pe.sections
        self.imports = pe.DIRECTORY_ENTRY_IMPORT
        self.bits = 32 if hex(pe.OPTIONAL_HEADER.Magic) == '0x10b' else 64

    def printFileInfo (self):
        print(f"{self.saveData['fileName']:~^100}\n"
        f"   File Type: {self.saveData['fileType']}\n"
        f"   MIME Type: {self.saveData['mimeType']}\n"
        f"   Size:      {self.saveData['size']}\n"
        f"   Entropy:   {round(self.saveData['entropy'],3)}\n\n"

        f"   MD5:       {self.saveData['md5']}\n"
        f"   SHA-256:   {self.saveData['sha256']}\n"
        f"   SSDEEP:    {self.saveData['ssdeep']}\n")
        # f"   IMAGE:     {self.images.returnHash('full')}\n")

    def printHeaderInfo (self):
        print (f"{'Header Information':~^100}\n"
                )

    def printPEInfo (self):
        print(f"{'Manalyzer Information':~^100}\n"
        f"   {self.bits}-bit program")
        for i in self.manalyzer.summary() :
            print (f"   {i+':':<20} {self.manalyzer.summary()[i]}")
        print()

    def printSectionInfo (self):
        print(f"{'Sections':~^100}")
        for section in self.sections:
            x = section.Name.decode().rstrip(chr(0))
            print(f"   {x:<10}{dic.dSections.get(x, 'Unknown')}\n"
            # f"        Image Hash   - {self.images.returnHash(x)}\n"
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

import os
import string

import MetadataModule as mm

ALPHABET = string.ascii_letters
FILE = "/home/ryan/MalFiles/PEFiles/lokibot"
SAVE_IMAGE = False
SAVE_PATH = "./images/shino"

def main ():
    dataObj = mm.MetaDataObject (FILE)

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
        os.makedirs(SAVE_PATH, exist_ok=True)

    main ()

# for entry in pe.DIRECTORY_ENTRY_IMPORT:
    # print(str(entry.dll)[2:-1])
    # dictInfo["imports"].append(entry.dll.decode().strip())
    # for imp in entry.imports:
        # dictInfo["apis"].append(imp.name.decode().strip())

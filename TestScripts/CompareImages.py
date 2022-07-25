import json
import argparse
import imagehash
import numpy as np

class FileObject ():
    def __init__ (self, jsonObj):
        self.name = jsonObj["name"]
        self.packer = jsonObj["packer"]
        self.icon = jsonObj["ico"]
        self.full = jsonObj["full"]
        self.sections = jsonObj["sections"]

    def SectionNames (self):
        return self.sections.keys()

    def SectionHashes (self, name):
        return self.sections[name][1:]

    def IconHashes (self):
        return self.icon[1:]

    def FullHashes (self):
        return self.full[1:]

def CompareLists (l1, l2):
    if not l1 or not l2:
        return []

    diffs = []
    for i in range(4):
        x = imagehash.hex_to_hash(l1[i])
        y = imagehash.hex_to_hash(l2[i])
        diffs.append(x - y)
    return diffs

def buildObjects (file):
    objs = []
    with open(file, "r", encoding='utf-8') as f:
        while item := f.readline():
            jsonObj = json.loads(item)
            objs.append(FileObject(jsonObj))
    return objs

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Processes the created metadata file from SectionedImage')
    parser.add_argument('-f', '--file', dest='file', type=str,
            help='the metadata file')

    args = parser.parse_args()


    if args.file is not None:
        objs = buildObjects(args.file)
        icoArr = [[0 for x in range(len(objs)-1)] for y in range(len(objs)-1)]
        for i in range (len(objs)-1):
            for j in range(i+1, len(objs)-1):
                print (f"Comparing {objs[i].name} & {objs[j].name}")

                icos = np.array(CompareLists(objs[i].IconHashes(), objs[j].IconHashes()))
                if len(icos) > 0 and np.average(icos) == 0:
                    icoArr[i][j], icoArr[j][i] = 1, 1
                print (f"   Icons: {icos}")

                print (f"   Full: {CompareLists (objs[i].FullHashes(), objs[j].FullHashes())}\n")

                matches = []
                randoms = []
                for x in objs[i].SectionNames():
                    for y in objs[j].SectionNames():
                        res = CompareLists(objs[i].SectionHashes(x), objs[j].SectionHashes(y))

                        if x == y:
                            matches.append(f"        {x} & {y}: {res}")
                        else:
                            randoms.append(f"        {x} & {y}: {res}")

                mostSections = max(len(objs[i].SectionNames()), len(objs[j].SectionNames()))
                print (f"   Matched ({len(matches)}/{mostSections}):")
                print('\n'.join(matches))
                # print ("\n   Others:")
                # print('\n'.join(randoms))
                print ()

    else:
        parser.print_help()

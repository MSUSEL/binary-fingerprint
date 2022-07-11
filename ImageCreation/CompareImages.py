import json
import argparse
import imagehash

class FileObject ():
    def __init__ (self, jsonObj):
        self.name = jsonObj["name"]
        self.packer = jsonObj["packer"]
        self.icon = jsonObj["ico"]
        self.full = jsonObj["full"]
        self.sections = jsonObj["sections"]

    # def AverageHashes (self):
        # return [self.sections[x][1] for x in self.sections]

    # def CropResitantHashes (self):
        # return [self.sections[x][2] for x in self.sections]

    # def WaveletHashes (self):
        # return [self.sections[x][3] for x in self.sections]

    # def PerceptualHashes (self):
        # return [self.sections[x][4] for x in self.sections]

    # def DifferenceHashes (self):
        # return [self.sections[x][5] for x in self.sections]
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
        return None

    diffs = []
    for i in range(5):
        if i == 1:
            continue

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
        for i in range (len(objs)-1):
            for j in range(i+1, len(objs)-1):
                print (f"Comparing {objs[i].name} & {objs[j].name}")
                print (f"   Icons: {CompareLists (objs[i].IconHashes(), objs[j].IconHashes())}")
                print (f"   Full: {CompareLists (objs[i].FullHashes(), objs[j].FullHashes())}")
                print ("   Sections: ")

                for x in objs[i].SectionNames():
                    for y in objs[j].SectionNames():
                        if x == y:
                            res = CompareLists(objs[i].SectionHashes(x), objs[j].SectionHashes(y))
                            print (f"        {x} & {y}: {res}")
                print ()
    else:
        parser.print_help()

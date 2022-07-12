#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This is a program to create black and white images from PE files
"""

import time
import os
import re
import subprocess
import argparse
import json
import imagehash
import pefile
import numpy as np
from PIL import Image as im
from extracticon import ExtractIcon

# WIDTH_TABLE=[(10,32), (30,64), (60,128), (100,256), (200,384), (500,512), (1000,768), (1001,1024)]

class SectionPE ():

    MAX_FILE_SIZE = 50000 * 1024

    def __init__ (self, file, out, width, low):
        self.file = os.path.expanduser(file)
        self.width = width
        self.threshold = low * width
        name = os.path.basename(file).split('.')[0]

        if out[-1] == '/':
            out = out[0:-1]
        self.out = f"{out}/{name}/"

        if os.stat(self.file).st_size > self.MAX_FILE_SIZE:
            print ("    Error; File too big")
            return

        try:
            self.pe = pefile.PE(self.file, fast_load=True)
        except Exception as e:
            print (f"    Error ({name}): {e}")
            return

        os.makedirs(self.out, exist_ok=True)
        os.makedirs(self.out + "icos/", exist_ok=True)

        info = {'name': name}
        try:
            pepack = subprocess.run(['pepack', self.file], capture_output=True, check=True)
            info["packer"] = pepack.stdout.decode()[8:].strip()
        except Exception:
            info["packer"] = "NaN"

        info["sections"] = self.partImage()
        info.update(self.fullImage())
        info.update(self.extractIcos())
        # self.extractImages()

        with open(f"{out}/details.txt", "a+", encoding='utf-8') as f:
            f.write(json.dumps(info)+'\n')

        print("Done\n")

    def gethashes(self, img):
        x = [str(imagehash.average_hash(img)),
             # str(imagehash.crop_resistant_hash(img)),
             str(imagehash.whash(img)),
             str(imagehash.phash(img)),
             str(imagehash.dhash(img))]
        return x

    def fullImage (self):
        array = []
        with open(self.file, "rb") as f:
            while byte := f.read(self.width):
                array.append(list(byte))

        array[-1] += [0 for x in range(self.width-len(array[-1]))]

        np_array = np.array(array)
        data = im.fromarray((np_array * 255).astype(np.uint8))
        data.save(f"{self.out}/full.png")
        return {'full': [os.stat(self.file).st_size] + self.gethashes(data)}

    def partImage (self):
        saved = {}
        with open(self.file, "rb") as f:
            for i in self.pe.sections:
                name = i.Name.decode().rstrip(chr(0))
                start = i.PointerToRawData
                size = i.SizeOfRawData
                if size < self.threshold:
                    continue

                f.seek(start)
                bincode = f.read(size)
                bincode += b"\x00"*(self.width-(len(bincode)%self.width))
                array = [[bincode[x] for x in range(y*self.width, (y+1)*self.width)]
                        for y in range(int(len(bincode)/self.width))]

                np_array = np.array(array)
                data = im.fromarray((np_array * 255).astype(np.uint8))
                data.save(f"{self.out}/{name.replace('.','')}.png")
                saved[name.replace('.','')] = [size] + self.gethashes(data)
        return saved

    def extractImages (self):
        count = 0
        with open(self.file, "rb") as f:
            read_file = f.read()
            png = rb"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A[\s\S]*?\x49\x45\x4E\x44"
            for img in re.findall(png, read_file):
                with open(f"{self.out}/icos/a{count}.png", "wb") as g:
                    g.write(img)
                count += 1

            jpg = rb"\xFF\xD8\xFF[\s\S]*?\xFF\xD9"
            for img in re.findall(jpg, read_file):
                with open(f"{self.out}/icos/a{count}.jpg", "wb") as g:
                    g.write(img)
                count += 1

            gif = rb"\x00\x00\x3B[\s\S]*?\x47\x49\x46\x38\x39\x61"
            for img in re.findall(gif, read_file):
                with open(f"{self.out}/icos/a{count}.gif", "wb") as g:
                    g.write(img)
                count += 1

    def extractIcos(self):
        self.pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        extractor = ExtractIcon(self.pe)

        groups = extractor.get_group_icons()

        largest = None
        size = 0
        for group in groups:
            for i in range(len(group)):
                img = extractor.export(group, i)
                img.save(f"{self.out}/icos/b{i}.png")
                x = os.stat(f"{self.out}/icos/b{i}.png").st_size
                if x > size:
                    size = x
                    largest = img

        if largest is not None:
            return {"ico": [size] + self.gethashes(largest)}
        return {"ico": []}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create black and white images from PE files')
    parser.add_argument('-f', '--file', dest='file', type=str,
            help='the single file to parse to image')
    parser.add_argument('-d', '--directory', dest='dir', type=str,
            help='the directory to parse')
    parser.add_argument('-l', '--list', dest='list', type=str,
            help='a file containing file paths to be parsed')
    parser.add_argument('-o', '--output_folder', dest='out', type=str, default='imgs',
            help='parent directory to save images to')
    # parser.add_argument('--depth', dest='depth', type=int, default=0,
            # help='Amount of subdirectories to scan')
    parser.add_argument('-s', '--save_metadata', dest='meta', action='store_true',
            help='option to save metadata about the file')
    parser.add_argument('-w', '--width', dest='width', type=int, default=512,
            help='width of generated image')
    parser.add_argument('-mi', '--min_size', dest='min', type=int, default=3,
            help='minimum size of section in order to be saved')
    parser.add_argument('-ma', '--max_count', dest='max', type=int, default=-1,
            help='maximum number of files to process; default is all')

    args = parser.parse_args()
    start = time.time()

    # If a single file was specified
    if args.file is not None:
        print ("Processing", args.file)
        SectionPE(args.file, args.out, args.width, args.min)
        print (f"Processed 1 in {time.time() - start:.2} seconds")

    # If a directory was specified
    elif args.dir is not None:
        count = 0
        try:
            directories = [args.dir]
            while len(directories) > 0:
                for file in os.listdir(directories[0]):
                    if args.max != -1 and args.max <= count:
                        raise Exception ("Reached specified count")
                    if os.path.isfile(directories[0]+'/'+file):
                        print ("Processing", directories[0]+'/'+file)
                        SectionPE(directories[0]+'/'+file, args.out, args.width, args.min)
                    else:
                        directories.append(args.dir+'/'+file)
                    count += 1
                del directories[0]
        except Exception as e:
            print (e)
            # sys.exit(1)
        print (f"Processed {count} in {time.time() - start:.2} seconds")

    # if a file specifying a list of files is passed in
    elif args.list is not None:
        count = 0
        with open(args.list, "r", encoding='utf-8') as f:
            while item := f.readline():
                if args.max != -1 and args.max <= count:
                    raise Exception ("Reached specified count")
                print ("Processing", item.strip())
                try:
                    SectionPE(item.strip(), args.out, args.width, args.min)
                    count += 1
                except Exception as e:
                    print(e)
                    # sys.exit(1)
                print ()
        print (f"Processed {count} in {time.time()-start:.2f} seconds")

    else:
        parser.print_help()

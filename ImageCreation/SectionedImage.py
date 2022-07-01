#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This is a program to create black and white images from PE files
"""

import sys
import os
import re
import argparse
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

        self.partImage()
        self.fullImage()
        # self.extractImages()
        self.extractIcos()

    def fullImage (self):
        array = []
        with open(self.file, "rb") as f:
            while byte := f.read(self.width):
                array.append(list(byte))

        array[-1] += [0 for x in range(self.width-len(array[-1]))]

        np_array = np.array(array)
        data = im.fromarray((np_array * 255).astype(np.uint8))
        data.save(f"{self.out}/full.png")

    def partImage (self):
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
                data.save(f"{self.out}/({name}).png")

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

        for group in groups:
            for i in range(len(group)):
                img = extractor.export(group, i)
                img.save(f"{self.out}/icos/b{i}.png")

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
    parser.add_argument('-m', '--min_size', dest='min', type=int, default=3,
            help='minimum size of section in order to be saved')

    args = parser.parse_args()

    # If a single file was specified
    if args.file is not None:
        print ("Processing", args.file)
        x = SectionPE(args.file, args.out, args.width, args.min)

    elif args.dir is not None:
        try:
            for file in os.listdir(args.dir):
                if os.path.isfile(args.dir+'/'+file):
                    print ("Processing", args.dir+'/'+file)
                    x = SectionPE(args.dir+'/'+file, args.out, args.width, args.min)
        except Exception as e:
            print (e)
            sys.exit(1)

    elif args.list is not None:
        try:
            with open(args.list, "r", encoding='utf-8') as f:
                while item := f.readline():
                    print ("Processing", item.strip())
                    x = SectionPE(item.strip(), args.out, args.width, args.min)
        except Exception as e:
            print(e)
            sys.exit(1)

    else:
        parser.print_help()

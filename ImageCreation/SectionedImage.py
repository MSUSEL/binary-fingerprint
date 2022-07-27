#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This is a program to create black and white images from PE files
"""

import time
import os
import subprocess
import argparse
import json
import imagehash
import pefile
import numpy as np
from PIL import Image as im
from extracticon import ExtractIcon

MAX_FILE_SIZE = 50000 * 1024

def getHashes(img):
    return [str(imagehash.average_hash(img)),
            str(imagehash.whash(img)),
            str(imagehash.phash(img)),
            str(imagehash.dhash(img))]

def fileToImage (file, outRoot, width, low):
    # Set up variables
    file = os.path.expanduser(file)
    threshold = low * width
    name = os.path.basename(file).split('.')[0]
    out = os.path.join(outRoot, name)
    info = {'name': name}

    # Limit how big a file can be to process
    if os.stat(file).st_size > MAX_FILE_SIZE:
        return "Error; File too big"

    # Attempt to load as a PE file
    try:
        pe = pefile.PE(file, fast_load=True)
    except Exception as e:
        return f"Error: {e}"

    # Attempt to add packer information
    try:
        pepack = subprocess.run(['pepack', file], capture_output=True, check=True)
        info["packer"] = pepack.stdout.decode()[8:].strip()
    except Exception:
        info["packer"] = "NaN"

    # Save image and add image hashes to info
    try:
        os.makedirs(out, exist_ok=True)
        os.makedirs(out + "/icos/", exist_ok=True)
        info["sections"] = partImage(file, pe, out, width, threshold)
        info.update(fullImage(file, out, width))
        info.update(extractIcos(pe, out))
    except Exception as e:
        return e

    # Append information to details file
    with open(f"{outRoot}/details.txt", "a+", encoding='utf-8') as f:
        f.write(json.dumps(info)+'\n')

    return "Done"

def fullImage (file, out, width):
    # Read file a with at a time into array
    array = []
    with open(file, "rb") as f:
        while byte := f.read(width):
            array.append(list(byte))
    array[-1] += [0 for x in range(width-len(array[-1]))]

    # Convert to np array and use pillow to save as black and white image
    np_array = np.array(array)
    data = im.fromarray((np_array * 255).astype(np.uint8))
    data.save(f"{out}/full.png")
    return {'full': [os.stat(file).st_size] + getHashes(data)}

def partImage (file, pe, out, width, threshold):
    saved = {}
    with open(file, "rb") as f:
        for i in pe.sections:
            # Find start and end of section
            name = i.Name.decode().rstrip(chr(0))
            start = i.PointerToRawData
            size = i.SizeOfRawData

            # If the section size is too small skip it
            if size < threshold:
                continue

            # Seek to the start of section in file, read data
            # Cut the data into 2d array of widths
            f.seek(start)
            bincode = f.read(size)
            bincode += b"\x00"*(width-(len(bincode)%width))
            array = [[bincode[x] for x in range(y*width, (y+1)*width)]
                    for y in range(int(len(bincode)/width))]

            # Convert to np arry and use pillow to save as black and white image
            np_array = np.array(array)
            data = im.fromarray((np_array * 255).astype(np.uint8))
            data.save(f"{out}/{name.replace('.','')}.png")
            saved[name.replace('.','')] = [size] + getHashes(data)
    return saved

def extractIcos(pe, out):
    # Load the resources directory and send to external script to extract icons
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
    extractor = ExtractIcon(pe)
    groups = extractor.get_group_icons()

    # Go through each extracted icon
    largest = None
    size = 0
    for i, group in enumerate(groups):
        img = extractor.export(group, i)
        img.save(f"{out}/icos/b{i}.png")
        x = os.stat(f"{out}/icos/b{i}.png").st_size
        if x > size:
            size = x
            largest = img

    # Return image hash is there is an icon otherwise skip
    if largest is not None:
        return {"ico": [size] + getHashes(largest)}
    return {"ico": []}

def saveInfo (file, outRoot, width, low):
    # Append the result of each attempt to res file as well as prints it
    with open(f"{outRoot}/res.txt", "a+", encoding='utf-8') as f:
        print (f"Processing {file}")
        f.write(f"Processing {file}\n")

        retVal = fileToImage(file, outRoot, width, low)
        print (retVal + '\n')
        f.write(retVal + '\n\n')

def generateReport (out):
    print ("\nGenerating Report:")

    # Variables
    res = os.path.join(out,"res.txt")
    det = os.path.join(out,"details.txt"))
    total, success = 0, 0
    packers, icons = 0, 0
    sections = {}

    # Dictionary containing all tracked errors
    errDic = {"File Not Found" : 0, "Header Length Issue" : 0, "DOS Header Magic" : 0,
              "Unknown File Extension" : 0, "Invalid NT Header" : 0, "Invalid e_lfanew" : 0,
              "Embedded null byte" : 0, "Invalid start byte" : 0, "Invalid continuation byte" : 0,
              "NoneType cant save" : 0, "Data cant be fetched" : 0, "Index out of range" : 0, "Others" : 0}

    # Open the results file and count errors and successes
    with open(res, "r", encoding='utf-8') as f:
        while item := f.readline():
            if "Processing" in item:
                total += 1
            elif item == "Done\n":
                success += 1
            else:
                errDic["File Not Found"] += 1 if "[Errno 2]" in item else 0
                errDic["Invalid NT Header"] += 1 if "NT Headers" in item else 0
                errDic["Invalid start byte"] += 1 if "start byte" in item else 0
                errDic["Invalid e_lfanew"] += 1 if "e_lfanew" in item else 0
                errDic["Invalid continuation byte"] += 1 if "continuation byte" in item else 0
                errDic["Index out of range"] += 1 if "out of range" in item else 0
                errDic["Embedded null byte"] += 1 if "null byte" in item else 0
                errDic["Unknown File Extension"] += 1 if "file extension" in item else 0
                errDic["NoneType cant save"] += 1 if "NoneType" in item else 0
                errDic["Header Length Issue"] += 1 if "length less" in item else 0
                errDic["Data cant be fetched"] += 1 if "be fetched" in item else 0
                errDic["DOS Header Magic"] += 1 if "DOS Header magic not found" in item else 0

    # Open the details sections to number of sections
    with open(det, "r", encoding='utf-8') as f:
        while item := f.readline():
            jsonObj = json.loads(item)
            x = len(jsonObj["sections"])
            sections.setdefault(x, 0)
            sections[x] += 1
            icons += 1 if len(jsonObj["ico"]) > 0 else 0
            packers += 1 if jsonObj["packer"] != "no packer found" else 0

    # Join dictionaries together
    errorCounts = "\n".join([f"{v:6} - {k} " for (k, v) in sorted(errDic.items(), key=lambda item: item[1], reverse=True) if v>0])
    sectionCounts = "\n".join(list(f"{v:6} - {k} Sections" for (k, v) in sorted(sections.items())))

    # Report text creation
    outStr =  f"Errors:\n{errorCounts}\n\n"
    outStr += f"Total In: {total}\n"
    outStr += f"Total Success: {success}\n"
    outStr += f"Total Errors: {sum(errDic.values())}\n\n"

    outStr += f"Section Counts:\n{sectionCounts}\n\n"
    outStr += f"With Icons: {icons}\nWithout Icons: {total-icons}\n\n"
    outStr += f"Packed: {packers}\nNot Packed: {total-packers}"

    # Prints and saves the report
    with open(os.path.join(args.out, "report.txt"), "w", encoding='utf-8') as f:
        print (outStr)
        f.write(outStr)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create black and white images from PE files')
    parser.add_argument('-f', '--file', dest='file', type=str,
            help='A single file to parse to image')
    parser.add_argument('-d', '--directory', dest='dir', type=str,
            help='A directory to parse')
    parser.add_argument('-l', '--list', dest='list', type=str,
            help='A file containing file paths to be parsed')
    parser.add_argument('-o', '--output_folder', dest='out', type=str, default='imgs',
            help='Output directory to save images')
    parser.add_argument('-w', '--width', dest='width', type=int, default=512,
            help='Width of generated image')
    parser.add_argument('-mi', '--min_size', dest='min', type=int, default=3,
            help='Minimum height of section in order to be saved')
    parser.add_argument('-ma', '--max_count', dest='max', type=int, default=-1,
            help='Maximum number of files to process; default is all')

    args = parser.parse_args()
    start = time.time()

    os.makedirs(args.out, exist_ok=True)
    count = 0

    try:
        # If a single file was specified
        if args.file is not None:
            saveInfo (args.file, args.out, args.width, args.min)
            count += 1

        # If a directory was specified
        elif args.dir is not None:
            for directory, sublist, filelist in os.walk(args.dir):
                for file in filelist:
                    if args.max != -1 and args.max <= count:
                        raise KeyboardInterrupt

                    path = os.path.join(directory, file)
                    if os.path.isfile(path):
                        saveInfo (path, args.out, args.width, args.min)
                        count += 1

        # If a file specifying a list of files is passed in
        elif args.list is not None:
            count = 0
            with open(args.list, "r", encoding='utf-8') as f:
                while item := f.readline():
                    if args.max != -1 and args.max <= count:
                        raise KeyboardInterrupt

                    saveInfo (item.strip(), args.out, args.width, args.min)
                    count += 1

        # Otherwise proper usage hasn't been met
        else:
            parser.print_help()

    except KeyboardInterrupt:
        print ("Exiting...")
    finally:
        # Construct, save, and print a report on program end
        print (f"\nProcessed {count} in {time.time()-start} seconds")
        generateReport(args.out)

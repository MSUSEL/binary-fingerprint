import os
import time
import json
import argparse
import numpy as np
from PIL import ImageChops, Image

def calcdiff(im1, im2):
    im2 = Image.open(im2)
    try:
        dif = ImageChops.difference(im1, im2)
        return np.mean(np.array(dif))
    except Exception:
        return 99999

def constructMatrix (file, directory, threshold):
    dic = {}
    with open (file, "r", encoding='utf-8') as f:
        while line := f.readline():
            dic[json.loads(line)["name"]] = []

    folderWithIcos = []
    for folder in os.listdir(directory):
        if len(os.listdir(f"{directory}/{folder}/icos")) > 0:
            folderWithIcos.append(folder)

    while folder := folderWithIcos.pop(0):
        ico = os.listdir(f"{directory}/{folder}/icos")
        if len(ico) > 0:
            try:
                for baseIcon in ico:
                    im1 = Image.open(f"{directory}/{folder}/icos/{baseIcon}")
                    for cmpFld in folders:
                        for im2 in os.listdir(f"{directory}/{cmpFld}/icos"):
                            diff = calcdiff(im1, f"{directory}/{cmpFld}/icos/{im2}")
                            if diff < threshold:
                                dic[folder].append(cmpFld)
                                dic[cmpFld].append(folder)
                                print (folder, cmpFld, diff)
                                raise Exception
            except Exception:
                continue
    print (dic)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create matrix of similar things')
    parser.add_argument("-d", "--directory", dest="dir", type=str, required=True,
            help='directory to scan')
    parser.add_argument("-f", '--details', dest='det', type=str, required=True,
            help='detail file to load')
    parser.add_argument("-t", '--threshold', dest='thresh', type=int, default=2,
            help='comparison index')

    args = parser.parse_args()

    start = time.time()

    constructMatrix(args.det, args.dir, args.thresh)

    print (f"Finished in {time.time() - start} seconds")

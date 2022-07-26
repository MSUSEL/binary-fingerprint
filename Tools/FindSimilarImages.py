import argparse
import time
import os
import numpy as np
from PIL import ImageChops, Image

def buildDic (file):
    dic = {}
    with open(file, "r", encoding='utf-8') as f:
        while line := f.readline():
            arr = line.split('\t')
            dic[arr[1]] = arr[3].strip().replace('.', '_')
    return dic

def calcdiff(im1, im2):
    im2 = Image.open(im2)
    try:
        dif = ImageChops.difference(im1, im2)
        return np.mean(np.array(dif))
    except Exception:
        return 99999

def findImages (cmpimg, root, threshold, dic):
    im1 = Image.open(cmpimg)
    count, total = 0, 0

    for directory, sublist, filelist in os.walk(root):
        for file in filelist:
            dif = calcdiff (im1, os.path.join(directory, file))
            if dif < threshold:
                classif = dic.get(file.split('.')[0], 'NA')
                if classif == 'NA':
                    classif = dic.get(directory.split('/')[-1], 'NA')
                if classif == 'NA':
                    classif = dic.get(directory.split('/')[-2], 'NA')

                print(f"{os.path.join(directory, file)} - {classif}")
                count += 1
            total += 1

    print (f"Found {count}/{total} matching images")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Find similar images')
    parser.add_argument('-i', '--image', dest='img', type=str, required=True,
            help='Image to to compare against')
    parser.add_argument('-d', '--directory', dest='dir', type=str, required=True,
            help='Directory to scan')
    parser.add_argument('-c', '--classif', dest='classif', type=str,
            help='Optional file containing hashes and classif info')
    parser.add_argument('-t', '--threshold', dest='thresh', type=int, default=10,
            help='Threshold to be considered the same image')


    args = parser.parse_args()
    start = time.time()

    dic = buildDic(args.classif) if args.classif is not None else {}
    findImages(args.img, args.dir, args.thresh, dic)

    print (f"Finished in {time.time() - start} seconds")

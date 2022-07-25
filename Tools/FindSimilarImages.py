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
    dirs = [root]
    count = 0
    total = 0
    while len(dirs) > 0:
        for file in os.listdir(dirs[0]):
            if os.path.isfile(dirs[0]+'/'+file):
                dif = calcdiff (im1, dirs[0]+'/'+file)
                if dif < threshold:
                    classif = dic.get(file.split('.')[0], 'NA')
                    if classif == 'NA':
                        classif = dic.get(dirs[0].split('/')[-1], 'NA')
                    if classif == 'NA':
                        classif = dic.get(dirs[0].split('/')[-2], 'NA')

                    print(f"{dirs[0]}/{file} - {classif}")
                    count += 1
            else:
                dirs.append(dirs[0]+'/'+file)
            total += 1
        del dirs[0]

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

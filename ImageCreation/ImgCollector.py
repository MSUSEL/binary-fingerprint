import argparse
import shutil
import os

def buildDic (file):
    dic = {}
    with open(file, "r", encoding='utf-8') as f:
        while line := f.readline():
            arr = line.split('\t')
            dic[arr[1]] = arr[3].strip().replace('.', '_')
    return dic

def saveImgs (root, out, dic):
    os.makedirs(out, exist_ok=True)

    for folder in os.listdir(root):
        path = root +'/' + folder
        if os.path.isdir (path):
            imgs = [x for x in os.listdir(path) if not os.path.isdir(f"{path}/{x}")]

            subfolder = dic.get(folder, '')
            os.makedirs(out + '/' + subfolder, exist_ok=True)

            for i in imgs:
                shutil.copyfile(f"{path}/{i}",f'{out}/{subfolder}/{i}_{folder}.png')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Collect recovered icons from pe files')
    parser.add_argument('-o', '--output_folder', dest='out', type=str, default='icos',
            help='parent directory to save icos to')
    parser.add_argument('-d', '--directory', dest='dir', type=str, required=True,
            help='directory to scan from')
    parser.add_argument('-c', '--classif', dest='classif', type=str,
            help='file containing hashes and classif info')

    args = parser.parse_args()

    if args.classif is not None:
        dic = buildDic (args.classif)
        saveImgs (args.dir, args.out, dic)
    else:
        saveImgs (args.dir, args.out, {})

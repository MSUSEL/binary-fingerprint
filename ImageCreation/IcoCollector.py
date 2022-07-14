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


def saveIcos (root, out, dic):
    os.makedirs(out, exist_ok=True)

    for folder in os.listdir(root):
        if os.path.isdir (root + '/' + folder):
            path = root +'/' + folder + '/icos/'
            icos = os.listdir(path)
            x = sorted (icos, key=lambda ico : os.stat(path + ico).st_size, reverse=True)

            if len(x) > 0:
                subfolder = dic.get(folder, '')
                os.makedirs(out + '/' + subfolder, exist_ok=True)
                shutil.copyfile(f"{path}/{x[0]}",f'{out}/{subfolder}/{folder}.png')

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
        saveIcos (args.dir, args.out, dic)
    else:
        saveIcos (args.dir, args.out, {})

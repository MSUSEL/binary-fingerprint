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

def saveImgs (root, out, name, dic):
    os.makedirs(out, exist_ok=True)

    for folder in os.listdir(root):
        path = root +'/' + folder
        if os.path.isdir (path):
            imgs = [x for x in os.listdir(path) if not os.path.isdir(f"{path}/{x}")]

            subfolder = dic.get(folder, '')
            os.makedirs(out + '/' + subfolder, exist_ok=True)

            for i in imgs:
                if i in name:
                    shutil.copyfile(f"{path}/{i}",f'{out}/{subfolder}/{i}_{folder}.png')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Copy images or icons to one central folder')
    parser.add_argument('-o', '--output_folder', dest='out', type=str, default='collection',
            help='Output directory to save collected images')
    parser.add_argument('-d', '--directory', dest='dir', type=str, required=True,
            help='Directory to collect from')
    parser.add_argument('-c', '--classif', dest='classif', type=str,
            help='Optional file containing hashes and classif info')
    parser.add_argument('-i', '--icons', dest='ico', action='store_true',
            help='Option to collect icons')
    parser.add_argument('-n', '--name', dest='name', type=str, nargs='+',
            help='List of names of image to collect')

    args = parser.parse_args()

    if args.ico and args.name is not None:
        print ("Error: Use either -i for icons or specify name using -n")

    dic = buildDic (args.classif) if args.classif is not None else {}

    if args.ico:
        saveIcos (args.dir, args.out, dic)
    elif args.name is not None:
        saveImgs (args.dir, args.out, args.name, dic)
    else:
        print ("Error: Use either -i for icons or specify name using -n")

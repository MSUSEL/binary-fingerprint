import os
import shutil
import pickle
import argparse

def buildDic (file):
    dic = {}
    with open(file, "r", encoding='utf-8') as f:
        while line := f.readline():
            arr = line.split('\t')
            dic[arr[1]] = arr[3].strip().replace('.', '_')
    return dic

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Save cluster for easier viewing')
    parser.add_argument("-d", "--directory", dest="dir", type=str, required=True,
            help='Directory to scan')
    parser.add_argument("-l", "--list", dest="l", type=str, required=True,
            help='Cluster list to use')
    parser.add_argument("-n", "--cluster", dest="numb", type=int, required=True,
            help='Cluster number')
    parser.add_argument("-c", "--hashes", dest="classif", type=str, required=True,
            help='Classification file')
    parser.add_argument("-o", "--out", dest="out", type=str,
            help='Directory to save cluster to')

    args = parser.parse_args()

    dic = buildDic(args.classif)
    clusterDic = {}

    out = args.out if args.out is not None else f"cluster{args.numb}"
    os.makedirs(out, exist_ok=True)

    with open(args.l, "rb") as f:
        clusters = pickle.load(f)
        try:
            cluster = clusters[args.numb]
        except IndexError:
            print ("Error: Cluster not found")
            exit (1)

        for i in cluster:
            clusterDic.setdefault(dic[i], [])
            clusterDic[dic[i]].append(i)
            shutil.copytree(f"{args.dir}/{i}", f"{out}/{dic[i].replace('/','_')}-{i}")

    total = 0
    print (f"Cluster {args.numb} from {args.l}\n")
    for i in clusterDic:
        print (i)
        print ('\n'.join(clusterDic[i]))
        print ()
        total += len(clusterDic[i])
    print (f"Total Count: {total}")

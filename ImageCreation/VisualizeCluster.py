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
    parser = argparse.ArgumentParser(description='Create matrix of similar things')
    parser.add_argument("-d", "--directory", dest="dir", type=str, required=True,
            help='directory to scan from')
    parser.add_argument("-l", "--list", dest="l", type=str, required=True,
            help='pickled list')
    parser.add_argument("-n", "--cluster", dest="numb", type=int, required=True,
            help='cluster number')
    parser.add_argument("-c", "--hashes", dest="classif", type=str, required=True,
            help='classification file')
    parser.add_argument("-o", "--out", dest="out", type=str, default="collection",
            help='directory to save cluster to')

    args = parser.parse_args()

    dic = buildDic(args.classif)
    clusterDic = {}

    os.makedirs(args.out, exist_ok=True)

    with open(args.l, "rb") as f:
        clusters = pickle.load(f)
        cluster = clusters[args.numb]

        for i in cluster:
            clusterDic.setdefault(dic[i], [])
            clusterDic[dic[i]].append(i)
            shutil.copytree(f"{args.dir}/{i}", f"{args.out}/{dic[i].replace('/','_')}-{i}")

    print (f"Cluster {args.numb} from {args.l}\n")
    for i in clusterDic:
        print (i)
        print ('\n'.join(clusterDic[i]))
        print ()

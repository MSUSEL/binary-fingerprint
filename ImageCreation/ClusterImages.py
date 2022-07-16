import os
import time
import shutil
import argparse
import itertools
import pickle
import numpy as np
import networkx as nx
from PIL import ImageChops, Image

def buildDic (file):
    dic = {}
    with open(file, "r", encoding='utf-8') as f:
        while line := f.readline():
            arr = line.split('\t')
            dic[arr[1]] = arr[3].strip().replace('.', '_')
    return dic

def calcdiff(im1, im2, directory, f1, f2):
    im1 = Image.open(f"{directory}/{f1}/icos/{im1}")
    im2 = Image.open(f"{directory}/{f2}/icos/{im2}")
    try:
        dif = ImageChops.difference(im1, im2)
        return np.mean(np.array(dif))
    except Exception:
        return 99999

def constructMatrix (directory, out, hashfile, threshold):
    dic = {}

    print ("Finding icons:")
    folderWithIcos = []
    for folder in os.listdir(directory):
        for i in os.listdir(f"{directory}/{folder}/icos"):
            if os.stat(f"{directory}/{folder}/icos/{i}").st_size < 83:
                os.remove(f"{directory}/{folder}/icos/{i}")
                print (f"Removed {i} for being too small")
        if len(os.listdir(f"{directory}/{folder}/icos")) > 0:
            folderWithIcos.append(folder)

    print ("Running comparisons:")
    # folderWithIcos = folderWithIcos[:50]
    while folder := folderWithIcos.pop(0):
        initIcos = os.listdir(f"{directory}/{folder}/icos")
        for cmpFld in folderWithIcos:
            cmpIcos = os.listdir(f"{directory}/{cmpFld}/icos")
            cmps = [calcdiff(a, b, directory, folder, cmpFld) for (a, b) in itertools.product(initIcos, cmpIcos)]
            if min(cmps) < threshold:
                dic.setdefault(folder, [])
                dic[folder].append(cmpFld)
        if len(folderWithIcos) == 0:
            break

    print ("Creating Graph and clustering:")
    os.makedirs (out)
    g = nx.Graph(dic)
    nx.draw(g, with_labels=False)
    with open(f"{out}/graph.pkl", 'wb') as f:
        pickle.dump(g, f)

    clusterList = []
    for i in (g.subgraph(c) for c in nx.connected_components(g)):
        clusterList.append(list(i))
        # print (list(i))

    with open(f"{out}/list.pkl", 'wb') as f:
        pickle.dump(clusterList, f)

    labelClusters (directory, out, hashfile, f"{out}/list.pkl")

def labelClusters (directory, out, hashfile, pklfile):
    with open (pklfile, "rb") as f:
        clusterList = pickle.load(f)

    print ("Building Hash Database:")
    hashes = buildDic(hashfile)

    print ("Labeling and saving clusters:")
    for count, i in enumerate(clusterList):
        os.makedirs(f"{out}/cluster{count}")
        print (f"Cluster {count}: ")
        amts = {}
        for j in i:
            amts.setdefault(hashes[j], 0)
            amts[hashes[j]] += 1

            for ico in os.listdir(f"{directory}/{j}/icos"):
                shutil.copyfile(f"{directory}/{j}/icos/{ico}", f"{out}/cluster{count}/{ico.replace('b', j)}")

        for j in sorted(amts):
            print (f"{j} - {amts[j]}")
        print ()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create matrix of similar things')
    parser.add_argument("-d", "--directory", dest="dir", type=str, required=True,
            help='directory to scan from')
    parser.add_argument("-c", '--classif', dest='classif', type=str, required=True,
            help='file containing hashes and classif info')
    parser.add_argument("-t", '--threshold', dest='thresh', type=float, default=.5,
            help='comparison index')
    parser.add_argument('-o', '--output', dest='out', type=str, default='clusters',
            help='output directory')
    parser.add_argument("-l", '--list', dest='l', type=str,
            help='pickle file from saved clustered list')

    args = parser.parse_args()

    start = time.time()

    if args.l is not None:
        labelClusters(args.dir, args.out, args.classif, args.l)
    else:
        constructMatrix(args.dir, args.out, args.classif, args.thresh)

    print (f"Finished in {time.time() - start} seconds")

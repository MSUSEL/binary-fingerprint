import os
import sys
import time
import shutil
import argparse
import itertools
import pickle
import numpy as np
import networkx as nx
from PIL import ImageChops, Image

def buildDic (file):
    # Takes in file that is MD5 SHA256 Packer Classification
    dic = {}
    with open(file, "r", encoding='utf-8') as f:
        while line := f.readline():
            arr = line.split('\t')
            dic[arr[1]] = arr[3].strip().replace('.', '_')
    return dic

def calcdiff(im1, im2, directory, f1, f2):
    # Loads two images and compares them together using ImageChops
    im1 = Image.open(f"{directory}/{f1}/icos/{im1}")
    im2 = Image.open(f"{directory}/{f2}/icos/{im2}")
    try:
        dif = ImageChops.difference(im1, im2)
        return np.mean(np.array(dif))
    except Exception:
        return 99999

def constructImage (directory, threshold, name):
    print ("Finding Matching Images:")
    dic = {}
    folderWithImgs = []

    # Walks through directory to find specified images
    # Removes malformed (too small) images
    for folder in os.listdir(directory):
        if os.path.exists(f"{directory}/{folder}/{name}"):
            if os.stat(f"{directory}/{folder}/{name}").st_size < 83:
                os.remove(f"{directory}/{folder}/{name}")
                print (f"Removed {name} for being too small")
            else:
                folderWithImgs.append(folder)

    # Determines if anything was found
    if len(folderWithImgs) == 0:
        print ("No matches found, exiting....")
        sys.exit(1)
    else:
        print (f"Found {len(folderWithImgs)} matching images")

    # Starts running comparisons between images
    print ("Running comparisons:")
    while folder := folderWithImgs.pop(0):
        im1 = Image.open(f"{directory}/{folder}/{name}")
        for cmpFld in folderWithImgs:
            try:
                im2 = Image.open(f"{directory}/{cmpFld}/{name}")
                dif = ImageChops.difference(im1, im2)
                if np.mean(np.array(dif)) < threshold:
                    dic.setdefault(folder, [])
                    dic[folder].append(cmpFld)
            except Exception:
                continue
        if len(folderWithImgs) == 0:
            break

    return dic

def constructIcon (directory, threshold):
    print ("Finding icons:")
    dic = {}
    folderWithIcos = []

    # Walks through directory to find icons
    # Removes malformed (too small) icons
    for folder in os.listdir(directory):
        for i in os.listdir(f"{directory}/{folder}/icos"):
            if os.stat(f"{directory}/{folder}/icos/{i}").st_size < 83:
                os.remove(f"{directory}/{folder}/icos/{i}")
                print (f"Removed {i} for being too small")
        if len(os.listdir(f"{directory}/{folder}/icos")) > 0:
            folderWithIcos.append(folder)

    # Exits if nothing found
    if len(folderWithIcos) == 0:
        print ("No matches found, exiting....")
        sys.exit(1)
    else:
        print (f"Found {len(folderWithIcos)} icons")

    # Compares all icons together
    print ("Running comparisons:")
    while folder := folderWithIcos.pop(0):
        initIcos = os.listdir(f"{directory}/{folder}/icos")
        for cmpFld in folderWithIcos:
            cmpIcos = os.listdir(f"{directory}/{cmpFld}/icos")
            # Uses itertools to compare all icons in folder with all icons in other folder
            cmps = [calcdiff(a, b, directory, folder, cmpFld) for (a, b) in itertools.product(initIcos, cmpIcos)]
            if min(cmps) < threshold:
                dic.setdefault(folder, [])
                dic[folder].append(cmpFld)
        if len(folderWithIcos) == 0:
            break

    return dic

def createGraph (out, dic):
    print ("Creating Graph and clustering:")

    # Make directory and graph
    os.makedirs (out)
    g = nx.Graph(dic)

    # Save graph as pickled file
    with open(f"{out}/graph.pkl", 'wb') as f:
        pickle.dump(g, f)

    # Determine all subgraphs created (aka clusters)
    clusterList = []
    for i in (g.subgraph(c) for c in nx.connected_components(g)):
        clusterList.append(list(i))

    # Save list as pickled file
    with open(f"{out}/list.pkl", 'wb') as f:
        pickle.dump(clusterList, f)

def labelClusters (directory, out, hashfile, pklfile, section):
    # Load in pickled list file as clusterList
    with open (pklfile, "rb") as f:
        clusterList = pickle.load(f)

    # Build classification list
    print ("Building Hash Database:")
    hashes = buildDic(hashfile)

    # Label and save clusters
    print ("Labeling and saving clusters:\n")
    for count, cluster in enumerate(clusterList):
        # Create labeled directory
        os.makedirs(f"{out}/cluster{count}")
        print (f"Cluster {count}: ")

        # Collect how many of each label are there
        amts = {}
        for j in cluster:
            amts.setdefault(hashes[j], 0)
            amts[hashes[j]] += 1

            # Either copy all images as b- or the specified name
            if section is not None:
                shutil.copyfile(f"{directory}/{j}/{section}", f"{out}/cluster{count}/{j}.png")
            else:
                for ico in os.listdir(f"{directory}/{j}/icos"):
                    shutil.copyfile(f"{directory}/{j}/icos/{ico}", f"{out}/cluster{count}/{ico.replace('b', j)}")

        # Print cluster's classif information and count
        print ('\n'.join([f"{key} - {val}" for (key, val) in sorted(amts.items())]) + '\n')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create matrix of similar things')
    parser.add_argument("-d", "--directory", dest="dir", type=str, required=True,
            help='Directory holding pictures to compare')
    parser.add_argument("-c", '--classif', dest='classif', type=str, required=True,
            help='File containing hashes and classif info')
    parser.add_argument("-t", '--threshold', dest='thresh', type=float, default=2,
            help='Comparison index. 0 exact match, 255 all match')
    parser.add_argument('-o', '--output', dest='out', type=str, default='clusters',
            help='Output directory')
    parser.add_argument("-li", dest='icolist', type=str,
            help='Pickle file from saved ico clustered list')
    parser.add_argument("-ls", dest='sectionlist', type=str,
            help='Pickle file from saved section clustered list')
    parser.add_argument("-n", '--name', dest='name', type=str,
            help='Name of section to compare')

    args = parser.parse_args()
    start = time.time()

    # If we are reading an pickled icon list file
    if args.icolist is not None:
        labelClusters(args.dir, args.out, args.classif, args.icolist, None)

    # If we are reading a pickled section list file
    elif args.sectionlist is not None:
        labelClusters(args.dir, args.out, args.classif, args.sectionlist, args.name)

    # If we are clustering on a name
    elif args.name is not None:
        dic = constructImage(args.dir, args.thresh, args.name)
        createGraph (args.out, dic)
        labelClusters (args.dir, args.out, args.classif, f"{args.out}/list.pkl", args.name)

    # If we are clustering on icons
    else:
        dic = constructIcon(args.dir, args.thresh)
        createGraph (args.out, dic)
        labelClusters (args.dir, args.out, args.classif, f"{args.out}/list.pkl", None)

    print (f"Finished in {time.time() - start} seconds")

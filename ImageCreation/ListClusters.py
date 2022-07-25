import sys
import pickle
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create matrix of similar things')
    parser.add_argument("-l", "--lists", dest="l", type=str, nargs='+', required=True,
            help='directory to scan from')
    parser.add_argument("-s", "--hash", dest="hash", type=str, required=True,
            help='hash to search in the lists')

    args = parser.parse_args()

    lists = []

    for i in args.l:
        with open(i, "rb") as f:
            x = pickle.load(f)
            for count, j in enumerate(x):
                if args.hash in j:
                    print (f"Cluster {count} in {i}")
                    print (f"Contains {len(j)} other entries")
                    print ()
                    lists.append(set(j))


                    # print (j)

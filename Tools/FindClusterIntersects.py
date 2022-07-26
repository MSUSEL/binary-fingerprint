import sys
import pickle
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Compare two pickled cluster lists')
    parser.add_argument("-l", "--lists", dest="l", type=str, nargs='+', required=True,
            help='Pickled lists to compare')

    args = parser.parse_args()

    if len(args.l) != 2:
        print ("Error: Enter exactly two lists")
        sys.exit(1)

    with open(args.l[0], "rb") as f:
        l1 = list(map(set, pickle.load(f)))

    with open(args.l[1], "rb") as f:
        l2 = list(map(set, pickle.load(f)))

    count = 0
    count2 = 0
    matches = []
    for i in l1:
        for j in l2:
            len1 = len(i)
            len2 = len(j)
            inter = i.intersection(j)

            if i == j:
                count2 += 1

            if (len(inter) == len1 or len(inter) == len2):
                count += 1
                matches.append(inter)

    print (f"Found {count2}/{len(l1)} exact matches")
    print (f"Matched {count}/{len(l1)} clusters")
    print ()
    print (f"Found {count2}/{len(l2)} exact matches")
    print (f"Matched {count}/{len(l2)} clusters")

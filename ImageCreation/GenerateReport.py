import json
import argparse

def listErrors (file):
    total = 0
    success = 0
    errDic = {"File Not Found" : 0,
              "Header Length Issue" : 0,
              "DOS Header Magic" : 0,
              "Unknown File Extension" : 0,
              "Invalid NT Header" : 0,
              "Invalid e_lfanew" : 0,
              "Embedded null byte" : 0,
              "Invalid start byte" : 0,
              "Invalid continuation byte" : 0,
              "NoneType cant save" : 0,
              "Data cant be fetched" : 0,
              "Index out of range" : 0,
              "Others" : 0}
    with open(file, "r", encoding='utf-8') as f:
        while item := f.readline():
            if "Processing" in item:
                total += 1
            elif item == "Done\n":
                success += 1
            elif "[Errno 2]" in item:
                errDic["File Not Found"] += 1
            elif "NT Headers" in item:
                errDic["Invalid NT Header"] += 1
            elif "start byte" in item:
                errDic["Invalid start byte"] += 1
            elif "e_lfanew" in item:
                errDic["Invalid e_lfanew"] += 1
            elif "continuation byte" in item:
                errDic["Invalid continuation byte"] += 1
            elif "out of range" in item:
                errDic["Index out of range"] += 1
            elif "null byte" in item:
                errDic["Embedded null byte"] += 1
            elif "file extension" in item:
                errDic["Unknown File Extension"] += 1
            elif "NoneType" in item:
                errDic["NoneType cant save"] += 1
            elif "length less" in item:
                errDic["Header Length Issue"] += 1
            elif "be fetched" in item:
                errDic["Data cant be fetched"] += 1
            elif "DOS Header magic not found" in item:
                errDic["DOS Header Magic"] += 1
            elif item != '\n' and "Processed" not in item:
                errDic["Others"] += 1
                # print (item)

    print ("Errors:")
    for i in dict(sorted(errDic.items(), key=lambda item: item[1], reverse=True)):
        if errDic[i] > 0:
            print (f"  {errDic[i]:5} - {i}")

    print ()
    print (f"Total In: {total}")
    print (f"Total Success: {success}")
    print (f"Total Errors: {sum(errDic.values())}")
    print ()

    return total


def listInfo (file, total):
    sections = {}
    packers = 0
    icons = 0
    with open(file, "r", encoding='utf-8') as f:
        while item := f.readline():
            jsonObj = json.loads(item)
            x = len(jsonObj["sections"])

            sections.setdefault(f"{x} Sections", 0)
            sections[f"{x} Sections"] += 1

            if len(jsonObj["ico"]) > 0:
                icons += 1

            if jsonObj["packer"] != "no packer found":
                packers += 1

    print ("Section Counts:")
    for i in sorted(sections.keys()):
        print (f"  {sections[i]:5} - {i}")

    print ()
    print (f"With Icons: {icons}")
    print (f"Without Icons: {total-icons}")
    print ()

    print (f"Packed: {packers}")
    print (f"Not Packed: {total-packers}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create a report from image data')
    parser.add_argument('-d', '--detail', dest='det', type=str, required=True,
            help='the detail file')
    parser.add_argument('-r', '--result', dest='res', type=str, required=True,
            help='the results file')

    args = parser.parse_args()

    print ("Report Generated:\n\n")

    total = listErrors(args.res)

    listInfo (args.det, total)

import os
import subprocess
import csv
import Pecheck

path = "./TestFile"

largeDataStructure = {}
largeDataStructure["basis"] = ["filename","malware","fileSize"]

for testfilename in os.listdir(path):
    inputFile = open(path + "/" + testfilename, "a")
    
    largeDataStructure[testfilename] = [testfilename,"true",os.path.getsize(path + "/" + testfilename)]

    inputFile.close();

print(largeDataStructure)

outputFile = open("outputFile.csv", "w+")
outputWriter = csv.writer(outputFile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
for key in largeDataStructure.keys():
    print(largeDataStructure[key])
    outputWriter.writerow(largeDataStructure[key])


outputFile.close()

    
    

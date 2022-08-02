import os
import subprocess
import csv

#A program to collect data about malware using Manalyze and other system operations
#
#Made for use in the 2022 MSU reu
#
#@Author: Noah Neundorfer
#@Date: 8-1-2022

manalyze = "/home/noah/Programs/Manalyze/bin/manalyze --plugins=all"
pathMal = "/mnt"
pathBen = "/home/noah/Programs/Basic Framework/binary"

largeDicDic= {}
largeDicDic["basis"] = ["Filename","MalwareType","FileSize",
			"Packed", "Overlay", "HidingImports", "MalwareFunctions",
			"CryptoUsed", "DomainNames", "UndesirableBehavior",
			"IllegitimatePrograms", "AntiDebug", "WindowsNativeAPI",
			"AbnormalResources", "PEiDSignature", "Dropper",
			"BrowserReferences", "CompanyName", "MatchingCompiler", "PossibleCompilersCount"]


#function: adds relvant aspects to dictionary passed in.				
def performDataExtract(thisDic):
	thisDic["HidingImports"] = True if ("The program may be hiding some of its imports:" in manalyzeResult) else False
	thisDic["Overlay"] = True if ("The file contains overlay data." in manalyzeResult) else False
	thisDic["CryptoUsed"] = True if ("Cryptographic algorithms detected in the binary:" in manalyzeResult) else False
	thisDic["Packed"] = True if (("The PE is possibly packed." in manalyzeResult) or ("The PE is packed" in manalyzeResult)) else False
	thisDic["IllegitimatePrograms"] = True if ("The PE contains functions most legitimate programs don't use." in manalyzeResult) else False
	thisDic["UndesirableBehavior"] = True if ("Strings found in the binary may indicate undesirable behavior:" in manalyzeResult) else False
	thisDic["MalwareFunctions"] = True if ("The PE contains functions mostly used by malware." in manalyzeResult) else False
	thisDic["AntiDebug"] = True if ("Functions which can be used for anti-debugging purposes:" in manalyzeResult) else False
	thisDic["WindowsNativeAPI"] = True if ("Uses Windows's Native API:" in manalyzeResult) else False
	thisDic["DomainNames"] = True if ("Contains domain names:" in manalyzeResult) else False
	thisDic["AbnormalResources"] = True if ("The PE's resources present abnormal characteristics" in manalyzeResult) else False
	thisDic["PEiDSignature"] = True if ("PEiD Signature:" in manalyzeResult) else False
	thisDic["Dropper"] = True if ("The PE is possibly a dropper." in manalyzeResult) else False
	thisDic["BrowserReferences"] = True if ("Contains references to internet browsers:" in manalyzeResult) else False
	if ("Matching compiler(s):" in manalyzeResult):
		compResult = manalyzeResult[manalyzeResult.find("Matching compiler(s):\n")+23:]
		compResult = compResult[:compResult.find("\n\n")]
		compCount = compResult.count("\n")+1
		thisDic["PossibleCompilersCount"] =  compCount
		thisDic["MatchingCompiler"] = "unknown" if (compCount != 1) else compResult.strip("\n\t ")
	else:
		thisDic["PossibleCompilersCount"] =  0
		thisDic["MatchingCompiler"] = "unknown"
		
		
	if ("CompanyName" in manalyzeResult):                                                                                           #If company is present, add, else "unknown"
		trimed = manalyzeResult[manalyzeResult.find("CompanyName"):]
			 
		trimed = (trimed[:trimed.find("\n")+1]).strip("CompanyName:").strip()
			 
		if(trimed != ""):                                                                                                       #Often "Company name" is present, but an actual name is not
			thisDic["CompanyName"] = trimed
		else:
			thisDic["CompanyName"] = "unknown"
	else:
		thisDic["CompanyName"] = "unknown"



#Make type List-------------------------------------------------

inputFile = open("HashesAndClassif.txt", "r")           #file contains hashes of files associated with malware types.
hashDic = {}                                    

for line in inputFile:                                  #Goes line by line adding hash/type pair to hashDic
	lineArray = line.split("\t")
	nameFamily = [lineArray[3].split(".")[0],lineArray[3][lineArray[3].find(".")+1:lineArray[3].find("/")]]
	
	hashDic[lineArray[1]] = nameFamily
	
hashKeys = hashDic.keys()
inputFile.close()



#BEGIN PROGRAM---------------------------------------------------
i = 1                                                                                                           #Starting indices
j = 1000000000000000                                                                                            #Max indices, arbitrarilly large
for sdName in os.listdir(pathMal):                                                                              #below loops into all malware files.
	for nName in os.listdir(pathMal+"/"+sdName):
		if "vol" in nName:
			for startHashName in os.listdir(pathMal+"/"+sdName+ "/"+nName):
				newPath = pathMal+ "/"+sdName + "/"+nName + "/" +startHashName
				for testfilename in os.listdir(newPath):
					if testfilename in hashKeys:                                            #Only look at malware files we have associated types for
						
						largeDicDic[testfilename] = {"Filename":testfilename,"FileSize":os.path.getsize(newPath + "/" + testfilename)}
						thisDic = largeDicDic[testfilename]
						
						thisDic["MalwareType"] = hashDic[testfilename][0] if hashDic[testfilename][0] != "trojan" else hashDic[testfilename][1] #Uses hashDic for malware type
						

						try:
							manalyzeResult = os.popen(manalyze + " "+newPath + "/" + testfilename).read()
							if (manalyzeResult.strip() == "* Manalyze 0.9 *"):      #If Manalyze fails to find
								raise Exception
							
							performDataExtract(thisDic)
						
						except:
							largeDicDic.pop(testfilename)                           #If we fail to find all needed data, remove instace
						
						
						
						print(str(i) + "-----------------------------------------------------------")
						i +=1
				if(i>j):                                                                        #Multiple if(i>j) used to break all the way out of loops
					break
			if(i>j):
				break
		if(i>j):
			break
	if(i>j):
		break
			
			
		
#BEGIN FINAL------------------------------------------------------------

largeDataStructure = {}

for key in largeDicDic.keys():
	largeDataStructure[key] = []    
	if(key != "basis"):                                                                                     #Basis = first row with column names
		for innerkey in sorted(largeDicDic[key].keys()):                                                #use sorted function to ensure same order on all files
			largeDataStructure[key].append(largeDicDic[key][innerkey])
			
	else:
		for val in sorted(largeDicDic[key]):
			largeDataStructure[key].append(val)

outputFile = open("outputFile.csv", "w+")
outputWriter = csv.writer(outputFile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
for key in largeDataStructure.keys():
	outputWriter.writerow(largeDataStructure[key])


outputFile.close()

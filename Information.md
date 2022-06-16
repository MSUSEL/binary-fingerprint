# Useful Information

Listed below are some useful background sites/books/tools/info that I've collected while researching malware for the 22 Summer REU at MSU

## Background Knowledge
What is Malware - 
* [Malwarebytes Malware Overview](https://www.malwarebytes.com/malware)

What Types of Malware Exist - 
* [Kasperky Classification Tree](https://www.kaspersky.com/resource-center/threats/malware-classifications)
* [22 Types of Malware](https://www.upguard.com/blog/types-of-malware)
* [Geeks for Geeks Malware Types](https://www.geeksforgeeks.org/malware-and-its-types/)

Malware Analysis Lectures - 
* [DSU CSC-432 S22 Lectures](https://www.youtube.com/watch?v=9OO_SD3Oaa0&list=PLynyJsHgQaJ1XeNjEQ0F2fEGkzaNIcVxT&index=1)
* [Dr. Josh Stroschein's Videos](https://www.youtube.com/c/DrJoshStroschein)

## Useful Textbooks
Malware Analysis and Detection Engineering: A Comprehensive Approach to Detect and Analyze Modern Malware ([link](https://msu-primo.hosted.exlibrisgroup.com/permalink/f/1a5h0rp/01TRAILS_ALMA51280617800003366))  
&emsp; ⤷ Useful for a broad overview of techniques used within malware  
&emsp; ⤷ details windows API calls and what malware may use them  
&emsp; ⤷ code injection, process hollowing, and API hooking  
&emsp; ⤷ packing and other hiding techniques  
&emsp; ⤷ anti-virus and how it works  

Practical Malware Analysis : A Hands-On Guide to Dissecting Malicious Software ([link](https://msu-primo.hosted.exlibrisgroup.com/permalink/f/1a5h0rp/01TRAILS_ALMA51286893260003366))  
&emsp; ⤷ Good overview of static/dynamic analysis techniques  
&emsp; ⤷ Chapter 12 covers covert techniques really well  

Malware Analyst's Cookbook and DVD : Tools and Techniques for Fighting Malicious Code([link](https://msu-primo.hosted.exlibrisgroup.com/permalink/f/1a5h0rp/01TRAILS_ALMA51286329370003366))  
&emsp; ⤷ Information about using yara and other detection methods  

Malware analysis using artificial intelligence and deep learning ([link](https://msu-primo.hosted.exlibrisgroup.com/permalink/f/1a5h0rp/01TRAILS_ALMA71283868340003366))  
&emsp; ⤷ Good overview of tried techniques for malware & deep learning
&emsp; ⤷ Has pretty much every machine learning type

Malware data science attack detection and attribution([link](https://msu-primo.hosted.exlibrisgroup.com/permalink/f/1a5h0rp/01TRAILS_ALMA51278476250003366))  
&emsp; ⤷ Very good source  
&emsp; ⤷ Does a very good job at explaining machine learning with malware  
&emsp; ⤷ Lots of good information - chapter 6-8 especially  

## Other Good Links
Malware Machine Learning: 
https://www.sciencedirect.com/science/article/pii/S2214212621000648#b20  
&emsp; ⤷ Has a list of features to detect malware  
&emsp; ⤷ Has some challenges to detection  

Malware Image Classification: 
https://dl.acm.org/doi/pdf/10.1145/2016904.2016908  
&emsp; ⤷ Good overview on classifying malware based on images  

https://arxiv.org/pdf/1903.11551.pdf  
&emsp; ⤷ Another good overview of classifying malware based on images  

Control Flow Graphs:  
https://www.sciencedirect.com/topics/computer-science/control-flow-graph  
&emsp; ⤷ Overview of flow graphs  

## Possible Features
Miscellaneous:
* Compile Time Stamp
* Author
* File Name
* Header names (nonsense or normal)
* ASLR, DEP, etc.

Extracted Information:
* Strings (possible domains/urls, format strings, unique strings, registry keys)
* API Imports/Hooks
* Library Dependencies
* Possible reused code known to be used by malware
* Debug information
* Mutex names

Encryption (does not necessarily mean malicious):
* Using cryptographic functions
* Packing 
* Entropy of sections

More Advanced Methods:
* Control flow graph
* Image creation

## Possible Hinderances
* Obfuscation - hiding it's true intent
* Packing - using packers to compress data (really hard for static analysis)
* Polymorphism - code that does the same thing but looks different
* Metamorhpism - Code that changes itself during replication
* Adversarial malware - Strategically adding stuff to throw off machine learning

## Possible Tools
MSOffice:
 * oledump
 
Pdf:
 * pdfparser
 
Binaries:  
* General information
  * PECheck
  * Manalyze
* String Extraction
  * Madiant Floss
  * Strings
* View Instructions/Hex
  * objdump
  * Ghidra
  * IDA
* Online Sandboxes/Information
  * Virus Total
  * Any.run
* Packers
  * UPX
* View imports
  * ldd
  * nm

Interesting Github Projects:
* [Impfuzzy](https://github.com/JPCERTCC/impfuzzy/tree/master/impfuzzy_for_Neo4j)  
* [asm2vec](https://github.com/Lancern/asm2vec)

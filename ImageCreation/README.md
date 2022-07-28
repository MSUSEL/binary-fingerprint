# Image-Based Malware Analysis
A folder containing the relevant scripts and descriptions for the Image-Based analysis portion of the project

## Background  
Because of the various forms of malware, as well as the sophisticated techniques that malware authors use to mask or spoof malware, malware recognition techniques require creative representations of the malware. One such representation is to transpose a byte-by-byte representation of a malicious file into a grayscale image, with the byte value of 0 being black and 255 white. This creates a standard image file, with the content of the image being black and white pixels. However, since malicious files may be filled with erroneous data, comparing exact images becomes problematic and distinctive features may be lost. By breaking the binary into its pre-defined segments and generating grayscale images for each section, we can isolate similar sections. Following, we can utilize existing machine learning algorithms to cluster based on the grayscale segments. This process reveals how malware segments have been re-used or spoofed.  


## Image Creation
The image below shows the resulting cluster graph when the text sections are compared using a simple image difference algorithm. Each blue dot is a collection of 2 or more connected nodes.
<p align="center"><img width="600" height="300" src="../Pictures/ClusterGraph.png"></p>

## Goals


## Results
Below are three interesting cluters. Each element in the cluster has exactly, or near exactly the same .text section. This indicates that these samples are related. However, in the labels provided by VirtusTotal, these samples are labeled uniquely. This disconnect requires further study into how viruses are classified and the relationship between certain malware families.  

These results are interesting as it shows that it is possible to compare malware based on their segments and that potentially different malware may be reusing the same code. This demonstrates that a certain cluster can be represented by a single image, which represents a fingerprint for that class of malware. By using a single image fingerprint per cluster we can speed up malware detection techniques.

### Cluster #10:
![Cluster10](../Pictures/Cluster10.png)

### Cluster #259:
![Cluster259](../Pictures/Cluster259.png)

### Cluster# #435:
![Cluster435](../Pictures/Cluster435.png)


## SectionedImage.py

## ClusterImages.py

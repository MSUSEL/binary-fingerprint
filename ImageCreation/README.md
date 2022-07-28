# Image-Based Malware Analysis
A folder containing the relevant scripts and descriptions for the Image-Based analysis portion of the project

## Background  
Because of the various forms of malware, as well as the sophisticated techniques that malware authors use to mask or spoof malware, malware recognition techniques require creative representations of the malware. One such representation is to transpose a byte-by-byte representation of a malicious file into a grayscale image, with the byte value of 0 being black and 255 white. This creates a standard image file, with the content of the image being black and white pixels. However, since malicious files may be filled with erroneous data, comparing exact images becomes problematic and distinctive features may be lost. By breaking the binary into its pre-defined segments and generating grayscale images for each section, we can isolate similar sections. Following, we can utilize existing machine learning algorithms to cluster based on the grayscale segments. This process reveals how malware segments have been re-used or spoofed.  


## Image Creation
The image below shows the resulting cluster graph when the text sections are compared using a simple image difference algorithm. Each blue dot is a collection of 2 or more connected nodes.

## Goals

## Results

## SectionedImage.py

## ClusterImages.py

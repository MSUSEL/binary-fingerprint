## Results
A collection of 6645 unique, labeled samples were used to form the results. From these samples 608 clusters were formed. While most clusters were the same family or same malware classifications, there were a handful of clusters showing unique characteristics. Below are 3 such clusters. Within these clusters, the .text sections are identical or near identical, meaning that the code used in the program matches between all of them. This demonstrates that there is similarity between these programs. However, when viewing the VirusTotal classifications for these samples, it was found that they are very different, sometimes not even in the same family. Further, the samples in cluster 259 are near identical in the entirety, with various small difference, and yet the classifications from VirusTotal are vastly different. The reasoning for this is unknown and requires further study into how malware is classified and the relationship between these files. 

These results are interesting as it shows that it is possible to compare malware based on their segments and that potentially different malware may be reusing the same code. This demonstrates that a certain cluster can be represented by a single image, which represents a fingerprint for that class of malware. By using a single image fingerprint per cluster we can speed up malware detection techniques.

### Cluster #10:
![Cluster10](../../Pictures/Cluster10.png)

### Cluster #259:
![Cluster259](../../Pictures/Cluster259.png)

### Cluster# #435:
![Cluster435](../../Pictures/Cluster435.png)

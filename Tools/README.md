# Various Python Tools
A folder containing useful python tools created/used for the project: 

### AppendVTDataToDB.py  
Purpose: 

### FindClusterIntersects.py            
Purpose: To compare two cluster lists created by -, and find their intersections. Useful for determining how many of the same items clustered together from different clustering aspects.  
Usage: FindClusterIntersects.py -l list1.pkl list2.pkl  
  -> Lists the clusters that are the same between list1 and list2

### FindFilesByMagic.py                   
Purpose: To search through a directory and find files that match an inputed file magic type.  
Usage: FindFilesByMagic.py -d ~/Executables -f PE DLL  
  -> Looks through directory Executables and prints file paths for any file whose type has either PE or DLL  

### FindSimilarImages.py        
Purpose: Search through directory to find similar images to the one specified. Uses the python pillow imagechops library to compare pixel by pixel to determine similarity. Has option to classify the image if the image creation was done using -.  
Usage: FindSimilarImages.py -i img.png -d ~/Pictures  
  -> Will print file path to any image that matches against img.png in ~/Pictures

### FixDBDuplicates.py
Purpose:

### HashToMalwareFolder.py
Purpose: Construct file paths based on the file structure of the malware box based on the hash.  
Usage: HashToMalwareFolder.py 

### ImageCollector.py
Purpose: To copy created malware images or icons into a central folder.  
Usage: ImageCollector.py -d ~/MalwareImage -i  
  -> Saves all extracted icons into default folder  
Usage: ImageCollector.py -d ~/MalwareImage -n text.png -o ~/TextPngs  
  -> Saves all images names text.png to new directory TextPngs  

### JsonMetaToDB.py
Purpose:

### ListAssociatedClusters.py
Purpose: Given a SHA256 hash, return which clusters the hash appears in.  
Usage: ListAssociatedCluster.py -l list1.pkl list2.pkl -s 123...  
  -> Returns cluster number that 123... appears in from both list1 and list2  

### RenderGraph.py
Purpose: Renders the pickled networkx graph saved by -.   
Usage: RenderGraph.py -f graph.pkl  
  -> Renders graph using MatPlotLib  

### RestoreFromImg.py
Purpose: Takes a created black and white image and restores it back to its original form. Size is necessary to trim off added blank space at the end of the image.  
Usage: RestoreFromImage.py -f full.png -s 1000  
  -> Let full.png be a created image from an exe file. This restores the original exe file.  

### SectionCounts.py
Purpose: Lists the count of all sections found during image creation process.  
Usage: SectionCounts.py -f details.txt  
  -> Prints a list of sections and their counts found in details.txt  

### VisualizeCluster.py
Purpose: Makes visualizing a cluster easier by copying all cluster images into a central folder.  
Usage: VisualizeCluster.py -d ~/MalwareImages -l textlist.pkl -n 10 -c Hashes.txt  
  -> Saves cluster #10 from textlist.pkl into default folder
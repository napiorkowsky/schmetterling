# schmetterling

This script will help you to create hash sets of naked pictures in selected folder.

## Description

 Project created for needs of forensic IT analyzes. If you have to select all nacked pictures from evidence drive you can do it in multiple ways.
 I use X-Ways for this, but it take forever to look at all images and click/mark/tag every second. I came up with idea to make a script that would recognize nude photos but at a higher level than skin color. 
 Script creates hash set for these interesting/nude files. Then I go through the files and verify accuracy but since now I don't have to click every second picture, just let's say just one on screen
 There is also a functionality creating list of checksums (MD5 and SHA1) for all files.

## Getting Started

### Dependencies
  It's created mainly for WSL under Win10. I used three already existing components
* https://github.com/canaydogan/nudity
* https://github.com/hhatto/nude.py
* https://github.com/notAI-tech/NudeNet/
   
  Which require:
* Python 3.6-3.7 
* tensorflow 1.14-1.15
   
  To see progress bar you will need also
* tqdm


### Installing
* pip3 install --upgrade pip
* pip3 install tqdm
* pip3 install tensorflow==1.14.0

* pip3 install nudity
* pip3 install nudepy
* pip3 install nudenet


### Executing program

```
schmetterling.py <directory> [-list] [-nudity] [-nude] [-nudenet]
```

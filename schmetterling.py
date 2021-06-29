#!/usr/bin/python3

# Requirements
# Python 3.6-3.7 
# tensorflow 1.14-1.15

# filenames with these extensions will be analyzed
pictures_extensions = [".jpg", ".jpeg", ".png", ".gif"] 
# chunk size in bytes used in MD5 and SHA1 functions
bsize = 512

# Hash sets in X-Ways format requires definition of hash type in first line e.g. MD5
# In software like Autopsy by (The Sleuth Kit) hash set starts with checksum.
# To prepare hash set in required format, uncomment proper hash set type:
hashset_type = "xways"
# hashset_type = "autopsy"


# this function is calculating MD5 for file
def md5_for_file(current_file):                                              
    from hashlib import md5
    hash_md5 = md5()
    with open(current_file, "rb") as f:
        data = f.read(bsize)
        while len(data) > 0:
            hash_md5.update(data)
            data = f.read(bsize)
    return hash_md5

# this function is calculating SHA1 for file
def sha1_for_file(current_file): 
    from hashlib import sha1
    hash_sha1 = sha1()
    with open(current_file, "rb") as f:
        data = f.read(bsize)
        while len(data) > 0:
            hash_sha1.update(data)
            data = f.read(bsize)
    return hash_sha1

def main():
    import sys, os
    import base64
    from sys import argv
    from datetime import datetime
    from tqdm import tqdm   
    argv = sys.argv[1:]
    # timestamp is required for creating unique reports filenames
    now = datetime.now().strftime("%Y-%m-%d  %H.%M.%S")
    
    try:
        # this condition validate that first argument was given (directory)
        if argv[0]:
            try:
                # this condition validate that first argument was given (modules)
                if argv[1]:                                        
                    # this condition validate that given argument points to directory
                    if os.path.isdir(argv[0]):
                        # list of all files in given directory
                        file_list = list()
                        print(f"[+] Analysing \"{argv[0]}\"")
                        # loop will follow each directory recursively and add each file with full path to file_list
                        for dir_path, dir_names, file_names in os.walk(argv[0]):
                            for file in file_names:
                                file_list.append(os.path.join(dir_path, file))
                        
                        # this condition validate that file_list contains any records
                        if len(file_list) > 0:
                            # this condition validate that -list parameter was given
                            if '-list' in argv:
                                import csv
                                try:
                                    # create unique filename for report  
                                    csv_file = "".join((argv[0]," -list ",str(now),".csv")).replace("/","").replace("\\","")
                                    f = open(csv_file, mode='w')
                                    writer=csv.writer(f)
                                    # add first line to describe report content
                                    writer.writerow(['file','MD5','SHA1'])
                                    # loop will follow each file from file_list
                                    for file in tqdm(file_list, desc="Progress in '-list'"):
                                        # it's necessary to check if we are dealing with file or hyperlink, symlink, etc.  
                                        if os.path.isfile(file):
                                            try:
                                                # write row to csv report with pattern full path and filename, MD5 hash, SHA1 hash 
                                                writer.writerow([file , str(md5_for_file(file).hexdigest()) , str(sha1_for_file(file).hexdigest())])
                                            except:
                                                # an exception by hashing file, missing privileges for example
                                                print(f"[!] Unable to hash file (possible missing privileges): {file}")
                                        else:
                                            # an exception by file validation 
                                            print(f"[!] This object is not a file (possible hard link): {file}")
                                    f.close()
                                    print(f"[+] Report saved in current working directory as \"{csv_file}\"")         
                                except:
                                    # an exception by creation report file
                                    print(f"[x] Error in '-list' module, CSV file not created!")

                            # https://github.com/canaydogan/nudity
                            # this condition validate that -nudity parameter was given
                            if '-nudity' in argv:  
                                from nudity import Nudity
                                nudity = Nudity()
                                # set of MD5 hashes for files identified as "important"  
                                md5_set_nudity = set()
                                # variable used to count identified files
                                hits_nudity = 0
                                pbar = tqdm(file_list, desc="Progress '-nudity'")
                                # loop will follow each file from file_list
                                for file in pbar:
                                    # extract file extension
                                    extension = os.path.splitext(file)[1]
                                    # this condition validate that file with obtained extension should be analyzed
                                    if extension in pictures_extensions:
                                        try:
                                            # this condition returns True or False for analyzed file
                                            if nudity.has(file):
                                                # if file is identified as "important" MD5 hash is calculated and goes to set
                                                md5_set_nudity.add(str(md5_for_file(file).hexdigest()))
                                                # hits counter is incremented
                                                hits_nudity+=1
                                                # progress bar is updated with hits counter
                                                pbar.set_postfix(Hits=hits_nudity)
                                        except:
                                            # an exception by file analyze 
                                            print(f"[!] Error in '-nudity' module, unable to analyze file: {file}")
                                
                                # report creation
                                if hits_nudity > 0:
                                    # create unique filename for hash set 
                                    nudity_file = "".join((argv[0]," -nudity ",str(now),".txt")).replace("/","").replace("\\","")
                                    f = open(nudity_file, mode='w')                         
                                    # add first line to describe hash types, it's required by X-Ways
                                    if hashset_type == "xways":
                                        f.write("MD5\n")
                                    # loop will iterate all items in set and write them to hashset                                
                                    for i in md5_set_nudity:
                                        f.write(i + "\n")
                                    f.close()
                                    #notification about analyze results
                                    print(f"[+] Potentially {hits_nudity} hits has been found by '-nudity' module")
                                    print(f"[+] Report saved in current working directory as \"{nudity_file}\"")
                                else:
                                    print(f"[+] No hits has been found by '-nudity' module, no report will be created")
                            
                            # https://github.com/hhatto/nude.py
                            # this condition validate that -nude parameter was given
                            if '-nude' in argv: 
                                import nude
                                from nude import Nude
                                # set of MD5 hashes for files identified as "important"  
                                md5_set_nude = set()
                                # variable used to count identified files
                                hits_nude=0
                                pbar = tqdm(file_list, desc="Progress '-nude'")
                                # loop will follow each file from file_list
                                for file in pbar:
                                    # extract file extension
                                    extension = os.path.splitext(file)[1]
                                    # this condition validate that file with obtained extension should be analyzed
                                    if extension in pictures_extensions:
                                        try:
                                            # his condition returns True or False for analyzed file
                                            if nude.is_nude(file):
                                                # if file is identified as "important" MD5 hash is calculated and goes to set
                                                md5_set_nude.add(str(md5_for_file(file).hexdigest()))
                                                # hits counter is incremented
                                                hits_nude+=1
                                                # progress bar is updated with hits counter
                                                pbar.set_postfix(Hits=hits_nude)
                                        except:
                                            # an exception by file analyze
                                            print(f"[!] Error in '-nude' module, unable to analyze file: {file}")
                                
                                # report creation
                                if hits_nude > 0:
                                    # create unique filename for hash set
                                    nude_file = "".join((argv[0]," -nude ",str(now),".txt")).replace("/","").replace("\\","")
                                    f = open(nude_file, mode='w')                         
                                    # add first line to describe hash types, it's required by X-Ways
                                    if hashset_type == "xways":
                                        f.write("MD5\n")
                                    # loop will iterate all items in set and write them to hash set
                                    for i in md5_set_nude:
                                        f.write(i + "\n")
                                    f.close()
                                    # notification about analyze results
                                    print(f"[+] Potentially {hits_nude} hits has been found by '-nude' module")
                                    print(f"[+] Report saved in current working directory as \"{nude_file}\"")
                                else:
                                    print(f"[+] No hits has been found by '-nude' module, no report will be created")  
                            
                            # https://github.com/notAI-tech/NudeNet/
                            # this condition validate that -nudenet parameter was given
                            if '-nudenet' in argv:  
                                from nudenet import NudeDetector
                                detector = NudeDetector()
                                # set of MD5 hashes for files identified as "important"
                                md5_set_nudenet = set()
                                # variable used to count identified files
                                hits_nudenet=0
                                # detector returns dictionaries like this:
                                # {'box': [173, 42, 270, 142], 'score': 0.6749449372291565, 'label': 'FACE_F'}
                                # {'box': [244, 427, 294, 485], 'score': 0.581946849822998, 'label': 'EXPOSED_GENITALIA_F'} 
                                #  it's necessary to define labels of interest
                                nudenet_classes = ["EXPOSED_BREAST_F", "EXPOSED_ANUS", "EXPOSED_GENITALIA_F", "EXPOSED_GENITALIA_M", "EXPOSED_BUTTOCKS"]
                                pbar = tqdm(file_list, desc="Progress '-nudenet'")
                                # loop will follow each file from file_list
                                for file in pbar:
                                    # extract file extension
                                    extension = os.path.splitext(file)[1]
                                    # this condition validate that file with obtained extension should be analyzed
                                    if extension in pictures_extensions:
                                        try:
                                            # his condition returns dictionary as example above 
                                            current_picture = detector.detect(file, mode='fast')
                                            # lets iterate dictionary elements
                                            for dict in current_picture:
                                                # this condition validate that 'label' contains value of interest
                                                if dict['label'] in nudenet_classes:
                                                    # if file is identified as "important" MD5 hash is calculated and goes to set
                                                    md5_set_nudenet.add(str(md5_for_file(file).hexdigest()))
                                                    # hits counter is incremented
                                                    hits_nudenet+=1
                                                    # progress bar is updated with hits counter
                                                    pbar.set_postfix(Hits=hits_nudenet)
                                                    # only one class is required to define file as "important", there is no need to add file multiple times to set
                                                    break
                                        except:
                                            # an exception by file analyze
                                            print(f"[!] Error in '-nudenet' module, unable to analyze file: {file}")
                                
                                # report creation
                                if hits_nudenet > 0:
                                    # create unique filename for hash set
                                    nudenet_file = "".join((argv[0]," -nudenet ",str(now),".txt")).replace("/"," ").replace("\\"," ")
                                    f = open(nudenet_file, mode='w')                         
                                    # add first line to describe hash types, it's required by X-Ways
                                    if hashset_type == "xways":
                                        f.write("MD5\n")
                                    # loop will iterate all items in set and write them to hash set
                                    for i in md5_set_nudenet:
                                        f.write(i + "\n")
                                    f.close()
                                    # notification about analyze results
                                    print(f"[+] Potentially {hits_nudenet} hits has been found by '-nudenet' module")
                                    print(f"[+] Report saved in current working directory as \"{nudenet_file}\"")
                                else:
                                    print(f"[+] No hits has been found by '-nudenet' module, no report will be created")
                            
                            # this condition validate that at least one parameter was given
                            if ('-list' or '-nudity' or '-nude' or '-nudenet') not in argv:
                                print(f"[x] Missing work parameter")
                                print(f"[x] Try skrypt.py <directory> [-list] [-nudity] [-nude] [-nudenet]")


# exceptions error messages handling
                        else:
                            print(f"[x] Directory is empty, nothing to do in \"{argv[0]}\"")
                    else:
                        print(f"[x] \"{argv[0]}\" is not a valid directory")
                        print(f"[x] Try skrypt.py <directory> [-list] [-nudity] [-nude] [-nudenet]")

            except Exception as e:
                print(f"[x] Missing work parameter")
                print(f"[x] Try skrypt.py <directory> [-list] [-nudity] [-nude] [-nudenet]")
                print(f"[x] {e}")
                
    except Exception as e:
        print(f"[x] Missing evidence directory")
        print(f"[x] Try skrypt.py <directory> [-list] [-nudity] [-nude] [-nudenet]") 
        print(f"[x] {e}")

if __name__ == '__main__':
	main()

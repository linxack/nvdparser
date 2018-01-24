# nvdparser
##Script to get the latest known vulnerabilities from NVD.

Author: Rafael Murillo
Twitter: @cehrmurillo
Blog: https://almost4hacker.blogspot.mx/
Version: 0.1

This script was born from the need to obtain the most recent vulnerabilities from the NVD feeds for certain technologies (operating systems and applications).


##DEPENDENCIES
Keep it simple ... You only need Python v. 2.7.13

##HOW TO USE
First of all, you should only modify the last line of the * nvdparser.py * file and add the systems and applications from which you want to get the latest vulnerabilities.

You must write the names in a way that matches what the NVD feed shows.

Since you have the script ready according to your needs, you should only execute it with:

`python nvdparser`

This will create two files:

**all_vulnerbilities.txt** Showing all the vulnerabilities obtained from the NVD feed.

**filtered.txt** That shows only the vulnerabilities that correspond to the filters you made in the previous step. THIS IS THE FILE THAT INTERESTS US.

# IIS_Installation

This script will install and configure IIS on a server (IIS 8.5 and onwards).

Written by Irtaza Chohan (http://www.lostintheclouds.net & https://github.com/IrtazaChohan/Align-Crypto-Policy)

This will install various roles and configure IIS using security best practise and replace the default IIS website with a custom one.
The location of the custom IIS page needs to be in the same folder as this script.

Various verbs are configured, request filtering and authentication are also setup accordingly.

This has been tested on:

- Windows Server 2012 R2
- Windows Server 2016
- Windows Server 2019


NOTES:

1. You need to have Administrative rights on the server to run this script. 
2. If no argument entered it will default to install on D: drive
3. If you want to enter a different drive then enter in the format <DRIVE>: ie E: F: etc - anything else other than a valid drive the script will fail. 
 
 
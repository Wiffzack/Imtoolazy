# Snort-Windows-Interacting-Tool
A small program that converts the conspicuousness of the Snort log into 
Windows Firewall Rules. In the next version if some network problems 
occurs it should offer the user some solutions. It is compatible with py2exe.
This is necessary because it is a simple alternative to get admin 
rights , which are required to add Rules to the Windows Firewall.

Instruction:

Install Snort :
https://www.snort.org/downloads/snort/Snort_2_9_9_0_Installer.exe

Configure Snort - Add rules (Copy in the rules Folder in the Snort folder)


Requirement for Compile:

Python 2.5.4 with py2exe

Python : https://www.python.org/download/releases/2.5.4/
py2exe : https://sourceforge.net/projects/py2exe/

Just Download and install them.

Customize the path to the Snort log folder in the logscan.py .
Example: os.chdir(r'C:\Snort\log') 

Compile Example:
python compile.py logscan.py




#Configure Snort !!!
The most important point is to configure Snort .Open snort.conf in Snort\etc

1. Find the line : ipvar HOME_NET any

and change the "any" to your home address space .
Example : ipvar HOME_NET 192.168.0.0/24

You can find your Address in many different ways :
cmd -> tracert -h 1 google.at or ipconfig /all or etc...

After this , change the Path to your Snort location :
var RULE_PATH D:\Snort\rules

var SO_RULE_PATH D:\Snort\rules

var PREPROC_RULE_PATH D:\Snort\preproc_rules


At least change the Path for the log files to your Snort folder !
config logdir: 
D:\Snort\log




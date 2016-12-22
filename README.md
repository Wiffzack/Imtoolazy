# Snort-Windows-Interacting-Tool
A small program that converts the conspicuousness of the Snort log into 
Windows Firewall Rules.In the next version if some network problems 
occurs it should offer the user some solutions.It is compatible with py2exe.
This is necessary becouse it is a simple alternative to get admin 
rights , which are necessary to add Rules to the Windows Firewall.

Instruction:

Install Snort :
https://www.snort.org/downloads/snort/Snort_2_9_9_0_Installer.exe

Configure Snort - Add rules (Copy in the rules Folder in the Snort folder)
Customize the snort.etc to your needs. You can take the Examples!



Requirement for Compile:

Python 2.5.4 with py2exe

Python : https://www.python.org/download/releases/2.5.4/
py2exe : https://sourceforge.net/projects/py2exe/

Just Download and install them.

Customize the path to the Snort log folder.
Example ! os.chdir(r'C:\Snort\log') 

Compile Example:
python compile.py scanlog.py



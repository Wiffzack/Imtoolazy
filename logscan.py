import mmap,os,sys,subprocess,time
from subprocess import Popen
lookup = 'UDP Filtered Portscan'
os.chdir(r'D:\Snort\log')
line_number = 0
line_num = 0
counter = 0
search_phrase = "[**]"
#search_phrase1 = "JAVASCRIPT OBFUSCATION LEVELS EXCEEDS"
str1= ("cmd /c netsh advfirewall firewall add rule name=rule1 dir=in action=block protocol=any remoteip=")
#line_number = int(raw_input('Enter the line number: '))
x = []
empty_line = []
blank=''
linec = 0

def printme():
	global counter
	counter += 1
	wordx = str1.split()
	indexn = str(counter)
	rulename = "".join(("name=rule", indexn))
	wordx[7] = rulename
	wordx = " ".join(wordx)
	print wordx
	f = open('alert.ids', "U")
	i = 1
	for line in f:
		if i == line_number:
			break
		i += 1
	words = line.split() 
	str2= words[3]
	wordx = "".join((wordx, str2))
	os.system(wordx)
	return;
	
def emptys():
	if line in ['\n', '\r\n']:
		print str(line_num)
		if any(str(line_num) in i for i in empty_line):
			print "Line already empty"
		else:
			empty_line.extend([str(line_num)])
		print empty_line
	
def file_len(fname):
	i = 0
	f = open(fname)
	for i, l in enumerate(f):
		pass
	f.close()
	return i + 1

	
while True:	
	last_line = file_len('alert.ids')
	myFile = open('alert.ids', "U")
	#num_lines = sum(1 for line in myFile)
	for line in myFile.readlines():
		line_num += 1
		emptys()
		if line_num == last_line:
			break
			time.sleep(1)
		if line.find(search_phrase) >= 0:
			line_nums=str(line_num)
			print "Dies ist ein Teststring"
			#if line_nums in [x]:
			if any(line_nums in s for s in x):
        pass
			else:
				x.extend([line_nums])
				line_number = line_num+2
				printme()
	time.sleep(1)
	myFile.close()
	line_num = 0

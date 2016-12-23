import mmap,os,sys,subprocess,time,socket
from subprocess import Popen
import _winreg as wreg
lookup = 'UDP Filtered Portscan'
os.chdir(r'D:\Snort\log')
line_number = line_num = counter = 0
compare = ['[**]'];
str1= ("cmd /c netsh advfirewall firewall add rule name=rule1 dir=in action=block protocol=any remoteip=")
str2= ("127.0.0.1 ")
str3= r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\'
#line_number = int(raw_input('Enter the line number: '))
x = []
empty_line = []
run = True

def lookup(addr):
	try:
		return socket.gethostbyaddr(addr)
	except socket.herror:
		return None, None, None
		
def ipextract():
	f = open('alert.ids', "U")
	i = 1
	for line in f:
		if i == line_number:
			break
		i += 1
	words = line.split() 
	str2= words[3]
	str2 = str2.split(":", 1)[0]
	return str2
	
def winreg(dnsname):
	regrule = "".join((str3, dnsname))
	print regrule
	key = wreg.CreateKey(wreg.HKEY_CURRENT_USER, regrule)
	wreg.SetValueEx(key, '*', 0, wreg.REG_DWORD, 0x00000004)

def firewallr():
	global counter
	counter += 1
	wordx = str1.split()
	indexn = str(counter)
	rulename = "".join(("name=rule", indexn))
	wordx[7] = rulename
	wordx = " ".join(wordx)
	wordx = "".join((wordx, ipextract()))
	print wordx
	os.system(wordx)
	return;
	
def emptys():
	if line in ['\n', '\r\n']:
		if any(str(line_num) in i for i in empty_line):
			pass
		else:
			empty_line.extend([str(line_num)])
	
def file_len(fname):
	i = 0
	f = open(fname)
	for i, l in enumerate(f):
		pass
	f.close()
	return i + 1

	
while run:	
	last_line = file_len('alert.ids')
	myFile = open('alert.ids', "U")
	for line in myFile.readlines():
		line_num += 1
		emptys()
		if line_num == last_line:
			time.sleep(1)
			break
		if line.find(compare[0]) >= 0:
			line_nums=str(line_num)
			if any(line_nums in s for s in x):
				pass
			else:
				x.extend([line_nums])
				if 'portscan' in line:
					line_number = line_num+2
					print "easy"
					firewallr()
				if 'OBFUSCATION' in line:
					line_number = line_num+2
					name,alias,addresslist = lookup(ipextract())
					winreg(name)			
	time.sleep(1)
	myFile.close()
	line_num = 0

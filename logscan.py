import mmap,os,os.path,sys,subprocess,time,socket
from subprocess import Popen
import _winreg as wreg
PATH= 'alert.ids'
os.chdir(r'D:\Snort\log')
line_number = line_num = counter = 0
compare = ['[**]'];
str1 = ("cmd /c netsh advfirewall firewall add rule name=rule1 dir=in action=block protocol=any remoteip=")
str2 = ("127.0.0.1 ")
str3 = r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\'
str4 = r'SYSTEM\\CurrentControlSet\\Services\\TcpIp\\Parameters\\'
str5 = r'SYSTEM\\CurrentControlSet\\services\\DNS\\Parameters\\'
str6 = r'SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters\\'
str7 = r'wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2'
x = []
empty_line = []
cache = []
blockedip = []
ip = []
run = True
DETACHED_PROCESS = 0x00000008


def lookup(addr):
	try:
		return socket.gethostbyaddr(addr)
	except socket.herror:
		return None, None, None
		
def reverselookup(name):
	try:
		host = socket.gethostbyname(name)
		return host
	except socket.gaierror, err:
		print "cannot resolve hostname: ", name, err

def ipextract():
	f = open('alert.ids', "U")
	i = 1
	for line in f:
		if i == line_number:
			break
		i += 1
	words = line.split() 
	cache = words[1]
	cache = cache.split(":", 1)[0]
	if any(cache in s for s in blockedip):
		print "Es wurde ein Eintrag gefuden"
		return;
	else:
		blockedip.extend([cache])
		print cache
		f.close()
		return cache
	
def dnscheck():
	ip = ipextract()
	if not ip:
		return;
	else:
		print ip
		name,alias,addresslist = lookup(ip)
		ip2 = reverselookup(name)
		winreg(name,'*',0x00000004,0,str3)
		if ip in ip2:
			pass
		else:
			print "Your DNS Cache is poisened!"
		
def synflood():
	winreg(name,'SynAttackProtect',0x00000002,1,str4)
	winreg(name,'TcpMaxPortsExhausted',0x00000005,1,str4)
	winreg(name,'TcpMaxHalfOpen',0x000001F4,1,str4)
	winreg(name,'TcpMaxHalfOpenRetried',0x00000190,1,str4)
	
def icmp():
	winreg(name,'EnableICMPRedirect',0x00000000,1,str4)
	
def snmp():
	winreg(name,'EnableDeadGWDetect',0x00000000,1,str4)
	
def additional():
	winreg(name,'DisableIPSourceRouting',0x00000001,1,str4)
	winreg(name,'EnableMulticastForwarding',0x00000000,1,str4)
	winreg(name,'IPEnableRouter',0x00000000,1,str4)
	winreg(name,'EnableAddrMaskReply',0x00000000,1,str4)
	
def afdprotection():
	winreg(name,'EnableDynamicBacklog',0x00000001,1,str5)
	winreg(name,'MinimumDynamicBacklog',0x00000014,1,str5)
	winreg(name,'MaximumDynamicBacklog',0x00004E20,1,str5)
	winreg(name,'DynamicBacklogGrowthDelta',0x0000000A,1,str5)
	
def winreg(dnsname, regn, rvalue,rpath,str):
	regrule = "".join((str3, dnsname))
	print regrule
	if rpath == 0:
		key = wreg.CreateKey(wreg.HKEY_CURRENT_USER, regrule)
	else:
		key = wreg.CreateKey(wreg.HKEY_LOCAL_MACHINE, regrule)
	wreg.SetValueEx(key, regn, 0, wreg.REG_DWORD, rvalue)

def firewallr():
	global counter
	counter += 1
	wordx = str1.split()
	indexn = str(counter)
	rulename = "".join(("name=rule", indexn))
	wordx[7] = rulename
	wordx = " ".join(wordx)
	cache = ipextract()
	if not cache:
		return;
	else:
		wordx = "".join((wordx, cache))
		print wordx
		os.system(wordx)
		return;
		
def dnetbios():
	os.system(str7)
	
def addhost():
	ip = ipextract()
	if not ip:
		return;
	else:
		os.chdir(r'C:\Windows\System32\drivers\etc')
		#os.chdir(r'C:\Users\Gregor\Desktop')
		cache = "".join(ip)
		print cache
		try:
			fileObj = open('hosts', "a")
			fileObj.write(cache + "\n")
			fileObj.close()
		except IOError:
			pass
		os.chdir(r'D:\Snort\log')
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

	
#pid = subprocess.Popen([sys.executable, "D:\Snort\log\http.py"],creationflags=DETACHED_PROCESS).pid
#pid1 = subprocess.Popen([sys.executable, "D:\Snort\log\pop3.py"],creationflags=DETACHED_PROCESS).pid
#pid2 = subprocess.Popen([sys.executable, "D:\Snort\log\smtpfake.py"],creationflags=DETACHED_PROCESS).pid
try:
	if os.path.isfile(PATH) and os.access(PATH, os.R_OK):
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
						line_number = line_num+2
						if 'scan' in line:
							firewallr()
						if 'OBFUSCATION' in line:
							dnscheck()
						if 'EXCEEDS' in line:
							dnscheck()
						if 'flood' in line:
							synflood()
						if 'ddos' in line:
							icmp()
						if 'snmp' in line:
							snmp()
						if 'cmd/unix/generic' in line:
							firewallr()
						if 'exploit' in line:
							dnscheck()
							firewallr()
						if 'suspicious' in line:
							addhost()
						if 'NBTStat' in line:
							dnetbios()
			time.sleep(1)
			myFile.close()
			line_num = 0
	else:
		print "Either file is missing or is not readable"
except KeyboardInterrupt:
	try:
		try:
			print "All removed"
			os.remove(PATH)
			sys.exit(0)
		except OSError:
			pass
	except SystemExit:
		os._exit(0)

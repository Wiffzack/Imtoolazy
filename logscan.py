from __future__ import division
import mmap,os,os.path,sys,subprocess,time,socket
from subprocess import Popen
import _winreg as wreg
PATH= 'alert.ids'
os.chdir(r'D:\Snort\log')
line_number = line_num = counter = counterc = problemc = 0
ldp = 0.0
compare = ['[**]'];
str1 = ("cmd /c netsh advfirewall firewall add rule name=rule1 dir=in action=block protocol=any remoteip=")
str2 = ("127.0.0.1 ")
str3 = r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\'
str4 = r'SYSTEM\\CurrentControlSet\\Services\\TcpIp\\Parameters\\'
str5 = r'SYSTEM\\CurrentControlSet\\services\\DNS\\Parameters\\'
str6 = r'SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters\\'
str7 = r'wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2'
str8 = r'netsh int tcp set security mpp=enabled'
str9 = r'netsh int tcp set heuristics forcews=enabled'
str10 = r'netsh advfirewall set allprofiles state on'
str11 = r'ipconfig /release'
str12 = r'ipconfig /renew'
str13 = r'netsh int ip set global taskoffload=disabled'
str14 = r'netsh interface ip set interface 10 retransmittime=3000'
str15 = r'NETSH INT TCP SET HEURISTICS DISABLED'
str16 = r'NETSH INT TCP SET GLOBAL AUTOTUNINGLEVEL=DISABLED'
str17 = r'NETSH INT TCP SET GLOBAL RSS=ENABLED'
str18 = r'IPCONFIG /FLUSHDNS'
str19 = r'netsh int tcp set supplemental congestionprovider=ctcp'
str20 = r'netsh int tcp set global chimney=enabled'
str21 = r'netsh int ipv4 set dynamicport tcp start=1025 num=65535'
str22 = r'netsh int ipv4 set subinterface 10 mtu=1492 store=persistent'
str23 = r'netsh int ip reset c:\logdatei.log; netsh winsock reset'
str24 = r'powershell Disable-NetAdapterLso -Name *'
str25 = r'net stop Dhcp && net start Dhcp'
str26 = r'netsh int tcp set global autotuninglevel=disabled'
x = []; name = '';empty_line = [];cache = [];cache2 = [];blockedip = [];ip = [];run = True
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
		return;

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
	global name
	ip = ipextract()
	if not ip:
		return;
	else:
		print ip
		name,alias,addresslist = lookup(ip)
		if not name:
			print "Name not resolvable!"
			return;
		ip2 = reverselookup(name)
		winreg(name,'*',0x00000004,0,str3)
		if ip in ip2:
			pass
		else:
			print "Your DNS Cache is poisened!"
		
def synflood():
	os.system(str8)
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
	
def tcpdrop():
	os.system(str21)
	winreg(name,'TcpTimedWaitDelay',0x0000003C,1,str4)
	winreg(name,'MaxUserPort',0x00008000,1,str4)
	winreg(name,'MaxFreeTcbs',0x0000ffff,1,str4)
	winreg(name,'MaxHashTableSize',0x00004000,1,str4)
	
def tcpdrops():
	winreg(name,'TcpMaxConnectRetransmissions',0x00000004,1,str4)
	winreg(name,'TcpMaxDataRetransmissions',0x0000000A,1,str4)
	winreg(name,'KeepAliveInterval',0x000007D0,1,str4)	

def winreg(dnsname, regn, rvalue,rpath,str):
	if not dnsname:
		pass
	else:
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
		cache = str2
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
	
def tracertc():
	cmd = 'tracert -d -h 1 www.google.at'.split()
	count2 = 0
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	while True:
		line = p.stdout.readline()
		if line != '':
			count2 += 1
			if count2 == 5:
				cache = line.split()
				return cache[7]
			else:
				pass
		else:
			break
	print p.communicate()[0]
	return;
	
def pingc():
	global problemc
	counterc = 0
	cmd = 'ping.exe -n 1 '
	try:
		cmd = "".join((cmd, tracertc())).split()
	except:
		print "Network is not working properly"
		diagnose()
		return;
	count2 = problemc = 0
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = p.stdout.readline()
		if line != '':
			count2 += 1
			if count2 == 3:
				cache = line.split()
				print cache
				cache2 = cache[4]
				cache = cache[5]
				if cache == "TTL=64":
					print "Everthing seems right!!!!!!!!!!!+"
					pass
				else:
					print "Something in your network is not normal!!!"
				cache2 = cache2.split("=", 1)[1]
				cache2 = cache2.split("ms", 1)[0]
				if int(cache2) > 3:
					counterc += 1
					if counterc == 3:
						print "Network time abnormal!"
				#return cache[5]
			else:
				pass
		else:
			break
	print p.communicate()[0]
	return;
	
def firewallc():
	count2 = 0
	cmd = 'netsh advfirewall show currentprofile'.split()
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = p.stdout.readline()
		if line != '':
			count2 += 1
			if count2 == 4:
				cache = line.split()
				cache = cache[1]
				if cache == "EIN":
					pass
				else:
					print "Error try to active Windows Firewall"
					try:
						os.system(str10)
					except:
						print "Couldnt activate Windows Firewall"
						sys.exit(0)
			else:
				pass
		else:
			break
	print p.communicate()[0]
	return;
	
def arpc():
	cmd = 'arp -a'.split()
	count2 = 0
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = p.stdout.readline()
		if line != '':
			count2 += 1
			if count2 == 2:
				cache =  line.split()
				cache = cache[3]
				cache = int(cache, 16)
				#cache = cache.split("x", 1)[1]
				return cache
			else:
				pass
		else:
			break
	print p.communicate()[0]
	return;
	
def netviewc():
	cmd = 'net view'.split()
	count2 = 0
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = p.stdout.readline()
		if line != '':
			count2 += 1
		else:
			if (count2-2) > 5:
				print "Network seems to be bigger , increase retransmit time"
				cache = str14.split()
				cache2 = str(arpc())
				cache[5] = cache2
				cache = " ".join(cache)
				os.system(cache)
				break
		break
	print p.communicate()[0]
	return;
	
def redirectc():
	cmd = 'net config rdr'.split()
	count2 = 0
	try:
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	except:
		print "Redirector Issues Found"
	print p.communicate()[0]
	return;
	
def ipstatsc():
	cmd = 'netsh interface ipv4 show ipstats'.split()
	count2 = 0
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = p.stdout.readline()
		if line != '':
			count2 += 1
			if count2 == 5:
				cache = line.split()
				recdp = (int(cache[3])/100)
				print recdp
			if count2 == 6:
				 cache = line.split()
				 cache = int(cache[3])
				 if cache > 10:
					print "Please enable Flow Control or try to reduce the bandwidht"
			if count2 == 10:
				cache = line.split()
				reciveddp = int(cache[3])
				print reciveddp
				calc = reciveddp/recdp
				print calc
				if calc > 2:
					print "Your network drop more than 2% of the packets!"
					ldp = calc
					os.system(str19)
					os.system(str20)
					os.system(str26)
					tcpdrop()
					netviewc()
		else:
			break
	print p.communicate()[0]
	return;
	
def dlso(command):
	cmd = command.split()
	try:
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
		print p.communicate()[0]
	except:
		print "Something went wrong"
	return;
	
def diagnose():
	problemc += 1
	if problemc == 1:
		print "Release Adresses and try to renew them"
		os.system(str11)
		os.system(str12)
	else:
		if problemc == 2:
			dlso(str24)
			os.system(str13)
			os.system(str15)
			os.system(str16)
			os.system(str17)
			print "Well Fuck"
			if problemc == 3:
				print "No Solution found  -> reset TCP"
				os.system(str23)
				if problemc == 4:
					print "Im not able to solve this! Sorry"
	return;
	
def everything():
	firewallc()
	ipstatsc()
	pingc()

#pid = subprocess.Popen([sys.executable, "D:\Snort\log\http.py"],creationflags=DETACHED_PROCESS).pid
#pid1 = subprocess.Popen([sys.executable, "D:\Snort\log\pop3.py"],creationflags=DETACHED_PROCESS).pid
#pid2 = subprocess.Popen([sys.executable, "D:\Snort\log\smtpfake.py"],creationflags=DETACHED_PROCESS).pid
#time.sleep(999)
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
					everything()
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
			time.sleep(10)
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

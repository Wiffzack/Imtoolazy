# w.balloon_tip by https://gist.github.com/boppreh

from __future__ import division
import mmap,os,os.path,sys,subprocess,time,socket,struct,win32con
from subprocess import Popen
from Tkinter import *
from tkFileDialog import askopenfilename
from tkFileDialog  import askdirectory  
import _winreg as wreg
from win32api import *
from win32gui import *
import errno
PATH= 'alert.ids'
line_number = line_num = counter = counterc = problemc = 0
ldp = 0.0;cv = 10.0;cv2 = 5.0;aptn = 15
compare = ['[**]'];
str1 = ("cmd /c netsh advfirewall firewall add rule name=rule1 dir=in action=block protocol=any remoteip=")
str2 = ("127.0.0.1 ")
str3 = r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\'
str4 = r'SYSTEM\\CurrentControlSet\\Services\\TcpIp\\Parameters\\'
str5 = r'SYSTEM\\CurrentControlSet\\services\\DNS\\Parameters\\'
str6 = r'SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters\\'
str7 = r'cmd /c wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2'
str8 = r'netsh int tcp set security mpp=enabled'
str9 = r'netsh int tcp set heuristics forcews=enabled'
str10 = r'netsh advfirewall set allprofiles state on'
str11 = r'ipconfig /release *Wifi* && ipconfig /release *Ethernet*'
str12 = r'ipconfig /renew *Wifi* && ipconfig /renew *Ethernet*'
str13 = r'netsh int ip set global taskoffload=disabled'
str14 = r'netsh interface ip set interface 10 retransmittime=3000'
str15 = r'netsh INT TCP SET HEURISTICS DISABLED'
str16 = r'netsh INT TCP SET GLOBAL AUTOTUNINGLEVEL=DISABLED'
str17 = r'netsh INT TCP SET GLOBAL RSS=ENABLED'
str18 = r'IPCONFIG /FLUSHDNS'
str19 = r'netsh int tcp set supplemental congestionprovider=ctcp'
str20 = r'netsh int tcp set global chimney=enabled'
str21 = r'netsh int ipv4 set dynamicport tcp start=1025 num=65535'
str22 = r'netsh int ipv4 set subinterface 10 mtu=1492 store=persistent'
str23 = r'netsh int ip reset c:\logdatei.log; netsh winsock reset'
str24 = r'powershell Disable-NetAdapterLso -Name *'
str25 = r'cmd /c net stop Dhcp && net start Dhcp'
str26 = r'netsh int tcp set global autotuninglevel=disabled'
str27 = 'wmic logicaldisk get caption'
str28 = 'fsutil dirty query ' 
str29 = 'wmic diskdrive get status'
str30 = 'netsh dnsclient set dnsservers name=10 source=static address=8.8.8.8 validate=no'
str31 = 'powershell Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force'
str32 = 'powershell Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 0 -Force'
x = []; name = '';empty_line = [];cache = [];cache2 = [];blockedip = [];ip = [];appc = [];run = True
DETACHED_PROCESS = 0x00000008

class WindowsBalloonTip:
    def __init__(self):
        message_map = {
                win32con.WM_DESTROY: self.OnDestroy,
        }
        # Register the Window class.
        wc = WNDCLASS()
        self.hinst = wc.hInstance = GetModuleHandle(None)
        wc.lpszClassName = "PythonTaskbar"
        wc.lpfnWndProc = message_map # could also specify a wndproc.
        self.classAtom = RegisterClass(wc)

    def balloon_tip(self,title, msg):
        # Create the Window.
        style = win32con.WS_OVERLAPPED | win32con.WS_SYSMENU
        self.hwnd = CreateWindow( self.classAtom, "Taskbar", style, \
                0, 0, win32con.CW_USEDEFAULT, win32con.CW_USEDEFAULT, \
                0, 0, self.hinst, None)
        UpdateWindow(self.hwnd)
        iconPathName = os.path.abspath(os.path.join( sys.path[0], "balloontip.ico" ))
        icon_flags = win32con.LR_LOADFROMFILE | win32con.LR_DEFAULTSIZE
        try:
           hicon = LoadImage(self.hinst, iconPathName, \
                    win32con.IMAGE_ICON, 0, 0, icon_flags)
        except:
          hicon = LoadIcon(0, win32con.IDI_APPLICATION)
        flags = NIF_ICON | NIF_MESSAGE | NIF_TIP
        nid = (self.hwnd, 0, flags, win32con.WM_USER+20, hicon, "tooltip")
        Shell_NotifyIcon(NIM_ADD, nid)
        Shell_NotifyIcon(NIM_MODIFY, \
                         (self.hwnd, 0, NIF_INFO, win32con.WM_USER+20,\
                          hicon, "Balloon  tooltip",msg,200,title))
        # self.show_balloon(title, msg)
        DestroyWindow(self.hwnd)

    def OnDestroy(self, hwnd, msg, wparam, lparam):
        nid = (self.hwnd, 0)
        Shell_NotifyIcon(NIM_DELETE, nid)
        PostQuitMessage(0) # Terminate the app.


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
		#print "cannot resolve hostname: ", name, err
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
		#print "Es wurde ein Eintrag gefuden"
		return;
	else:
		blockedip.extend([cache])
		#w.balloon_tip("Firewall Rule added", cache)
		f.close()
		return cache
	
def dnscheck():
	global name
	ip = ipextract()
	if not ip:
		return;
	else:
		#print ip
		name,alias,addresslist = lookup(ip)
		if not name:
			#print "Name not resolvable!"
			return;
		ip2 = reverselookup(name)
		winreg(name,'*',0x00000004,0,str3)
		if ip in ip2:
			pass
		else:
			w.balloon_tip("Your DNS Cache is poisened!", "Disconnect immediately!")
		
def synflood():
	os.system(str8)
	winreg(name,'SynAttackProtect',0x00000002,1,str4)
	winreg(name,'TcpMaxPortsExhausted',0x00000005,1,str4)
	winreg(name,'TcpMaxHalfOpen',0x000001F4,1,str4)
	winreg(name,'TcpMaxHalfOpenRetried',0x00000190,1,str4)
	winreg(name,'TcpMaxDataRetransmissions',0x00000003,1,str4)
	winreg(name,'EnablePMTUDiscovery',0x00000000,1,str4)
	
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
		regrule = str4
	else:
		regrule = "".join((str3, dnsname))
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
		counter -= 1
		return;
	else:
		wordx = "".join((wordx, cache))
		os.system(wordx)
		return;
		
def dnetbios():
	os.system(str7)

def dsmb():
	os.system(str31)
	os.system(str32)
	
def addhost():
	ip = ipextract()
	if not ip:
		return;
	else:
		os.chdir(r'C:\Windows\System32\drivers\etc')
		cache = str2
		cache = "".join(ip)
		w.balloon_tip("Add entry to host", "mmh")
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
	cmd = 'tracert -d -h 1 www.google.de'.split()
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
	return;
	
# Next time should check ttl value
def pingc():
	global aptn
	counterc = 0
	cmd = 'ping.exe -n 1 '
	try:
		cmd = "".join((cmd, tracertc())).split()
	except:
		diagnose()
		return;
	count2 = problemc = 0
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = p.stdout.readline()
		if line != '':
			count2 += 1
			if count2 == 3:
				try:
					cache = line.split()
					cache2 = cache[4]
					cache = cache[5]
					if cache == "TTL=64":
						pass
					else:
						w.balloon_tip("Network abnormal!", "Be careful")
					cache2 = cache2.split("=", 1)[1]
					cache2 = cache2.split("ms", 1)[0]
					apto = aptn
					aptn = int(cache2)
					if int(cache2) > (apto+5):
						counterc += 1
						if counterc == 3:
							w.balloon_tip("Network time abnormal", "Instabil")
				except:
					break
			else:
				pass
		else:
			break
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
					w.balloon_tip("Error Windows Firewall disabled", "Try to activate")
					try:
						os.system(str10)
					except:
						w.balloon_tip("Couldnt activate Windows Firewall", "Error: 1")
						sys.exit(0)
			else:
				pass
		else:
			break
	return;
	
#Give the default gateway ip even if several devices as VM are used !!!
def ipowershell(choose):
	try:
		cmd = """powershell "Get-WmiObject -Class Win32_IP4RouteTable | where { $_.destination -eq '0.0.0.0' -and $_.mask -eq '0.0.0.0'} | Sort-Object metric1 | select nexthop, metric1, interfaceindex"""
		count2 = 0
		print cmd
		b = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
		time.sleep(2)
		while True:
			line = b.stdout.readline()
			if line != '':
				count2 += 1
				if count2 == 4:
					print line
					cache =  line.split()
					if choose == 0:
						cache = cache[0]
						print cache
						return cache
					else:
						cache = cache[2]
						print cache
						return cache
				else:
					pass
			else:
				break
		return;
	except:
		cmd = """powershell Get-NetIPConfiguration | Foreach IPv4DefaultGateway"""
		count2 = 0
		b = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
		time.sleep(2)
		while True:
			line = b.stdout.readline()
			if line != '':
				count2 += 1
				if count2 == 5:
					print line
					cache =  line.split()
					cache = cache[0]
					return cache
				else:
					pass
			else:
				break
		return;

#Only works if the defautl gateway is the first device in the list !!! Patched !	
def arpc():
	return ipowershell(1)
	
def nslookupc():
	cmd = 'cmd /c nslookup google.com'.split()
	count2 = 0
	try:
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
		while True:
			line = p.stdout.readline()
			if line != '':
				count2 += 1
				if count2 == 1:
					cache =  line.split()
					cache = cache[0]
					if cache == "DNS":
						w.balloon_tip("DNS Server works not properly", "Change to google")
						cache2 = str30.split()
						cache = "".join(("name=", str(arpc())))
						cache2[6] = cache 
						cache2 = " ".join((cache2))
						os.system(cache2)
						break
				else:
					pass
			else:
				break
		return;
	except:
		while True:
			response = requests.get('http://www.google.com')
			if response.status_code == requests.codes.ok:
				pass
			else:
				pass
			break
		return;
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
			try:
				cache = nmap()
				if (count2-2 > cache):
					w.balloon_tip("Hidden User in the network", "No reason to be scared")
			except:
				pass
			if (count2-2) > 5:
				w.balloon_tip("network seems bigger", "Increase transmit time out")
				cache = str14.split()
				cache2 = str(arpc())
				cache[7] = cache2
				cache = " ".join(cache)
				os.system(cache)
				break
		break
	return;
	
def nmap():
	cmd = 'nmap -PR '
	ip = ipowershell(0)
	part0 = ip.split(".", 1)[0]
	part1 = ip.split(".", 2)[1]
	part2 = ip.split(".", 3)[2]
	ips =  "".join([cmd,part0,'.',part1,'.',part2,'.0/24'])
	print ips
	count2 = 0
	c = subprocess.Popen(ips, stdout=subprocess.PIPE, stderr=None)
	time.sleep(1)
	while True:
		line = c.stdout.readline()
		if line != '':
			count2 += 1
			lastl = line
		else:
			cache = lastl.split()
			cache = cache[5]
			cache = int(cache.split("(", 1)[1])
			return cache
	return;
	
	
def redirectc():
	cmd = 'net config rdr'.split()
	count2 = 0
	try:
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	except:
		w.balloon_tip("Redirector Issues Found", "No solution now")
	return;
	
def ipstatsc():
	global cv 
	global cv2
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
				#print recdp
			if count2 == 6:
				 cache = line.split()
				 cache = int(cache[3])
				 if cache > cv:
					w.balloon_tip("Transmission error occured", "Next time maybe")
					cv = (cache)
					print cache
					print cv
			if count2 == 10:
				cache = line.split()
				reciveddp = int(cache[3])
				#print reciveddp
				calc = reciveddp/recdp
				#print calc
				if calc > cv2:
					cv2 = (calc)
					w.balloon_tip("Drop Rate over 5%", "Your network drop more than 5% of the packets!")
					ldp = calc
					#os.system(str19)
					os.system(str20)
					os.system(str26)
					tcpdrop()
					netviewc()
					time.sleep(2)
		else:
			break
	return;
	
def dlso(command):
	cmd = command.split()
	try:
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	except:
		w.balloon_tip("Large Send Offload ", "Couldnt deactivated")
	return;
	
def diagnose():
	global problemc
	problemc += 1
	if problemc == 3:
		w.balloon_tip("Network is not working properly", "Start diagnose")
		os.system(str11)
		os.system(str12)
		w.balloon_tip("Release Adresses and try to renew them", "Try to connect: reconnect")
	else:
		if problemc == 4:
			dlso(str24)
			os.system(str13)
			os.system(str15)
			os.system(str16)
			os.system(str17)
			if problemc == 5:
				w.balloon_tip("No Solution found  -> reset TCP", "Good Luck")
				os.system(str23)
				if problemc == 6:
					w.balloon_tip("Im not able to solve this", "Good Luck")
	return;
	
def everything():
	checksmart()
	firewallc()
	ipstatsc()
	pingc()
	checkapp()

def initials():
	nslookupc()
	
# Disk check part	Nothing interesting!
def fsutilc(string):
	cmd = "".join((str28, string))
	count = 0
	try:
		b = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	except:
		pass
	while True:
		line = b.stdout.readline()
		if line != '':
			count += 1
			try:
				if count == 1:
					cache = line.split()
					cache = cache[4]
					#print cache
					if cache == "NICHT":
						pass
					else:
						#print "Device Wrong"
						w.balloon_tip("Dirty Flags ", string)
						pass
				else:
					pass
			except:
				pass
				#print "Only works with Windows Filesystem"
		else:
			break
	return;


def checknfts():
	count2 = 0
	cmd = 'cmd /c wmic logicaldisk get caption'.split()
	a = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = a.stdout.readline()
		if line != '':
			count2 += 1
			if count2 > 1:
				try:
					cache = line.split()
					cache = cache[0]
					#print cache
					if not cache:
						pass
					else:
						fsutilc(cache)
				except:
					break
			else:
				pass
		else:
			break
	return;	
	
def checksmart():
	count2 = 0
	cmd = str29.split()
	a = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = a.stdout.readline()
		if line != '':
			count2 += 1
			if count2 > 1:
				try:
					cache = line.split()
					cache = cache.split("=", 1)[1]
					cache = cache[0]
					#print cache
					if not cache:
						pass
					else:
						if cache == "OK":
							pass
						else:
							#print "S.M.A.R.T Error ! Its time for backups!"
							w.balloon_tip("S.M.A.R.T Error ! ", "Its time for backups!")
							os.system("wmic diskdrive get model, name, status")
							checknfts()
				except:
					break
			else:
				pass
		else:
			break
	return;	

#Simple way of port checking .
def checkport(port):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		sock.bind(('0.0.0.0', port))
		sock.listen(1)
		sock.close
		return;
	except  socket.error, v:
		errorcode=v[0]
		if errorcode==errno.EADDRINUSE:
			return 1
		else:
			w.balloon_tip("Unknow Port Error occured", "Sorry")
		
def checkapp():
	if checkport(20) and any('FTP' not in s for s in appc):
		appc.extend(['FTP'])
		w.balloon_tip("FTP Server", "Port 20 in use!")
	if checkport(22) and any('SSH' not in s for s in appc):
		appc.extend(['SSH'])
		w.balloon_tip("SSH found", "Port 22 in use!")
	if checkport(53) and any('DNS' not in s for s in appc):
		appc.extend(['DNS'])
		w.balloon_tip("DNS Server", "Port 53 in use!")
	if (checkport(80) or checkport(443)) and not (any('HTTP' in s for s in appc)):
		appc.extend(['HTTP'])
		w.balloon_tip("Webserver found", "Port 80/443 in use!")
		synflood()
		icmp()
		dsmb()
		dnetbios()
	if checkport(161) and any('SNMP' not in s for s in appc):
		appc.extend(['SNMP'])
		w.balloon_tip("SNMP Server found", "Port 161 in use!")
		snmp()
	if checkport(445) and any('microsoft-ds' not in s for s in appc):
		appc.extend(['microsoft-ds'])
		w.balloon_tip("microsoft-ds found", "Port 445 in use!")
	if checkport(554) and any('rtsp' not in s for s in appc):
		appc.extend(['rtsp'])
		w.balloon_tip("rtsp found", "Port 554 in use!")
	if checkport(5357) and any('wsdapi' not in s for s in appc):
		appc.extend(['wsdapi'])
		w.balloon_tip("wsdapi found", "Port 5357 in use!")

#pid = subprocess.Popen([sys.executable, "D:\Snort\log\http.py"],creationflags=DETACHED_PROCESS).pid
#pid1 = subprocess.Popen([sys.executable, "D:\Snort\log\pop3.py"],creationflags=DETACHED_PROCESS).pid
#pid2 = subprocess.Popen([sys.executable, "D:\Snort\log\smtpfake.py"],creationflags=DETACHED_PROCESS).pid
#w.balloon_tip("Title for popup", "This is the popup's message")
#time.sleep(999)
#checknfts()
w = WindowsBalloonTip()
initials()
try:
	os.chdir(r'D:\Snort\log')
except:
	Tk().withdraw()
	fname = askdirectory()
	for ch in ['//']:
		if ch in fname:
			fname=fname.replace(ch,"\\")
	print fname
	os.chdir(fname)
try:
	while run:
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
			w.balloon_tip("Either file is missing or is not readable", "No admin rights?")
except KeyboardInterrupt:
	try:
		try:
			w.balloon_tip("Shutdown succesful", "Goodbye")
			os.remove(PATH)
			sys.exit(0)
		except OSError:
			pass
	except SystemExit:
		os._exit(0)

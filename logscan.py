# w.balloon_tip by https://gist.github.com/boppreh
# ram by https://www.blog.pythonlibrary.org/2010/01/27/getting-windows-system-information-with-python/
# http://code.google.com/p/psutil/

from __future__ import division
import mmap,os,os.path,sys,subprocess,time,socket,struct,win32con,platform,re,pythoncom,ctypes
#import pyHook as hook
from subprocess import Popen
import Tkinter
from tkFileDialog import askopenfilename
from tkFileDialog  import askdirectory  
import _winreg as wreg
from win32api import *
from win32gui import *
from win32com.client import GetObject
import errno
PATH= 'alert.ids'
fname = r'D:\Snort\log'
line_number = line_num = counter = counterc = problemc = cool = 0
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
str33 = 'netsh int tcp set global dca=enabled'
str34 = 'netsh int tcp set global rsc=enabled'
str35 = 'SOFTWARE\\Microsoft\\Direct3D\\'
str36 = 'SOFTWARE\\Microsoft\\DirectDraw\\'
str37 = 'SOFTWARE\\Microsoft\\Direct3D\\Drivers\\'
str38 = 'SOFTWARE\\WOW6432Node\\Microsoft\\Direct3D\\'
str39 = 'SOFTWARE\\WOW6432Node\\Microsoft\\DirectDraw\\'
str40 = 'CurrentControlSet\\Control\\GraphicsDrivers\\'
str41 = 'SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\'
x = []; name = '';empty_line = [];cache = [];cache2 = [];blockedip = [];ip = [];appc = [];run = True;arch = ''
cpuinfo = is_windows = somestring = ''
DETACHED_PROCESS = 0x00000008

bits = platform.architecture()[0]
is_windows = platform.system().lower() == 'windows'

test_key_name = "SOFTWARE\\Python Registry Test Key - Delete Me"

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

def get_cpu_info_from_registry():
	'''
	FIXME: Is missing many of the newer CPU flags like sse3
	Returns the CPU info gathered from the Windows Registry. Will return None if
	not on Windows.
	'''
	global is_windows
	global cpuinfo


	# Just return None if not on Windows
	if not is_windows:
		return None
	
	try:
		import _winreg as winreg
	except :
		import winreg
		

	# Get the CPU arch and bits
	key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
	raw_arch_string = winreg.QueryValueEx(key, "PROCESSOR_ARCHITECTURE")[0]
	winreg.CloseKey(key)
	arch, bits = parse_arch(raw_arch_string)

	# Get the CPU MHz
	#key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Hardware\Description\System\CentralProcessor\0")
	#processor_hz = winreg.QueryValueEx(key, "~Mhz")[0]
	#winreg.CloseKey(key)
	#processor_hz = to_hz_string(processor_hz)

	# Get the CPU name
	key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Hardware\Description\System\CentralProcessor\0")
	processor_brand = winreg.QueryValueEx(key, "ProcessorNameString")[0]
	x = ['i3','i5','i7','Xeon','Core 2','Itanium','duo']
	if any(s in l for l in x for s in processor_brand):
		tune()
	winreg.CloseKey(key)

	# Get the CPU vendor id
	key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Hardware\Description\System\CentralProcessor\0")
	vendor_id = winreg.QueryValueEx(key, "VendorIdentifier")[0]
	winreg.CloseKey(key)

	# Get the CPU features
	key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Hardware\Description\System\CentralProcessor\0")
	feature_bits = winreg.QueryValueEx(key, "FeatureSet")[0]
	winreg.CloseKey(key)

	def is_set(bit):
		mask = 0x80000000 >> bit
		retval = mask & feature_bits > 0
		return retval

	# http://en.wikipedia.org/wiki/CPUID
	# http://unix.stackexchange.com/questions/43539/what-do-the-flags-in-proc-cpuinfo-mean
	# http://www.lohninger.com/helpcsuite/public_constants_cpuid.htm
	flags = {
		'fpu' : is_set(0), # Floating Point Unit
		'vme' : is_set(1), # V86 Mode Extensions
		'de' : is_set(2), # Debug Extensions - I/O breakpoints supported
		'pse' : is_set(3), # Page Size Extensions (4 MB pages supported)
		'tsc' : is_set(4), # Time Stamp Counter and RDTSC instruction are available
		'msr' : is_set(5), # Model Specific Registers
		'pae' : is_set(6), # Physical Address Extensions (36 bit address, 2MB pages)
		'mce' : is_set(7), # Machine Check Exception supported
		'cx8' : is_set(8), # Compare Exchange Eight Byte instruction available
		'apic' : is_set(9), # Local APIC present (multiprocessor operation support)
		'sepamd' : is_set(10), # Fast system calls (AMD only)
		'sep' : is_set(11), # Fast system calls
		'mtrr' : is_set(12), # Memory Type Range Registers
		'pge' : is_set(13), # Page Global Enable
		'mca' : is_set(14), # Machine Check Architecture
		'cmov' : is_set(15), # Conditional MOVe instructions
		'pat' : is_set(16), # Page Attribute Table
		'pse36' : is_set(17), # 36 bit Page Size Extensions
		'serial' : is_set(18), # Processor Serial Number
		'clflush' : is_set(19), # Cache Flush
		#'reserved1' : is_set(20), # reserved
		'dts' : is_set(21), # Debug Trace Store
		'acpi' : is_set(22), # ACPI support
		'mmx' : is_set(23), # MultiMedia Extensions
		'fxsr' : is_set(24), # FXSAVE and FXRSTOR instructions
		'sse' : is_set(25), # SSE instructions
		'sse2' : is_set(26), # SSE2 (WNI) instructions
		'ss' : is_set(27), # self snoop
		#'reserved2' : is_set(28), # reserved
		'tm' : is_set(29), # Automatic clock control
		'ia64' : is_set(30), # IA64 instructions
		'3dnow' : is_set(31) # 3DNow! instructions available
	}

	# Get a list of only the flags that are true
	flags = [k for k, v in flags.items() if v]
	flags.sort()

	return {
	#'vendor_id' : vendor_id,
	#'brand' : processor_brand,
	#'hz' : to_friendly_hz(processor_hz, 6),
	#'raw_hz' : to_raw_hz(processor_hz, 6),
	#'arch' : arch,
	#'bits' : bits,
	#'count' : multiprocessing.cpu_count(),
	#'raw_arch_string' : raw_arch_string,

	#'l2_cache_size' : 0,
	#'l2_cache_line_size' : 0,
	#'l2_cache_associativity' : 0,

	#'stepping' : 0,
	#'model' : 0,
	#'family' : 0,
	#'processor_type' : 0,
	#'extended_model' : 0,
	#'extended_family' : 0,
	#'flags' : flags
	}
	
def parse_arch(raw_arch_string):
	global arch
	arch, bits = None, None
	raw_arch_string = raw_arch_string.lower()
	
	# X86
	#	if re.match('^i\d86$|^x86$|^x86_32$|^i86pc$|^ia32$|^ia-32$|^bepc$', raw_arch_string):
	z = ['86','i86pc','ia32','ia-32']
	if any(raw_arch_string in s for s in z):
		arch = 'X86_32'
		bits = 32
	#elif re.search('^x64$|^x86_64$|^x86_64t$|^i686-64$|^amd64$|^ia64$|^ia-64$', raw_arch_string):
	z = ['86_64','x64','i686-64','amd64','ia64','ia-64','AMD64']
	if any(raw_arch_string in s for s in z):
		arch = 'X86_64'
		bits = 64
	# ARM
	#elif re.search('^armv8-a$', raw_arch_string):
	if "armv8" in raw_arch_string: 
		arch = 'ARM_8'
		bits = 64
	#elif re.search('^armv7$|^armv7[a-z]$|^armv7-[a-z]$', raw_arch_string):
	elif "armv7" in raw_arch_string: 
		arch = 'ARM_7'
		bits = 32
	#elif re.search('^armv8$|^armv8[a-z]$|^armv8-[a-z]$', raw_arch_string):
	elif "armv8" in raw_arch_string: 
		arch = 'ARM_8'
		bits = 32
	# PPC
	#elif re.search('^ppc32$|^prep$|^pmac$|^powermac$', raw_arch_string):
	elif "ppc32" in raw_arch_string: 	
		arch = 'PPC_32'
		bits = 32
	#elif re.search('^powerpc$|^ppc64$', raw_arch_string):
	elif "ppc64" in raw_arch_string: 
		arch = 'PPC_64'
		bits = 64
	# SPARC
	#elif re.search('^sparc32$|^sparc$', raw_arch_string):
	elif "sparc32" in raw_arch_string: 
		arch = 'SPARC_32'
		bits = 32
	#elif re.search('^sparc64$|^sun4u$|^sun4v$', raw_arch_string):
	elif "sun4v" in raw_arch_string: 
		arch = 'SPARC_64'
		bits = 64

	return (arch, bits)
	
def getac():
	class PowerClass(Structure):
		_fields_ = [('ACLineStatus', c_byte),
				('BatteryFlag', c_byte),
				('BatteryLifePercent', c_byte),
				('Reserved1',c_byte),
				('BatteryLifeTime',c_ulong),
				('BatteryFullLifeTime',c_ulong)]    
	powerclass = PowerClass()
	result = windll.kernel32.GetSystemPowerStatus(byref(powerclass))
	return powerclass.BatteryLifePercent

def ram():
	kernel32 = ctypes.windll.kernel32
	c_ulong = ctypes.c_ulong
	class MEMORYSTATUS(ctypes.Structure):
		_fields_ = [
			('dwLength', c_ulong),
			('dwMemoryLoad', c_ulong),
			('dwTotalPhys', c_ulong),
			('dwAvailPhys', c_ulong),
			('dwTotalPageFile', c_ulong),
			('dwAvailPageFile', c_ulong),
			('dwTotalVirtual', c_ulong),
			('dwAvailVirtual', c_ulong)
		]
 
	memoryStatus = MEMORYSTATUS()
	memoryStatus.dwLength = ctypes.sizeof(MEMORYSTATUS)
	kernel32.GlobalMemoryStatus(ctypes.byref(memoryStatus))
	mem = memoryStatus.dwTotalPhys / (1024*1024)
	availRam = memoryStatus.dwAvailPhys / (1024*1024)
	if availRam < 512:
		w.balloon_tip("Low Memory available", "Expect low performance")
	if mem >= 1000:
		mem = mem/1000
		totalRam = str(mem) + ' GB'
	else:
#        mem = mem/1000000
		totalRam = str(mem) + ' MB'
	#return (totalRam, availRam)
	return
	
def errorg(argument):
	switcher = {
		1: "This device is not configured correctly.",
		2: "Windows cannot load the driver for this device.",
		3: "The driver for this device might be corrupted, or your system may be running low on memory or other resources.",
		4: "This device is not working properly. One of its drivers or your registry might be corrupted.",
		5: "The driver for this device needs a resource that Windows cannot manage.",
		6: "The boot configuration for this device conflicts with other devices.",
		7: "Cannot filter.",
		8: "The driver loader for the device is missing.",
		9: "This device is not working properly because the controlling firmware is reporting the resources for the device incorrectly.",
		10: "This device cannot start.",
		11: "This device failed.",
		12: "This device cannot find enough free resources that it can use.",
		13: "Windows cannot verify this device's resources",
		14: "This device cannot work properly until you restart your computer.",
		15: "This device is not working properly because there is probably a re-enumeration problem. ",
		16: "Windows cannot identify all the resources this device uses.",
		17: "This device is asking for an unknown resource type.",
		18: "Reinstall the drivers for this device.",
		19: "Failure using the VxD loader.",
		20: "Your registry might be corrupted.",
		21: "System failure: Try changing the driver for this device. If that does not work, see your hardware documentation. Windows is removing this device.",
		22: "This device is disabled.",
		23: "System failure: Try changing the driver for this device. If that doesn't work, see your hardware documentation. ",
		24: "This device is not present, is not working properly, or does not have all its drivers installed.",
		25: "Windows is still setting up this device.",
		26: "Windows is still setting up this device.",
		27: "This device does not have valid log configuration.",
		28: "The drivers for this device are not installed.",
		29: "This device is disabled because the firmware of the device did not give it the required resources. ",
		30: "This device is using an Interrupt Request (IRQ) resource that another device is using.",
		31: "This device is not working properly because Windows cannot load the drivers required for this device.",
		}
	return switcher.get(argument, '')

def gpustatuserror(argument):
    switcher = {
		"Error": " Error indicates that this element might be OK but that another element, on which it is dependent, is in error",
		"Degraded": "Degraded indicates the ManagedElement is functioning below normal.",
		"Unknown": " indicates the implementation is in general capable of returning this property, but is unable to do so at this time.",
		"Pred Fail": "Predictive Failure indicates that an element is functioning normally but a failure is predicted in the near future. ",
		"Starting": "Starting indicates that the element is in the process of going to an Enabled state.",
		"Stopping": " Stopping is the value assigned to OperationalStatus, then this property may contain an explanation as to why an object is being stopped.",
		"Service": "In Service describes an element that is in service and operational.",
		"Stressed": "Stressed states are overload, overheated, and so on.",
		"NonRecover": "Non-Recoverable Error indicates that this element is in an error condition that requires human intervention.",
		"No Contact": "No Contact indicates that the monitoring system has knowledge of this element, but has never been able to establish communications with it.",
		"Lost Comm": "Lost Communication indicates that the ManagedSystem Element is known to exist and has been contacted successfully in the past, but is currently unreachable.",
    }
    return switcher.get(argument, "None")
	
def getgpu():
	WMI = GetObject('winmgmts:')
	for battery in WMI.InstancesOf('Win32_VideoController'):
		if battery.ConfigManagerErrorCode != 0:
			w.balloon_tip("GPU Error occured", errorg(battery.ConfigManagerErrorCode))
			getgpustatus()
		
def getgpustatus():
	WMI = GetObject('winmgmts:')
	for battery in WMI.InstancesOf('Win32_VideoController'):
		if battery.Status == "Lost Comm":
			gputimeout()
			
		
def available_cpu_count():
    try:
        import psutil
        return psutil.cpu_count()   # psutil.NUM_CPUS on old versions
    except (ImportError, AttributeError):
        pass

    # Windows
    try:
        res = int(os.environ['NUMBER_OF_PROCESSORS'])

        if res > 0:
            return res
    except (KeyError, ValueError):
        pass

        res = 0
        while '\ncpu' + str(res) + ':' in dmesg:
            res += 1

        if res > 0:
            return res
    except OSError:
        pass
    raise Exception('Can not determine number of CPUs on this system')
	
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
		
#Give the size of the temp folder back		
def get_size(start_path = '.'):
	os.chdir('C:\\temp')
	total_size = 0
	for dirpath, dirnames, filenames in os.walk(start_path):
		for f in filenames:
			fp = os.path.join(dirpath, f)
			total_size += os.path.getsize(fp)
	return total_size
		
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
	
def directxs():
	winreg(name,'PSGPNumThreads',available_cpu_count(),1,str35)
	winreg(name,'PSGPNumThreads',available_cpu_count(),1,str35)
	
def directxoff():
	winreg(name,'DisablePSGP',0x00000001,1,str35)
	winreg(name,'EmulationOnly',0x00000001,1,str36)
	winreg(name,'SoftwareOnly',0x00000001,1,str37)
	if arch == "X86_64":
		winreg(name,'EmulationOnly',0x00000001,1,str38)
		winreg(name,'SoftwareOnly',0x00000001,1,str39)
		winreg(name,'DisablePSGP',0x00000001,1,str38)
	
def directxon():
	winreg(name,'DisablePSGP',0x00000000,1,str35)
	winreg(name,'EmulationOnly',0x00000000,1,str36)
	winreg(name,'SoftwareOnly',0x00000000,1,str37)
	if arch == "X86_64":
		winreg(name,'EmulationOnly',0x00000000,1,str38)
		winreg(name,'SoftwareOnly',0x0000000,1,str39)
		winreg(name,'DisablePSGP',0x00000000,1,str38)
		
def gputimeout():
	winreg(name,'TdrDelay',0x00000014,1,str40)
	
def lanmantune():
	winreg(name,'SizReqBuf',0x0000ffff,1,str41)
	
def tcpinitialrtt(value):
	cache =  "".join(['SYSTEM\\CurrentControlSet\\Services\\TcpIp\\Parameters\\Interfaces\\',networkid()])
	print cache
	winreg(name,'TCPInitialRtt',value,1,cache)

def tune():
	os.system(str15)
	os.system(str33)
	os.system(str34)

def winreg(dnsname, regn, rvalue,rpath,str):
	print dnsname
	if not dnsname:
		regrule = str
	else:
		regrule = "".join((str3, dnsname))
	if rpath == 0:
		key = wreg.CreateKey(wreg.HKEY_CURRENT_USER, regrule)
	else:
		key = wreg.CreateKey(wreg.HKEY_LOCAL_MACHINE, regrule)
	wreg.SetValueEx(key, regn, 0, wreg.REG_DWORD, rvalue)
	wreg.CloseKey(key)
	key.Close()
	

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
		b = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
		time.sleep(2)
		while True:
			line = b.stdout.readline()
			if line != '':
				count2 += 1
				if count2 == 4:
					cache =  line.split()
					if choose == 0:
						cache = cache[0]
						return cache
					else:
						cache = cache[2]
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
				return
			else:
				return
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
	print "3"
	checksmart()
	checktemp()
	firewallc()
	ipstatsc()
	pingc()
	checkapp()
	getgpu()
	print "4"

def initials():
	global fname
	nslookupc()
	info = get_cpu_info_from_registry()
	
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
					if not cache:
						pass
					else:
						if cache == "OK":
							pass
						else:
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
	
def setapm(level):
	global cool
	if level == 1:
		cmd = 'hdparm.exe -B 128 sda'.split()
		cmd1 = 'hdparm.exe -B 128 hda'.split()
	else:
		cmd = 'hdparm.exe -B 255 sda'.split()
		cmd1 = 'hdparm.exe -B 255 hda'.split()
	try:
		os.chdir(r'C:\Program Files (x86)\hdparm')
	except:
		Tk().withdraw()
		hdparmd = askdirectory()
		for ch in ['//']:
			if ch in hdparmd:
				hdparmd=hdparmd.replace(ch,"\\")
		print fname
		os.chdir(hdparmd)
	subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=None)
	w.balloon_tip("APM level Set", "Finish")
	os.chdir(fname)
	cool = 1
	
def setwc(level):
	if level == 0:
		cmd = 'hdparm.exe -W0 hda'.split()
		cmd1 = 'hdparm.exe -W0 hdb'.split()
	else:
		cmd = 'hdparm.exe -W1 hda'.split()
		cmd1 = 'hdparm.exe -W1 hdb'.split()
	try:
		os.chdir(r'C:\Program Files (x86)\hdparm')
	except:
		Tk().withdraw()
		hdparmd = askdirectory()
		for ch in ['//']:
			if ch in hdparmd:
				hdparmd=hdparmd.replace(ch,"\\")
		print fname
		os.chdir(hdparmd)
	subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=None)
	w.balloon_tip("Disabled Write Cache", "Finish")
	os.chdir(fname)
	
#except seems not really to work!
def checktemp():
	cmd = """powershell  Get-PhysicalDIsk | Get-StorageReliabilityCounter |  Select-Object Temperature"""
	count2 = 0
	b = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = b.stdout.readline()
		if line != '':
			count2 += 1
			if count2 == 4:
				print line
				cache =  line.split()
				cache = int(cache[0])
				if cache > 59:
					w.balloon_tip("Hard disk temperature exceeds critical values!", "You should decrease the APM Level")
					if cool == 0:
						try:
							setapm(1)
						except:
							pass
						break
			else:
				pass
		else:
			break
	return;
	try:
		cmd = """powershell Get-WmiObject -Class Win32_PerfFormattedData_Counters_ThermalZoneInformation |Select-Object Name,Temperature"""
		count2 = 0
		b = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
		while True:
			line = b.stdout.readline()
			if line != '':
				count2 += 1
				if count2 == 4:
					cache =  line.split()
					cache = int(cache[1])
					cache = cache - 273
					if cache > 65:
						w.balloon_tip("Motherboard temperature exceeds critical values!", "Cool down")
						break
				else:
					pass
			else:
				break
		return;
	except:
		cmd = 'cmd /c wmic /namespace:\\root\cimv2 PATH Win32_PerfFormattedData_Counters_ThermalZoneInformation get Temperature'.split()
		count2 = 0
		b = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
		time.sleep(1)
		while True:
			line = b.stdout.readline()
			if line != '':
				count2 += 1
				if count2 == 2:
					print line
					cache =  line.split()
					cache = int(cache[0])
					cache = cache - 273
					if cache > 59:
						w.balloon_tip("Hard disk temperature exceeds critical values!", "Decrease lifetime of harddisk")
				else:
					pass
			else:
				break
		return;
	
#Read the  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*
def networkid():
	cmd = """powershell "Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | Select-Object -Property [a-z]* -ExcludeProperty IPX*,WINS* | where { $_.InterfaceIndex -eq '7'} | Sort-Object GatewayCostMetric | Select-Object SettingID"""
	cache = cmd.split()
	cache[19] =  "".join([ipowershell(1),'}'])
	cache = " ".join(cache)
	count2 = 0
	c = subprocess.Popen(cache, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = c.stdout.readline()
		if line != '':
			count2 += 1
			if count2 == 4:
				cache =  line.split()
				cache = cache[0]
				return cache
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
			w.balloon_tip("Unknow Port Error occured", str(port))
			return 1
		
def checkapp():
	if checkport(20) and not any('FTP' in s for s in appc):
		appc.extend(['FTP'])
		w.balloon_tip("FTP Server", "Port 20 in use!")
		lanmantune()
	if checkport(22) and not any('SSH' in s for s in appc):
		appc.extend(['SSH'])
		w.balloon_tip("SSH found", "Port 22 in use!")
	if checkport(53) and not any('DNS' in s for s in appc):
		appc.extend(['DNS'])
		w.balloon_tip("DNS Server", "Port 53 in use!")
	if (checkport(80) or checkport(443)) and not (any('HTTP' in s for s in appc)):
		appc.extend(['HTTP'])
		w.balloon_tip("Webserver found", "Port 80/443 in use!")
		synflood()
		icmp()
		dsmb()
		dnetbios()
		setwc(0)
	if checkport(161) and not any('SNMP' in s for s in appc):
		appc.extend(['SNMP'])
		w.balloon_tip("SNMP Server found", "Port 161 in use!")
		snmp()
	#if checkport(445) and not any('microsoft-ds' in s for s in appc):
	#	appc.extend(['microsoft-ds'])
	#	w.balloon_tip("microsoft-ds found", "Port 445 in use!")
	if checkport(554) and not any('rtsp' in s for s in appc):
		appc.extend(['rtsp'])
		w.balloon_tip("rtsp found", "Port 554 in use!")
	#if checkport(5357) and not any('wsdapi' in s for s in appc):
	#	appc.extend(['wsdapi'])
	#	w.balloon_tip("wsdapi found", "Port 5357 in use!")
	

#pid = subprocess.Popen([sys.executable, "D:\Snort\log\http.py"],creationflags=DETACHED_PROCESS).pid
#pid1 = subprocess.Popen([sys.executable, "D:\Snort\log\pop3.py"],creationflags=DETACHED_PROCESS).pid
#pid2 = subprocess.Popen([sys.executable, "D:\Snort\log\smtpfake.py"],creationflags=DETACHED_PROCESS).pid
#w.balloon_tip("Title for popup", "This is the popup's message")
#checknfts()
w = WindowsBalloonTip()
#getgpustatus()	
#time.sleep(999)
initials()
try:
	os.chdir(fname)
except:
	Tk().withdraw()
	fname = askdirectory()
	for ch in ['//']:
		if ch in fname:
			fname=fname.replace(ch,"\\")
	print fname
	os.chdir(fname)
print "2"
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

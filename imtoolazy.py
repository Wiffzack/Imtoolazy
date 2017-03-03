# w.balloon_tip by https://gist.github.com/boppreh
# ram by https://www.blog.pythonlibrary.org/2010/01/27/getting-windows-system-information-with-python/
# http://code.google.com/p/psutil/


from __future__ import division
import sys                      # access to basic things like sys.argv
import os                       # access pathname utilities
from functools import wraps
import posixpath
is_py2 = sys.version[0] == '2'
if is_py2:
	try:
		from tkFileDialog import askopenfilename
		from tkFileDialog  import askdirectory  
		import _winreg as wreg
		import Tkinter
		import Queue
	except ImportError:
		 os.system('python -m pip install wx')
else:
	try:
		from tkinter import *
		import tkinter.filedialog
		from tkinter import filedialog
		from multiprocessing import Queue
		import wx.adv
		import winreg as wreg
	except ImportError:
		 os.system('python -m pip install wx')

try:
	import mmap,os.path,subprocess,time,socket,struct,win32con,platform,re,ctypes,win32ui,math,psutil,threading,string,win32process,wx
	from subprocess import Popen
	#from win32api import *
	import win32api
	from win32gui import *
	import win32gui
	from win32com.client import GetObject
	import errno
	import pythoncom
	from ctypes.wintypes import HWND
	from ctypes import *
	from win32file import *
	from winioctlcon import FSCTL_GET_REPARSE_POINT
	from fcntl import fcntl, F_GETFL, F_SETFL
	from os import O_NONBLOCK, read
	#import pyHook
	#from pygame.locals import *
	from pymouse import PyMouse
	from gglsbl import SafeBrowsingList
	from base64 import b64encode, b64decode

	import logging
	log = logging.getLogger()
	log.addHandler(logging.NullHandler())

	from gglsbl.utils import to_hex
	from gglsbl.protocol import SafeBrowsingApiClient, URL
	from gglsbl.storage import SqliteStorage, ThreatList, HashPrefixList
except ImportError:
	os.system('python -m pip install pygame nmap')
	
try:
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    from apiclient.discovery import build
    from apiclient.errors import HttpError
	

import urllib.parse as urllib
from urllib import parse as urlparse
	
import json
import hashlib
import contextlib
import sqlite3
import logging
from gglsbl.utils import to_hex
from gglsbl.protocol import SafeBrowsingApiClient, URL
from gglsbl.storage import SqliteStorage, ThreatList, HashPrefixList
from base64 import b64encode, b64decode
from gglsbl3 import SafeBrowsingList
#from gglsbl.utils import to_hex
	

PATH= 'alert.ids'
fname = r'D:\Snort\log'
line_number = line_num = counter = counterc = problemc = cool = startm = endm = windowsize = ProcessID = oProcessID = 0
# Different times for ping
ldp = 0.0;cv = 10.0;cv2 = 5.0;aptn = 15
# Temperatur k= 1/t*ln(Ta-Tu/(Tn-Tu)) -> T = Tu*(Ta-Tu)*e^-kt
# System depending constant
Tu = 20;Ta = 25;Tn = t = 0
#Need some time , not finish now(obvious mistake!)
k = -0.00878084723396
compare = ['[**]'];
sysdrivestrjava = '\ProgramData\Oracle\Java\javapath'
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
str42 = 'netsh int tcp set global initialRto=1000'
str43 = 'netsh interface ip delete arpcache'
str44 = 'SYSTEM\\CurrentControlSet\\services\\DNS\\Parameters\\'
str45 = 'SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\'
str46 = 'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SubSystems\\'
str47 = 'powershell Set-NetAdapterAdvancedProperty -Name * -RegistryKeyword "CtsToItself" -Registryvalue "1"'
str48 = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\'
str49 = 'System\\CurrentControlSet\\Services\\MRXSmb\\Parameters\\'
str50 = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\explorer\\SCAPI\\'
x = []; name = '';empty_line = [];cache = [];cache2 = [];blockedip = [];ip = [];appc = [];run = True;arch = '';ose = '';powercfgl = [];
setmod = 2
cpuinfo = is_windows = somestring = ''
DETACHED_PROCESS = 0x00000008

# URL Blocklist download !
# If not already downloaded , download the necessary files and apply changes!
#
#url1 = ['http://www.malwaredomainlist.com/hostslist/hosts.txt', 'https://adaway.org/hosts.txt', 'https://hosts-file.net/ad_servers.txt', 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext']
url1 = ['https://adaway.org/hosts.txt', 'https://hosts-file.net/ad_servers.txt', 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext']

## Switch for 
normalmode = 1

# Google Api
# Please request your own api key !!!
google_api = 'AIzaSyCZ1H60_jeoasn-BPcUPUk-fYBBrW6VNS0'

# Disk access times
last_disk_time = None
last_time = None

bits = platform.architecture()[0]
is_windows = platform.system().lower() == 'windows'

IP_MTU_DISCOVER   = 10
IP_PMTUDISC_DONT  =  0  # Never send DF frames.
IP_PMTUDISC_WANT  =  1  # Use per route hints.
IP_PMTUDISC_DO    =  2  # Always DF.
IP_PMTUDISC_PROBE =  3  # Ignore dst pmtu.

# Mouse Coordinates
mosposx = ()
mosposold = ()

# Queue
if is_py2:
	my_queue = Queue.Queue()
else:
	my_queue = Queue()

#Taskbar icon
TRAY_TOOLTIP = 'System Tray Demo'
TRAY_ICON = 'icon.png'

#Path of the programm : For example ->C:\Programme\bla\bla
pathname = os.path.dirname(sys.argv[0]) 
spath = os.path.abspath(pathname)

#Mouse stats 
state_left = win32api.GetKeyState(0x01)  # Left button down = 0 or 1. Button up = -127 or -128
state_right = win32api.GetKeyState(0x02)  # Right button down = 0 or 1. Button up = -127 or  -128


# Check if file is no link!
# Doenst work , do anything at all.
__all__ = ['islink', 'readlink']

# Win32file doesn't seem to have this attribute.
FILE_ATTRIBUTE_REPARSE_POINT = 1024
# To make things easier.
REPARSE_FOLDER = (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)

# For the parse_reparse_buffer function
SYMBOLIC_LINK = 'symbolic'
MOUNTPOINT = 'mountpoint'
GENERIC = 'generic'

log = logging.getLogger()
log.addHandler(logging.NullHandler())

def get_versions():
    return json.loads(version_json)

# Part of the google safe browse function
version_json = '''
{
 "date": "2017-02-21T10:50:24+0100",
 "dirty": false,
 "error": null,
 "full-revisionid": "602dce43d96946ccd942fd8262c97aae7a6b79bb",
 "version": "v1.4.3"
}
'''  # END VERSION_JSON

__version__ = get_versions()['version']
del get_versions


class StopThread(StopIteration):
    pass

threading.SystemExit = SystemExit, StopThread

# A not so good implementation of threads!
class Thread(threading.Thread):
	def stop(self):
		self.__stop = True

	def _bootstrap(self):
		#self.iterations = 0
		#self.daemon = True  
		# OK for main to exit even if instance is still running
		#self.paused = True  # start out paused
		if threading._trace_hook is not None:
			raise ValueError('Cannot run thread with tracing!')
		self.__stop = False
		sys.settrace(self.__trace)
		super()._bootstrap()

	def __trace(self, frame, event, arg):
		if self.__stop:
			raise StopThread()
		return self.__trace
	
#wx.adv.TaskBarIcon	
class TaskBarIconWindow(wx.adv.TaskBarIcon):
	def __init__(self):
		super(TaskBarIconWindow, self).__init__()
		self.set_icon(TRAY_ICON)
		self.Bind(wx.adv.EVT_TASKBAR_LEFT_DOWN, self.on_left_down)

	def CreatePopupMenu(self):
		menu = wx.Menu()
		create_menu_item(menu, 'Say Hello', self.on_hello)
		menu.AppendSeparator()
		create_menu_item(menu, 'Exit', self.on_exit)
		return menu

	def set_icon(self, path):
		#from wx import IconFromBitmap
		if is_py2:
			icon = wx.IconFromBitmap(wx.Bitmap(path))
		else:
			icon =	wx.Icon(wx.Bitmap(path))
		self.SetIcon(icon, TRAY_TOOLTIP)

	def on_left_down(self, event):
		print ('Tray icon was left-clicked')

	def on_hello(self, event):
		print ('Hello, world!')

	def on_exit(self, event):
		os.system("taskkill /f /im python.exe")
		wx.CallAfter(self.Destroy)


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
		
class SqliteStorage(object):
    """Storage abstraction for local GSB cache"""
    def __init__(self, db_path):
        self.db_path = db_path
        do_init_db = not os.path.isfile(db_path)
        log.info('Opening SQLite DB {}'.format(db_path))
        self.db = sqlite3.connect(db_path)
        if do_init_db:
            log.info('SQLite DB does not exist, initializing')
            self.init_db()
        self.db.cursor().execute('PRAGMA synchronous = 0')

    @contextlib.contextmanager
    def get_cursor(self):
        dbc = self.db.cursor()
        try:
            yield dbc
        finally:
            dbc.close()

    def init_db(self):
        with self.get_cursor() as dbc:
            dbc.execute(
            """CREATE TABLE threat_list (
                threat_type character varying(128) NOT NULL,
                platform_type character varying(128) NOT NULL,
                threat_entry_type character varying(128) NOT NULL,
                client_state character varying(42),
                timestamp timestamp without time zone DEFAULT current_timestamp,
                PRIMARY KEY (threat_type, platform_type, threat_entry_type)
                )"""
            )
            dbc.execute(
            """CREATE TABLE full_hash (
                value BLOB NOT NULL,
                threat_type character varying(128) NOT NULL,
                platform_type character varying(128) NOT NULL,
                threat_entry_type character varying(128) NOT NULL,
                downloaded_at timestamp without time zone DEFAULT current_timestamp,
                expires_at timestamp without time zone NOT NULL DEFAULT current_timestamp,
                malware_threat_type varchar(32),
                PRIMARY KEY (value, threat_type, platform_type, threat_entry_type)
                )"""
            )
            dbc.execute(
            """CREATE TABLE hash_prefix (
                value BLOB NOT NULL,
                cue character varying(4) NOT NULL,
                threat_type character varying(128) NOT NULL,
                platform_type character varying(128) NOT NULL,
                threat_entry_type character varying(128) NOT NULL,
                timestamp timestamp without time zone DEFAULT current_timestamp,
                negative_expires_at timestamp without time zone NOT NULL DEFAULT current_timestamp,
                PRIMARY KEY (value, threat_type, platform_type, threat_entry_type),
                FOREIGN KEY(threat_type, platform_type, threat_entry_type)
                    REFERENCES threat_list(threat_type, platform_type, threat_entry_type)
                    ON DELETE CASCADE
                )"""
            )
            dbc.execute(
                """CREATE INDEX idx_hash_prefix_cue ON hash_prefix (cue)"""
            )
            dbc.execute(
                """CREATE INDEX idx_full_hash_expires_at ON full_hash (expires_at)"""
            )
            dbc.execute(
                """CREATE INDEX idx_full_hash_value ON full_hash (value)"""
            )
        self.db.commit()

    def lookup_full_hashes(self, hash_values):
        "Query DB to see if hash is blacklisted"
        q = '''SELECT threat_type,platform_type,threat_entry_type, expires_at < current_timestamp AS has_expired
                FROM full_hash WHERE value IN ({})
        '''
        output = []
        with self.get_cursor() as dbc:
            dbc.execute(q.format(','.join(['?']*len(hash_values))), [sqlite3.Binary(hv) for hv in hash_values])
            for h in dbc.fetchall():
                threat_type, platform_type, threat_entry_type, has_expired = h
                threat_list = ThreatList(threat_type, platform_type, threat_entry_type)
                output.append((threat_list, has_expired))
        return output

    def lookup_hash_prefix(self, cues):
        """Lookup hash prefixes by cue (first 4 bytes of hash)

        Returns a tuple of (threat_list, value, negative_cache_expired).
        """
        q = '''SELECT value,threat_type,platform_type,threat_entry_type,
                    negative_expires_at > current_timestamp AS negative_cache_expired
                FROM hash_prefix WHERE cue IN ({})
        '''
        output = []
        with self.get_cursor() as dbc:
            dbc.execute(q.format(','.join(['?'] * len(cues))), cues)
            for h in dbc.fetchall():
                value, threat_type, platform_type, threat_entry_type, negative_cache_expired = h
                threat_list = ThreatList(threat_type, platform_type, threat_entry_type)
                output.append((threat_list, bytes(value), negative_cache_expired))
        return output

    def store_full_hash(self, threat_list, hash_value, cache_duration, malware_threat_type):
        "Store full hash found for the given hash prefix"

        log.info('Storing full hash {} to list {} with cache duration {}'.format(to_hex(hash_value), str(threat_list), cache_duration))
        qi = '''INSERT OR IGNORE INTO full_hash
                    (value, threat_type, platform_type, threat_entry_type, malware_threat_type, downloaded_at)
                VALUES
                    (?, ?, ?, ?, ?, current_timestamp)
        '''
        qu = "UPDATE full_hash SET expires_at=datetime(current_timestamp, '+{} SECONDS') \
            WHERE value=? AND threat_type=? AND platform_type=? AND threat_entry_type=?"

        i_parameters = [sqlite3.Binary(hash_value), threat_list.threat_type,
                    threat_list.platform_type, threat_list.threat_entry_type, malware_threat_type]
        u_parameters = [sqlite3.Binary(hash_value), threat_list.threat_type,
                    threat_list.platform_type, threat_list.threat_entry_type]

        with self.get_cursor() as dbc:
            dbc.execute(qi, i_parameters)
            dbc.execute(qu.format(int(cache_duration)), u_parameters)
        self.db.commit()

    def delete_hash_prefix_list(self, threat_list):
        q = '''DELETE FROM hash_prefix
                    WHERE threat_type=? AND platform_type=? AND threat_entry_type=?
        '''
        parameters = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        with self.get_cursor() as dbc:
            dbc.execute(q, parameters)
        self.db.commit()

    def cleanup_full_hashes(self, keep_expired_for=60*60*12):
        """Remove long expired full_hash entries.
        """
        q = '''DELETE FROM full_hash WHERE expires_at=datetime(current_timestamp, '{} SECONDS')
        '''
        log.info('Cleaning up full_hash entries expired more than {} seconds ago.'.format(keep_expired_for))
        with self.get_cursor() as dbc:
            dbc.execute(q.format(int(keep_expired_for)))
        self.db.commit()

    def update_hash_prefix_expiration(self, threat_list, prefix_value, negative_cache_duration):
        q = "UPDATE hash_prefix SET negative_expires_at=datetime(current_timestamp, '+{} SECONDS') \
            WHERE value=? AND threat_type=? AND platform_type=? AND threat_entry_type=?"
        parameters = [sqlite3.Binary(prefix_value), threat_list.threat_type,
                    threat_list.platform_type, threat_list.threat_entry_type]
        with self.get_cursor() as dbc:
            dbc.execute(q.format(int(negative_cache_duration)), parameters)
        self.db.commit()

    def get_threat_lists(self):
        """Get a list of known threat lists including clientState values.
        """
        q = '''SELECT threat_type,platform_type,threat_entry_type,client_state FROM threat_list'''
        output = []
        with self.get_cursor() as dbc:
            dbc.execute(q)
            for h in dbc.fetchall():
                threat_type, platform_type, threat_entry_type, client_state = h
                threat_list = ThreatList(threat_type, platform_type, threat_entry_type)
                output.append((threat_list, client_state))
        return output

    def add_threat_list(self, threat_list):
        """Add threat list entry if it does not exist.
        """
        q = '''INSERT OR IGNORE INTO threat_list
                    (threat_type, platform_type, threat_entry_type, timestamp)
                VALUES
                    (?, ?, ?, current_timestamp)
        '''
        params = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        with self.get_cursor() as dbc:
            dbc.execute(q, params)
        self.db.commit()

    def delete_threat_list(self, threat_list):
        """Delete threat list entry.
        """
        log.info('Deleting cached threat list "{}"'.format(repr(threat_list)))
        q = '''DELETE FROM threat_list
                    WHERE threat_type=? AND platform_type=? AND threat_entry_type=?
        '''
        params = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        with self.get_cursor() as dbc:
            dbc.execute(q, params)
        self.db.commit()

    def update_threat_list_client_state(self, threat_list, client_state):
        log.info('Setting client_state of threat list {} to {}'.format(str(threat_list), client_state))
        q = '''UPDATE threat_list SET timestamp=current_timestamp, client_state=?
            WHERE threat_type=? AND platform_type=? AND threat_entry_type=?'''
        params = [client_state, threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        with self.get_cursor() as dbc:
            dbc.execute(q, params)
        self.db.commit()

    def hash_prefix_list_checksum(self, threat_list):
        """Returns SHA256 checksum for alphabetically-sorted concatenated list of hash prefixes
        """
        q = '''SELECT value FROM hash_prefix
                WHERE threat_type=? AND platform_type=? AND threat_entry_type=?
                ORDER BY value
        '''
        params = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        with self.get_cursor() as dbc:
            dbc.execute(q, params)
            all_hashes = b''.join([ bytes(h[0]) for h in dbc.fetchall() ])
            checksum = hashlib.sha256(all_hashes).digest()
        return checksum

    def populate_hash_prefix_list(self, threat_list, hash_prefix_list):
        log.info('Storing {} entries of hash prefix list {}'.format(len(hash_prefix_list), str(threat_list)))
        q = '''INSERT INTO hash_prefix
                    (value, cue, threat_type, platform_type, threat_entry_type, timestamp)
                VALUES
                    (?, ?, ?, ?, ?, current_timestamp)
        '''
        with self.get_cursor() as dbc:
            records = [[sqlite3.Binary(prefix_value), to_hex(prefix_value[0:4]), threat_list.threat_type,
                        threat_list.platform_type, threat_list.threat_entry_type] for prefix_value in hash_prefix_list]
            dbc.executemany(q, records)
        #self.db.commit()

    def get_hash_prefix_values_to_remove(self, threat_list, indices):
        log.info('Removing {} records from threat list "{}"'.format(len(indices), str(threat_list)))
        indices = set(indices)
        q = '''SELECT value FROM hash_prefix
                WHERE threat_type=? AND platform_type=? AND threat_entry_type=?
                ORDER BY value
        '''
        params = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type]
        values_to_remove = []
        with self.get_cursor() as dbc:
            dbc.execute(q, params)
            i = 0
            for h in dbc.fetchall():
                v = bytes(h[0])
                if i in indices:
                    values_to_remove.append(v)
                i += 1
        return values_to_remove

    def remove_hash_prefix_indices(self, threat_list, indices):
        """Remove records matching idices from a lexicographically-sorted local threat list.
        """
        batch_size = 40
        q = '''DELETE FROM hash_prefix
                WHERE threat_type=? AND platform_type=? AND threat_entry_type=? AND value IN ({})
        '''
        prefixes_to_remove = self.get_hash_prefix_values_to_remove(threat_list, indices)
        with self.get_cursor() as dbc:
            for i in range(0, len(prefixes_to_remove), batch_size):
                remove_batch = prefixes_to_remove[i:(i+batch_size)]
                params = [threat_list.threat_type, threat_list.platform_type, threat_list.threat_entry_type] + \
                                [sqlite3.Binary(b) for b in remove_batch]
                dbc.execute(q.format(','.join(['?'] * len(remove_batch))), params)

    def total_cleanup(self):
        "Reset local cache"
        with self.get_cursor() as dbc:
            q = 'DROP TABLE threat_list'
            dbc.execute(q)
            q = 'DROP TABLE hash_prefix'
            dbc.execute(q)
            q = 'DROP TABLE full_prefix'
            dbc.execute(q)
        self.db.commit()
        self.init_db()

		
def autoretry(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        global _fail_count
        while True:
            try:
                r = func(*args, **kwargs)
                _fail_count = 0
                return r
            except HttpError as e:
                if not (hasattr(e, 'resp') and 'status' in e.resp \
                        and e.resp['status'].isdigit and int(e.resp['status']) >= 500):
                    raise # we do not want to retry auth errors etc.
                _fail_count += 1
                wait_for = min(2**(_fail_count - 1) * 15 * 60 * (1 + random.random()), 24*60*60)
                log.exception('Call Failed for {} time(s). Retrying in {} seconds: {}'.format(_fail_count, wait_for, str(e)))
                time.sleep(wait_for)
            except socket.error as e:
                transient_error_wait = 2
                log.exception('Socket error, retrying in {} seconds.'.format(transient_error_wait))
                time.sleep(transient_error_wait)
    return wrapper
		
class SafeBrowsingApiClient(object):
    def __init__(self, developer_key, client_id='python-gglsbl', client_version=__version__, discard_fair_use_policy=True):
        self.client_id = client_id
        self.client_version = client_version
        self.discard_fair_use_policy = discard_fair_use_policy
        if self.discard_fair_use_policy:
            log.warn('Circumventing request frequency throttling is against Safe Browsing API policy.')
        self.service = build('safebrowsing', 'v4', developerKey=developer_key)
        self.next_request_no_sooner_than = None

    def set_wait_duration(self, minimum_wait_duration):
        if self.discard_fair_use_policy:
            return
        if minimum_wait_duration is None:
            self.next_request_no_sooner_than = None
            return
        self.next_request_no_sooner_than = time.time() + float(minimum_wait_duration.rstrip('s'))

    def fair_use_delay(self):
        if self.next_request_no_sooner_than is not None:
            sleep_for = self.next_request_no_sooner_than - time.time()
            log.info('Sleeping for {} seconds until next request.'.format(sleep_for))
            time.sleep(sleep_for)

    @autoretry
    def get_threats_lists(self):
        """Retrieve all available threat lists
        """
        response = self.service.threatLists().list().execute()
        self.set_wait_duration(response.get('minimumWaitDuration'))
        return response['threatLists']

    @autoretry
    def get_threats_update(self, client_state):
        """Fetch hash prefixes update for given threat list.

        client_state is a dict which looks like {(threatType, platformType, threatEntryType): clientState}
        """
        request_body = {
                "client": {
                "clientId":       self.client_id,
                "clientVersion":  self.client_version,
            },
            "listUpdateRequests": []
        }
        for (threat_type, platform_type, threat_entry_type), current_state in client_state.items():
            request_body['listUpdateRequests'].append(
                {
                    "threatType":      threat_type,
                    "platformType":    platform_type,
                    "threatEntryType": threat_entry_type,
                    "state":           current_state,
                    "constraints": {
                        "supportedCompressions": ["RAW"]
                    }
                }
            )
        response = self.service.threatListUpdates().fetch(body=request_body).execute()
        self.set_wait_duration(response.get('minimumWaitDuration'))
        return response['listUpdateResponses']

    @autoretry
    def get_full_hashes(self, prefixes, client_state):
        """Find full hashes matching hash prefixes.

        client_state is a dict which looks like {(threatType, platformType, threatEntryType): clientState}
        """
        request_body = {
          "client": {
            "clientId":      self.client_id,
            "clientVersion": self.client_version,
          },
          "clientStates": [],
          "threatInfo": {
            "threatTypes":      [],
            "platformTypes":    [],
            "threatEntryTypes": [],
            "threatEntries": [],
          }
        }
        for prefix in prefixes:
            request_body['threatInfo']['threatEntries'].append({"hash": b64encode(prefix).decode()})
        for ((threatType, platformType, threatEntryType), clientState) in client_state.items():
            request_body['clientStates'].append(clientState)
            if threatType not in request_body['threatInfo']['threatTypes']:
                request_body['threatInfo']['threatTypes'].append(threatType)
            if platformType not in request_body['threatInfo']['platformTypes']:
                request_body['threatInfo']['platformTypes'].append(platformType)
            if threatEntryType not in request_body['threatInfo']['threatEntryTypes']:
                request_body['threatInfo']['threatEntryTypes'].append(threatEntryType)
        response = self.service.fullHashes().find(body=request_body).execute()
        self.set_wait_duration(response.get('minimumWaitDuration'))
        return response
		
class URL(object):
    "URL representation suitable for lookup"
    def __init__(self, url):
        self.url = str(url)

    @property
    def hashes(self):
        "Hashes of all possible permutations of the URL in canonical form"
        for url_variant in self.url_permutations(self.canonical):
            url_hash = self.digest(url_variant)
            yield url_hash

    @property
    def canonical(self):
        "Convert URL to its canonical form"
        def full_unescape(u):
            uu = urllib.unquote(u)
            if uu == u:
                return uu
            else:
                return full_unescape(uu)
        def quote(s):
            safe_chars = '!"$&\'()*+,-./:;<=>?@[\\]^_`{|}~'
            return urllib.quote(s, safe=safe_chars)
        url = self.url.strip()
        url = url.replace('\n', '').replace('\r', '').replace('\t', '')
        url = url.split('#', 1)[0]
        url = quote(full_unescape(url))
        url_parts = urlparse.urlsplit(url)
        if not url_parts[0]:
            url = 'http://%s' % url
            url_parts = urlparse.urlsplit(url)
        protocol = url_parts.scheme
        host = full_unescape(url_parts.hostname)
        path = full_unescape(url_parts.path)
        query = url_parts.query
        if not query and '?' not in url:
            query = None
        if not path:
            path = '/'
        has_trailing_slash = (path[-1] == '/')
        path = posixpath.normpath(path).replace('//', '/')
        if has_trailing_slash and path[-1] != '/':
            path = path + '/'
        user = url_parts.username
        port = url_parts.port
        host = host.strip('.')
        host = re.sub(r'\.+', '.', host).lower()
        if host.isdigit():
            try:
                host = socket.inet_ntoa(struct.pack("!I", int(host)))
            except:
                pass
        if host.startswith('0x') and '.' not in host:
            try:
                host = socket.inet_ntoa(struct.pack("!I", int(host, 16)))
            except:
                pass
        quoted_path = quote(path)
        quoted_host = quote(host)
        if port is not None:
            quoted_host = '%s:%s' % (quoted_host, port)
        canonical_url = '%s://%s%s' % (protocol, quoted_host, quoted_path)
        if query is not None:
            canonical_url = '%s?%s' % (canonical_url, query)
        return canonical_url

    @staticmethod
    def url_permutations(url):
        """Try all permutations of hostname and path which can be applied
        to blacklisted URLs"""
        def url_host_permutations(host):
            if re.match(r'\d+\.\d+\.\d+\.\d+', host):
                yield host
                return
            parts = host.split('.')
            l = min(len(parts),5)
            if l > 4:
                yield host
            for i in range(l-1):
                yield '.'.join(parts[i-l:])
        def url_path_permutations(path):
            yield path
            query = None
            if '?' in path:
                path, query =  path.split('?', 1)
            if query is not None:
                yield path
            path_parts = path.split('/')[0:-1]
            curr_path = ''
            for i in range(min(4, len(path_parts) )):
                curr_path = curr_path + path_parts[i] + '/'
                yield curr_path
        protocol, address_str = urllib.splittype(url)
        host, path = urllib.splithost(address_str)
        user, host = urllib.splituser(host)
        host, port = urllib.splitport(host)
        host = host.strip('/')
        seen_permutations = set()
        for h in url_host_permutations(host):
            for p in url_path_permutations(path):
                u = '%s%s' % (h, p)
                if u not in seen_permutations:
                    yield u
                    seen_permutations.add(u)

    @staticmethod
    def digest(url):
        "Hash the URL"
        return hashlib.sha256(url.encode('utf-8')).digest()
		
		
class SafeBrowsingList(object):
    """Interface for Google Safe Browsing API

    supporting partial update of the local cache.
    https://developers.google.com/safe-browsing/v4/
    """

    def __init__(self, api_key, db_path='/temp/gsb_v4.db', discard_fair_use_policy=False,
                        platforms = None):
        """Constructor.

        Args:
            api_key: string, a key for API authentication.
            db_path: string, path to SQLite DB file to store cached data.
            discard_fair_use_policy: boolean, disable request frequency throttling (only for testing).
            platforms: list, threat lists to look up, default includes all platforms.
        """
        self.api_client = SafeBrowsingApiClient(api_key, discard_fair_use_policy=discard_fair_use_policy)
        self.storage = SqliteStorage(db_path)
        self.platforms = platforms

    def _verify_threat_list_checksum(self, threat_list, remote_checksum):
        local_checksum = self.storage.hash_prefix_list_checksum(threat_list)
        return remote_checksum == local_checksum

    def update_hash_prefix_cache(self):
        """Update locally cached threat lists.
        """
        self.api_client.fair_use_delay()
        self.storage.cleanup_full_hashes()
        threat_lists_to_remove = dict()
        for ts, cs in self.storage.get_threat_lists():
            threat_lists_to_remove[repr(ts)] = ts
        threat_lists = self.api_client.get_threats_lists()
        for entry in threat_lists:
            threat_list = ThreatList.from_api_entry(entry)
            if self.platforms is None or threat_list.platform_type in self.platforms:
                self.storage.add_threat_list(threat_list)
                try:
                    del threat_lists_to_remove[repr(threat_list)]
                except KeyError:
                    pass
        for ts in threat_lists_to_remove.values():
            self.storage.delete_hash_prefix_list(ts)
            self.storage.delete_threat_list(ts)
        del threat_lists_to_remove

        self.api_client.fair_use_delay()
        threat_lists = self.storage.get_threat_lists()
        client_state = dict([(t.as_tuple(), s) for t,s in threat_lists])
        for response in self.api_client.get_threats_update(client_state):
            response_threat_list = ThreatList(response['threatType'], response['platformType'], response['threatEntryType'])
            if response['responseType'] == 'FULL_UPDATE':
                self.storage.delete_hash_prefix_list(response_threat_list)
            for r in response.get('removals', []):
                self.storage.remove_hash_prefix_indices(response_threat_list, r['rawIndices']['indices'])
            for a in response.get('additions', []):
                hash_prefix_list = HashPrefixList(a['rawHashes']['prefixSize'], b64decode(a['rawHashes']['rawHashes']))
                self.storage.populate_hash_prefix_list(response_threat_list, hash_prefix_list)
            expected_checksum = b64decode(response['checksum']['sha256'])
            if self._verify_threat_list_checksum(response_threat_list, expected_checksum):
                log.info('Local cache checksum matches the server: {}'.format(to_hex(expected_checksum)))
                self.storage.update_threat_list_client_state(response_threat_list, response['newClientState'])
            else:
                raise Exception('Local cache checksum does not match the server: "{}". Consider removing {}'.format(to_hex(expected_checksum), self.storage.db_path))

    def _sync_full_hashes(self, hash_prefixes):
        """Download full hashes matching hash_prefixes.

        Also update cache expiration timetsamps.
        """
        threat_lists = self.storage.get_threat_lists()
        client_state = dict([(t.as_tuple(), s) for t,s in threat_lists])
        self.api_client.fair_use_delay()
        fh_response = self.api_client.get_full_hashes(hash_prefixes, client_state)

        # update negative cache for each hash prefix
        # store full hash (insert or update) with positive cache bumped up
        for m in fh_response['matches']:
            threat_list = ThreatList(m['threatType'], m['platformType'], m['threatEntryType'])
            hash_value = b64decode(m['threat']['hash'])
            cache_duration = int(m['cacheDuration'].rstrip('s'))
            malware_threat_type = None
            for metadata in m['threatEntryMetadata'].get('entries', []):
                k = b64decode(metadata['key'])
                v = b64decode(metadata['value'])
                if k == 'malware_threat_type':
                    malware_threat_type = v
            self.storage.store_full_hash(threat_list, hash_value, cache_duration, malware_threat_type)

        negative_cache_duration = int(fh_response['negativeCacheDuration'].rstrip('s'))
        for prefix_value in hash_prefixes:
            for threat_list in threat_lists:
                self.storage.update_hash_prefix_expiration(threat_list[0], prefix_value, negative_cache_duration)

    def lookup_url(self, url):
        """Look up specified URL in Safe Browsing threat lists."""
        url_hashes = URL(url).hashes
        list_names = self._lookup_hashes(url_hashes)
        if list_names:
            return list_names
        return None

    def _lookup_hashes(self, full_hashes):
        """Lookup URL hash in blacklists

        Returns names of lists it was found in.
        """
        full_hashes = list(full_hashes)
        cues = [to_hex(fh[0:4]) for fh in full_hashes]
        result = []
        try:
            matching_prefixes = {}
            matching_full_hashes = set()
            is_potential_threat = False
            # First lookup hash prefixes which match full URL hash
            for (threat_list, hash_prefix, negative_cache_expired) in self.storage.lookup_hash_prefix(cues):
                for full_hash in full_hashes:
                    if full_hash.startswith(hash_prefix):
                        is_potential_threat = True
                        # consider hash prefix negative cache as expired if it is expired in at least one threat list
                        matching_prefixes[hash_prefix] = matching_prefixes.get(hash_prefix, False) or negative_cache_expired
                        matching_full_hashes.add(full_hash)
            # if none matches, URL hash is clear
            if not is_potential_threat:
                return []
            # if there is non-expired full hash, URL is blacklisted
            matching_expired_threat_lists = set()
            for threat_list, has_expired in self.storage.lookup_full_hashes(matching_full_hashes):
                if has_expired:
                    matching_expired_threat_lists.add(threat_list)
                else:
                    result.append(threat_list)
            if result:
                return result

            # If there are no matching expired full hash entries
            # and negative cache is still current for all prefixes, consider it safe
            if len(matching_expired_threat_lists) == 0 and sum(map(int, matching_prefixes.values())):
                log.info('Negative cache hit.')
                return []

            # Now we can assume that there are expired matching full hash entries and/or
            # cache prefix entries with expired negative cache. Both require full hash sync.
            self._sync_full_hashes(matching_prefixes.keys())
            # Now repeat full hash lookup
            for threat_list, has_expired in self.storage.lookup_full_hashes(matching_full_hashes):
                if not has_expired:
                    result.append(threat_list)
        except:
            self.storage.db.rollback()
            raise
        return result
		
		
# Avira !  Extras > Configuration > General > Security > Uncheck the option: Protect Windows hosts file from changes.
def loadBadDomains(name,url):
	import requests
	import shutil
	os.chdir(pathname)
	cache = []
	# List from http://www.malwaredomainlist.com/hostslist/hosts.txt
	# http://www.abuse.ch/zeustracker/blocklist.php?download=domainblocklist for ZeusDomains
	# Parse the file and add the domains.
	try:
		f = open(name,"r")
	except IOError:
		try:
			response = requests.get(url, stream=True)
			if response.status_code == 200:
				with open(name, 'wb') as f:
					f.write(response.content)
			while not len(response.content):
				pass
			print ("first")
		except requests.exceptions.Timeout:
			from parallel_sync import wget
			wget.download('/tmp', url1, filenames=name, extract=False)
			print ("first 2")

	f = open(name,"r")

	lines = f.readlines()
	i = 0
	for line in lines:
		#print (line)
		if( line[0] != "#"):
			domain = line.replace("\r\n","").split(" ")
			if(len(domain)> 1):
				if 'localhost' in line:
					pass
				else:
					cache = resolvename(domain[1])
					if not cache:
						pass
					else:
						for urlx in cache:
							wordx = "".join((str1, urlx))
							time.sleep(1)
							os.system(wordx)
							time.sleep(1)
					#print (domain[2])
					#name = "Bad domain %d" % i
					i = i +1
				
	#wordx = str1.split()
	#wordx = " ".join)		
	f.close()
	return

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
	
	
def islink(fpath):
    """ Windows islink implementation. """
    if GetFileAttributes(fpath) & REPARSE_FOLDER == REPARSE_FOLDER:
        return True
    return False


def parse_reparse_buffer(original, reparse_type=SYMBOLIC_LINK):
    """ Implementing the below in Python:

    typedef struct _REPARSE_DATA_BUFFER {
        ULONG  ReparseTag;
        USHORT ReparseDataLength;
        USHORT Reserved;
        union {
            struct {
                USHORT SubstituteNameOffset;
                USHORT SubstituteNameLength;
                USHORT PrintNameOffset;
                USHORT PrintNameLength;
                ULONG Flags;
                WCHAR PathBuffer[1];
            } SymbolicLinkReparseBuffer;
            struct {
                USHORT SubstituteNameOffset;
                USHORT SubstituteNameLength;
                USHORT PrintNameOffset;
                USHORT PrintNameLength;
                WCHAR PathBuffer[1];
            } MountPointReparseBuffer;
            struct {
                UCHAR  DataBuffer[1];
            } GenericReparseBuffer;
        } DUMMYUNIONNAME;
    } REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

    """
    # Size of our data types
    SZULONG = 4 # sizeof(ULONG)
    SZUSHORT = 2 # sizeof(USHORT)

    # Our structure.
    # Probably a better way to iterate a dictionary in a particular order,
    # but I was in a hurry, unfortunately, so I used pkeys.
    buffer = {
        'tag' : SZULONG,
        'data_length' : SZUSHORT,
        'reserved' : SZUSHORT,
        SYMBOLIC_LINK : {
            'substitute_name_offset' : SZUSHORT,
            'substitute_name_length' : SZUSHORT,
            'print_name_offset' : SZUSHORT,
            'print_name_length' : SZUSHORT,
            'flags' : SZULONG,
            'buffer' : u'',
            'pkeys' : [
                'substitute_name_offset',
                'substitute_name_length',
                'print_name_offset',
                'print_name_length',
                'flags',
            ]
        },
        MOUNTPOINT : {
            'substitute_name_offset' : SZUSHORT,
            'substitute_name_length' : SZUSHORT,
            'print_name_offset' : SZUSHORT,
            'print_name_length' : SZUSHORT,
            'buffer' : u'',
            'pkeys' : [
                'substitute_name_offset',
                'substitute_name_length',
                'print_name_offset',
                'print_name_length',
            ]
        },
        GENERIC : {
            'pkeys' : [],
            'buffer': ''
        }
    }

    # Header stuff
    buffer['tag'] = original[:SZULONG]
    buffer['data_length'] = original[SZULONG:SZUSHORT]
    buffer['reserved'] = original[SZULONG+SZUSHORT:SZUSHORT]
    original = original[8:]

    # Parsing
    k = reparse_type
    for c in buffer[k]['pkeys']:
        if type(buffer[k][c]) == int:
            sz = buffer[k][c]
            bytes = original[:sz]
            buffer[k][c] = 0
            for b in bytes:
                n = ord(b)
                if n:
                    buffer[k][c] += n
            original = original[sz:]

    # Using the offset and length's grabbed, we'll set the buffer.
    buffer[k]['buffer'] = original
    return buffer

def readlink(fpath):
    """ Windows readlink implementation. """
    # This wouldn't return true if the file didn't exist, as far as I know.
    if not islink(fpath):
        return None

    # Open the file correctly depending on the string type.
    handle = CreateFileW(fpath, GENERIC_READ, 0, None, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, 0) \
                if type(fpath) == unicode else \
            CreateFile(fpath, GENERIC_READ, 0, None, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, 0)

    # MAXIMUM_REPARSE_DATA_BUFFER_SIZE = 16384 = (16*1024)
    buffer = DeviceIoControl(handle, FSCTL_GET_REPARSE_POINT, None, 16*1024)
    # Above will return an ugly string (byte array), so we'll need to parse it.

    # But first, we'll close the handle to our file so we're not locking it anymore.
    CloseHandle(handle)

    # Minimum possible length (assuming that the length of the target is bigger than 0)
    if len(buffer) < 9:
        return None
    # Parse and return our result.
    result = parse_reparse_buffer(buffer)
    offset = result[SYMBOLIC_LINK]['substitute_name_offset']
    ending = offset + result[SYMBOLIC_LINK]['substitute_name_length']
    rpath = result[SYMBOLIC_LINK]['buffer'][offset:ending].replace('\x00','')
    if len(rpath) > 4 and rpath[0:4] == '\\??\\':
        rpath = rpath[4:]
    return rpath

# Doenst work !
def realpath(fpath):
    from os import path
    while islink(fpath):
        rpath = readlink(fpath)
        if not path.isabs(rpath):
            rpath = path.abspath(path.join(path.dirname(fpath), rpath))
        fpath = rpath
    return fpath
	
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
	if powerclass.BatteryLifePercent < 5:
		w.balloon_tip("Battery Low", "Time to look for the charger")
	return powerclass.BatteryLifePercent

def ram(choose):
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
	if choose == 1:
		return availRam
	if choose == 0:
		return
	
def windowStatus2(hwnd):
    status = {
        "enabled": ctypes.windll.user32.IsWindowEnabled(hwnd) != 0,
        "iconic": ctypes.windll.user32.IsIconic(hwnd) != 0,
        "zoomed": ctypes.windll.user32.IsZoomed(hwnd) != 0,
        "visible": ctypes.windll.user32.IsWindowVisible(hwnd) != 0,
        "hung": ctypes.windll.user32.IsHungAppWindow(hwnd) != 0,
        "foreground": ctypes.windll.user32.GetForegroundWindow() == hwnd
    }
    return status
	
def windowStatus(ProcessID):
	hwnd = get_hwnds_for_pid(ProcessID)
	counter = 0
	handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, ProcessID)
	while ctypes.windll.user32.IsHungAppWindow(hwnd):
		if counter > 0:
			pass
		else:
			win32process.SetPriorityClass(handle, win32process.REALTIME_PRIORITY_CLASS)
			counter = 1
	win32process.SetPriorityClass(handle, win32process.NORMAL_PRIORITY_CLASS)
	
def get_hwnds_for_pid (pid):
	import win32gui
	def callback (hwnd, hwnds):
		if win32gui.IsWindowVisible (hwnd) and win32gui.IsWindowEnabled (hwnd):
			_, found_pid = win32process.GetWindowThreadProcessId (hwnd)
			if found_pid == pid:
				hwnds.append (hwnd)
		return True

	hwnds = []
	win32gui.EnumWindows (callback, hwnds)
	return hwnds
	
# Give foreground application more rights :	
class ForegroundWindow(threading.Thread):
	def stop(self):
		self.__stop = True

	def __init__(self, my_queue): 
		#self.daemon = True
		threading.Thread.__init__(self)
		self.my_queue = my_queue

	def run(self):
		import win32gui,win32api
		global ProcessID,oProcessID
		while True:
			time.sleep(1)
			try:
				fgWindow = win32gui.GetForegroundWindow()
				threadID, ProcessID = win32process.GetWindowThreadProcessId(fgWindow)
				process = psutil.Process(ProcessID)
				print (process.name())
				print (oProcessID)
				print (ProcessID)
				if (ProcessID != oProcessID):
					#print "Hallo"
					handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, ProcessID)
					win32process.SetPriorityClass(handle, win32process.ABOVE_NORMAL_PRIORITY_CLASS)
					powercfgc(process.name())
					if oProcessID:
						#print "Meno"
						handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, oProcessID)
						win32process.SetPriorityClass(handle,  win32process.NORMAL_PRIORITY_CLASS)
				oProcessID = ProcessID
			except  psutil.NoSuchProcess:
				pass

# Every move has his own reason

def OnMouseEvent():
	global mosposx,mosposold
	mosposx, mosposy = win32api.GetCursorPos()
	mosposold = mosposx
	print (mosposx)
	mosposx = mosposx
	if not (mosposx == mosposold):
		pass
	return True

def mainmouse():
	import win32api
	global state_left,state_right
	while True:
		a = win32api.GetKeyState(0x01)
		b = win32api.GetKeyState(0x02)

		if a != state_left:  # Button state changed
			state_left = a
			if a < 0:
				OnMouseEvent()
				pass
				#print('Left Button Pressed')
			else:
				pass
				#print('Left Button Released')

		if b != state_right:  # Button state changed
			state_right = b
			if b < 0:
				OnMouseEvent()
				pass
				#print('Right Button Pressed')
			else:
				pass
				#print('Right Button Released')
		time.sleep(0.001)
	
def create_menu_item(menu, label, func):
	item = wx.MenuItem(menu, -1, label)
	menu.Bind(wx.EVT_MENU, func, id=item.GetId())
	menu.AppendItem(item)
	return item
	
class IconMain(threading.Thread):
	def stop(self):
		self.__stop = True

	def __init__(self, my_queue): 
		#self.daemon = True
		threading.Thread.__init__(self)
		self.my_queue = my_queue

	def run(self):
		global pathname,spath,TRAY_ICON
		os.chdir(spath)
		#app = wx.PySimpleApp()
		app = wx.App()
		TaskBarIconWindow()
		app.MainLoop()

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
		
# expect wddm driver!
def getgpu():
	WMI = GetObject('winmgmts:')
	for battery in WMI.InstancesOf('Win32_VideoController'):
		if battery.ConfigManagerErrorCode != 0:
			w.balloon_tip("GPU Error occured", errorg(battery.ConfigManagerErrorCode))
			getgpustatus()
		
def getgpustatus():
	WMI = GetObject('winmgmts:')
	for battery in WMI.InstancesOf('Win32_VideoController'):
		if "Lost Comm" in battery.Status:
			gputimeout()
			pcic(0)
			
		
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
	except socket.gaierror:
		#print "cannot resolve hostname: ", name, err
		return;
		
def resolvename(name):
	ip_list = []
	try:
		ais = socket.getaddrinfo(name,0,0,0,0)
		for result in ais:
			ip_list.append(result[-1][0])
			ip_list = list(set(ip_list))
		return (ip_list)
	except socket.gaierror:
		pass

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
		print (name)
		ip2 = reverselookup(name)
		sbl = SafeBrowsingList(google_api)
		if sbl.lookup_url(name) != 'None':
			w.balloon_tip("Page known for Malware!", "Be careful!")
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
	
def dnsprotection():
	winreg(name,'SocketPoolSize',0x00002710,1,str44)
	
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
	if "X86_64" in arch:
		winreg(name,'EmulationOnly',0x00000001,1,str38)
		winreg(name,'SoftwareOnly',0x00000001,1,str39)
		winreg(name,'DisablePSGP',0x00000001,1,str38)
	
def directxon():
	winreg(name,'DisablePSGP',0x00000000,1,str35)
	winreg(name,'EmulationOnly',0x00000000,1,str36)
	winreg(name,'SoftwareOnly',0x00000000,1,str37)
	if "X86_64" in arch:
		winreg(name,'EmulationOnly',0x00000000,1,str38)
		winreg(name,'SoftwareOnly',0x0000000,1,str39)
		winreg(name,'DisablePSGP',0x00000000,1,str38)
		
def gputimeout():
	winreg(name,'TdrDelay',0x00000014,1,str40)
	
def lanmantune():
	winreg(name,'SizReqBuf',0x0000ffff,1,str41)
	
def tcpinitialrtt(value):
	cache =  "".join(['SYSTEM\\CurrentControlSet\\Services\\TcpIp\\Parameters\\Interfaces\\',networkid()[2:-1]])
	winreg(name,'TCPInitialRtt',value,1,cache)
	
def tcpinitialRto(value):
	cmd = 'netsh int tcp set global initialRto='
	cache =  "".join([cmd,str(value)])
	os.system(cache)
	
def tcpackfre(value):
	cache =  "".join(['SYSTEM\\CurrentControlSet\\Services\\TcpIp\\Parameters\\Interfaces\\',networkid()[2:-1]])
	winreg(name,'TcpAckFrequency',value,1,cache)
	
# 2 Recommend
def TcpDelAckTicks(value):
	cache =  "".join(['SYSTEM\\CurrentControlSet\\Services\\TcpIp\\Parameters\\Interfaces\\',networkid()[2:-1]])
	winreg(name,'TcpDelAckTicks',value,1,cache)
	
def DisableDHCPMediaSense():
	winreg(name,'DisableDHCPMediaSense',0x00000001,1,str4)
		
#https://technet.microsoft.com/en-us/library/cc938205.aspx
# 0:Timestamps and window scaling are disabled. 1:Window scaling is enabled. 2:	Timestamps are enabled. 3: Timestamps and window scaling are enabled.
def disablewindowscaling():
	global windowsize
	cache =  "".join(['SYSTEM\\CurrentControlSet\\Services\\TcpIp\\Parameters\\Interfaces\\',networkid()[2:-1]])
	try:
		winreg(name,'TcpWindowSize',windowsize,1,cache)
	except IOError:
		winreg(name,'GlobalMaxTcpWindowSize',windowsize,1,str4)
	winreg(name,'Tcp1323Opts',0x00000010,1,str4)
	
# On slow networks some unnecessary function should be disabled to allow normal experience
def windowsmb(choose):
	if choose == 1:
		winreg(name,'UseDesktopIniCache',0x00000001,1,str48)
		winreg(name,'NoRemoteRecursiveEvents',0x00000001,1,str48)
		winreg(name,'NoRemoteChangeNotify',0x00000001,1,str48)
		winreg(name,'StartRunNoHOMEPATH',0x00000001,1,str48)
		winreg(name,'NoRecentDocsNetHood',0x00000001,1,str48)
		winreg(name,'NoDetailsThumbnailOnNetwork',0x00000001,1,str48)
		winreg(name,'InfoCacheLevel',0x00000010,1,str49)
		winreg(name,'Flags',0x00100c02,1,str50)
	else:
		winreg(name,'UseDesktopIniCache',0x00000000,1,str48)
		winreg(name,'NoRemoteRecursiveEvents',0x00000000,1,str48)
		winreg(name,'NoRemoteChangeNotify',0x00000000,1,str48)
		winreg(name,'StartRunNoHOMEPATH',0x00000000,1,str48)
		winreg(name,'NoRecentDocsNetHood',0x00000000,1,str48)
		winreg(name,'NoDetailsThumbnailOnNetwork',0x00000000,1,str48)
		winreg(name,'InfoCacheLevel',0x00000001,1,str49)

	
#PCI Express Power Management Settings : 0 : disable 1 : Attempt to use the L0S state when link is idle. 2: Attempt to use the L1 state when the link is idle.
def pcic(value):
	cache =  "".join([str45[2:-1],'501a4d13-42af-4429-9fd1-a8218c268e20\\ee12f906-d277-404b-b6da-e5fa1a576df5\DefaultPowerSchemeValues\\381b4222-f694-41f0-9685-ff5bb260df2e\\'])
	winreg(name,'DcSettingIndex',value,1,cache)
	winreg(name,'AcSettingIndex',value,1,cache)
	cache =  "".join([str45[2:-1],'501a4d13-42af-4429-9fd1-a8218c268e20\\ee12f906-d277-404b-b6da-e5fa1a576df5\DefaultPowerSchemeValues\\a1841308-3541-4fab-bc81-f71556f20b4a\\'])
	winreg(name,'DcSettingIndex',value,1,cache)
	winreg(name,'AcSettingIndex',value,1,cache)
	

#GUID des Energieschemas: 381b4222-f694-41f0-9685-ff5bb260df2e  (Ausbalanciert)
#GUID des Energieschemas: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (Hoechstleistung)
#GUID des Energieschemas: a1841308-3541-4fab-bc81-f71556f20b4a  (Energiesparmodus)

# Adjusts the refresh rate to save power and maintain visual quality.NVIDIA Display Power Saving technology
#
def displaysaving():
	os.system('powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 89cc76a4-f226-4d4b-a040-6e9a1da9b882 1')
	os.system('powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 7516b95f-f776-4464-8c53-06167f40cc99 89cc76a4-f226-4d4b-a040-6e9a1da9b882 1')
	os.system('powercfg -setacvalueindex a1841308-3541-4fab-bc81-f71556f20b4a 7516b95f-f776-4464-8c53-06167f40cc99 89cc76a4-f226-4d4b-a040-6e9a1da9b882 1')
	
def wlansaving(choose):
	if choose == 1:
		os.system('powercfg -setacvalueindex a1841308-3541-4fab-bc81-f71556f20b4a 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 3')
		os.system('powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 3')
		os.system('powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 3')
	else:
		os.system('powercfg -setacvalueindex a1841308-3541-4fab-bc81-f71556f20b4a 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0')
		os.system('powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0')
		os.system('powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0')		
	
# Show interesting behavoir
def ArpCacheLifet():
	winreg(name,'ArpCacheMinReferencedLife',0x0000ffff,1,str4)
	winreg(name,'ArpRetryCount',0x00000001,1,str4)

# Intel(WLAN) keywords : list will be extended
def disableoffloaddriver():
	cmd1 = """powershell Set-NetAdapterAdvancedProperty -Name * -RegistryKeyword "*PMARPOffload" -Registryvalue 0"""
	cmd2 = """powershell Set-NetAdapterAdvancedProperty -Name * -RegistryKeyword "*PMNSOffload" -Registryvalue 0"""
	try:
		a = subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=None)
		b = subprocess.Popen(cmd2, stdout=subprocess.PIPE, stderr=None)
	except IOError:
		#Probably wrong keywords , almost i tried!
		pass
	

def mtus(value):
	cmd = 'netsh int ipv4 set subinterface 10 mtu=1472 store=persistent'.split()
	cmd[5] = arpc()
	print (cmd)
	if value == 0:
		cmd[6] = 'mtu=576'
	else:
		pass
	cmd = " ".join(cmd)
	os.system(cmd)

# Doenst seem to work
def mtudisc():
	s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	hostName = ipowershell(0)[1:-1]
	Port = 53
	s.connect((hostName, Port))
	s.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
	try:
		s.send(b'#' * 1473)
	except socket.error:
		option = getattr(IN, 'IP_MTU', 14)
	else:
		return
	
# Some things which should already be done since i dont know
def tune():
	tcpinitialrtt(1000)
	os.system(str15)
	os.system(str33)
	os.system(str34)

# Adds values to the registry only REG_DWORD and inform the system about the change !
def winreg(dnsname, regn, rvalue,rpath,str):
	from win32gui import SendMessage
	print (dnsname)
	if not dnsname:
		regrule = str
	else:
		regrule = "".join((str3, dnsname[2:-1]))
	if rpath == 0:
		key = wreg.CreateKey(wreg.HKEY_CURRENT_USER, regrule)
	else:
		key = wreg.CreateKey(wreg.HKEY_LOCAL_MACHINE, regrule)
	wreg.SetValueEx(key, regn, 0, wreg.REG_DWORD, rvalue)
	wreg.CloseKey(key)
	key.Close()
	SendMessage(win32con.HWND_BROADCAST, win32con.WM_SETTINGCHANGE, 0, 0)
	if rpath == 0:
		os.system('RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True')
	
# Check if Firewall is enabled(check!)
#Simple but effectiv
def firewallr():
	global counter
	counter += 1
	wordx = str1.split()
	indexn = str(counter)
	rulename = "".join(("name=rule", indexn[2:-1]))
	wordx[7] = rulename
	wordx = " ".join(wordx)
	cache = ipextract()
	if not cache:
		counter -= 1
		return;
	else:
		wordx = "".join((wordx[2:-1], cache[2:-1]))
		os.system(wordx)
		return;
		
def dnetbios():
	os.system(str7)

def dsmb():
	os.system(str31)
	os.system(str32)
	
#Avira couse problems with this !
def addhost():
	ip = ipextract()
	if not ip:
		return;
	else:
		os.chdir(r'C:\Windows\System32\drivers\etc')
		cache = str2
		cache = "".join(ip[2:-1])
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
	count2 = 0;lastline = ''
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	while True:
		line = p.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count2 += 1;lastline = line
			if count2 == 5:
				cache = line.split()
				return cache[7]
			else:
				pass
		else:
			break
	return;
	
# Next time should check ttl value.
def pingc():
	global aptn
	counterc = 0
	lastline = ''
	cmd = 'ping.exe -n 1 '
	try:
		cmd = "".join((cmd, str(tracertc())[2:-1])).split()
		print (cmd)
	except IOError:
		diagnose()
		return;
	count2 = problemc = 0
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = p.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			lastline = line
			count2 += 1;lastline = line
			if count2 == 3:
				try:
					cache = line.split()
					cache2 = cache[4]
					cache = cache[5]
					print (cache)
					if b"TTL=64" in cache or b"TTL=127" in cache:
						pass
					else:
						w.balloon_tip("Network abnormal!", "Wait for opportunity")
					cache2 = cache2.split(b"=", 1)[1]
					cache2 = cache2.split(b"ms", 1)[0]
					apto = aptn
					aptn = int(cache2)
					if int(cache2) > (apto+5):
						counterc += 1
						if counterc == 3:
							w.balloon_tip("Network time abnormal", "Instabil")
				except IOError:
					break
			else:
				pass
		else:
			break
	#print (p.communicate()[0])
	return;
	
def firewallc():
	count2 = 0;lastline = ''
	cmd = 'netsh advfirewall show currentprofile'.split()
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = p.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count2 += 1;lastline = line
			if count2 == 4:
				cache = line.split()
				cache = cache[1]
				if b'EIN' in cache:
					pass
				else:
					w.balloon_tip("Error Windows Firewall disabled", "Try to activate")
					try:
						os.system(str10)
					except IOError:
						w.balloon_tip("Couldnt activate Windows Firewall", "Error: 1")
						sys.exit(0)
			else:
				pass
		else:
			break
	return;
	
#Give the default gateway ip even if several devices as VM are used . Yes this was sometimes a problem.
def ipowershell(choose):
	try:
		cmd = """powershell "Get-WmiObject -Class Win32_IP4RouteTable | where { $_.destination -eq '0.0.0.0' -and $_.mask -eq '0.0.0.0'} | Sort-Object metric1 | select nexthop, metric1, interfaceindex"""
		count2 = 0;lastline = ''
		b = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
		time.sleep(2)
		while True:
			line = b.stdout.readline();line = line.rstrip()
			if line != '' and lastline != line:
				count2 += 1;lastline = line
				if count2 == 4:
					cache =  line.split()
					if choose == 0:
						cache = cache[0]
						cache = str(cache)[1:]
						print (cache)
						return (cache)
					if choose == 1:
						cache = int(cache[2])
						return str(cache)
					if choose == 2:
						cache = int(cache[1])
						return cache
				else:
					pass
			else:
				break
		return;
	except IOError:
		cmd = """powershell Get-NetIPConfiguration | Foreach IPv4DefaultGateway"""
		count2 = 0;lastline = ''
		b = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
		time.sleep(2)
		while True:
			line = b.stdout.readline();line = line.rstrip()
			if line != '' and lastline != line:
				count2 += 1;lastline = line
				if count2 == 5:
					cache =  line.split()
					cache = cache[0]
					return cache
				else:
					pass
			else:
				break
		return;
		
def getmtuv():
	count2 = 0;lastline = ''
	cmd = 'netsh interface ipv4 show subinterface '
	ips =  "".join([cmd,arpc()[2:-1]])
	p = subprocess.Popen(ips, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = p.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count2 += 1;lastline = line
			if count2 == 4:
				cache = line.split()
				cache = cache[0]
				return cache
			else:
				pass
		else:
			break
	return;
	
# get WLAN TX
# Intel : Get-NetAdapterAdvancedProperty -Name * -RegistryKeyword "IbssTxPower" | select RegistryValue
# Value 0,25,50,75,100
def readptx():
	count2 = 0;lastline = ''
	cmd = '''powershell Get-NetAdapterAdvancedProperty -Name * -RegistryKeyword "IbssTxPower" | select RegistryValue'''
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = p.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count2 += 1;lastline = line
			if count2 == 4:
				cache = line.split(b"{", 1)[1]
				cache = cache.split(b"}", 1)[0]
				print (cache)
				return int(cache)
			else:
				pass
		else:
			break
	return;

def setptx(value):
	count2 = 0;lastline = ''
	cmd = '''powershell Set-NetAdapterAdvancedProperty -Name * -RegistryKeyword "IbssTxPower" -Registryvalue '''
	easy = '"'
	cmd =  "".join([cmd,easy,str(value),easy])
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	
	
# dBm = (quality / 2) - 100  where quality: [0 to 100]
# FSPL = Ptx - CLtx + AGtx + AGrx - CLrx - Prx - FM
# d = 10 ^ (( FSPL - K - 20 log10( f )) / 20 )
# 10*log10(P/ 0.001)
#
# Transmit power:
#Lowest: Sets the adapter to the lowest transmit power. Increase the number of coverage areas or confine a coverage area. 
#You should reduce the coverage area in high traffic areas to improve overall transmission quality and avoid congestion or interference with other devices.

def wlanc():
		time.sleep(1)
		try:
			print ("Easy 1-2-3")
			count2 = 0;lastline = ''
			cmd = """powershell (netsh wlan show interfaces) -Match '^\s+Signal' -Replace '^\s+Signal\s+:\s+',''"""
			p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
			while True:
				line = p.stdout.readline();line = line.rstrip()
				if line != '' and lastline != line:
					count2 += 1;lastline = line
					if count2 == 1:
						cache = line
						cache = int(cache.split(b"%", 1)[0])
						dBm = ((cache/2)-100)
						d = 10**((27.55-((20*math.log10(2412))+dBm))/20)
						if (cache < 80):
							readtx = readptx()
							if (readtx != 100):
								readtx = readtx + 25
								setptx(cache)
							if readtx == 100:
								wlansaving(1)
						if (cache > 95):
							readtx = readptx()
							if (readtx != 0):
								readtx = readtx - 25
								setptx(readtx)
							if readtx == 100:
								wlansaving(0)
						return cache
					else:
						pass
				else:
					break
		except IOError:
			print ("Error")

class wlansignalstrenght(threading.Thread):
	def stop(self):
		self.__stop = True

	def __init__(self, my_queue): 
		##self.daemon = True
		threading.Thread.__init__(self)
		self.my_queue = my_queue

	def run(self):
		while True:
			wlanc()

# Intel
# Use mixed mode protection to avoid data collisions in a mixed 802.11b and 802.11g environment.
# Use Request to Send/Clear to Send (RTS/CTS) in an environment where clients may not hear each other. 
# Use CTS-to-self to gain more throughput in an environment where clients are within hearing proximity.(work?)

def wlanrecommendsettings(choose):
	if choose == 1:
		cmd = '''powershell Set-NetAdapterAdvancedProperty -Name * -RegistryKeyword "RoamAggressiveness" -Registryvalue "2"'''
	if choose == 0:
		cmd = '''powershell Set-NetAdapterAdvancedProperty -Name * -RegistryKeyword "RoamAggressiveness" -Registryvalue "0"'''
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	

def latencyc():
	while True:
		global aptn
		counterc = 0
		cmd = 'ping.exe -n 8 google.com '
		count2 = 0;lastline = ''
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
		while True:
			line = p.stdout.readline();line = line.rstrip()
			if line != '' and lastline != line:
				count2 += 1;lastline = line
				if count2 == 16:
					try:
						cache = line.split()
						cache2 = (cache[8])
						if cache2:							
							print (cache2)
							cache2 = cache2.split(b"ms", 1)[0]
							print (cache2)
							return float(cache2)
						else:
							break
					except IOError:
						break
				else:
					pass
			else:
				break
		return;		

# Windows 10 List!
# https://support.microsoft.com/de-at/help/299540/an-explanation-of-the-automatic-metric-feature-for-ipv4-routes
def metricvalue(argument):
	switcher = {
		75: "0,0625",
		65: "0,125s",
		55: "0.5",
		45: "2,5",
		35: "10",
		25: "20",
		20: "25",
		15: "250",
		10: "1250",
		5: "2500",
		}
	return switcher.get(argument, '')	
		
# RTT is time depending function and need to be adjusted for every connection.
#
# 35 is random !
# windowsmb : https://blogs.technet.microsoft.com/askperf/2007/09/21/windows-explorer-and-smb-traffic/
def wmetric():
	global windowsize
	metv = int(ipowershell(2))
	if metv > 35 :
		windowsmb(1)
	value = metricvalue(metv)
	cache = float('131.072')*int(latencyc())*float(metricvalue((ipowershell(2))))
	mtu = int(getmtuv())
	cache = cache/(mtu-20)
	windowsize = int(cache * (mtu-20))
	disablewindowscaling()
	print (metricvalue(value))
	print ("Fuck ...............")


#Old function already replaced
def arpc():
	return ipowershell(1)
	
# DNS run on port 53 udp/tcp
def nslookupc():
	cmd = 'cmd /c nslookup google.de'.split()
	count2 = 0;lastline = ''
	try:
		print ("test")
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
		while True:
			line = p.stdout.readline();line = line.rstrip()
			if line != '' and lastline != line:
				count2 += 1;lastline = line
				if count2 == 1:
					cache =  line.split()
					cache = cache[0]
					if 'DNS' in cache or '***' in cache:
						w.balloon_tip("DNS Server works not properly", "Check router")
						if udpport(ipowershell(0)[1:-1],53):
							w.balloon_tip("Router DNS Service not avaibale", "Change to Google")
							cache2 = str30.split()
							cache = "".join(("name=", str(arpc()[2:-1])))
							cache2[6] = cache 
							cache2 = " ".join((cache2))
							os.system(cache2)
						return
				else:
					pass
			else:
				break
		return;
	except IOError:
		while True:
			response = requests.get('http://www.google.com')
			if response.status_code == requests.codes.ok:
				return 
			else:
				return
			break
		return;
	return;
		
# CTS-to-self
# Require Nmap like everything else too, if you want a more detailed info.
def netviewc():
	cmd = 'net view'.split()
	count2 = 0;lastline = ''
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = p.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count2 += 1;lastline = line
		else:
			try:
				cache = nmap()
				if (count2-2 > cache):
					w.balloon_tip("Hidden User in the network", "No reason to be scared")
			except IOError:
				pass
			if (count2-2) > 5:
				w.balloon_tip("network seems bigger", "Increase transmit time out")
				cache = str14.split()
				cache2 = str(arpc())
				cache[7] = cache2
				cache = " ".join(cache)
				os.system(cache)
				os.system(str47)
				wlanrecommendsettings(1)
			else:
				wlanrecommendsettings(0)
				break
		break
	return;
	
def nmap():
	cmd = 'nmap -PR '
	ip = ipowershell(0)[1:-1]
	part0 = ip.split(".", 1)[0]
	part1 = ip.split(".", 2)[1]
	part2 = ip.split(".", 3)[2]
	ips =  "".join([cmd,part0,'.',part1,'.',part2,'.0/24'])
	count2 = 0;lastline = ''
	c = subprocess.Popen(ips, stdout=subprocess.PIPE, stderr=None)
	time.sleep(1)
	while True:
		line = c.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count2 += 1;lastline = line
			lastl = line
		else:
			cache = lastl.split()
			cache = cache[5]
			cache = int(cache.split("(", 1)[1])
			return cache
	return;
	
	
def redirectc():
	cmd = 'net config rdr'.split()
	count2 = 0;lastline = ''
	try:
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	except IOError:
		w.balloon_tip("Redirector Issues Found", "No solution now")
	return;
	
def ipstatsc(mode):
	global cv 
	global cv2
	cmd = 'netsh interface ipv4 show ipstats'.split()
	count2 = 0;lastline = ''
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = p.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count2 += 1;lastline = line
			if count2 == 5:
				cache = line.split()
				recdp = (int(cache[3])/100)
				#print recdp
			if count2 == 6:
				cache = line.split()
				cache = int(cache[3])
				if cache > cv:
					cv = cache
					print (cache)
					print (cv)
			if count2 == 10:
				cache = line.split()
				reciveddp = int(cache[3])
				calc = reciveddp/recdp
				print (calc)
				if mode == 0:
					if calc > cv2:
						cv2 = calc
						# Average drop rate is between 2-3% (Source Google)
						w.balloon_tip("Drop Rate over 5%", "Your network drop more than 5% of the packets!")
						ldp = calc
						os.system(str20)
						os.system(str26)
						tcpdrop()
						tcpdrops()
						netviewc()
				else:
					return (calc)
		else:
			break
	return;
	
def dlso(command):
	cmd = command.split()
	try:
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	except IOError:
		w.balloon_tip("Large Send Offload ", "Couldnt deactivated")
	return;
	
def dhcpnew():
	os.system(str11)
	os.system(str12)
	
def diagnose():
	global problemc
	problemc += 1
	if problemc == 3:
		w.balloon_tip("Network is not working properly", "Start quess the reason")
		dhcpnew()
		w.balloon_tip("Release Adresses and try to renew them", "Try to connect: reconnect")
		# If you changed the default name of your connection this will not work
		# ipconfig /release couse error if you use Hamachi or VMware!
	if problemc == 4:
		if ipforwarding():
			if dhcpcheck():
				pass
			else:
				w.balloon_tip("DHCP Service doesnt work correctly", "Your router is the Problem!")
		else:
			pass
	if problemc == 5:
		dlso(str24)
		os.system(str13)
		os.system(str15)
		os.system(str16)
		os.system(str17)
		disableoffloaddriver()
		dhcpnew()
	if problemc == 6:
		DisableDHCPMediaSense()
		dhcpnew()
	if problemc == 7:
		os.system(str43)
		dhcpnew()
	if problemc == 8:
		w.balloon_tip("No Solution found  -> reset TCP", "Good Luck")
		os.system(str23)
	if problemc == 9:
		w.balloon_tip("Im not able to solve this", "Good Luck")
	return;
	
# Give the file name from the url to the block function.
# .php exception => !
def blockad():
	for urls in url1:
		if ".php" in urls:
			part0 = urls.split("/")[-1]
			part0 = part0.split("?")[0]
			part0 = "".join((part0, ".txt"))
			
		else:
			urlc = urls
			part0 = urlc.split("/")[-1]
		print (part0,urls)
		loadBadDomains(part0,urls)
		
	
def everything():
	checksmart()
	checktemp()
	firewallc()
	ipstatsc(0)
	pingc()
	checkapp()
	getgpu()
	checkmode()

def initials():
	global fname,startm,mousec,foregroundc,pathname,spath,wlancheck
	startm = time.time()
	#nslookupc()
	
	info = get_cpu_info_from_registry()
	mtudisc()
	ArpCacheLifet()
	enviromentcjava()
	#Initial Subprocess must be killed sometime
	#t = threading.Thread(name='child procs', target=mainmouse)
	#t.start()
	wmetric()
	mousec = Thread(target=mainmouse)
	mousec.start()
	wlancheck = wlansignalstrenght(my_queue)
	wlancheck.start()
	foregroundc = ForegroundWindow(my_queue)
	foregroundc.start()
	spath = os.path.abspath(pathname)
	icons = IconMain(my_queue)
	icons.start()
	netviewc()
	#easyp = Thread(target=wmetric)
	#easyp.start()
	
# Disk check part	Nothing interesting!
def fsutilc(string):
	cmd = "".join((str28, str(string)[2:-1]))
	count = 0
	try:
		b = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	except IOError:
		pass
	while True:
		line = b.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count += 1
			try:
				if count == 1:
					cache = line.split()
					cache = cache[4]
					#print cache
					if "NICHT" in cache:
						pass
					else:
						#print "Device Wrong"
						w.balloon_tip("Dirty Flags ", str(string))
						pass
				else:
					pass
			except IOError:
				pass
				#print "Only works with Windows Filesystem"
		else:
			break
	return;


def checknfts():
	count2 = 0;lastline = ''
	cmd = 'cmd /c wmic logicaldisk get caption'.split()
	a = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = a.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count2 += 1;lastline = line
			if count2 > 1:
				try:
					cache = line.split()
					cache = cache[0]
					#print cache
					if not cache:
						pass
					else:
						fsutilc(cache)
				except IOError:
					break
			else:
				pass
		else:
			break
	return;	
	
def checksmart():
	count2 = 0;lastline = ''
	cmd = str29.split()
	a = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = a.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count2 += 1;lastline = line
			if count2 > 1:
				try:
					cache = line.split()
					#cache = cache.split("=", 1)[1]
					cache = str(cache[0])
					if not cache:
						pass
					else:
						if 'OK' in cache:
							pass
						else:
							w.balloon_tip("S.M.A.R.T Error ! ", "Its time for backups!")
							os.system("wmic diskdrive get model, name, status")
							checknfts()
				except LookupError:
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
	except IOError:
		Tk().withdraw()
		hdparmd = askdirectory()
		for ch in ['//']:
			if ch in hdparmd:
				hdparmd=hdparmd.replace(ch,"\\")
		print (fname)
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
	except IOError:
		Tk().withdraw()
		hdparmd = askdirectory()
		for ch in ['//']:
			if ch in hdparmd:
				hdparmd=hdparmd.replace(ch,"\\")
		print (fname)
		os.chdir(hdparmd)
	subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
	subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=None)
	w.balloon_tip("Disabled Write Cache", "Finish")
	os.chdir(fname)
	
def diskload():
	global last_disk_time
	counter = 0
	for x in range(0, 10):
		curr_time = time.time()
		counters = psutil.disk_io_counters()
		read_time = counters.read_time
		write_time = counters.write_time
		curr_disk_time = read_time + write_time

		if last_disk_time is not None:
			ddisk = curr_disk_time - last_disk_time
			dtime = curr_time - last_time
			disk_rate = ddisk / dtime
			diff = 500 + round(disk_rate / 3000)
			print (diff)
			print (disk_rate)
			if diff > 550:
				pass
			else:
				time.sleep(0.2)
			if disk_rate != 0:
				counter+=1
		last_disk_time = curr_disk_time
		last_time = curr_time
		time.sleep(0.05)
	if counter >= 5:
		return 1
	
# Temperatur change slow no need to check faster
def checktemp():
	global Tn,t,Ta,k,startm,endm
	endm = time.time()
	if (endm-startm) > 50:
		print ("Aenderung")
		print (endm-startm)
		cmd = """powershell  Get-PhysicalDIsk | Get-StorageReliabilityCounter |  Select-Object Temperature"""
		count2 = 0;lastline = ''
		b = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
		while True:
			line = b.stdout.readline();line = line.rstrip()
			if line != '' and lastline != line:
				count2 += 1;lastline = line
				if count2 == 4:
					cache =  line.split()
					cache = int(cache[0])
					Tn = cache
					if cache > 45:
						w.balloon_tip("Hard disk temperature exceeds default values!", "APM Level will set lower")
						end = (math.log((Ta-Tu)/(59-Tu))/k)
						w.balloon_tip("Time remaining until temperatur exceed crit values", end)			
						if cool == 0 and diskload():
							try:
								setapm(1)
							except IOError:
								pass
							break
				else:
					pass
			else:
				break
		cache = 1/(endm-startm)*math.log((Ta-Tu)/(Tn-Tu))
		k = ((cache+k)/2)
		startm = time.time()
		#Do nothing
		try:
			try:
				cmd = 'cmd /c wmic /namespace:\\root\cimv2 PATH Win32_PerfFormattedData_Counters_ThermalZoneInformation get Temperature'.split()
				count2 = 0;lastline = ''
				b = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
				time.sleep(1)
				while True:
					line = b.stdout.readline();line = line.rstrip()
					if line != '' and lastline != line:
						count2 += 1;lastline = line
						if count2 == 2:
							cache =  line.split()
							cache = int(cache[0])
							cache = cache - 273
							if cache > 59 and  cache != 0:
								w.balloon_tip("Hard disk temperature exceeds critical values!", "Decrease lifetime of harddisk")
						else:
							pass
					else:
						break
				return;
			except IOError:
				cmd = """powershell Get-WmiObject -Class Win32_PerfFormattedData_Counters_ThermalZoneInformation |Select-Object Name,Temperature"""
				count2 = 0;lastline = ''
				b = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
				while True:
					line = b.stdout.readline();line = line.rstrip()
					if line != '' and lastline != line:
						count2 += 1;lastline = line
						if count2 == 4:
							cache =  line.split()
							cache = int(cache[1])
							cache = cache - 273
							if cache > 65 and  cache != 0:
								w.balloon_tip("Motherboard temperature exceeds critical values!", "Cool down")
								break
						else:
							pass
					else:
						break
				return;
		except IOError:
			cmd = '''powershell Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace "root/wmi |Select-Object CurrentTemperature"'''
			count2 = 0;lastline = ''
			b = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
			time.sleep(1)
			while True:
				line = b.stdout.readline();line = line.rstrip()
				if line != '' and lastline != line:
					count2 += 1;lastline = line
					if count2 == 2:
						cache =  line.split()
						cache = int(cache[0])
						cache = (cache/10) - 273
						if cache > 59 and  cache != 0:
							w.balloon_tip("Hard disk temperature exceeds critical values!", "Decrease lifetime of harddisk")
					else:
						pass
				else:
					break
			return;
		
def dhcpcheck():
	cmd = "nmap -sU -p 67 --script dhcp-discover "
	ips =  ''.join([str(cmd),ipowershell(0)[1:-1]])
	count2 = 0;lastline = ''
	b = subprocess.Popen(ips, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = b.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count2 += 1;lastline = line
			if count2 == 6:
				if b"open" in line:
					return 1;
				else:
					return 0;
		else:
			break
			
def ipforwarding():
	cmd = "nmap -sn --script ip-forwarding --script-args target=www.example.com "
	ips =  ''.join([str(cmd),ipowershell(0)[1:-1]])
	count2 = 0;lastline = ''
	b = subprocess.Popen(ips, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = b.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count2 += 1;lastline = line
			if count2 > 1:
				if b"enabled" in line:
					return 1;
				else:
					pass
		else:
			break
			
#dns brute force
def dnsrecursion():
	cmd = "nmap -sU -p 53 --script=dns-recursion "
	ips =  ''.join([str(cmd),ipowershell(0)[1:-1]])
	count2 = 0;lastline = ''
	b = subprocess.Popen(ips, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = b.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count2 += 1;lastline = line
			print (line)
			if count2 > 1:
				if b"enabled" in line:
					return 1;
				else:
					pass
		else:
			break
		
#https://www.blackmoreops.com/2015/06/02/router-hack-how-to-hack-adsl-router-using-nmap/
def tcpwrapped():
	cmd = "nmap -sS -sV -p 80 -T5 -v -v -n -oG - -Pn "
	ips =  ''.join([str(cmd),ipowershell(0)[1:-1]])
	count2 = 0;lastline = ''
	b = subprocess.Popen(ips, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = b.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count2 += 1;lastline = line
			print (line)
			if count2 > 1:
				if b"tcpwrapped" in line:
					return 1;
				else:
					pass
		else:
			break
			
def webapplication():
	cmd = "nmap --script http-enum "
	ips =  ''.join([str(cmd),ipowershell(0)[1:-1]])
	count2 = 0;lastline = ''
	b = subprocess.Popen(ips, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = b.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count2 += 1;lastline = line
			print (line)
			if count2 > 1:
				if b"http-enum:" in line:
					return 1;
				else:
					pass
		else:
			break
			

def powercfgc(programm):
	if not (any(programm in s for s in powercfgl)):
		cmd = 'powercfg /requestsoverride PROCESS chrome.exe AWAYMODE'.split()
		cmd[3] = programm
		print (cmd)
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
		powercfgl.extend([programm])
	else:
		pass


#Read the  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*
def networkid():
	cmd = """powershell "Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | Select-Object -Property [a-z]* -ExcludeProperty IPX*,WINS* | where { $_.InterfaceIndex -eq '7'} | Sort-Object GatewayCostMetric | Select-Object SettingID"""
	cache = cmd.split()
	cache[19] =  "".join([ipowershell(1)[2:-1],'}'])
	cache = " ".join(cache)
	count2 = 0;lastline = ''
	print (cache)
	c = subprocess.Popen(cache, stdout=subprocess.PIPE, stderr=None)
	while True:
		line = c.stdout.readline();line = line.rstrip()
		if line != '' and lastline != line:
			count2 += 1;lastline = line
			if count2 == 4:
				cache = line.split()
				cache = str(cache[0])
				print (cache)
				return cache
			else:
				pass
		else:
			break
	return;

def udpport(host,port):
	q = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		 q.connect((host, port))
		 q.shutdown(2)
		 print ("Success connecting to ")
		 print (host + " on port: " + str(port))
		 return 1;
	except IOError:
		 print ("Cannot connect to ")
		 print (host + " on port: " + str(port))
		 return 0;
	
	
#Simple way of port checking .
def checkport(port):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		sock.bind(('0.0.0.0', port))
		sock.listen(1)
		sock.close
		return;
	except socket.error:
		return 1
		#errorcode=v[0]
		#if errorcode==errno.EADDRINUSE:
		#	return 1
		#else:
		#	w.balloon_tip("Unknow Port Error occured", str(port))
		#	return 1
		
# im fucking stupid : Ports can use TCP/UDP at the same time 
def checkapp():
	if checkport(20) and not any('FTP' in s for s in appc):
		appc.extend(['FTP'])
		#w.balloon_tip("FTP Server", "Port 20 in use!")
		lanmantune()
	if checkport(22) and not any('SSH' in s for s in appc):
		appc.extend(['SSH'])
		#w.balloon_tip("SSH found", "Port 22 in use!")
	if checkport(53) and not any('DNS' in s for s in appc):
		appc.extend(['DNS'])
		w.balloon_tip("DNS Server", "Port 53 in use!")
		dnsprotection()
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
		#w.balloon_tip("rtsp found", "Port 554 in use!")
	#if checkport(5357) and not any('wsdapi' in s for s in appc):
	#	appc.extend(['wsdapi'])
	#	w.balloon_tip("wsdapi found", "Port 5357 in use!")
	if checkport(30033) and not any('TS3F' in s for s in appc):
		appc.extend(['TS3F'])
	if checkport(10011) and not any('TS3Q' in s for s in appc):
		appc.extend(['TS3Q'])
	
	
def allprocess():
	cmd = 'WMIC PROCESS get Caption'
	proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
	for line in proc.stdout:
		print (line)
	
def processExists(processname):
    tlcall = 'TASKLIST', '/FI', 'imagename eq %s' % processname
    tlproc = subprocess.Popen(tlcall, shell=True, stdout=subprocess.PIPE)
    tlout = tlproc.communicate()[0].strip().split(b'\r\n')
    if len(tlout) > 1 and (processname) in tlout[-1]:
        return True
    else:
        return False

# Define Modes -> Example : PowerPoint -> Presentation Mode	, Steam -> Gaming Mode and so on...
def checkmode():
	if processExists(b'steam.exe'):
		setmodel(0)
	elif processExists(b'chrome.exe'):
		setmodel(1)
	
def setmodel(mode):
	global setmod
	if mode == 0 and (setmod != 0):
		#low latency
		mtus(0)
		tcpinitialRto(1000)
		tcpackfre(1)
		os.system('netsh int tcp set global rsc=disabled')
		os.system('netsh INT TCP SET GLOBAL AUTOTUNINGLEVEL=experimental')
		setmod = 0
	elif mode == 1 and (setmod != 1):
		#bandwidht
		mtus(1)
		tcpinitialRto(3000)
		tcpackfre(2)
		os.system('netsh int tcp set global rsc=enabled')
		os.system('netsh INT TCP SET GLOBAL AUTOTUNINGLEVEL=normal')
		setmod = 1
		
#check for audio input devices except : Microsoft Soundmapper
def checkperipherieaudio():
	import pyaudio as pya
	try:
		winmm= windll.winmm
		numb = winmm.waveInGetNumDevs()
		if numb:
			return numb
		else:
			return False
	except IOError:
		counter = 0
		p = pya.pyaudio.PyAudio()
		info = p.get_host_api_info_by_index(0)
		numdevices = info.get('deviceCount')
		for i in range(0, numdevices):
			if ((p.get_device_info_by_host_api_device_index(0, i).get('maxInputChannels')) > 0):
				if 'Mikrofon' in p.get_device_info_by_host_api_device_index(0, i).get('name'):
					counter += 1
				else:
					return False
					#w.balloon_tip("Mikrofon found", "Nothing else")
					#print "Input Device id ", i, " - ", p.get_device_info_by_host_api_device_index(0, i).get('name')
		return counter
				
#check camera				
def checkperipherievideo():
	#import pygame.camera
	#import pygame
	pygame.camera.init()
	try:
		cam = pygame.camera.Camera(0,(640,480),"RGB")
		cam.start()
		img =  pygame.Surface((640,480))
		cam.get_image(img)
		#pygame.image.save(img, "img2.jpg")
		cam.stop()
		#w.balloon_tip("Camera found", "Nothing else")
		return True
	except IOError:
		return False
	
def getsysletter():
	sysdrive = os.getenv('WINDIR')
	part0 = sysdrive.split("\\", 1)[0]
	return part0
	
#Check if Java Enviroment is set correctly (only 64x)
def enviromentcjava():
	cmd =  "".join([getsysletter(),sysdrivestrjava])
	if (not os.environ.get(cmd)) and ('X86_64' in arch):
		pass
	else:
		pass


#pid = subprocess.Popen([sys.executable, "D:\Snort\log\http.py"],creationflags=DETACHED_PROCESS).pid
#pid1 = subprocess.Popen([sys.executable, "D:\Snort\log\pop3.py"],creationflags=DETACHED_PROCESS).pid
#pid2 = subprocess.Popen([sys.executable, "D:\Snort\log\smtpfake.py"],creationflags=DETACHED_PROCESS).pid
#w.balloon_tip("Title for popup", "This is the popup's message")
#checknfts()
w = WindowsBalloonTip()
#getgpustatus()	
#tcpinitialrtt(2888)
#apprun('Chrome')
#print(psutil.cpu_percent())
#ForegroundWindow()
#readptx()
#checksmart()
#powercfgc("firefox.exe")
#sbl = SafeBrowsingList('AIzaSyCZ1H60_jeoasn-BPcUPUk-fYBBrW6VNS0')
#print (sbl.lookup_url('http://38zu.cn'))
blockad()
#loadBadDomains(url1)
#resolvename("yieldlab.net")
#time.sleep(999)
initials()
#time.sleep(999)
try:
	os.chdir(fname)
except IOError:
	Tk().withdraw()
	fname = askdirectory()
	for ch in ['//']:
		if ch in fname:
			fname=fname.replace(ch,"\\")
	print (fname)
	os.chdir(fname)
print ("2")
try:
	while run:
		if normalmode == 1:
			if (os.path.isfile(PATH) and os.access(PATH, os.R_OK)):
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
								print ("3")
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
								print ("4")
					time.sleep(10)
					myFile.close()
					line_num = 0
			else:
				w.balloon_tip("Either file is missing or is not readable", "No admin rights?")
		else:
			time.sleep(10)
			everything()
except KeyboardInterrupt:
	try:
		try:
			w.balloon_tip("Shutdown succesful", "Goodbye")
			#Important :close all threads
			#mousec._Thread__stop()
			foregroundc._Thread__stop()
			foregroundc.stop()
			icons.stop()
			os.system("taskkill /f /im python.exe")
			os.remove(PATH)
			sys.exit(0)
		except OSError:
			pass
	except SystemExit:
		os._exit(0)

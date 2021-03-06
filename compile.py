import sys
from distutils.core import setup
import py2exe
import sys,platform

entry_point = sys.argv[1]
sys.argv.pop()
sys.argv.append('py2exe')
sys.argv.append('-q')

arch = platform.architecture()[0]
if "64bit" in arch:
	opts = {
		'py2exe': {
			#"includes": ["ctypes", "logging"],
			'excludes' : ["tcl",'_psutil_bsd', '_psutil_linux', '_psutil_osx', '_psutil_posix', '_psutil_sunos', 'builtins', 'winreg'],
			'dll_excludes': ["tcl84.dll", "tk84.dll"],
			'compressed': 1,
			'optimize': 2,
		}
	}
if "32bit" in arch:
	opts = {
		'py2exe': {
			#"includes": ["ctypes", "logging"],
			'excludes' : ["tcl",'_psutil_bsd', '_psutil_linux', '_psutil_osx', '_psutil_posix', '_psutil_sunos', 'builtins', 'winreg'],
			'dll_excludes': ["tcl84.dll", "tk84.dll"],
			'compressed': 1,
			'optimize': 2,
			'bundle_files': 1
		}
	}

setup(console=[entry_point], options=opts, zipfile=None)

"""
PyInstaller Runtime Hook — Force-set TCL_LIBRARY and TK_LIBRARY
before any Tcl/Tk initialization occurs.
"""
import os
import sys

_base = sys._MEIPASS  # guaranteed to be set inside a frozen PyInstaller app

# Walk MEIPASS once to locate init.tcl and tk.tcl
_tcl_lib = None
_tk_lib = None
for _root, _dirs, _files in os.walk(_base):
    if _tcl_lib is None and 'init.tcl' in _files:
        _tcl_lib = _root.replace('\\', '/')
    if _tk_lib is None and 'tk.tcl' in _files:
        _tk_lib = _root.replace('\\', '/')
    if _tcl_lib and _tk_lib:
        break

if _tcl_lib:
    os.environ['TCL_LIBRARY'] = _tcl_lib
if _tk_lib:
    os.environ['TK_LIBRARY'] = _tk_lib

"""A console scope root that sends exact protocol bytes and owns two tools."""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import subprocess
import sys
import time

kernel = ctypes.WinDLL('kernel32', use_last_error=True)
ui = ctypes.WinDLL('user32', use_last_error=True)
handler = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)


@handler
def receive(code):
    Path('root.interrupt').write_text(str(code), encoding='ascii')
    os._exit(0)


kernel.SetConsoleCtrlHandler.argtypes = [handler, wintypes.BOOL]
kernel.SetConsoleCtrlHandler.restype = wintypes.BOOL
if not kernel.SetConsoleCtrlHandler(receive, True):
    raise ctypes.WinError(ctypes.get_last_error())
kernel.GetConsoleWindow.restype = wintypes.HWND
ui.IsWindowVisible.argtypes = [wintypes.HWND]
ui.IsWindowVisible.restype = wintypes.BOOL
window = kernel.GetConsoleWindow()
Path('root.visible').write_text(str(bool(window and ui.IsWindowVisible(window))), encoding='ascii')
assert sys.stdin.buffer.read() == b'owned input marker'
sys.stdout.buffer.write(b'PROTOCOL-OUT:0\x00\xff\n')
sys.stdout.buffer.flush()
sys.stderr.buffer.write(b'PROTOCOL-ERR:0\x00\xfe\n')
sys.stderr.buffer.flush()

children = {}
for name, command in {
    'powershell': ['powershell.exe', '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'tool.ps1'],
    'python': [sys.executable, '-I', '-B', 'tool.py'],
}.items():
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    children[name] = child
    Path(f'{name}.pid').write_text(str(child.pid), encoding='ascii')
Path('root.ready').write_text('ready', encoding='ascii')
until = time.monotonic() + 70
while not Path('normal-exit').exists() and time.monotonic() < until:
    time.sleep(.025)
for child in children.values():
    assert child.wait(timeout=8) == 0

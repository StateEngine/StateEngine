import ctypes
from ctypes import wintypes
from pathlib import Path
import time

handler = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)

@handler
def receive(code):
    Path('python.interrupt').write_text(str(code), encoding='ascii')
    return False

kernel = ctypes.WinDLL('kernel32', use_last_error=True)
kernel.SetConsoleCtrlHandler.argtypes = [handler, wintypes.BOOL]
kernel.SetConsoleCtrlHandler.restype = wintypes.BOOL
if not kernel.SetConsoleCtrlHandler(receive, True):
    raise ctypes.WinError(ctypes.get_last_error())
Path('python.ready').write_text('ready')
deadline = time.monotonic() + 80
while time.monotonic() < deadline and not Path('normal-exit').exists():
    time.sleep(.05)

"""Cleanup authority for an exclusively created native fixture directory."""
import os
from pathlib import Path
import shutil
import stat


if os.name == 'nt':
    import ctypes
    from ctypes import wintypes

    class FileId(ctypes.Structure):
        _fields_ = [('volume', ctypes.c_ulonglong), ('file', ctypes.c_ubyte * 16)]

    class Attributes(ctypes.Structure):
        _fields_ = [('attributes', wintypes.DWORD), ('tag', wintypes.DWORD)]

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                   wintypes.LPVOID, wintypes.DWORD]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL


def _close(handle):
    if os.name == 'nt':
        if not kernel.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        os.close(handle)


def _open(path, deny_delete=False):
    if os.name == 'nt':
        # Read attributes, no inherited handle, open the entry itself. Creation
        # pins permit ordinary fixture mutations; cleanup locks its ancestors.
        handle = kernel.CreateFileW(str(path), 0x80, 3 if deny_delete else 7,
                                    None, 3, 0x02000000 | 0x00200000, None)
        if handle in (None, ctypes.c_void_p(-1).value):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            attributes, identity = Attributes(), FileId()
            for kind, value in [(9, attributes), (18, identity)]:
                if not kernel.GetFileInformationByHandleEx(handle, kind, ctypes.byref(value),
                                                           ctypes.sizeof(value)):
                    raise ctypes.WinError(ctypes.get_last_error())
            if not attributes.attributes & 0x10 or attributes.attributes & 0x400:
                raise OSError('fixture directory is a reparse point or changed kind')
            return handle, (identity.volume, bytes(identity.file))
        except BaseException:
            _close(handle)
            raise
    handle = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(handle)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError('fixture root changed kind')
        return handle, (metadata.st_dev, metadata.st_ino)
    except BaseException:
        _close(handle)
        raise


class DirectoryOwner:
    """Retain the created root and every physical ancestor until explicit cleanup.

    A failed or interrupted case never calls remove; dropping this object only
    closes its native handles. Passing cleanup refuses replacement or redirected
    ancestry. Descendant links remain entries, not recursive deletion targets.
    """
    def __init__(self, root):
        self._pins = []
        original, identity = _open(root)
        try:
            self.root = Path(root).resolve(strict=True)
            if self.root.parent == self.root:
                raise ValueError('a created fixture child is required')
            for path in [self.root, *self.root.parents]:
                handle, found = _open(path)
                self._pins.append((path, handle, found))
            if self._pins[0][2] != identity:
                raise OSError('fixture root changed while binding cleanup')
        except BaseException:
            self.close()
            raise
        finally:
            _close(original)

    def remove(self):
        if not self._pins:
            raise OSError('fixture cleanup authority is already closed')
        guards = []
        try:
            for path, _held, identity in reversed(self._pins):
                handle, found = _open(path, deny_delete=path != self.root)
                guards.append(handle)
                if found != identity:
                    raise OSError(f'fixture directory identity changed: {path}')
            if os.name == 'posix':
                # Resolve the final child relative to its retained native parent,
                # rather than reopening a temporary ancestor spelling.
                shutil.rmtree(self.root.name, dir_fd=self._pins[1][1])
            else:
                shutil.rmtree(self.root)
        except BaseException as error:
            print(f'retained fixture root {self.root}: cleanup refused or failed: {error}',
                  flush=True)
            raise
        finally:
            for handle in reversed(guards):
                _close(handle)
        self.close()

    def close(self):
        pins, self._pins = self._pins, []
        for _path, handle, _identity in reversed(pins):
            _close(handle)

    def __del__(self):
        try:
            self.close()
        except (OSError, AttributeError):
            # Destruction never authorizes deletion or conceals the original
            # case error. The process still owns any unclosed native handle.
            pass

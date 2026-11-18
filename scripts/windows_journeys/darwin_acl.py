"""Read and clear macOS extended access entries through a held descriptor."""
import ctypes
import errno

from harness_matrix.io import require


def require_private_acl(descriptor, establish=False):
    native = ctypes.CDLL(None, use_errno=True)
    native.acl_init.argtypes, native.acl_init.restype = (ctypes.c_int,), ctypes.c_void_p
    native.acl_get_fd.argtypes, native.acl_get_fd.restype = (ctypes.c_int,), ctypes.c_void_p
    native.acl_set_fd.argtypes = (ctypes.c_int, ctypes.c_void_p)
    native.acl_size.argtypes, native.acl_size.restype = (ctypes.c_void_p,), ctypes.c_ssize_t
    native.acl_free.argtypes = (ctypes.c_void_p,)

    empty = native.acl_init(0)
    require(empty, 'Could not allocate an empty native credential ACL')
    try:
        if establish:
            require(native.acl_set_fd(descriptor, empty) == 0, 'Private credential ACL could not be cleared')
        ctypes.set_errno(0)
        observed = native.acl_get_fd(descriptor)
        if not observed:
            require(ctypes.get_errno() == errno.ENOENT, 'Private credential ACL is unreadable')
            return
        try:
            # Darwin's external ACL size counts every entry, including inherited ones.
            empty_size = native.acl_size(empty)
            require(empty_size > 0 and native.acl_size(observed) == empty_size,
                    'Credential path has an extended ACL entry or unreadable ACL size')
        finally:
            native.acl_free(observed)
    finally:
        native.acl_free(empty)

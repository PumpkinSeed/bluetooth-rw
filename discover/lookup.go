package discover

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	LUP_DEEP                = 0x0001
	LUP_CONTAINERS          = 0x0002
	LUP_NOCONTAINERS        = 0x0004
	LUP_NEAREST             = 0x0008
	LUP_RETURN_NAME         = 0x0010
	LUP_RETURN_TYPE         = 0x0020
	LUP_RETURN_VERSION      = 0x0040
	LUP_RETURN_COMMENT      = 0x0080
	LUP_RETURN_ADDR         = 0x0100
	LUP_RETURN_BLOB         = 0x0200
	LUP_RETURN_ALIASES      = 0x0400
	LUP_RETURN_QUERY_STRING = 0x0800
	LUP_RETURN_ALL          = 0x0FF0
	LUP_RES_SERVICE         = 0x8000

	LUP_FLUSHCACHE    = 0x1000
	LUP_FLUSHPREVIOUS = 0x2000

	LUP_NON_AUTHORITATIVE      = 0x4000
	LUP_SECURE                 = 0x8000
	LUP_RETURN_PREFERRED_NAMES = 0x10000
	LUP_DNS_ONLY               = 0x20000

	LUP_ADDRCONFIG           = 0x100000
	LUP_DUAL_ADDR            = 0x200000
	LUP_FILESERVER           = 0x400000
	LUP_DISABLE_IDN_ENCODING = 0x00800000
	LUP_API_ANSI             = 0x01000000

	LUP_RESOLUTION_HANDLE = 0x80000000
)

const socket_error = uintptr(^uint32(0))

const errnoERROR_IO_PENDING = 997

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall.EINVAL
)

var (
	modws2_32                 = windows.NewLazySystemDLL("ws2_32.dll")
	procWSALookupServiceBegin = modws2_32.NewProc("WSALookupServiceBeginW")
	procWSALookupServiceNext  = modws2_32.NewProc("WSALookupServiceNextW")
	procWSALookupServiceEnd   = modws2_32.NewProc("WSALookupServiceEnd")
)

func WSALookupServiceBegin(querySet *WSAQUERYSET, flags uint32, handle *windows.Handle) error {
	var qs = unsafe.Pointer(querySet)

	r, _, errNo := syscall.SyscallN(procWSALookupServiceBegin.Addr(), uintptr(qs), uintptr(flags), uintptr(unsafe.Pointer(handle)))
	if r == socket_error {
		return errnoErr(errNo)
	}

	return nil
}

func WSALookupServiceNext(handle windows.Handle, flags uint32, size *int32, q *WSAQUERYSET) error {
	r, _, errNo := syscall.SyscallN(procWSALookupServiceNext.Addr(), uintptr(handle), uintptr(flags), uintptr(unsafe.Pointer(size)), uintptr(unsafe.Pointer(q)))
	if r == socket_error {
		return errnoErr(errNo)
	}
	return nil
}

func WSALookupServiceEnd(handle windows.Handle) error {
	r, _, errNo := syscall.SyscallN(procWSALookupServiceEnd.Addr(), uintptr(handle))
	if r == socket_error {
		return errnoErr(errNo)
	}
	return nil
}

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	return e
}

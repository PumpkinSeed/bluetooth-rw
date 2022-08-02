package discover

// #include <windows.h>
import "C"

import (
	"fmt"
	"strings"
	"syscall"
	"unicode/utf16"
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

func Scan(q WSAQUERYSET) error {
	var flags uint32 = LUP_CONTAINERS
	flags |= LUP_RETURN_NAME
	flags |= LUP_RETURN_ADDR

	var handle windows.Handle = 0

	var err error
	// _, _, err = procWSALookupServiceBegin.Call(
	// 	uintptr(unsafe.Pointer(&rawQ)),
	// 	uintptr(flags),
	// 	uintptr(unsafe.Pointer(&handle)),
	// )
	// if err != nil {
	// 	return err
	// }
	// var (
	// 	modws2_32                 = windows.NewLazySystemDLL("ws2_32.dll")
	// 	procWSALookupServiceBegin = modws2_32.NewProc("WSALookupServiceBeginA")
	// 	// procWSALookupServiceNext  = modws2_32.NewProc("WSALookupServiceNextA")
	// 	// procWSALookupServiceEnd   = modws2_32.NewProc("WSALookupServiceEnd")
	// )
	addr := procWSALookupServiceBegin.Addr()
	//flagsRaw := []byte{18, 1, 0, 0}
	//fmt.Println(flagsRaw)
	const sz = int(unsafe.Sizeof(WSAQUERYSET{}))
	var querySet WSAQUERYSET
	querySet.NameSpace = 16
	querySet.Size = uint32(sz)
	q1 := unsafe.Pointer(&querySet)

	r1, _, e1 := syscall.SyscallN(addr, uintptr(q1), uintptr(flags), uintptr(unsafe.Pointer(&handle)))
	if r1 == socket_error {
		err = errnoErr(e1)
		return fmt.Errorf("procWSALookupServiceBegin: %s", err.Error())
	}

	var size = int32(120)
	for i := 0; i < 5; i++ {
		var querySet2 = NewWSAQUERYSET()
		q2 := unsafe.Pointer(&querySet2)
		nextAddr := procWSALookupServiceNext.Addr()
		r2, _, e2 := syscall.SyscallN(nextAddr, uintptr(handle), uintptr(flags), uintptr(unsafe.Pointer(&size)), uintptr(q2))
		if r2 == socket_error {
			err = errnoErr(e2)
			if strings.Contains(err.Error(), "No more results") {
				break
			}
			fmt.Printf("procWSALookupServiceNext: %s\n", err.Error())
		}

		if querySet2.ServiceInstanceName != nil {
			//fmt.Println("not nil")
			str := CStringToString(querySet2.ServiceInstanceName)
			fmt.Printf("%s\n", str)
		}

	}

	r3, _, e3 := syscall.SyscallN(procWSALookupServiceEnd.Addr(), uintptr(handle))
	if r3 == socket_error {
		err = errnoErr(e3)
		return fmt.Errorf("procWSALookupServiceNext: %s", err.Error())
	}

	//windows.Close(handle)
	return nil
}

type CString *uint16

func CStringToString(cs CString) (s string) {
	if cs != nil {
		us := make([]uint16, 0, 256)
		for p := uintptr(unsafe.Pointer(cs)); ; p += 2 {
			u := *(*uint16)(unsafe.Pointer(p))
			if u == 0 {
				return string(utf16.Decode(us))
			}
			us = append(us, u)
		}
	}
	return ""
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

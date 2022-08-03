package discover

import (
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// https://docs.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-wsaquerysetw
type WSAQUERYSET struct {
	Size                uint32
	ServiceInstanceName Wchar
	ServiceClassId      *windows.GUID
	Version             *WSAVersion
	Comment             Wchar
	NameSpace           uint32
	NSProviderId        *windows.GUID
	Context             Wchar
	NumberOfProtocols   uint32
	AfpProtocols        *AFProtocols
	QueryString         Wchar
	NumberOfCsAddrs     uint32
	SaBuffer            *AddrInfo
	OutputFlags         uint32
	Blob                *BLOB
}

func (w WSAQUERYSET) ServiceInstanceNameToString() string {
	return WcharToString(w.ServiceInstanceName)
}

func (w WSAQUERYSET) CommentToString() string {
	return WcharToString(w.Comment)
}

func (w WSAQUERYSET) ContextToString() string {
	return WcharToString(w.Context)
}

func (w WSAQUERYSET) QueryStringToString() string {
	return WcharToString(w.QueryString)
}

// https://docs.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-wsaversion
type WSAVersion struct {
	Version                  uint32 // DWORD
	EnumerationOfComparision int32  // WSAEcomparator enum
}

// https://docs.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-afprotocols
type AFProtocols struct {
	AddressFamily int32
	Protocol      int32
}

// https://docs.microsoft.com/en-us/windows/win32/winsock/sockaddr-2
type Sockaddr struct {
	Family uint16
	Data   [14]byte
}

// https://docs.microsoft.com/en-us/windows/win32/api/Ws2def/ns-ws2def-socket_address
type SocketAddress struct {
	Sockaddr       *Sockaddr
	SockaddrLength int
}

// https://docs.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-csaddr_info
type AddrInfo struct {
	LocalAddr  SocketAddress
	RemoteAddr SocketAddress
	SocketType int32
	Protocol   int32
}

// https://docs.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-blob
type BLOB struct {
	Size     uint32
	BlobData *byte // TODO how to represent a block of data in Go?
}

type Wchar *uint16

func WcharToString(w Wchar) string {
	if w != nil {
		us := make([]uint16, 0, 256)
		for p := uintptr(unsafe.Pointer(w)); ; p += 2 {
			u := *(*uint16)(unsafe.Pointer(p))
			if u == 0 {
				return string(utf16.Decode(us))
			}
			us = append(us, u)
		}
	}
	return ""
}

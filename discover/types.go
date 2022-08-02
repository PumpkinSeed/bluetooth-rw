package discover

import (
	"golang.org/x/sys/windows"
)

type Wchar uint16

// https://docs.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-wsaquerysetw
type WSAQUERYSET struct {
	Size                uint32
	ServiceInstanceName CString
	ServiceClassId      *windows.GUID
	Version             *WSAVersion
	Comment             *string
	NameSpace           uint32
	NSProviderId        *windows.GUID
	Context             *string
	NumberOfProtocols   uint32
	AfpProtocols        *AFProtocols
	QueryString         *string
	NumberOfCsAddrs     uint32
	SaBuffer            *AddrInfo
	OutputFlags         uint32
	Blob                *BLOB
}

func NewWSAQUERYSET() WSAQUERYSET {
	var serviceInstanceName CString
	var comment string
	var context string
	var queryString string

	return WSAQUERYSET{
		ServiceInstanceName: serviceInstanceName,
		ServiceClassId:      &windows.GUID{},
		Version:             &WSAVersion{},
		Comment:             &comment,
		NSProviderId:        &windows.GUID{},
		Context:             &context,
		AfpProtocols:        &AFProtocols{},
		QueryString:         &queryString,
		SaBuffer: &AddrInfo{
			LocalAddr: SocketAddress{
				Sockaddr: &Sockaddr{},
			},
			RemoteAddr: SocketAddress{
				Sockaddr: &Sockaddr{},
			},
		},
		Blob: &BLOB{},
	}
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

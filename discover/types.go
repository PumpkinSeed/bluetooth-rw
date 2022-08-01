package discover

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

type (
	//DWORD   uint32
	VString *string
)

type WSAQUERYSET struct {
	Size                uint32
	ServiceInstanceName *string
	ServiceClassId      windows.GUID
	Version             *WSAVersion
	Comment             *string
	NameSpace           uint32
	NSProviderId        windows.GUID
	Context             *string
	NumberOfProtocols   uint32
	AfpProtocols        AFProtocols
	QueryString         *string
	NumberOfCsAddrs     uint32
	SaBuffer            *AddrInfo
	OutputFlags         uint32
	Blob                *BLOB
}

func (w WSAQUERYSET) raw() rawWSAQuerySet {
	return rawWSAQuerySet{
		NameSpace: *(*[4]byte)(unsafe.Pointer(&w.NameSpace)),
	}
}

type rawWSAQuerySet struct {
	Size                [4]byte
	ServiceInstanceName [8]byte
	ServiceClassId      [8]byte
	Version             [8]byte
	Comment             [8]byte
	NameSpace           [4]byte
	NSProviderId        [8]byte
	Context             [8]byte
	NumberOfProtocols   [4]byte
	AfpProtocols        [8]byte
	QueryString         [8]byte
	NumberOfCsAddrs     [4]byte
	SaBuffer            [8]byte
	OutputFlags         [4]byte
	Blob                [8]byte
}

// dwSize							78 00 00 00
// lpszServiceInstanceName			b8 f9 7f 03 31 00 00 00
// lpVersion						10 4b 6c ee fe 7f 00 00
// lpszComment						91 00 00 00 0a 00 00 00
// dwNameSpace						10 00 00 00
// lpNSProviderId					a0 1a 51 9d 06 02 00 00
// lpszContext						b8 f9 7f 03 31 00 00 00
// dwNumberOfProtocols				01 00 00 00
// lpafpProtocols					37 2f ad ed fe 7f 00 00
// lpszQueryString					80 9e 50 9d 06 02 00 00
// dwNumberOfCsAddrs				e0 fa 7f 03
// lpcsaBuffer						80 9e 50 9d 06 02 00 00
// dwOutputFlags					01 00 00 00
// lpBlob							02 02 02 ec 02 00 00 00

// -----------------

type WSAVersion struct {
	Version                  uint32 // DWORD
	EnumerationOfComparision int    // WSAEcomparator enum
}

type AFProtocols struct {
	AddressFamily int
	Protocol      int
}
type AddrInfo struct {
	LocalAddr  SocketAddress
	RemoteAddr SocketAddress
	SocketType int
	Protocol   int
}

type SocketAddress struct {
	Sockaddr       *sockaddr
	SockaddrLength int
}

type sockaddr struct {
	family uint16
	data   [14]byte
}

type BLOB struct {
	Size     uint32
	BlobData *byte
}

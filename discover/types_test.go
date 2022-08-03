package discover

import (
	"fmt"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestNameSpace(t *testing.T) {
	const sz = int(unsafe.Sizeof(WSAQUERYSET{}))
	var querySet WSAQUERYSET
	querySet.NameSpace = 16
	querySet.Size = uint32(sz)
	var asByteSlice []byte = (*(*[sz]byte)(unsafe.Pointer(&querySet)))[:]
	for _, d := range asByteSlice {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")
}

func TestAFProtocols(t *testing.T) {
	const sz = int(unsafe.Sizeof(AFProtocols{}))
	var af AFProtocols
	af.AddressFamily = 12222
	af.Protocol = 12333123
	var asByteSlice []byte = (*(*[sz]byte)(unsafe.Pointer(&af)))[:]
	for _, d := range asByteSlice {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")
}

func TestWSAVersion(t *testing.T) {
	const sz = int(unsafe.Sizeof(WSAVersion{}))
	var version WSAVersion
	version.Version = 1234123
	version.EnumerationOfComparision = 1
	var asByteSlice []byte = (*(*[sz]byte)(unsafe.Pointer(&version)))[:]
	for _, d := range asByteSlice {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")
}

// Sockaddr

func TestSockaddr(t *testing.T) {
	const sz = int(unsafe.Sizeof(Sockaddr{}))
	var sa Sockaddr
	sa.Family = 44
	sa.Data = [14]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23}
	var asByteSlice []byte = (*(*[sz]byte)(unsafe.Pointer(&sa)))[:]
	for _, d := range asByteSlice {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")
}

func TestSocketAddress(t *testing.T) {
	const sz = int(unsafe.Sizeof(SocketAddress{}))
	var sa Sockaddr
	sa.Family = 44
	sa.Data = [14]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23}
	var socketAddress SocketAddress
	socketAddress.Sockaddr = &sa
	socketAddress.SockaddrLength = 10
	var asByteSlice []byte = (*(*[sz]byte)(unsafe.Pointer(&socketAddress)))[:]
	for _, d := range asByteSlice {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")
}

func TestAddrInfo(t *testing.T) {
	const sz = int(unsafe.Sizeof(AddrInfo{}))
	var sa Sockaddr
	sa.Family = 44
	sa.Data = [14]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23}
	var socketAddress SocketAddress
	socketAddress.Sockaddr = &sa
	socketAddress.SockaddrLength = 10

	var saLocal Sockaddr
	saLocal.Family = 44
	saLocal.Data = [14]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23}
	var socketAddressLocal SocketAddress
	socketAddressLocal.Sockaddr = &saLocal
	socketAddressLocal.SockaddrLength = 10

	addrInfo := AddrInfo{
		LocalAddr:  socketAddressLocal,
		RemoteAddr: socketAddress,
		SocketType: 300,
		Protocol:   12,
	}

	var asByteSlice []byte = (*(*[sz]byte)(unsafe.Pointer(&addrInfo)))[:]
	for _, d := range asByteSlice {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")
}

func TestIt(t *testing.T) {
	const sz = int(unsafe.Sizeof(WSAQUERYSET{}))
	var querySet WSAQUERYSET
	querySet.NameSpace = 16
	var serviceInstanceName Wchar
	querySet.ServiceInstanceName = serviceInstanceName

	serviceClassId, _ := windows.GUIDFromString("495353-43fe-7d4a-e58f-a99fafd205e4")
	querySet.ServiceClassId = &serviceClassId
	querySet.Version = &WSAVersion{
		Version:                  12,
		EnumerationOfComparision: 1,
	}
	var comment Wchar
	querySet.Comment = comment

	nsProviderId, _ := windows.GUIDFromString("495353-43fe-7d4a-e58f-a99fafd205e4")
	querySet.NSProviderId = &nsProviderId
	var context Wchar
	querySet.Context = context
	querySet.NumberOfProtocols = 123
	querySet.AfpProtocols = &AFProtocols{
		AddressFamily: 13,
		Protocol:      300,
	}
	var queryString Wchar
	querySet.QueryString = queryString
	querySet.NumberOfCsAddrs = 11111
	querySet.SaBuffer = &AddrInfo{
		SocketType: 14,
		Protocol:   300,
		RemoteAddr: SocketAddress{
			Sockaddr:       &Sockaddr{},
			SockaddrLength: 10,
		},
	}
	querySet.OutputFlags = 100
	querySet.Blob = &BLOB{
		Size: 10,
	}
	querySet.Size = uint32(sz)
	var asByteSlice []byte = (*(*[sz]byte)(unsafe.Pointer(&querySet)))[:]
	for _, d := range asByteSlice {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")

	var asByteSlice1 []byte = (*(*[int(unsafe.Sizeof(querySet.Size))]byte)(unsafe.Pointer(&querySet.Size)))[:]
	fmt.Print("Size: ")
	for _, d := range asByteSlice1 {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")

	var asByteSlice2 []byte = (*(*[int(unsafe.Sizeof(querySet.ServiceInstanceName))]byte)(unsafe.Pointer(&querySet.ServiceInstanceName)))[:]
	fmt.Print("ServiceInstanceName: ")
	for _, d := range asByteSlice2 {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")

	var asByteSlice2a []byte = (*(*[int(unsafe.Sizeof(querySet.ServiceClassId))]byte)(unsafe.Pointer(&querySet.ServiceClassId)))[:]
	fmt.Print("ServiceClassId: ")
	for _, d := range asByteSlice2a {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")

	var asByteSlice3 []byte = (*(*[int(unsafe.Sizeof(querySet.Version))]byte)(unsafe.Pointer(&querySet.Version)))[:]
	fmt.Print("Version: ")
	for _, d := range asByteSlice3 {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")

	var asByteSlice4 []byte = (*(*[int(unsafe.Sizeof(querySet.Comment))]byte)(unsafe.Pointer(&querySet.Comment)))[:]
	fmt.Print("Comment: ")
	for _, d := range asByteSlice4 {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")

	var asByteSlice5 []byte = (*(*[int(unsafe.Sizeof(querySet.NameSpace))]byte)(unsafe.Pointer(&querySet.NameSpace)))[:]
	fmt.Print("NameSpace: ")
	for _, d := range asByteSlice5 {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")

	var asByteSlice6 []byte = (*(*[int(unsafe.Sizeof(querySet.NSProviderId))]byte)(unsafe.Pointer(&querySet.NSProviderId)))[:]
	fmt.Print("NSProviderId: ")
	for _, d := range asByteSlice6 {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")

	var asByteSlice7 []byte = (*(*[int(unsafe.Sizeof(querySet.Context))]byte)(unsafe.Pointer(&querySet.Context)))[:]
	fmt.Print("Context: ")
	for _, d := range asByteSlice7 {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")

	var asByteSlice8 []byte = (*(*[int(unsafe.Sizeof(querySet.NumberOfProtocols))]byte)(unsafe.Pointer(&querySet.NumberOfProtocols)))[:]
	fmt.Print("NumberOfProtocols: ")
	for _, d := range asByteSlice8 {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")

	var asByteSlice9 []byte = (*(*[int(unsafe.Sizeof(querySet.AfpProtocols))]byte)(unsafe.Pointer(&querySet.AfpProtocols)))[:]
	fmt.Print("AfpProtocols: ")
	for _, d := range asByteSlice9 {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")

	var asByteSlice10 []byte = (*(*[int(unsafe.Sizeof(querySet.QueryString))]byte)(unsafe.Pointer(&querySet.QueryString)))[:]
	fmt.Print("QueryString: ")
	for _, d := range asByteSlice10 {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")

	var asByteSlice11 []byte = (*(*[int(unsafe.Sizeof(querySet.NumberOfCsAddrs))]byte)(unsafe.Pointer(&querySet.NumberOfCsAddrs)))[:]
	fmt.Print("NumberOfCsAddrs: ")
	for _, d := range asByteSlice11 {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")

	var asByteSlice12 []byte = (*(*[int(unsafe.Sizeof(querySet.SaBuffer))]byte)(unsafe.Pointer(&querySet.SaBuffer)))[:]
	fmt.Print("SaBuffer: ")
	for _, d := range asByteSlice12 {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")

	var asByteSlice13 []byte = (*(*[int(unsafe.Sizeof(querySet.OutputFlags))]byte)(unsafe.Pointer(&querySet.OutputFlags)))[:]
	fmt.Print("OutputFlags: ")
	for _, d := range asByteSlice13 {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")

	var asByteSlice14 []byte = (*(*[int(unsafe.Sizeof(querySet.Blob))]byte)(unsafe.Pointer(&querySet.Blob)))[:]
	fmt.Print("Blob: ")
	for _, d := range asByteSlice14 {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")
}

func value(name string, x interface{}) {
	const sz = int(unsafe.Sizeof(x))
	var asByteSlice []byte = (*(*[sz]byte)(unsafe.Pointer(&x)))[:]
	fmt.Printf("%s: ", name)
	for _, d := range asByteSlice {
		fmt.Printf("%02x ", d)
	}
	fmt.Print("\n")
}

// 78 00 00 00 00 00 00 00 37 2f ad ed fe 7f 00 00 60 9e 91 23 1b 02 00 00 00 fa 9f 5d c2 00 00 00 60 9e 91 23 1b 02 00 00 10 00 00 00 00 00 00 00 02 02 02 ec 02 00 00 00 65 00 00 00 1b 02 00 00 bb f9 9f 5d c2 00 00 00 0b 00 00 00 00 00 00 00 b8 fa 9f 5d c2 00 00 00 07 00 00 00 00 00 00 00 eb 8a b1 ed fe 7f 00 00 f6 00 00 00 00 00 00 00 f3 ff ff 7f 00 00 00 00
// 90 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

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

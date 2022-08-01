package discover

import (
	"fmt"
	"testing"
	"unsafe"
)

func TestIt(t *testing.T) {

	const sz = int(unsafe.Sizeof(WSAQUERYSET{}))
	var querySet WSAQUERYSET
	querySet.NameSpace = 16
	serviceInstanceName := "lofasz"
	querySet.ServiceInstanceName = &serviceInstanceName
	querySet.Version = &WSAVersion{
		Version:                  12,
		EnumerationOfComparision: 1,
	}
	comment := "comment"
	querySet.Comment = &comment
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

package discover

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func Scan() error {
	var flags uint32 = LUP_CONTAINERS
	flags |= LUP_RETURN_NAME
	flags |= LUP_RETURN_ADDR

	var querySet WSAQUERYSET
	querySet.NameSpace = 16
	querySet.Size = uint32(unsafe.Sizeof(WSAQUERYSET{}))

	var handle windows.Handle
	err := WSALookupServiceBegin(&querySet, flags, &handle)
	if err != nil {
		return err
	}

	var size = int32(unsafe.Sizeof(WSAQUERYSET{}))
	for i := 0; i < 5; i++ {
		var q WSAQUERYSET
		q, err = WSALookupServiceNext(handle, flags, size, &querySet)
		if err != nil {
			if strings.Contains(err.Error(), "No more results") {
				fmt.Printf("WSALookupServiceNext: %s\n", err.Error())
				break
			}
			fmt.Printf("WSALookupServiceNext: %s\n", err.Error())
		}

		recvDevice(&q)
	}

	err = WSALookupServiceEnd(handle)
	if err != nil {
		return fmt.Errorf("WSALookupServiceEnd: %s", err.Error())
	}

	//err = windows.Close(handle)
	fmt.Println("start of wait in the Scan function")
	time.Sleep(2 * time.Second)
	fmt.Println("finish wait in the Scan function")
	return nil
}

func recvDevice(querySet *WSAQUERYSET) {
	if querySet == nil {
		return
	}
	if querySet.ServiceInstanceName != nil {
		var addr string
		for _, e := range querySet.SaBuffer.RemoteAddr.Sockaddr.Data {
			if e != 0 {
				addr += fmt.Sprintf("%x", e)
			}
		}
		fmt.Printf("%s -> %s\n", querySet.ServiceInstanceNameToString(), string(addr))
	}
}

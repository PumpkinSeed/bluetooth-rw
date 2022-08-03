package discover

import (
	"fmt"
	"testing"
	"unsafe"
)

func TestScanner(t *testing.T) {
	q := WSAQUERYSET{
		NameSpace: 16,
	}
	fmt.Println("test start")
	q.Size = uint32(unsafe.Sizeof(q))
	err := Scan(q)
	fmt.Println("-----------test")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("test done")
}

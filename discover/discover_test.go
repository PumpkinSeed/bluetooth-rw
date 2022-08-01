package discover

import (
	"testing"
	"unsafe"
)

func TestScanner(t *testing.T) {
	q := WSAQUERYSET{
		NameSpace: 16,
	}
	q.Size = uint32(unsafe.Sizeof(q))
	err := Scan(q)
	if err != nil {
		t.Fatal(err)
	}
}

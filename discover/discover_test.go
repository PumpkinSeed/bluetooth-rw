package discover

import (
	"fmt"
	"testing"
)

func TestScanner(t *testing.T) {

	fmt.Println("test start")

	err := Scan()
	fmt.Println("-----------test")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("test done")
}

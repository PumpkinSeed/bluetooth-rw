package main

import (
	"fmt"
	"time"

	"github.com/Pumpkinseed/bluetooth/discover"
)

func main() {
	discover.Scan(discover.WSAQUERYSET{})
	fmt.Println("start of wait in the main")
	time.Sleep(2 * time.Second)
	fmt.Println("finish wait in the main")
}

package main

import "github.com/Pumpkinseed/bluetooth/discover"

func main() {
	discover.Scan(discover.WSAQUERYSET{})
}

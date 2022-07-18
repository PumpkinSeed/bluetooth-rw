package bluetooth

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"bitbucket.org/fluidpay/easylinkd/logging"
	"golang.org/x/sys/windows"
)

// NOTE: https://github.com/golang/go/issues/52325

var _ CommunicationDescriptor = &bluetooth{}

type bluetooth struct {
	Handle windows.Handle
	// SocketAddr     *unix.SockaddrRFCOMM
	Addr string
}

type RawSockaddrRFCOMM struct {
	Family  uint16
	Bdaddr  [6]uint8
	Channel uint8
	_       [1]byte
}

type SockaddrRFCOMM struct {
	// Addr represents a bluetooth address, byte ordering is little-endian.
	Addr [6]uint8

	// Channel is a designated bluetooth channel, only 1-30 are available for use.
	// Since Linux 2.6.7 and further zero value is the first available channel.
	Channel uint8

	raw RawSockaddrRFCOMM
}

func (sa *SockaddrRFCOMM) sockaddr() (unsafe.Pointer, int32, error) {
	sa.raw.Family = 32
	sa.raw.Channel = sa.Channel
	sa.raw.Bdaddr = sa.Addr
	return unsafe.Pointer(&sa.raw), int32(unsafe.Sizeof(sa.raw)), nil
}

type SockaddrBth struct {
	family         uint16
	BtAddr         [6]byte
	ServiceClassId windows.GUID
	Port           uint16
}

func (sa *SockaddrBth) sockaddr() (unsafe.Pointer, int32, error) {
	// if sa.Port < 0 || sa.Port > 31 {
	// 	return nil, 0, windows.EINVAL
	// }
	sa.family = 32
	p := (*[2]byte)(unsafe.Pointer(&sa.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	return unsafe.Pointer(sa), int32(unsafe.Sizeof(*sa)), nil
}

func Bluetooth(addr string) (CommunicationDescriptor, error) {
	fd, err := windows.Socket(windows.AF_BTH, windows.SOCK_STREAM, windows.BTHPROTO_RFCOMM)
	if err != nil {
		return nil, err
	}

	// fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_STREAM, unix.BTPROTO_RFCOMM)
	// if err != nil {
	// 	return nil, err
	// }
	//logging.Debug("unix socket returned a file descriptor: ", fd)
	g, _ := windows.GenerateGUID()
	s := SockaddrBth{
		BtAddr:         [6]byte{},
		ServiceClassId: g,
		Port:           1,
	}
	if err := windows.Connect(fd, s); err != nil {
		return nil, err
	}
	logging.Debug("unix socket linked with an RFCOMM")

	return &bluetooth{
		//FileDescriptor: fd,
		//SocketAddr:     socketAddr,
		Addr: addr,
	}, nil
}

func (b *bluetooth) Read(dataLen int) (int, []byte, error) {

	var data = make([]byte, dataLen)
	n, err := windows.Read(b.Handle, data)
	if err != nil {
		return 0, nil, err
	}
	logging.Debug(fmt.Sprintf(">>>>>>>>>>>> protoComm.Read: %v", data[:n]))
	return 12, data, nil
}

func (b *bluetooth) Write(d []byte) error {
	logging.Debug(fmt.Sprintf(">>>>>>>>>>>> protoComm.Write: %v", d))
	_, err := windows.Write(b.Handle, d)
	if err != nil {
		return err
	}
	return nil
}

func (b bluetooth) Close() error {
	return windows.Close(b.Handle)
}

// str2ba converts MAC address string representation to little-endian byte array
func str2ba(addr string) [6]byte {
	a := strings.Split(addr, ":")
	var b [6]byte
	for i, tmp := range a {
		u, _ := strconv.ParseUint(tmp, 16, 8)
		b[len(b)-1-i] = byte(u)
	}
	return b
}

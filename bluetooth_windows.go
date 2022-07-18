package comm

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"
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

// type RawSockaddrRFCOMM struct {
// 	Family  uint16
// 	Bdaddr  [6]uint8
// 	Channel uint8
// 	_       [1]byte
// }

// type SockaddrRFCOMM struct {
// 	// Addr represents a bluetooth address, byte ordering is little-endian.
// 	Addr [6]uint8

// 	// Channel is a designated bluetooth channel, only 1-30 are available for use.
// 	// Since Linux 2.6.7 and further zero value is the first available channel.
// 	Channel uint8

// 	raw RawSockaddrRFCOMM
// }

// func (sa *SockaddrRFCOMM) sockaddr() (unsafe.Pointer, int32, error) {
// 	sa.raw.Family = 32
// 	sa.raw.Channel = sa.Channel
// 	sa.raw.Bdaddr = sa.Addr
// 	return unsafe.Pointer(&sa.raw), int32(unsafe.Sizeof(sa.raw)), nil
// }

type SockaddrBth struct {
	family         uint16
	BtAddr         [6]byte
	ServiceClassId windows.GUID
	Port           uint64
}

func (sa *SockaddrBth) sockaddr() (unsafe.Pointer, int32, error) {
	// if sa.Port < 0 || sa.Port > 31 {
	// 	return nil, 0, windows.EINVAL
	// }
	sa.family = 32
	p := (*[2]byte)(unsafe.Pointer(&sa.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	fmt.Println(" --- SizeOf: ", unsafe.Sizeof(*sa))
	fmt.Println(" --- SizeOf int32: ", int32(unsafe.Sizeof(*sa)))
	return unsafe.Pointer(sa), int32(unsafe.Sizeof(*sa)), nil
}

func Bluetooth(addr string) (CommunicationDescriptor, error) {
	var d syscall.WSAData
	e := syscall.WSAStartup(uint32(0x202), &d)
	if e != nil {
		logging.Error("syscall.WSAStartup")
		return nil, e
	}

	fd, err := Socket(windows.AF_BTH, windows.SOCK_STREAM, windows.BTHPROTO_RFCOMM)
	if err != nil {
		logging.Error("windows.Socket")
		return nil, err
	}

	// fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_STREAM, unix.BTPROTO_RFCOMM)
	// if err != nil {
	// 	return nil, err
	// }
	//logging.Debug("unix socket returned a file descriptor: ", fd)
	g, err := windows.GUIDFromString("{49535343-FE7D-4AE5-8FA9-9FAFD205E455}")
	if err != nil {
		logging.Error("windows.GUIDFromString")
		return nil, err
	}
	s := SockaddrBth{
		BtAddr:         str2ba(addr),
		ServiceClassId: g,
		// Port:           6,
	}
	if err := Connect(fd, s); err != nil {
		logging.Error("Connect")
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

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
/// COPY
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

func Connect(fd windows.Handle, sa SockaddrBth) (err error) {
	ptr, n, err := sa.sockaddr()
	if err != nil {
		return err
	}
	return connect(fd, ptr, n)
}

const socket_error = uintptr(^uint32(0))

var (
	modws2_32   = windows.NewLazySystemDLL("ws2_32.dll")
	procconnect = modws2_32.NewProc("connect")
	procsocket  = modws2_32.NewProc("socket")
)

func connect(s windows.Handle, name unsafe.Pointer, namelen int32) (err error) {
	fmt.Println(procconnect.Addr())
	fmt.Println(procconnect.Name)
	//r1, _, e1 := syscall.Syscall(procconnect.Addr(), 3, uintptr(s), uintptr(name), uintptr(namelen))
	r1, _, e1 := procconnect.Call(uintptr(s), uintptr(name), uintptr(namelen))
	//r1, _, e1 := syscall.SyscallN(procconnect.Addr(), 3, uintptr(s), uintptr(name), uintptr(namelen))
	if r1 == socket_error {
		logging.Error(" syscall.Syscall")
		err = e1
	}
	return
}

const (
	errnoERROR_IO_PENDING = 997

	InvalidHandle = ^windows.Handle(0)
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall.EINVAL
)

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	return e
}

func Socket(domain, typ, proto int) (fd windows.Handle, err error) {
	// if domain == AF_INET6 && SocketDisableIPv6 {
	// 	return InvalidHandle, syscall.EAFNOSUPPORT
	// }
	return socket(int32(domain), int32(typ), int32(proto))
}

func socket(af int32, typ int32, protocol int32) (handle windows.Handle, err error) {
	r0, _, e1 := procsocket.Call(uintptr(af), uintptr(typ), uintptr(protocol))
	//r0, _, e1 := syscall.Syscall(procsocket.Addr(), 3, uintptr(af), uintptr(typ), uintptr(protocol))
	handle = windows.Handle(r0)
	if handle == InvalidHandle {
		logging.Error(e1)
	}
	return
}

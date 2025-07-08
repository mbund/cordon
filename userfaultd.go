package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"syscall"
	"unsafe"

	"github.com/loopholelabs/userfaultfd-go/pkg/constants"

	"golang.org/x/sys/unix"
)

// const constants.UFFDIO_API untyped int = 3222841919

const (
	UFFDIO_API = 3222841919
)

type UFFD uintptr

func Register(length int) ([]byte, UFFD, uintptr, error) {
	pagesize := os.Getpagesize()

	uffd, _, errno := syscall.Syscall(unix.SYS_USERFAULTFD, 0, 0, 0)
	if int(uffd) == -1 {
		return []byte{}, 0, 0, fmt.Errorf("%v", errno)
	}

	uffdioAPI := constants.NewUffdioAPI(
		constants.UFFD_API,
		0,
	)

	if _, _, errno = syscall.Syscall(
		syscall.SYS_IOCTL,
		uffd,
		constants.UFFDIO_API,
		uintptr(unsafe.Pointer(&uffdioAPI)),
	); errno != 0 {
		return []byte{}, 0, 0, fmt.Errorf("%v", errno)
	}

	l := int(math.Ceil(float64(length)/float64(pagesize)) * float64(pagesize))
	b, err := syscall.Mmap(
		-1,
		0,
		l,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS,
	)
	if err != nil {
		return []byte{}, 0, 0, fmt.Errorf("%v", errno)
	}

	// b[2] = 0x41

	start := uintptr(unsafe.Pointer(&b[0]))

	uffdioRegister := constants.NewUffdioRegister(
		constants.CULong(start),
		constants.CULong(l),
		constants.UFFDIO_REGISTER_MODE_MISSING,
	)

	if _, _, errno = syscall.Syscall(
		syscall.SYS_IOCTL,
		uffd,
		constants.UFFDIO_REGISTER,
		uintptr(unsafe.Pointer(&uffdioRegister)),
	); errno != 0 {
		return []byte{}, 0, 0, fmt.Errorf("%v", errno)
	}

	return b[:length], UFFD(uffd), start, nil
}

var (
	ErrUnexpectedEventType = errors.New("unexpected event type")
)

func Handle(uffd UFFD, start uintptr, src io.ReaderAt) error {
	pagesize := os.Getpagesize()

	for {
		if _, err := unix.Poll(
			[]unix.PollFd{{
				Fd:     int32(uffd),
				Events: unix.POLLIN,
			}},
			-1,
		); err != nil {
			return err
		}

		buf := make([]byte, unsafe.Sizeof(constants.UffdMsg{}))
		if _, err := syscall.Read(int(uffd), buf); err != nil {
			return err
		}

		msg := (*(*constants.UffdMsg)(unsafe.Pointer(&buf[0])))
		if constants.GetMsgEvent(&msg) != constants.UFFD_EVENT_PAGEFAULT {
			return ErrUnexpectedEventType
		}

		arg := constants.GetMsgArg(&msg)
		pagefault := (*(*constants.UffdPagefault)(unsafe.Pointer(&arg[0])))

		addr := constants.GetPagefaultAddress(&pagefault)

		p := make([]byte, pagesize)
		if n, err := src.ReadAt(p, int64(uintptr(addr)-start)); err != nil {
			// We always read full pages; the last read can thus `EOF` if the file isn't an exact multiple of `pagesize`
			if !(errors.Is(err, io.EOF) && n != 0) {
				return err
			}
		}

		cpy := constants.NewUffdioCopy(
			p,
			addr&^constants.CULong(pagesize-1),
			constants.CULong(pagesize),
			0,
			0,
		)

		log.Println("Resolving page fault")

		if _, _, errno := syscall.Syscall(
			syscall.SYS_IOCTL,
			uintptr(uffd),
			constants.UFFDIO_COPY,
			uintptr(unsafe.Pointer(&cpy)),
		); errno != 0 {
			return fmt.Errorf("%v", errno)
		}
	}
}

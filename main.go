package main

import (
	"bytes"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type abcReader struct{}

func (a abcReader) ReadAt(p []byte, off int64) (n int, err error) {
	log.Println("Reading at offset", off)

	n = copy(p, bytes.Repeat([]byte{'A' + byte(off%20)}, len(p)))

	return n, nil
}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Attach count_packets to the network interface.
	link, err := link.AttachLSM(link.LSMOptions{
		Program: objs.RestrictConnect,
	})
	if err != nil {
		log.Fatal("Attaching LSM:", err)
	}
	defer link.Close()

	b, uffd, start, err := Register(4096)
	if err != nil {
		log.Fatal("Registering userfaultfd:", err)
	}
	log.Printf("Registered userfaultfd at %#x", start)

	err = objs.UserPtr.Set(uint64(start))
	if err != nil {
		log.Fatal("Setting user pointer in map: ", err)
	}

	err = objs.Pid.Set(uint32(os.Getpid()))
	if err != nil {
		log.Fatal("Setting PID in map: ", err)
	}

	_ = b

	go func() {
		for {
			if err := Handle(uffd, start, abcReader{}); err != nil {
				log.Fatal("Handling userfaultfd:", err)
			}
		}
	}()

	// go func() {
	// 	time.Sleep(2 * time.Second)
	// 	log.Printf("reading from userfaultfd: %d", b[0])
	// 	// b[0] = 0x43
	// }()

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	// tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		// case <-tick:
		// var count uint64
		// err := objs.PktCount.Lookup(uint32(0), &count)
		// if err != nil {
		// 	log.Fatal("Map lookup:", err)
		// }
		// log.Printf("Received %d packets", count)
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}

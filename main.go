package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
)

func main() {
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	link1, err := link.AttachLSM(link.LSMOptions{
		Program: objs.RestrictConnect,
	})
	if err != nil {
		log.Fatal("Attaching LSM:", err)
	}
	defer link1.Close()

	// err = objs.Pid.Set(uint32(os.Getpid()))
	err = objs.Pid.Set(uint32(2563492))
	if err != nil {
		log.Fatal("Setting PID in map: ", err)
	}

	// serve()

	log.Print("running...")

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}

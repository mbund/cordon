package main

import (
	"flag"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf/link"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/mbund/cordon/objs"
)

const runtimeDirectory = "/var/run/cordon"
const backingDirectory = runtimeDirectory + "/backing"
const backingExe = backingDirectory + "/cordon"
const fuseDirectory = runtimeDirectory + "/fuse"
const fuseExe = fuseDirectory + "/cordon"

func mustMkdirRoot(path string) {
	if err := os.MkdirAll(path, 0700); err != nil {
		slog.Error("Failed to create directory", "path", path, "err", err)
		os.Exit(1)
	}
	if err := os.Chown(path, 0, 0); err != nil {
		slog.Error("Failed to set ownership of directory", "path", path, "err", err)
		os.Exit(1)
	}
}

func main() {
	isDaemon := flag.Bool("daemon", false, "Run as a daemon")
	isSleeper := flag.Bool("sleeper", false, "Run as a sleeper")
	flag.Parse()
	if *isDaemon {
		os.Exit(daemon())
	}
	if *isSleeper {
		sleeper()
		return
	}

	slog.Info("No parameters")
}

func sleeper() {
	slog.Info("Starting cordon sleeper", "pid", os.Getpid())
	select {}
}

var bpfObjs objs.BpfObjects

func daemon() int {
	slog.Info("Starting cordon daemon")

	err := unix.Unmount(fuseDirectory, 0)
	if err == nil {
		slog.Warn("Unmounted existing FUSE mount", "path", fuseDirectory)
	}

	if errno, ok := err.(syscall.Errno); ok {
		switch errno {
		case syscall.EINVAL:
			slog.Debug("Preflight check succeeded, mount not busy", "path", fuseDirectory)
		case syscall.EBUSY:
			slog.Error("FUSE mount is busy", "path", fuseDirectory)
			return 1
		default:
			slog.Error("Unknown error in FUSE mount", "err", err, "path", fuseDirectory)
			return 1
		}
	}

	slog.Info("Creating directories")

	mustMkdirRoot(runtimeDirectory)
	mustMkdirRoot(backingDirectory)
	mustMkdirRoot(fuseDirectory)

	exe, err := os.Executable()
	if err != nil {
		slog.Error("Failed to get executable path", "err", err)
		return 1
	}
	slog.Info("Got self exe", "path", exe)

	slog.Info("Copying self exe", "from", exe, "to", backingExe)
	exeData, err := os.ReadFile(exe)
	if err != nil {
		slog.Error("Failed to read executable file", "path", exe, "err", err)
		return 1
	}

	if err := os.WriteFile(backingExe, exeData, 0700); err != nil {
		slog.Error("Failed to write executable file", "path", backingExe, "err", err)
		return 1
	}

	if err := os.Chmod(backingExe, 0700); err != nil {
		slog.Error("Failed to set permissions on executable file", "path", backingExe,
			"err", err)
		return 1
	}

	slog.Info("Creating FUSE", "path", fuseDirectory)

	root := &ExecFS{
		backingDir: backingDirectory,
	}

	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			DirectMount: true,
			AllowOther:  true,
			Name:        "execfs",
		},
	}

	server, err := fs.Mount(fuseDirectory, root, opts)
	if err != nil {
		slog.Error("Failed to mount FUSE", "err", err)
		return 1
	}

	defer func() {
		ms := 200
		var err error
		for {
			err = server.Unmount()
			ms *= 2
			if err == nil || ms > 5000 {
				break
			}
			slog.Warn("Did not unmount FUSE, retrying", "after_ms", ms)
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}

		if err != nil {
			slog.Error("Failed to unmount FUSE", "err", err)
		} else {
			slog.Info("Unmounted FUSE", "path", fuseDirectory)
		}
	}()

	slog.Info("Starting cordon sleeper", "path", fuseExe)
	sleeper := exec.Command(fuseExe, "--sleeper")
	if err := sleeper.Start(); err != nil {
		slog.Error("Failed to start sleeper process", "path", fuseExe, "err", err)
		return 1
	}
	slog.Info("Started sleeper process", "pid", sleeper.Process.Pid)
	defer func() {
		if err := sleeper.Process.Kill(); err != nil {
			slog.Error("Failed to kill sleeper process", "pid", sleeper.Process.Pid,
				"err", err)
		} else {
			slog.Info("Killed sleeper process", "pid", sleeper.Process.Pid)
		}
	}()

	if err := objs.LoadBpfObjects(&bpfObjs, nil); err != nil {
		slog.Error("Failed to load eBPF objects", "err", err)
		return 1
	}
	defer bpfObjs.Close()

	err = bpfObjs.Pid.Set(uint32(sleeper.Process.Pid))
	if err != nil {
		slog.Error("Failed to set PID in eBPF map", "pid", sleeper.Process.Pid, "err", err)
		return 1
	}

	link1, err := link.AttachLSM(link.LSMOptions{
		Program: bpfObjs.RestrictConnect,
	})
	if err != nil {
		slog.Error("Failed to attach LSM program", "err", err)
		return 1
	}
	defer link1.Close()

	slog.Info("Running...")

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-stop:
			slog.Info("Received signal, exiting..")
			return 0
		}
	}
}

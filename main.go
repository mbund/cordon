package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/creack/pty"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/mbund/cordon/objs"
)

const runtimeBaseDirectory = "/var/run/cordon"

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
	isSleeper := flag.Bool("sleeper", false, "Run as a sleeper")
	flag.Parse()
	if *isSleeper {
		sleeper()
		return
	}

	os.Exit(cli())
}

func sleeper() {
	slog.Info("Starting cordon sleeper", "pid", os.Getpid())
	select {}
}

var bpfObjs objs.BpfObjects

func cli() int {
	slog.Info("Starting cordon")

	originalUID := syscall.Getuid()
	originalGID := syscall.Getgid()

	if syscall.Geteuid() != 0 {
		slog.Error("This program must be setuid root")
		os.Exit(1)
	}

	dm := NewDNSManager()
	dm.StartListeners()
	defer dm.Close()

	go func() {
		time.Sleep(5 * time.Second)
		domain := dm.ReverseLookup(net.ParseIP("142.251.33.78"))
		slog.Info("found", "domain", domain)
	}()

	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		slog.Error("Failed to generate random id")
		return 1
	}
	id := hex.EncodeToString(bytes)
	slog.Info("generated", "id", id)

	backingDirectory := fmt.Sprintf("%s/%s/backing", runtimeBaseDirectory, id)
	backingExe := fmt.Sprintf("%s/cordon", backingDirectory)
	fuseDirectory := fmt.Sprintf("%s/%s/fuse", runtimeBaseDirectory, id)
	fuseExe := fmt.Sprintf("%s/cordon", fuseDirectory)

	mustMkdirRoot(backingDirectory)
	mustMkdirRoot(fuseDirectory)

	defer os.RemoveAll(fmt.Sprintf("%s/%s", runtimeBaseDirectory, id))

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
		slog.Error("Failed to set PID in eBPF", "pid", sleeper.Process.Pid, "err", err)
		return 1
	}

	cgroupPath := fmt.Sprintf("/sys/fs/cgroup/cordon/%s", id)
	if err := os.MkdirAll(cgroupPath, 0700); err != nil {
		slog.Error("Failed to create cgroupv2", "path", cgroupPath, "err", err)
		return 1
	}

	cgroupFile, err := os.Open(cgroupPath)
	if err != nil {
		slog.Error("Failed to open cgroup", "path", cgroupPath, "err", err)
		return 1
	}

	var stat unix.Stat_t
	if err := unix.Stat(cgroupPath, &stat); err != nil {
		slog.Error("Failed to stat cgroup", "path", cgroupPath, "err", err)
		return 1
	}
	cgroupId := stat.Ino
	slog.Info("cgroup", "ino", cgroupId)

	err = bpfObjs.TargetCgroup.Set(cgroupId)
	if err != nil {
		slog.Error("Failed to set target cgroup", "path", cgroupPath, "ino", cgroupId, "err", err)
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

	link2, err := link.AttachLSM(link.LSMOptions{
		Program: bpfObjs.FileOpen,
	})
	if err != nil {
		slog.Error("Failed to attach LSM program", "err", err)
		return 1
	}
	defer link2.Close()

	link3, err := link.AttachLSM(link.LSMOptions{
		Program: bpfObjs.SocketBind,
	})
	if err != nil {
		slog.Error("Failed to attach LSM program", "err", err)
		return 1
	}
	defer link3.Close()

	link4, err := link.AttachLSM(link.LSMOptions{
		Program: bpfObjs.BprmCheckSecurity,
	})
	if err != nil {
		slog.Error("Failed to attach LSM program", "err", err)
		return 1
	}
	defer link4.Close()

	link5, err := link.AttachTracing(link.TracingOptions{
		Program:    bpfObjs.X64SysSetuid,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		slog.Error("Failed to attach tracing program", "err", err)
		return 1
	}
	defer link5.Close()

	link6, err := link.AttachLSM(link.LSMOptions{
		Program: bpfObjs.CredPrepare,
	})
	if err != nil {
		slog.Error("Failed to attach LSM program", "err", err)
		return 1
	}
	defer link6.Close()

	cwd, err := os.Getwd()
	if err != nil {
		slog.Error("Failed to get cwd", "err", err)
		return 1
	}

	childExe, err := exec.LookPath(os.Args[1])
	if err != nil {
		slog.Error("Failed to look up path", "exe", os.Args[1])
		return 1
	}

	ptyMaster, ptySlave, err := pty.Open()
	if err != nil {
		slog.Error("Failed to open pty", "err", err)
		return 1
	}
	defer ptyMaster.Close()
	defer ptySlave.Close()

	slog.Info("Running...")

	childPid, err := syscall.ForkExec(childExe, os.Args[1:], &syscall.ProcAttr{
		Dir:   cwd,
		Env:   os.Environ(),
		Files: []uintptr{ptySlave.Fd(), ptySlave.Fd(), ptySlave.Fd()},
		Sys: &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: uint32(originalUID),
				Gid: uint32(originalGID),
			},
			Setsid:      true,
			Setctty:     true,
			Ctty:        0,
			UseCgroupFD: true,
			CgroupFD:    int(cgroupFile.Fd()),
		},
	})
	if err != nil {
		slog.Error("Failed to fork exec", "err", err)
		return 1
	}
	slog.Info("Started process", "pid", childPid)

	ptySlave.Close()

	go func() {
		_, _ = io.Copy(os.Stdout, ptyMaster)
	}()
	go func() {
		_, _ = io.Copy(ptyMaster, os.Stdin)
	}()

	stop := make(chan os.Signal, 1)

	go func() {
		var waitStatus syscall.WaitStatus
		_, _ = syscall.Wait4(childPid, &waitStatus, 0, nil)
		stop <- os.Interrupt
	}()

	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-stop:
			slog.Info("Sending kill signal to cgroupv2", "path", cgroupPath)

			err = os.WriteFile(fmt.Sprintf("%s/cgroup.kill", cgroupPath), []byte{'1'}, os.FileMode(0))
			if err != nil {
				slog.Error("Failed to kill cgroupv2", "path", cgroupPath, "err", err)
				return 1
			}

			slog.Info("Deleting cgroupv2", "path", cgroupPath)

			start := time.Now()
			for {
				if err = os.Remove(cgroupPath); err == nil {
					break
				}

				if time.Now().After(start.Add(5 * time.Second)) {
					slog.Error("Failed to delete cgroupv2", "path", cgroupPath, "err", err)
					return 1
				}
			}

			return 0
		}
	}
}

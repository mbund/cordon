package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/creack/pty"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/mbund/cordon/objs"
)

const runtimeBaseDirectory = "/var/run/cordon"

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
var backingDirectory string
var fuseDirectory string

func cli() int {
	originalUID := syscall.Getuid()
	originalGID := syscall.Getgid()

	if syscall.Geteuid() != 0 {
		slog.Error("This program must be setuid root")
		os.Exit(1)
	}

	f, err := tea.LogToFile("debug.log", "debug")
	if err != nil {
		fmt.Println("fatal:", err)
		os.Exit(1)
	}
	defer f.Close()

	dm := NewDNSManager()
	dm.StartListeners()
	defer dm.Close()

	id, err := generateId()
	if err != nil {
		slog.Error("Failed to generate id", "err", err)
		return 1
	}
	slog.Info("generated", "id", id)

	if err := preflight(id); err != nil {
		slog.Error("Failed to pass preflight checks", "err", err)
		return 1
	}
	defer postflight(id)

	var (
		eg             errgroup.Group
		cgroupManager  *cgroupManager
		fuseManager    *fuseManager
		ebpfManager    *ebpfManager
		sleeperManager *sleeperManager
	)
	eg.Go(func() error {
		var eg errgroup.Group
		eg.Go(func() error {
			return copySelfExe()
		})
		eg.Go(func() error {
			var err error
			fuseManager, err = NewFUSEManager()
			return err
		})

		var err error
		if err = eg.Wait(); err != nil {
			return err
		}

		sleeperManager, err = NewSleeperManager()
		return err
	})
	eg.Go(func() error {
		var err error
		cgroupManager, err = newCgroupv2(id)
		return err
	})

	eg.Go(func() error {
		var err error
		ebpfManager, err = NewEbpfManager()
		return err
	})

	defer func() {
		ebpfManager.Close()
		sleeperManager.Close()
		cgroupManager.Close()
		fuseManager.Close()
	}()

	if err := eg.Wait(); err != nil {
		slog.Error("Failed to start", "err", err)
		return 1
	}

	if err := ebpfManager.SetTargetCgroup(cgroupManager.Id()); err != nil {
		slog.Error("Failed to set target cgroup", "err", err)
		return 1
	}

	if err := ebpfManager.SetSleeperPid(uint32(sleeperManager.Pid())); err != nil {
		slog.Error("Failed to set sleeper pid", "err", err)
		return 1
	}

	childManager, err := NewChildManager(os.Args[1:], originalUID, originalGID, int(cgroupManager.Fd()))
	if err != nil {
		slog.Error("Failed to create child manager", "err", err)
		return 1
	}
	defer childManager.Close()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	select {
	case <-interrupt:
		slog.Info("Received interrupt signal, killing child process")
		return 2
	case code := <-childManager.exited:
		slog.Info("Child process exited", "pid", childManager.childPid, "code", code)
		return code
	}
}

func generateId() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %v", err)
	}
	id := hex.EncodeToString(bytes)
	return id, nil
}

func preflight(id string) error {
	backingDirectory = fmt.Sprintf("%s/%s/backing", runtimeBaseDirectory, id)
	if err := os.MkdirAll(backingDirectory, 0700); err != nil {
		return fmt.Errorf("failed to create backing directory: %v", err)
	}
	if err := os.Chown(backingDirectory, 0, 0); err != nil {
		return fmt.Errorf("failed to set ownership of backing directory: %v", err)
	}

	fuseDirectory = fmt.Sprintf("%s/%s/fuse", runtimeBaseDirectory, id)
	if err := os.MkdirAll(fuseDirectory, 0700); err != nil {
		return fmt.Errorf("failed to create fuse directory: %v", err)
	}
	if err := os.Chown(fuseDirectory, 0, 0); err != nil {
		return fmt.Errorf("failed to set ownership of fuse directory: %v", err)
	}

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
			return fmt.Errorf("fuse mount is busy: %v", err)
		default:
			slog.Error("Unknown error in FUSE mount", "err", err, "path", fuseDirectory)
			return fmt.Errorf("unknown error in FUSE mount: %v", err)
		}
	}

	return nil
}

func postflight(id string) error {
	return os.RemoveAll(fmt.Sprintf("%s/%s", runtimeBaseDirectory, id))
}

// cleanup is implicit from postflight
func copySelfExe() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	backingExe := fmt.Sprintf("%s/cordon", backingDirectory)

	slog.Info("Copying self exe", "from", exe, "to", backingExe)

	exeData, err := os.ReadFile(exe)
	if err != nil {
		return fmt.Errorf("failed to read executable file: %v", err)
	}

	if err := os.WriteFile(backingExe, exeData, 0700); err != nil {
		return fmt.Errorf("failed to write executable file: %v", err)
	}

	return nil
}

type fuseManager struct {
	server *fuse.Server
}

func NewFUSEManager() (*fuseManager, error) {
	slog.Info("New FUSE manager", "backingDirectory", backingDirectory, "fuseDirectory", fuseDirectory)
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
		return nil, fmt.Errorf("failed to mount FUSE: %v", err)
	}

	return &fuseManager{
		server: server,
	}, nil
}

func (fm *fuseManager) Close() error {
	if fm == nil || fm.server == nil {
		return nil
	}

	ms := 200
	var err error
	for {
		err = fm.server.Unmount()
		ms *= 2
		if err == nil || ms > 5000 {
			break
		}
		slog.Warn("Did not unmount FUSE, retrying", "after_ms", ms)
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}

	if err != nil {
		slog.Error("Failed to unmount FUSE", "err", err)
		return err
	} else {
		slog.Info("Unmounted FUSE", "path", fuseDirectory)
	}

	return nil
}

type sleeperManager struct {
	sleeper *exec.Cmd
}

func NewSleeperManager() (*sleeperManager, error) {
	fuseExe := fmt.Sprintf("%s/cordon", fuseDirectory)
	sleeper := exec.Command(fuseExe, "--sleeper")
	if err := sleeper.Start(); err != nil {
		return nil, fmt.Errorf("failed to start sleeper process: %v", err)
	}

	slog.Info("Started sleeper process", "pid", sleeper.Process.Pid)

	return &sleeperManager{
		sleeper: sleeper,
	}, nil
}

func (sm *sleeperManager) Close() error {
	if sm == nil || sm.sleeper == nil {
		return nil
	}

	if err := sm.sleeper.Process.Kill(); err != nil {
		slog.Error("Failed to kill sleeper process", "pid", sm.sleeper.Process.Pid, "err", err)
		return err
	}
	slog.Info("Killed sleeper process", "pid", sm.sleeper.Process.Pid)
	return nil
}

func (sm *sleeperManager) Pid() int {
	return sm.sleeper.Process.Pid
}

type cgroupManager struct {
	id   uint64
	path string
	file *os.File
}

func newCgroupv2(id string) (*cgroupManager, error) {
	cgroupPath := fmt.Sprintf("/sys/fs/cgroup/cordon/%s", id)
	if err := os.MkdirAll(cgroupPath, 0700); err != nil {
		slog.Error("Failed to create cgroupv2", "path", cgroupPath, "err", err)
		return nil, fmt.Errorf("failed to create cgroupv2: %v", err)
	}

	cgroupFile, err := os.Open(cgroupPath)
	if err != nil {
		slog.Error("Failed to open cgroup", "path", cgroupPath, "err", err)
		return nil, fmt.Errorf("failed to open cgroup: %v", err)
	}

	var stat unix.Stat_t
	if err := unix.Stat(cgroupPath, &stat); err != nil {
		slog.Error("Failed to stat cgroup", "path", cgroupPath, "err", err)
		return nil, fmt.Errorf("failed to stat cgroup: %v", err)
	}
	cgroupId := stat.Ino
	slog.Info("created cgroup", "ino", cgroupId)

	return &cgroupManager{
		id:   cgroupId,
		path: cgroupPath,
		file: cgroupFile,
	}, nil
}

func (c *cgroupManager) Close() error {
	if c == nil || c.file == nil {
		return nil
	}

	if err := c.file.Close(); err != nil {
		slog.Error("Failed to close cgroup", "path", c.path, "err", err)
		return err
	}

	slog.Debug("Sending kill signal to cgroupv2", "path", c.path)

	err := os.WriteFile(fmt.Sprintf("%s/cgroup.kill", c.path), []byte{'1'}, os.FileMode(0))
	if err != nil {
		slog.Error("Failed to kill cgroupv2", "path", c.path, "err", err)
		return err
	}

	start := time.Now()
	for {
		if err = os.Remove(c.path); err == nil {
			break
		}

		if time.Now().After(start.Add(5 * time.Second)) {
			slog.Error("Failed to delete cgroupv2", "path", c.path, "err", err)
			return err
		}
	}

	slog.Info("Deleted cgroupv2", "path", c.path)

	return nil
}

func (c *cgroupManager) Fd() uintptr {
	return c.file.Fd()
}

func (c *cgroupManager) Id() uint64 {
	return c.id
}

type ebpfManager struct {
	restrictConnect   link.Link
	fileOpen          link.Link
	socketBind        link.Link
	bprmCheckSecurity link.Link
	x64SysSetuid      link.Link
	credPrepare       link.Link
}

func NewEbpfManager() (*ebpfManager, error) {
	if err := objs.LoadBpfObjects(&bpfObjs, nil); err != nil {
		slog.Error("Failed to load eBPF objects", "err", err)
		return nil, fmt.Errorf("failed to load eBPF objects: %v", err)
	}

	var (
		em       = &ebpfManager{}
		errgroup errgroup.Group
	)

	errgroup.Go(func() error {
		link, err := link.AttachLSM(link.LSMOptions{
			Program: bpfObjs.RestrictConnect,
		})
		em.restrictConnect = link
		return err
	})

	errgroup.Go(func() error {
		link, err := link.AttachLSM(link.LSMOptions{
			Program: bpfObjs.FileOpen,
		})
		em.fileOpen = link
		return err
	})

	errgroup.Go(func() error {
		link, err := link.AttachLSM(link.LSMOptions{
			Program: bpfObjs.SocketBind,
		})
		em.socketBind = link
		return err
	})

	errgroup.Go(func() error {
		link, err := link.AttachLSM(link.LSMOptions{
			Program: bpfObjs.BprmCheckSecurity,
		})
		em.bprmCheckSecurity = link
		return err
	})

	errgroup.Go(func() error {
		link, err := link.AttachTracing(link.TracingOptions{
			Program:    bpfObjs.X64SysSetuid,
			AttachType: ebpf.AttachTraceFEntry,
		})
		em.x64SysSetuid = link
		return err
	})

	errgroup.Go(func() error {
		link, err := link.AttachLSM(link.LSMOptions{
			Program: bpfObjs.CredPrepare,
		})
		em.credPrepare = link
		return err
	})

	if err := errgroup.Wait(); err != nil {
		return nil, fmt.Errorf("failed to attach eBPF program: %v", err)
	}

	return em, nil
}

func (em *ebpfManager) Close() error {
	if em == nil {
		return nil
	}

	var errgroup errgroup.Group

	errgroup.Go(func() error {
		if em.restrictConnect != nil {
			return em.restrictConnect.Close()
		}
		return nil
	})

	errgroup.Go(func() error {
		if em.fileOpen != nil {
			return em.fileOpen.Close()
		}
		return nil
	})

	errgroup.Go(func() error {
		if em.socketBind != nil {
			return em.socketBind.Close()
		}
		return nil
	})

	errgroup.Go(func() error {
		if em.bprmCheckSecurity != nil {
			return em.bprmCheckSecurity.Close()
		}
		return nil
	})

	errgroup.Go(func() error {
		if em.x64SysSetuid != nil {
			return em.x64SysSetuid.Close()
		}
		return nil
	})

	errgroup.Go(func() error {
		if em.credPrepare != nil {
			return em.credPrepare.Close()
		}
		return nil
	})

	if err := errgroup.Wait(); err != nil {
		return fmt.Errorf("failed to close eBPF programs: %v", err)
	}

	if err := bpfObjs.Close(); err != nil {
		return fmt.Errorf("failed to close eBPF objects: %v", err)
	}

	return nil
}

func (em *ebpfManager) SetTargetCgroup(cgroupId uint64) error {
	if err := bpfObjs.TargetCgroup.Set(cgroupId); err != nil {
		return fmt.Errorf("failed to set target cgroup: %v", err)
	}

	return nil
}

func (em *ebpfManager) SetSleeperPid(pid uint32) error {
	if err := bpfObjs.Pid.Set(pid); err != nil {
		return fmt.Errorf("failed to set target pid: %v", err)
	}

	return nil
}

type childManager struct {
	childPid int
	pty      *os.File
	exited   chan int

	inAltBuffer atomic.Bool
	inDialog    atomic.Bool
	oldState    *term.State
}

func NewChildManager(args []string, originalUID, originalGID, cgroupFD int) (*childManager, error) {
	cm := &childManager{}

	ptyMaster, ptySlave, err := pty.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open pty: %v", err)
	}
	defer ptySlave.Close()
	cm.pty = ptyMaster

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get cwd: %v", err)
	}

	childExe, err := exec.LookPath(args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to look up path: %v", err)
	}

	childPid, err := syscall.ForkExec(childExe, args, &syscall.ProcAttr{
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
			CgroupFD:    cgroupFD,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fork exec: %v", err)
	}
	cm.childPid = childPid

	cm.pty = ptyMaster
	cm.setupTty()

	cm.exited = make(chan int, 1)
	go func() {
		var waitStatus syscall.WaitStatus
		_, _ = syscall.Wait4(childPid, &waitStatus, 0, nil)
		cm.exited <- waitStatus.ExitStatus()
	}()

	return cm, nil
}

func (cm *childManager) Close() error {
	if cm == nil || cm.pty == nil {
		return nil
	}

	cm.pty.Close()

	stdinFd := int(os.Stdin.Fd())
	if err := term.Restore(stdinFd, cm.oldState); err != nil {
		return fmt.Errorf("failed to restore terminal state: %v", err)
	}
	if err := unix.SetNonblock(stdinFd, false); err != nil {
		return fmt.Errorf("failed to set non-blocking stdin: %v", err)
	}

	return nil
}

var showDialogChan = make(chan struct{})
var closeDialogChan = make(chan struct{})

func (cm *childManager) setupTty() error {
	width, height, err := getTerminalSize()
	if err != nil {
		return fmt.Errorf("failed to get terminal size: %v", err)
	}

	if err := setPtySize(cm.pty, width, height); err != nil {
		return fmt.Errorf("failed to set initial PTY size: %v", err)
	}

	stdinFd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return fmt.Errorf("failed to set raw mode: %v", err)
	}
	cm.oldState = oldState

	if err := unix.SetNonblock(stdinFd, true); err != nil {
		return fmt.Errorf("failed to set non-blocking stdin: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	go func() {
		for range sigCh {
			if !cm.inDialog.Load() {
				width, height, err := getTerminalSize()
				if err == nil {
					setPtySize(cm.pty, width, height)
				}
			}
		}
	}()

	go func() {
		pollFd := []unix.PollFd{{Fd: int32(stdinFd), Events: unix.POLLIN}}
		buf := make([]byte, 1024)

		for {
			_, err := unix.Poll(pollFd, -1)
			if err != nil {
				continue
			}

			if cm.inDialog.Load() {
				continue
			}

			n, err := unix.Read(stdinFd, buf)
			if err == nil && n > 0 {
				data := buf[:n]
				dataStr := string(data)
				if strings.Contains(dataStr, "\x1b[?1049h") {
					cm.inAltBuffer.Store(true)
				} else if strings.Contains(dataStr, "\x1b[?1049l") {
					cm.inAltBuffer.Store(false)
				}

				cm.pty.Write(data)
			}
		}
	}()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := cm.pty.Read(buf)
			if err != nil {
				break
			}
			if n > 0 {
				data := buf[:n]
				dataStr := string(data)
				if strings.Contains(dataStr, "\x1b[?1049h") {
					cm.inAltBuffer.Store(true)
				} else if strings.Contains(dataStr, "\x1b[?1049l") {
					cm.inAltBuffer.Store(false)
				}

				os.Stdout.Write(data)
			}
		}
	}()

	go func() {
		for range showDialogChan {
			cm.inDialog.Store(true)

			wasInAltBuffer := cm.inAltBuffer.Load()

			if wasInAltBuffer {
				fmt.Print("\x1b[?1049l")
			}

			fmt.Print("\x1b7")

			m, err := tea.NewProgram(model{}).Run()
			if err != nil {
				slog.Error("Failed to run bubbletea program", "err", err)
				continue
			}

			fmt.Printf("\x1b[%dF\x1b[0J", strings.Count(m.View(), "\n"))

			fmt.Print("\x1b8")

			if wasInAltBuffer {
				fmt.Print("\x1b[?1049h")
				fmt.Fprint(cm.pty, "\x0c")
			}

			cm.inDialog.Store(false)
			closeDialogChan <- struct{}{}
		}
	}()

	return nil
}

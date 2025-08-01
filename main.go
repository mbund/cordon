package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
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

const (
	runtimeBaseDirectory = "/var/run/cordon"
	backingDir           = "backing"
	fuseDir              = "fuse"
)

var (
	cgroupManager     *CgroupManager
	fuseManager       *FUSEManager
	ebpfManager       *EBPFManager
	sleeperManager    *SleeperManager
	subprocessManager *SubprocessManager
	dnsManager        *DNSManager
	ttyManager        *TTYManager
)

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

	dnsManager = NewDNSManager()
	dnsManager.StartListeners()
	defer dnsManager.Close()

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

	var eg errgroup.Group
	eg.Go(func() error {
		var eg errgroup.Group
		eg.Go(func() error {
			return copySelfExe(id)
		})
		eg.Go(func() error {
			var err error
			fuseManager, err = NewFUSEManager(id)
			return err
		})

		var err error
		if err = eg.Wait(); err != nil {
			return err
		}

		sleeperManager, err = NewSleeperManager(id)
		return err
	})
	eg.Go(func() error {
		var err error
		cgroupManager, err = newCgroupManager(id)
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

	ebpfManager.bpfObjs.FilePolicyMap.Update(objs.BpfFileRequest{Path: stringToInt8Array("/nix/store/"), Accmode: unix.O_RDONLY}, true, ebpf.UpdateAny)
	ebpfManager.bpfObjs.FilePolicyMap.Update(objs.BpfFileRequest{Path: stringToInt8Array("/usr/lib64/"), Accmode: unix.O_RDONLY}, true, ebpf.UpdateAny)
	ebpfManager.bpfObjs.FilePolicyMap.Update(objs.BpfFileRequest{Path: stringToInt8Array("/dev/tty"), Accmode: unix.O_WRONLY}, true, ebpf.UpdateAny)
	ebpfManager.bpfObjs.FilePolicyMap.Update(objs.BpfFileRequest{Path: stringToInt8Array("/dev/tty"), Accmode: unix.O_RDONLY}, true, ebpf.UpdateAny)
	ebpfManager.bpfObjs.FilePolicyMap.Update(objs.BpfFileRequest{Path: stringToInt8Array("/dev/tty"), Accmode: unix.O_RDWR}, true, ebpf.UpdateAny)
	ebpfManager.bpfObjs.FilePolicyMap.Update(objs.BpfFileRequest{Path: stringToInt8Array("/dev/null"), Accmode: unix.O_RDONLY}, true, ebpf.UpdateAny)
	ebpfManager.bpfObjs.FilePolicyMap.Update(objs.BpfFileRequest{Path: stringToInt8Array("/dev/null"), Accmode: unix.O_WRONLY}, true, ebpf.UpdateAny)
	ebpfManager.bpfObjs.FilePolicyMap.Update(objs.BpfFileRequest{Path: stringToInt8Array("/dev/null"), Accmode: unix.O_RDWR}, true, ebpf.UpdateAny)

	ttyManager, err = NewTTYManager()
	if err != nil {
		slog.Error("Failed to create tty manager", "err", err)
		return 1
	}

	subprocessManager, err = NewSubprocessManager(os.Args[1:], originalUID, originalGID, int(cgroupManager.Fd()))
	if err != nil {
		slog.Error("Failed to create child manager", "err", err)
		return 1
	}
	defer subprocessManager.Close()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	select {
	case <-interrupt:
		slog.Info("Received interrupt signal, killing child process")
		return 2
	case code := <-subprocessManager.exited:
		slog.Info("Child process exited", "pid", subprocessManager.childPid, "code", code)
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
	backingDirectory := fmt.Sprintf("%s/%s/%s", runtimeBaseDirectory, id, backingDir)
	if err := os.MkdirAll(backingDirectory, 0700); err != nil {
		return fmt.Errorf("failed to create backing directory: %v", err)
	}
	if err := os.Chown(backingDirectory, 0, 0); err != nil {
		return fmt.Errorf("failed to set ownership of backing directory: %v", err)
	}

	fuseDirectory := fmt.Sprintf("%s/%s/%s", runtimeBaseDirectory, id, fuseDir)
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
func copySelfExe(id string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	backingExe := fmt.Sprintf("%s/%s/%s/cordon", runtimeBaseDirectory, id, backingDir)
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

type FUSEManager struct {
	server *fuse.Server
}

func NewFUSEManager(id string) (*FUSEManager, error) {
	backingDirectory := fmt.Sprintf("%s/%s/%s", runtimeBaseDirectory, id, backingDir)
	fuseDirectory := fmt.Sprintf("%s/%s/%s", runtimeBaseDirectory, id, fuseDir)
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

	return &FUSEManager{
		server: server,
	}, nil
}

func (fm *FUSEManager) Close() error {
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
		slog.Info("Unmounted FUSE")
	}

	return nil
}

type SleeperManager struct {
	sleeper *exec.Cmd
}

func NewSleeperManager(id string) (*SleeperManager, error) {
	fuseExe := fmt.Sprintf("%s/%s/%s/cordon", runtimeBaseDirectory, id, fuseDir)
	sleeper := exec.Command(fuseExe, "--sleeper")
	if err := sleeper.Start(); err != nil {
		return nil, fmt.Errorf("failed to start sleeper process: %v", err)
	}

	slog.Info("Started sleeper process", "pid", sleeper.Process.Pid)

	return &SleeperManager{
		sleeper: sleeper,
	}, nil
}

func (sm *SleeperManager) Close() error {
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

func (sm *SleeperManager) Pid() int {
	return sm.sleeper.Process.Pid
}

type CgroupManager struct {
	id             uint64
	path           string
	file           *os.File
	freezeRefcount atomic.Int64
}

func newCgroupManager(id string) (*CgroupManager, error) {
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

	return &CgroupManager{
		id:   cgroupId,
		path: cgroupPath,
		file: cgroupFile,
	}, nil
}

func (c *CgroupManager) Close() error {
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

func (c *CgroupManager) Freeze() error {
	v := c.freezeRefcount.Add(1)
	if v == 1 {
		slog.Info("Freezing cgroup", "path", c.path)
		return os.WriteFile(fmt.Sprintf("%s/cgroup.freeze", c.path), []byte{'1'}, os.FileMode(0))
	}
	return nil
}

func (c *CgroupManager) Thaw() error {
	v := c.freezeRefcount.Add(-1)
	if v == 0 {
		slog.Info("Thawing cgroup", "path", c.path)
		return os.WriteFile(fmt.Sprintf("%s/cgroup.freeze", c.path), []byte{'0'}, os.FileMode(0))
	}
	return nil
}

func (c *CgroupManager) Fd() uintptr {
	return c.file.Fd()
}

func (c *CgroupManager) Id() uint64 {
	return c.id
}

func (c *CgroupManager) SendSignal(signal syscall.Signal) error {
	procs, err := os.ReadFile(fmt.Sprintf("%s/cgroup.procs", c.path))
	if err != nil {
		return fmt.Errorf("failed to read cgroup.procs: %v", err)
	}

	for pid := range strings.SplitSeq(string(procs), "\n") {
		pidInt, err := strconv.Atoi(pid)
		if err != nil {
			continue
		}
		unix.Kill(pidInt, signal)
	}

	return nil
}

type EBPFManager struct {
	bpfObjs           objs.BpfObjects
	restrictConnect   link.Link
	fileOpen          link.Link
	socketBind        link.Link
	bprmCheckSecurity link.Link
	x64SysSetuid      link.Link
	credPrepare       link.Link
}

func NewEbpfManager() (*EBPFManager, error) {
	var (
		em       = &EBPFManager{}
		errgroup errgroup.Group
	)

	if err := objs.LoadBpfObjects(&em.bpfObjs, nil); err != nil {
		slog.Error("Failed to load eBPF objects", "err", err)
		return nil, fmt.Errorf("failed to load eBPF objects: %v", err)
	}

	errgroup.Go(func() error {
		link, err := link.AttachLSM(link.LSMOptions{
			Program: em.bpfObjs.RestrictConnect,
		})
		em.restrictConnect = link
		return err
	})

	errgroup.Go(func() error {
		link, err := link.AttachLSM(link.LSMOptions{
			Program: em.bpfObjs.FileOpen,
		})
		em.fileOpen = link
		return err
	})

	errgroup.Go(func() error {
		link, err := link.AttachLSM(link.LSMOptions{
			Program: em.bpfObjs.SocketBind,
		})
		em.socketBind = link
		return err
	})

	errgroup.Go(func() error {
		link, err := link.AttachLSM(link.LSMOptions{
			Program: em.bpfObjs.BprmCheckSecurity,
		})
		em.bprmCheckSecurity = link
		return err
	})

	errgroup.Go(func() error {
		link, err := link.AttachTracing(link.TracingOptions{
			Program:    em.bpfObjs.X64SysSetuid,
			AttachType: ebpf.AttachTraceFEntry,
		})
		em.x64SysSetuid = link
		return err
	})

	errgroup.Go(func() error {
		link, err := link.AttachLSM(link.LSMOptions{
			Program: em.bpfObjs.CredPrepare,
		})
		em.credPrepare = link
		return err
	})

	if err := errgroup.Wait(); err != nil {
		return nil, fmt.Errorf("failed to attach eBPF program: %v", err)
	}

	return em, nil
}

func (em *EBPFManager) Close() error {
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

	if err := em.bpfObjs.Close(); err != nil {
		return fmt.Errorf("failed to close eBPF objects: %v", err)
	}

	return nil
}

func (em *EBPFManager) SetTargetCgroup(cgroupId uint64) error {
	if err := em.bpfObjs.TargetCgroup.Set(cgroupId); err != nil {
		return fmt.Errorf("failed to set target cgroup: %v", err)
	}

	return nil
}

func (em *EBPFManager) SetSleeperPid(pid uint32) error {
	if err := em.bpfObjs.Pid.Set(pid); err != nil {
		return fmt.Errorf("failed to set target pid: %v", err)
	}

	return nil
}

type TTYManager struct {
	inAltBuffer atomic.Bool
	inDialog    atomic.Bool
	pty         *os.File

	interactive bool

	oldState  *term.State
	ptyMaster *os.File
	ptySlave  *os.File

	stdinR  *os.File
	stdoutW *os.File
	stderrW *os.File
}

func NewTTYManager() (*TTYManager, error) {
	tm := &TTYManager{}

	stdinFd := int(os.Stdin.Fd())
	isTerm := term.IsTerminal(stdinFd)
	tm.interactive = isTerm

	if isTerm {
		ptyMaster, ptySlave, err := pty.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open pty: %v", err)
		}
		tm.ptyMaster = ptyMaster
		tm.ptySlave = ptySlave
		tm.pty = ptyMaster

		width, height, err := getTerminalSize()
		if err != nil {
			return nil, fmt.Errorf("failed to get terminal size: %v", err)
		}

		if err := setPtySize(ptyMaster, width, height); err != nil {
			return nil, fmt.Errorf("failed to set initial PTY size: %v", err)
		}

		oldState, err := term.MakeRaw(stdinFd)
		if err != nil {
			return nil, fmt.Errorf("failed to set raw mode: %v", err)
		}
		tm.oldState = oldState

		if err := unix.SetNonblock(stdinFd, true); err != nil {
			return nil, fmt.Errorf("failed to set non-blocking stdin: %v", err)
		}

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGWINCH)
		go func() {
			for range sigCh {
				if !tm.inDialog.Load() {
					width, height, err := getTerminalSize()
					if err == nil {
						setPtySize(tm.pty, width, height)
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

				if tm.inDialog.Load() {
					continue
				}

				n, err := unix.Read(stdinFd, buf)
				if err == nil && n > 0 {
					data := buf[:n]
					dataStr := string(data)
					if strings.Contains(dataStr, "\x1b[?1049h") {
						tm.inAltBuffer.Store(true)
					} else if strings.Contains(dataStr, "\x1b[?1049l") {
						tm.inAltBuffer.Store(false)
					}

					tm.pty.Write(data)
				}
			}
		}()

		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := tm.pty.Read(buf)
				if err != nil {
					break
				}
				if n > 0 {
					data := buf[:n]
					dataStr := string(data)
					if strings.Contains(dataStr, "\x1b[?1049h") {
						tm.inAltBuffer.Store(true)
					} else if strings.Contains(dataStr, "\x1b[?1049l") {
						tm.inAltBuffer.Store(false)
					}

					os.Stdout.Write(data)
				}
			}
		}()
	} else {
		stdinR, stdinW, err := os.Pipe()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdin pipe: %v", err)
		}
		defer stdinR.Close()

		stdoutR, stdoutW, err := os.Pipe()
		if err != nil {
			stdinW.Close()
			return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
		}
		defer stdoutW.Close()

		stderrR, stderrW, err := os.Pipe()
		if err != nil {
			stdinW.Close()
			stdoutR.Close()
			return nil, fmt.Errorf("failed to create stderr pipe: %v", err)
		}
		defer stderrW.Close()

		tm.stdinR = stdinW
		tm.stdoutW = stdoutR
		tm.stderrW = stderrR

		go func() {
			io.Copy(os.Stdout, stdoutR)
			stdoutR.Close()
		}()
		go func() {
			io.Copy(os.Stderr, stderrR)
			stderrR.Close()
		}()
		go func() {
			io.Copy(stdinW, os.Stdin)
			stdinW.Close()
		}()
	}

	return tm, nil
}

func (tm *TTYManager) Files() []uintptr {
	if tm.interactive {
		return []uintptr{tm.ptySlave.Fd(), tm.ptySlave.Fd(), tm.ptySlave.Fd()}
	} else {
		return []uintptr{tm.stdinR.Fd(), tm.stdoutW.Fd(), tm.stderrW.Fd()}
	}
}

func (tm *TTYManager) IsInteractive() bool {
	return tm.interactive
}

func (tm *TTYManager) ShowDialog(m tea.Model) (tea.Model, error) {
	tm.inDialog.Store(true)

	wasInAltBuffer := tm.inAltBuffer.Load()

	if wasInAltBuffer {
		fmt.Print("\x1b[?1049l")
	}

	fmt.Print("\x1b7")

	m, err := tea.NewProgram(m).Run()
	if err != nil {
		slog.Error("Failed to run bubbletea program", "err", err)
		return m, err
	}

	fmt.Printf("\x1b[%dF\x1b[0J", strings.Count(m.View(), "\n"))

	fmt.Print("\x1b8")

	if wasInAltBuffer {
		fmt.Print("\x1b[?1049h")
		cgroupManager.SendSignal(syscall.SIGWINCH)
	}

	tm.inDialog.Store(false)

	return m, nil
}

func (tm *TTYManager) Close() error {
	if tm.interactive {
		stdinFd := int(os.Stdin.Fd())
		if err := term.Restore(stdinFd, tm.oldState); err != nil {
			return fmt.Errorf("failed to restore terminal state: %v", err)
		}
		if err := unix.SetNonblock(stdinFd, false); err != nil {
			return fmt.Errorf("failed to set non-blocking stdin: %v", err)
		}

		tm.ptyMaster.Close()
		tm.ptySlave.Close()
	} else {
		tm.stdinR.Close()
		tm.stdoutW.Close()
		tm.stderrW.Close()
	}

	return nil
}

type SubprocessManager struct {
	childPid int
	exited   chan int
}

func NewSubprocessManager(args []string, originalUID, originalGID, cgroupFD int) (*SubprocessManager, error) {
	sm := &SubprocessManager{}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get cwd: %v", err)
	}

	childExe, err := exec.LookPath(args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to look up path: %v", err)
	}

	absPath, err := filepath.Abs(childExe)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %v", err)
	}

	canonical, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate symlinks for path: %v", err)
	}

	ebpfManager.bpfObjs.FilePolicyMap.Update(objs.BpfFileRequest{Path: stringToInt8Array(canonical), Accmode: unix.O_RDONLY}, true, ebpf.UpdateAny)

	childPid, err := syscall.ForkExec(childExe, args, &syscall.ProcAttr{
		Dir:   cwd,
		Env:   os.Environ(),
		Files: ttyManager.Files(),
		Sys: &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: uint32(originalUID),
				Gid: uint32(originalGID),
			},
			UseCgroupFD: true,
			CgroupFD:    cgroupFD,
			Setsid:      ttyManager.IsInteractive(),
			Setctty:     ttyManager.IsInteractive(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fork exec: %v", err)
	}

	sm.exited = make(chan int, 1)
	go func() {
		var waitStatus syscall.WaitStatus
		_, _ = syscall.Wait4(childPid, &waitStatus, 0, nil)
		sm.exited <- waitStatus.ExitStatus()
	}()

	return sm, nil
}

func (sm *SubprocessManager) Close() error {
	return nil
}

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/mbund/cordon/objs"
)

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
var protocolMap = map[uint8]string{
	1:  "icmp",
	6:  "tcp",
	17: "udp",
	58: "icmpv6",
}

func protocolKeyword(proto uint16) string {
	if name, ok := protocolMap[uint8(proto)]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", proto)
}

func portKeyword(proto string, networkOrderPort uint16) string {
	hostPort := binary.BigEndian.Uint16([]byte{byte(networkOrderPort >> 8), byte(networkOrderPort & 0xff)})
	return knownPort(proto, hostPort)
}

var wellKnownPorts = map[string]map[uint16]string{
	"tcp": {
		20:   "ftp-data",
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "domain",
		80:   "http",
		110:  "pop3",
		143:  "imap",
		443:  "https",
		3306: "mysql",
		5432: "postgresql",
		6379: "redis",
	},
	"udp": {
		53:  "domain",
		67:  "dhcp",
		68:  "dhcp-client",
		123: "ntp",
		161: "snmp",
	},
}

func knownPort(proto string, port uint16) string {
	if m, ok := wellKnownPorts[proto]; ok {
		if name, ok := m[port]; ok {
			return fmt.Sprintf("%d (%s)", port, name)
		}
	}
	return fmt.Sprintf("%d (unknown)", port)
}

func uint32ToIP(n uint32) net.IP {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, n)
	return net.IP(b)
}

func handleConnect(req objs.BpfContextConnect) bool {
	daddr := uint32ToIP(req.Value.Daddr)
	proto := protocolKeyword(req.Value.Proto)
	dport := portKeyword(proto, req.Value.Dport)
	possibleHostnames := dnsManager.ReverseLookup(daddr)

	dialog := DefaultModel()
	dialog.prompt = fmt.Sprintf("Connect to %s %v on port %s over %s? (y/n)", daddr, possibleHostnames, dport, proto)

	tm, err := ttyManager.ShowDialog(dialog)
	if err != nil {
		slog.Error("Failed to show dialog", "err", err)
	}
	m := tm.(model)
	slog.Info("dialog model", "selected", m.selection)

	return m.selection
}

func CStringToGoString(cstr [4096]int8) string {
	var bytes []byte
	for _, b := range cstr {
		if b == 0 {
			break
		}
		bytes = append(bytes, byte(b))
	}
	return string(bytes)
}

func humanSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%dB", size)
	}
	div, exp := unit, 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(size)/float64(div), "KMGTPE"[exp])
}

func lsLikeInfo(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}

	stat := info.Sys().(*syscall.Stat_t)

	mode := info.Mode().String()

	nlink := stat.Nlink

	uid := strconv.Itoa(int(stat.Uid))
	gid := strconv.Itoa(int(stat.Gid))

	usr, err := user.LookupId(uid)
	if err != nil {
		usr = &user.User{Username: uid}
	}
	grp, err := user.LookupGroupId(gid)
	if err != nil {
		grp = &user.Group{Name: gid}
	}

	size := humanSize(info.Size())

	timestamp := info.ModTime().Format("Jan _2 15:04 2006")

	return fmt.Sprintf("%s %d %s %s %4s %s",
		mode, nlink, usr.Username, grp.Name, size, timestamp), nil
}

func fileLikeInfo(path string) (string, error) {
	out, err := exec.Command("file", "-b", path).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

type fileModel struct {
	accessMode  string
	affirmative string
	negative    string
	lslike      string
	filelike    string

	path         string
	splitIndexes []int
	splitIndex   int

	selection bool

	selectedStyle    lipgloss.Style
	unselectedStyle  lipgloss.Style
	promptStyle      lipgloss.Style
	borderStyle      lipgloss.Style
	highlightStyle   lipgloss.Style
	unhighlightStyle lipgloss.Style
}

func DefaultFileModel(path string, accessMode string) fileModel {
	splitIndexes := make([]int, 0, len(path)/6)
	for i, c := range path[:len(path)-1] {
		if c == '/' {
			splitIndexes = append(splitIndexes, i+1)
		}
	}
	splitIndexes = append(splitIndexes, len(path))

	ls, err := lsLikeInfo(path)
	if err != nil {
		slog.Error("failed to get ls like info", "path", path, "err", err)
	}

	var file string
	if path[len(path)-1] != '/' {
		file, err = fileLikeInfo(path)
		if err != nil {
			slog.Error("failed to get file like info", "path", path, "err", err)
		}
	}

	return fileModel{
		accessMode:       accessMode,
		affirmative:      "Yes",
		negative:         "No",
		selection:        true,
		path:             path,
		splitIndexes:     splitIndexes,
		splitIndex:       len(splitIndexes) - 1,
		lslike:           ls,
		filelike:         file,
		selectedStyle:    lipgloss.NewStyle().Background(lipgloss.Color("212")).Foreground(lipgloss.Color("232")).Padding(0, 3).Margin(0, 1),
		unselectedStyle:  lipgloss.NewStyle().Background(lipgloss.Color("235")).Foreground(lipgloss.Color("254")).Padding(0, 3).Margin(0, 1),
		promptStyle:      lipgloss.NewStyle().Foreground(lipgloss.Color("#7571F9")).Bold(true),
		borderStyle:      lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#7571F9")).Padding(1, 2),
		highlightStyle:   lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Bold(true),
		unhighlightStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Bold(true),
	}
}

func (fileModel) Init() tea.Cmd {
	return nil
}

func (m fileModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyEnter {
			return m, tea.Quit
		}
		switch msg.String() {
		case "y":
			m.selection = true
			return m, nil
		case "n":
			m.selection = false
			return m, nil
		case "left", "right", "h", "l":
			m.selection = !m.selection
			return m, nil
		case "up", "k":
			if m.splitIndex > 0 {
				m.splitIndex--
				ls, err := lsLikeInfo(m.path[:m.splitIndexes[m.splitIndex]])
				if err != nil {
					slog.Error("failed to get ls like info", "path", m.path[:m.splitIndexes[m.splitIndex]], "err", err)
				}
				m.lslike = ls
			}
			return m, nil
		case "down", "j":
			if m.splitIndex < len(m.splitIndexes)-1 {
				m.splitIndex++
				ls, err := lsLikeInfo(m.path[:m.splitIndexes[m.splitIndex]])
				if err != nil {
					slog.Error("failed to get ls like info", "path", m.path[:m.splitIndexes[m.splitIndex]], "err", err)
				}
				m.lslike = ls
			}
			return m, nil
		}
	}
	return m, nil
}

func (m fileModel) View() string {
	var aff, neg string
	if m.selection {
		aff = m.selectedStyle.Render(m.affirmative)
		neg = m.unselectedStyle.Render(m.negative)
	} else {
		aff = m.unselectedStyle.Render(m.affirmative)
		neg = m.selectedStyle.Render(m.negative)
	}

	kind := "file"
	if m.path[m.splitIndexes[m.splitIndex]-1] == '/' {
		kind = "all files under directory"
	}
	prompt := m.promptStyle.Render(fmt.Sprintf("Allow opening %s for ", kind)) + m.highlightStyle.Render(m.accessMode) + m.promptStyle.Render("?")

	path := m.highlightStyle.Render(m.path[:m.splitIndexes[m.splitIndex]]) + m.unhighlightStyle.Render(m.path[m.splitIndexes[m.splitIndex]:])

	file := m.filelike
	if m.path[m.splitIndexes[m.splitIndex]-1] == '/' {
		file = ""
	}

	return m.borderStyle.Render(lipgloss.JoinVertical(
		lipgloss.Left,
		m.promptStyle.Render(prompt)+"\n",
		path+"\n",
		m.promptStyle.Render(m.lslike),
		m.promptStyle.Render(file)+"\n",
		lipgloss.JoinHorizontal(lipgloss.Left, aff, neg),
	))
}

func handleFile(v objs.BpfContextFile) bool {
	path := CStringToGoString(v.Value.Path)
	accessMode := ""
	switch v.Value.Accmode & unix.O_ACCMODE {
	case unix.O_RDONLY:
		accessMode = "reading"
	case unix.O_WRONLY:
		accessMode = "writing"
	case unix.O_RDWR:
		accessMode = "reading and writing"
	}
	slog.Info("file_open", "path", path, "accessMode", accessMode)

	dialog := DefaultFileModel(path, accessMode)

	tm, err := ttyManager.ShowDialog(dialog)
	if err != nil {
		slog.Error("Failed to show dialog", "err", err)
	}
	m := tm.(fileModel)

	selectedPath := m.path[:m.splitIndexes[m.splitIndex]]

	slog.Info("dialog model", "selected", m.selection, "selectedPath", selectedPath)

	policy, err := createFilePolicy(selectedPath, v.Value.Accmode)
	slog.Info("policy", "ino", policy.I_ino, "s_dev", policy.S_dev)
	if err != nil {
		slog.Error("failed to create policy", "err", err)
	}
	err = ebpfManager.bpfObjs.FilePolicyMap.Update(policy, m.selection, ebpf.UpdateAny)
	if err != nil {
		slog.Error("failed to set policy", "err", err)
	}

	if !m.selection {
		go func() {
			cgroupManager.Close()
		}()
	}

	return m.selection
}

func handleSleep(milliseconds uint32) uint32 {
	slog.Info("sleep called", "milliseconds", milliseconds)
	time.Sleep(time.Duration(milliseconds) * time.Millisecond)

	return milliseconds
}

func handleMirror(v uint32) uint32 {
	return v
}

func handleXAddrRPC(id string, dest []byte, idx uint32) (uint32, syscall.Errno) {
	switch id {
	case "connect":
		slog.Info("Handling connect", "idx", idx)
		return handler(dest, idx, ebpfManager.bpfObjs.RequestArrayConnect, handleConnect)
	case "sleep":
		slog.Info("Handling sleep", "idx", idx)
		return handler(dest, idx, ebpfManager.bpfObjs.RequestArraySleep, handleSleep)
	case "mirror":
		slog.Info("Handling mirror", "idx", idx)
		return handler(dest, idx, ebpfManager.bpfObjs.RequestArrayMirror, handleMirror)
	case "file":
		slog.Info("Handling file", "idx", idx)
		return handler(dest, idx, ebpfManager.bpfObjs.RequestArrayFile, handleFile)
	}
	return 0, syscall.ENODATA
}

func handler[T, U any](dest []byte, idx uint32, ebpfMap *ebpf.Map, f func(req T) U) (uint32, syscall.Errno) {
	var req T
	err := ebpfMap.Lookup(idx, &req)
	if err != nil {
		slog.Error("Failed to lookup in map", "idx", idx, "err", err)
		return 0, syscall.EINVAL
	}

	ret := f(req)

	rv := reflect.ValueOf(ret)
	size := int(rv.Type().Size())
	if len(dest) < size {
		panic(fmt.Sprintf("destination too small: need %d bytes, have %d", size, len(dest)))
	}
	if !rv.CanAddr() {
		tmp := reflect.New(rv.Type()).Elem()
		tmp.Set(rv)
		rv = tmp
	}
	ptr := unsafe.Pointer(rv.UnsafeAddr())
	raw := unsafe.Slice((*byte)(ptr), size)
	copy(dest, raw)

	return uint32(binary.Size(ret)), 0
}

type MountInfo struct {
	MountID        int
	ParentID       int
	DeviceMajor    int
	DeviceMinor    int
	Root           string
	MountPoint     string
	MountOptions   string
	FilesystemType string
	MountSource    string
}

func ParseMountInfo() ([]MountInfo, error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var mounts []MountInfo
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) < 10 {
			continue
		}

		deviceField := fields[2]
		deviceParts := strings.Split(deviceField, ":")
		if len(deviceParts) != 2 {
			continue
		}

		major, err := strconv.Atoi(deviceParts[0])
		if err != nil {
			continue
		}

		minor, err := strconv.Atoi(deviceParts[1])
		if err != nil {
			continue
		}

		mountID, _ := strconv.Atoi(fields[0])
		parentID, _ := strconv.Atoi(fields[1])

		var fsType, mountSource string
		dashIndex := -1
		for i, field := range fields {
			if field == "-" {
				dashIndex = i
				break
			}
		}

		if dashIndex > 0 && dashIndex+1 < len(fields) {
			fsType = fields[dashIndex+1]
			if dashIndex+2 < len(fields) {
				mountSource = fields[dashIndex+2]
			}
		}

		mount := MountInfo{
			MountID:        mountID,
			ParentID:       parentID,
			DeviceMajor:    major,
			DeviceMinor:    minor,
			Root:           fields[3],
			MountPoint:     fields[4],
			MountOptions:   fields[5],
			FilesystemType: fsType,
			MountSource:    mountSource,
		}

		mounts = append(mounts, mount)
	}

	return mounts, scanner.Err()
}

func GetKernelDeviceID(path string) (uint32, error) {
	mounts, err := ParseMountInfo()
	if err != nil {
		return 0, err
	}

	var bestMount *MountInfo
	maxMatchLen := 0

	for _, mount := range mounts {
		if strings.HasPrefix(path, mount.MountPoint) {
			if len(mount.MountPoint) > maxMatchLen {
				bestMount = &mount
				maxMatchLen = len(mount.MountPoint)
			}
		}
	}

	if bestMount == nil {
		return 0, fmt.Errorf("no mount found for path %s", path)
	}

	kernelDeviceID := (uint32(bestMount.DeviceMajor) << 20) | uint32(bestMount.DeviceMinor)

	return kernelDeviceID, nil
}

func createFilePolicy(path string, accmode uint32) (objs.BpfFilePolicy, error) {
	kernelDevID, err := GetKernelDeviceID(path)
	if err != nil {
		return objs.BpfFilePolicy{}, err
	}

	var stat syscall.Stat_t
	err = syscall.Stat(path, &stat)
	if err != nil {
		return objs.BpfFilePolicy{}, err
	}

	return objs.BpfFilePolicy{
		I_ino:   uint32(stat.Ino),
		S_dev:   kernelDevID,
		Accmode: accmode,
	}, nil
}

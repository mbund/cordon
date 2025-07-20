package main

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"

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

func handleConnect(req objs.BpfConnectRequest) bool {
	daddr := uint32ToIP(req.Daddr)
	proto := protocolKeyword(req.Proto)
	dport := portKeyword(proto, req.Dport)
	possibleHostnames := dnsManager.ReverseLookup(daddr)

	dialog := DefaultModel()
	dialog.prompt = fmt.Sprintf("Connect to %s %v on port %s over %s? (y/n)", daddr, possibleHostnames, dport, proto)

	tm, err := subprocessManager.ShowDialog(dialog)
	if err != nil {
		slog.Error("Failed to show dialog", "err", err)
	}
	m := tm.(model)
	slog.Info("dialog model", "selected", m.selection)

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

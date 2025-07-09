package main

//go:generate sh -c "bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir objs -go-package objs -tags linux Bpf bpf.c

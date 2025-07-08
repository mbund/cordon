package main

import (
	"context"
	_ "embed"
	"log"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type CustomNode struct {
	fs.LoopbackNode
}

// var _ = (fs.NodeOpener)((*CustomNode)(nil))

func (n *CustomNode) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	log.Println("----------- Open called on CustomNode -----------")
	return n.LoopbackNode.Open(ctx, flags)
}

func newCustomNode(rootData *fs.LoopbackRoot, _ *fs.Inode, _ string, _ *syscall.Stat_t) fs.InodeEmbedder {
	n := &CustomNode{
		LoopbackNode: fs.LoopbackNode{
			RootData: rootData,
		},
	}
	return n
}

func serve() {
	// opts := &fs.Options{}
	// opts.Debug = true
	// orig := "sleep"
	// opts.MountOptions.Options = append(opts.MountOptions.Options, "fsname="+orig)
	// opts.MountOptions.Name = "customfs"
	// opts.NullPermissions = true
	// server, err := fs.Mount("./fuse", newCustomNode(&fs.LoopbackRoot{Path: orig, NewNode: newCustomNode}, nil, "", nil), opts)
	// if err != nil {
	// 	log.Fatalf("Mount fail: %v\n", err)
	// }

	// server.Wait()

	root, err := fs.NewLoopbackRoot("./sleep")
	if err != nil {
		log.Fatal(err)
	}
	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			Debug:         true,
			MaxStackDepth: 0,
		},
	}
	server, err := fs.Mount("/mnt/fuse", root, opts)
	if err != nil {
		log.Fatal(err)
	}
	server.Wait()
}

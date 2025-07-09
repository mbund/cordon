package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type ExecFS struct {
	fs.Inode
	backingDir string
}

var _ = (fs.NodeGetattrer)((*ExecFS)(nil))
var _ = (fs.NodeLookuper)((*ExecFS)(nil))
var _ = (fs.NodeReaddirer)((*ExecFS)(nil))

func (r *ExecFS) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = 0700
	return 0
}

func (r *ExecFS) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	fullPath := filepath.Join(r.backingDir, name)

	st, err := os.Stat(fullPath)
	if err != nil {
		return nil, syscall.ENOENT
	}

	var node fs.InodeEmbedder
	if st.IsDir() {
		node = &ExecDir{
			backingPath: fullPath,
		}
	} else {
		node = &ExecFile{
			backingPath: fullPath,
		}
	}

	out.Attr.Mode = uint32(st.Mode())
	out.Attr.Size = uint64(st.Size())
	out.Attr.Mtime = uint64(st.ModTime().Unix())
	out.Attr.Atime = uint64(st.ModTime().Unix())
	out.Attr.Ctime = uint64(st.ModTime().Unix())

	child := r.NewInode(ctx, node, fs.StableAttr{
		Mode: uint32(st.Mode()),
		Ino:  uint64(st.Sys().(*syscall.Stat_t).Ino),
	})

	return child, 0
}

func (r *ExecFS) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	entries, err := os.ReadDir(r.backingDir)
	if err != nil {
		return nil, syscall.EIO
	}

	var result []fuse.DirEntry
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		de := fuse.DirEntry{
			Name: entry.Name(),
			Mode: uint32(info.Mode()),
			Ino:  uint64(info.Sys().(*syscall.Stat_t).Ino),
		}
		result = append(result, de)
	}

	return fs.NewListDirStream(result), 0
}

type ExecDir struct {
	fs.Inode
	backingPath string
}

var _ = (fs.NodeGetattrer)((*ExecDir)(nil))
var _ = (fs.NodeLookuper)((*ExecDir)(nil))
var _ = (fs.NodeReaddirer)((*ExecDir)(nil))

func (d *ExecDir) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	st, err := os.Stat(d.backingPath)
	if err != nil {
		return syscall.ENOENT
	}

	out.Mode = uint32(st.Mode())
	out.Size = uint64(st.Size())
	out.Mtime = uint64(st.ModTime().Unix())
	out.Atime = uint64(st.ModTime().Unix())
	out.Ctime = uint64(st.ModTime().Unix())

	return 0
}

func (d *ExecDir) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	fullPath := filepath.Join(d.backingPath, name)

	st, err := os.Stat(fullPath)
	if err != nil {
		return nil, syscall.ENOENT
	}

	var node fs.InodeEmbedder
	if st.IsDir() {
		node = &ExecDir{
			backingPath: fullPath,
		}
	} else {
		node = &ExecFile{
			backingPath: fullPath,
		}
	}

	out.Attr.Mode = uint32(st.Mode())
	out.Attr.Size = uint64(st.Size())
	out.Attr.Mtime = uint64(st.ModTime().Unix())
	out.Attr.Atime = uint64(st.ModTime().Unix())
	out.Attr.Ctime = uint64(st.ModTime().Unix())

	child := d.NewInode(ctx, node, fs.StableAttr{
		Mode: uint32(st.Mode()),
		Ino:  uint64(st.Sys().(*syscall.Stat_t).Ino),
	})

	return child, 0
}

func (d *ExecDir) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	entries, err := os.ReadDir(d.backingPath)
	if err != nil {
		return nil, syscall.EIO
	}

	var result []fuse.DirEntry
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		de := fuse.DirEntry{
			Name: entry.Name(),
			Mode: uint32(info.Mode()),
			Ino:  uint64(info.Sys().(*syscall.Stat_t).Ino),
		}
		result = append(result, de)
	}

	return fs.NewListDirStream(result), 0
}

type ExecFile struct {
	fs.Inode
	backingPath string
}

var _ = (fs.NodeGetattrer)((*ExecFile)(nil))
var _ = (fs.NodeOpener)((*ExecFile)(nil))
var _ = (fs.NodeGetxattrer)((*ExecFile)(nil))

func (f *ExecFile) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	slog.Info("Getxattr", "attr", attr)
	segments := strings.Split(attr, ".")
	if len(segments) == 3 && segments[0] == "user" && segments[1] == "sleep" {
		duration, err := strconv.Atoi(segments[2])
		if err == nil {
			slog.Info("Sleeping", "duration", duration)
			time.Sleep(time.Duration(duration) * time.Millisecond)
		} else {
			slog.Error("Failed to parse sleep duration", "attr", attr, "err", err)
		}
	}

	return 0, syscall.ENODATA
}

func (f *ExecFile) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	st, err := os.Stat(f.backingPath)
	if err != nil {
		return syscall.ENOENT
	}

	out.Mode = uint32(st.Mode())
	out.Size = uint64(st.Size())
	out.Mtime = uint64(st.ModTime().Unix())
	out.Atime = uint64(st.ModTime().Unix())
	out.Ctime = uint64(st.ModTime().Unix())

	return 0
}

func (f *ExecFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	file, err := os.Open(f.backingPath)
	if err != nil {
		return nil, 0, syscall.EIO
	}

	return &ExecFileHandle{
		file: file,
	}, fuse.FOPEN_DIRECT_IO, 0
}

type ExecFileHandle struct {
	file *os.File
}

var _ = (fs.FileReader)((*ExecFileHandle)(nil))
var _ = (fs.FileReleaser)((*ExecFileHandle)(nil))

func (fh *ExecFileHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if _, err := fh.file.Seek(off, 0); err != nil {
		return nil, syscall.EIO
	}

	n, err := fh.file.Read(dest)
	if err != nil {
		return nil, syscall.EIO
	}

	return fuse.ReadResultData(dest[:n]), 0
}

func (fh *ExecFileHandle) Release(ctx context.Context) syscall.Errno {
	err := fh.file.Close()
	if err != nil {
		log.Printf("Error closing file handle: %v", err)
		return syscall.EIO
	}
	return 0
}

type ExecFSServer struct {
	server *fuse.Server
}

func (s *ExecFSServer) Serve(backingDir, mountPoint string) error {
	root := &ExecFS{
		backingDir: backingDir,
	}

	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			DirectMount: true,
			AllowOther:  true,
			Name:        "execfs",
		},
	}

	server, err := fs.Mount(mountPoint, root, opts)
	if err != nil {
		return fmt.Errorf("Failed to mount filesystem: %v", err)
	}
	s.server = server

	s.server.Wait()

	return nil
}

func (s *ExecFSServer) Close() error {
	return s.server.Unmount()
}

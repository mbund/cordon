package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// ExecFS represents our filesystem root
type ExecFS struct {
	fs.Inode
	backingDir string
}

// Ensure ExecFS implements the required interfaces
var _ = (fs.NodeGetattrer)((*ExecFS)(nil))
var _ = (fs.NodeLookuper)((*ExecFS)(nil))
var _ = (fs.NodeReaddirer)((*ExecFS)(nil))

// Getattr returns the attributes of the root directory
func (r *ExecFS) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = 0755
	return 0
}

// Lookup finds a file or directory by name
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

	// Set attributes
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

// Readdir returns directory entries
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

// ExecDir represents a directory in our filesystem
type ExecDir struct {
	fs.Inode
	backingPath string
}

var _ = (fs.NodeGetattrer)((*ExecDir)(nil))
var _ = (fs.NodeLookuper)((*ExecDir)(nil))
var _ = (fs.NodeReaddirer)((*ExecDir)(nil))

// Getattr returns the attributes of the directory
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

// Lookup finds a file or directory by name within this directory
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

	// Set attributes
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

// Readdir returns directory entries
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

// ExecFile represents a file in our filesystem
type ExecFile struct {
	fs.Inode
	backingPath string
}

var _ = (fs.NodeGetattrer)((*ExecFile)(nil))
var _ = (fs.NodeOpener)((*ExecFile)(nil))
var _ = (fs.NodeGetxattrer)((*ExecFile)(nil))

func (f *ExecFile) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	log.Printf("---------- Getxattr called on %s for attribute %s", f.backingPath, attr)
	time.Sleep(2000 * time.Millisecond)
	return 0, syscall.ENODATA
}

// Getattr returns the attributes of the file
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

// Open opens the file for reading
func (f *ExecFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	file, err := os.Open(f.backingPath)
	if err != nil {
		return nil, 0, syscall.EIO
	}

	return &ExecFileHandle{
		file: file,
	}, fuse.FOPEN_DIRECT_IO, 0
}

// ExecFileHandle represents an open file handle
type ExecFileHandle struct {
	file *os.File
}

var _ = (fs.FileReader)((*ExecFileHandle)(nil))
var _ = (fs.FileReleaser)((*ExecFileHandle)(nil))

// Read reads data from the file
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

// Release closes the file handle
func (fh *ExecFileHandle) Release(ctx context.Context) syscall.Errno {
	// return syscall.Errno(fh.file.Close())
	return syscall.EIO
}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <backing-directory> <mount-point>\n", os.Args[0])
		os.Exit(1)
	}

	backingDir := os.Args[1]
	mountPoint := os.Args[2]

	// Verify backing directory exists
	if _, err := os.Stat(backingDir); os.IsNotExist(err) {
		log.Fatalf("Backing directory %s does not exist", backingDir)
	}

	// Create mount point if it doesn't exist
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		log.Fatalf("Failed to create mount point: %v", err)
	}

	// Convert to absolute path
	backingDir, err := filepath.Abs(backingDir)
	if err != nil {
		log.Fatalf("Failed to get absolute path: %v", err)
	}

	// Create root filesystem node
	root := &ExecFS{
		backingDir: backingDir,
	}

	// Mount options for binary execution
	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			DirectMount: true,
			AllowOther:  true,
			Name:        "execfs",
			// Debug:       true,
		},
	}

	// Mount the filesystem
	server, err := fs.Mount(mountPoint, root, opts)
	if err != nil {
		log.Fatalf("Failed to mount filesystem: %v", err)
	}

	fmt.Printf("Mounting %s at %s\n", backingDir, mountPoint)
	fmt.Printf("Press Ctrl+C to unmount\n")

	// Wait for unmount
	server.Wait()
}

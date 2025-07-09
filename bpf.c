//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define AF_INET 2

const __u32 blockme = 0x01010101; // 1.1.1.1 -> int

s32 pid;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} ringbuf SEC(".maps");

static __always_inline int __sleep_internal(const char *xattr) {
    struct task_struct *task = bpf_task_from_pid(pid);
    if (!task) {
        return -1;
    }

    struct file *file = bpf_get_task_exe_file(task);
    if (!file) {
        bpf_task_release(task);
        return -1;
    }

    struct bpf_dynptr dynp;
    bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, &dynp);
    int err = bpf_get_file_xattr(file, xattr, &dynp);
    bpf_ringbuf_discard_dynptr(&dynp, 0);
    bpf_put_file(file);
    bpf_task_release(task);
    return err;
}

#define SLEEP(ms) __sleep_internal("user.sleep." #ms)

SEC("lsm.s/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret) {
    // Satisfying "cannot override a denial" rule
    if (ret != 0) {
        return ret;
    }

    // Only IPv4 in this example
    if (address->sa_family != AF_INET) {
        return 0;
    }

    // Cast the address to an IPv4 socket address
    struct sockaddr_in *addr = (struct sockaddr_in *)address;

    // Where do you want to go?
    __u32 dest = addr->sin_addr.s_addr;
    bpf_printk("lsm: found connect to %d", dest);

    SLEEP(5000);

    if (dest == blockme) {
        bpf_printk("lsm: blocking %d", dest);
        return -EPERM;
    }
    return 0;
}

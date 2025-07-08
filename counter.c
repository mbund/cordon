//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define AF_INET 2

const __u32 blockme = 0x01010101; // 1.1.1.1 -> int

s32 pid;
void *user_ptr;
// __u64 user_ptr;

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

    struct task_struct *task = bpf_task_from_pid(pid);
    if (!task) {
        bpf_printk("lsm: task not found");
        return -EPERM;
    }
    bpf_printk("lsm: task found for pid=%d", pid);
    __u8 buf[4];
    // void *user_ptr = (void *)0x100000;
    long err = bpf_copy_from_user_task(buf, 4, user_ptr, task, 0);
    bpf_printk("lsm: user_ptr=0x%llx, buf=%d,%d,%d,%d err=%d", (__u64)user_ptr, buf[0], buf[1], buf[2], buf[3], err);
    bpf_task_release(task);

    if (dest == blockme) {
        bpf_printk("lsm: blocking %d", dest);
        return -EPERM;
    }
    return 0;
}

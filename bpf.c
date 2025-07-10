//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "userspace_helper.c"

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define AF_INET 2

const __u32 blockme = 0x01010101; // 1.1.1.1 -> int

struct connect_request {
    __be32 daddr;
    __be16 dport;
};
struct connect_response {
    char string[16];
    bool verdict;
};
DEFINE_USERSPACE(connect, struct connect_request, struct connect_response)

DEFINE_USERSPACE(sleep, __u32, __u32)

DEFINE_USERSPACE(mirror, __u32, __u32)

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
    // bpf_printk("lsm: found connect to %d", dest);

    __u32 milliseconds = bpf_get_prandom_u32() % 4000 + 1000;
    userspace_blocking_sleep(&milliseconds);

    __u32 x  = bpf_get_prandom_u32();
    __u32 *y = userspace_blocking_mirror(&x);
    if (!y)
        return -EPERM;
    if (x != *y) {
        bpf_printk("lsm: NOT EQUAL %u != %u", x, *y);
    } else {
        bpf_printk("lsm: EQUAL %u == %u", x, *y);
    }

    if (dest == blockme) {
        bpf_printk("lsm: blocking %d", dest);
        return -EPERM;
    }
    return 0;
}

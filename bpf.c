//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "userspace_helper.c"

char LICENSE[] SEC("license") = "GPL";

__u64 target_cgroup;

#define EPERM 1
#define AF_INET 2

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
    if (bpf_get_current_cgroup_id() != target_cgroup)
        return ret;

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
    __u32 dest     = addr->sin_addr.s_addr;
    struct sock *s = sock->sk;
    if (s) {
        __u16 proto = s->sk_protocol;
        __u16 port  = bpf_htons(addr->sin_port);
        bpf_printk("lsm: found connect to %pI4 proto=%d port=%d", &dest, proto, port);
    }

    // __u32 milliseconds = bpf_get_prandom_u32() % 4000 + 1000;
    __u32 milliseconds = 5000;
    userspace_blocking_sleep(&milliseconds);

    if (dest == 0x01010101) {
        bpf_printk("lsm: blocking %pI4", &dest);
        return -EPERM;
    }
    return 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(file_open, struct file *file, int ret) {
    if (bpf_get_current_cgroup_id() != target_cgroup)
        return ret;

    if (ret != 0) {
        return ret;
    }

    loff_t size = file->f_inode->i_size;
    // if (size > 4096) {
    char path[256];
    int len = bpf_probe_read_str(path, sizeof(path), file->f_path.dentry->d_name.name);
    // if (path[0] == 'm' && path[1] == 'a' && path[2] == 'i' && path[3] == 'n') {
    //     // __u32 milliseconds = 1000;
    //     // userspace_blocking_sleep(&milliseconds);
    //     bpf_printk("file_open: %s", path);
    // }
    bpf_path_d_path(&file->f_path, path, sizeof(path));
    bpf_printk("file_open: %s", path);
    // }

    return 0;
}

SEC("lsm.s/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address, int addrlen, int ret) {
    if (bpf_get_current_cgroup_id() != target_cgroup)
        return ret;

    if (ret != 0) {
        return ret;
    }

    __u32 milliseconds = 1000;
    // userspace_blocking_sleep(&milliseconds);
    // bpf_printk("socket_open");

    return 0;
}

SEC("lsm.s/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm, int ret) {
    if (bpf_get_current_cgroup_id() != target_cgroup)
        return ret;

    if (ret != 0) {
        return ret;
    }

    __u32 milliseconds = 1000;
    // userspace_blocking_sleep(&milliseconds);
    // bpf_printk("bprm_check_security %s", bprm->filename);

    return 0;
}

struct correlation_context {
    __u32 tgid;
    __u32 pid;
    __u32 gid;
    __u32 uid;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct correlation_context);
    __uint(max_entries, 1);
} correlation_contexts SEC(".maps");

static __always_inline void get_correlation_context(struct correlation_context *correlation_context) {
    __u64 pid_tgid            = bpf_get_current_pid_tgid();
    correlation_context->tgid = pid_tgid >> 32;
    correlation_context->pid  = pid_tgid;

    __u64 uid_gid            = bpf_get_current_uid_gid();
    correlation_context->gid = uid_gid >> 32;
    correlation_context->uid = uid_gid;
}

static __always_inline void print_correlation_context(struct correlation_context *c) {
    bpf_printk("pid=%u, tgid=%u, uid=%u, gid=%u", c->pid, c->tgid, c->uid, c->gid);
}

static __always_inline bool compare_correlation_contexts(struct correlation_context *a, struct correlation_context *b) {
    return a->pid == b->pid && a->tgid == b->tgid && a->gid == b->gid;
}

static __always_inline void insert_correlation() {
    struct correlation_context correlation_context;
    get_correlation_context(&correlation_context);
    __u32 zero = 0;
    bpf_map_update_elem(&correlation_contexts, &zero, &correlation_context, BPF_ANY);
}

static __always_inline bool is_correlated() {
    __u32 zero                       = 0;
    struct correlation_context *prev = bpf_map_lookup_elem(&correlation_contexts, &zero);
    if (!prev)
        return false;
    bpf_map_delete_elem(&correlation_contexts, &zero);

    struct correlation_context correlation_context;
    get_correlation_context(&correlation_context);
    bool correlated = compare_correlation_contexts(prev, &correlation_context);
    if (correlated) {
        print_correlation_context(prev);
        print_correlation_context(&correlation_context);
    }
    return correlated;
}

SEC("lsm.s/cred_prepare")
int BPF_PROG(cred_prepare, struct cred *new, const struct cred *old, gfp_t gfp, int ret) {
    if (bpf_get_current_cgroup_id() != target_cgroup)
        return ret;

    if (ret != 0) {
        return ret;
    }

    if (!is_correlated())
        return 0;

    bpf_printk("cred_prepare %u -> %u", old->uid.val, new->uid.val);

    if (new->uid.val == 0) {
        __u32 milliseconds = 5000;
        userspace_blocking_sleep(&milliseconds);
        return -EPERM;
    }

    return 0;
}

SEC("fentry/__x64_sys_setuid")
int BPF_PROG(__x64_sys_setuid, uid_t uid) {
    if (bpf_get_current_cgroup_id() != target_cgroup)
        return 0;

    insert_correlation();

    bpf_printk("__x64_sys_setuid %u", uid);

    return 0;
}

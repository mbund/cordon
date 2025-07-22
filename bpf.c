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
    __u16 proto;
};
DEFINE_USERSPACE(connect, struct connect_request, bool)

DEFINE_USERSPACE(sleep, __u32, __u32)

DEFINE_USERSPACE(mirror, __u32, __u32)

SEC("lsm.s/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret) {
    if (bpf_get_current_cgroup_id() != target_cgroup)
        return ret;

    if (ret != 0)
        return ret;

    if (address->sa_family != AF_INET)
        return 0;

    struct sockaddr_in *addr = (struct sockaddr_in *)address;

    __u32 dest     = addr->sin_addr.s_addr;
    struct sock *s = sock->sk;
    if (!s)
        return -EPERM;

    // __u16 proto = s->sk_protocol;
    // __u16 port  = bpf_htons(addr->sin_port);
    // bpf_printk("lsm: found connect to %pI4 proto=%d port=%d", &dest, proto, port);

    struct connect_request req = {
        .daddr = addr->sin_addr.s_addr,
        .dport = bpf_htons(addr->sin_port),
        .proto = s->sk_protocol,
    };
    bool *verdict_ptr = userspace_blocking_connect(&req);
    int verdict       = -EPERM;

    if (verdict_ptr && *verdict_ptr)
        verdict = 0;

    return verdict;
}

static __always_inline int bpf_memcmp_safe(const void *s1, const void *s2, __u32 n) {
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;

    if (n > 256)
        n = 256;

    for (__u32 i = 0; i < n; i++) {
        if ((void *)(p1 + i + 1) > (void *)p1 + 256 || (void *)(p2 + i + 1) > (void *)p2 + 256)
            break;

        if (p1[i] < p2[i])
            return -1;
        if (p1[i] > p2[i])
            return 1;
    }

    return 0;
}

static __always_inline void safe_memcpy(void *dst, const void *src, __u32 len) {
    __u32 i;
    for (i = 0; i < len; i++) {
        ((volatile __u8 *)dst)[i] = ((volatile __u8 *)src)[i];
    }
}

struct file_request {
    char path[128];
    unsigned int accmode;
};
DEFINE_USERSPACE(file, struct file_request, bool)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[128]);
    __type(value, bool);
} file_policy_map SEC(".maps");

static __always_inline bool check_file_policy(char *path, __u32 len, unsigned int accmode) {
    bool *verdict = bpf_map_lookup_elem(&file_policy_map, path);
    if (!verdict) {
        struct file_request req = {
            .accmode = accmode,
        };
        safe_memcpy(&req.path, path, sizeof(req.path));

        bool *user_verdict = userspace_blocking_file(&req);
        if (!user_verdict)
            return false;

        return *user_verdict != 0;
    }

    return *verdict;
}

struct overlay_correlation {
    loff_t size;
    struct pt_regs pt_regs;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u64);
    __type(value, struct overlay_correlation);
    __uint(max_entries, 1);
} overlay_correlation_map SEC(".maps");

#define OVERLAYFS_SUPER_MAGIC 0x794c7630

SEC("lsm.s/file_open")
int BPF_PROG(file_open, struct file *file, int ret) {
    if (bpf_get_current_cgroup_id() != target_cgroup)
        return ret;

    if (ret != 0)
        return ret;

    char path[128];
    __u32 len = bpf_path_d_path(&file->f_path, path, sizeof(path));
    bpf_printk("%s", path);

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct overlay_correlation *overlay_correlation = bpf_map_lookup_elem(&overlay_correlation_map, &pid_tgid);
    if (overlay_correlation) {
        loff_t size = file->f_inode->i_size;
        if (overlay_correlation->size != size) {
            bpf_map_delete_elem(&overlay_correlation_map, &pid_tgid);
            return -EPERM;
        }
        struct pt_regs *pt_regs = (struct pt_regs *)bpf_task_pt_regs(bpf_get_current_task_btf());
        if (bpf_memcmp_safe(pt_regs, &overlay_correlation->pt_regs, sizeof(*pt_regs))) {
            bpf_map_delete_elem(&overlay_correlation_map, &pid_tgid);
            return -EPERM;
        }
        bpf_map_delete_elem(&overlay_correlation_map, &pid_tgid);
        return 0;
    }

    if (!check_file_policy(path, len, file->f_flags))
        return -EPERM;

    if (file->f_path.dentry->d_sb->s_magic == OVERLAYFS_SUPER_MAGIC) {
        struct pt_regs *pt_regs = (struct pt_regs *)bpf_task_pt_regs(bpf_get_current_task_btf());
        __u64 pid_tgid          = bpf_get_current_pid_tgid();
        loff_t size             = file->f_inode->i_size;

        struct overlay_correlation overlay_correlation = {
            .size    = size,
            .pt_regs = *pt_regs,
        };
        bpf_map_update_elem(&overlay_correlation_map, &pid_tgid, &overlay_correlation, BPF_ANY);

        return 0;
    }

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
    userspace_blocking_sleep(&milliseconds);
    // bpf_printk("socket_bind");

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

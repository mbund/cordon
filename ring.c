//go:build ignore

// #include <linux/bpf.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
// #include <bpf/bpf_helpers.h>

#define XATTR_RING(n) "user.ring." #n

#define NUM_RINGS 20

struct counter {
    struct bpf_spin_lock lock;
    __u32 next;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct counter);
} counter_map SEC(".maps") __hidden;

static __always_inline __u32 next_n() {
    __u32 key         = 0;
    struct counter *c = bpf_map_lookup_elem(&counter_map, &key);
    if (!c)
        return 0;

    bpf_spin_lock(&c->lock);
    __u32 idx = c->next++;
    bpf_spin_unlock(&c->lock);

    return idx % NUM_RINGS;
}

static __always_inline const char *get_dynamic_attr(__u32 n) {
    switch (n % NUM_RINGS) {
    case 0:
        return XATTR_RING(0);
    case 1:
        return XATTR_RING(1);
    case 2:
        return XATTR_RING(2);
    case 3:
        return XATTR_RING(3);
    case 4:
        return XATTR_RING(4);
    case 5:
        return XATTR_RING(5);
    case 6:
        return XATTR_RING(6);
    case 7:
        return XATTR_RING(7);
    case 8:
        return XATTR_RING(8);
    case 9:
        return XATTR_RING(9);
    case 10:
        return XATTR_RING(10);
    case 11:
        return XATTR_RING(11);
    case 12:
        return XATTR_RING(12);
    case 13:
        return XATTR_RING(13);
    case 14:
        return XATTR_RING(14);
    case 15:
        return XATTR_RING(15);
    case 16:
        return XATTR_RING(16);
    case 17:
        return XATTR_RING(17);
    case 18:
        return XATTR_RING(18);
    case 19:
        return XATTR_RING(19);
    default:
        return "unreachable";
    }
}

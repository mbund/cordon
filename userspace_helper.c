//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define NUM_RINGS 16

struct counter {
    struct bpf_spin_lock lock;
    __u32 next;
};

s32 pid;

#define DEFINE_USERSPACE(id, request_type, response_type) \
    struct { \
        __uint(type, BPF_MAP_TYPE_ARRAY); \
        __uint(max_entries, 1); \
        __type(key, __u32); \
        __type(value, struct counter); \
    } counter_map_##id SEC(".maps"); \
    static __always_inline __u32 __next_n_##id() { \
        __u32 key         = 0; \
        struct counter *c = bpf_map_lookup_elem(&counter_map_##id, &key); \
        if (!c) \
            return 0; \
        bpf_spin_lock(&c->lock); \
        __u32 idx = c->next++; \
        bpf_spin_unlock(&c->lock); \
        return idx % NUM_RINGS; \
    } \
    struct { \
        __uint(type, BPF_MAP_TYPE_ARRAY); \
        __type(key, __u32); \
        __type(value, request_type); \
        __uint(max_entries, NUM_RINGS); \
    } request_array_##id SEC(".maps"); \
    struct { \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
        __type(key, __u32); \
        __type(value, response_type); \
        __uint(max_entries, NUM_RINGS); \
    } response_array_##id SEC(".maps"); \
    static __always_inline const char *__get_dynamic_attr_##id(__u32 n) { \
        switch (n % NUM_RINGS) { \
        case 0: \
            return "user." #id ".0"; \
        case 1: \
            return "user." #id ".1"; \
        case 2: \
            return "user." #id ".2"; \
        case 3: \
            return "user." #id ".3"; \
        case 4: \
            return "user." #id ".4"; \
        case 5: \
            return "user." #id ".5"; \
        case 6: \
            return "user." #id ".6"; \
        case 7: \
            return "user." #id ".7"; \
        case 8: \
            return "user." #id ".8"; \
        case 9: \
            return "user." #id ".9"; \
        case 10: \
            return "user." #id ".10"; \
        case 11: \
            return "user." #id ".11"; \
        case 12: \
            return "user." #id ".12"; \
        case 13: \
            return "user." #id ".13"; \
        case 14: \
            return "user." #id ".14"; \
        case 15: \
            return "user." #id ".15"; \
        default: \
            return "unreachable"; \
        } \
    } \
    static __always_inline response_type *userspace_blocking_##id(request_type *req) { \
        struct task_struct *task = bpf_task_from_pid(pid); \
        if (!task) \
            return NULL; \
        struct file *file = bpf_get_task_exe_file(task); \
        if (!file) { \
            bpf_task_release(task); \
            return NULL; \
        } \
        struct bpf_dynptr dynp; \
        __u32 n            = __next_n_##id(); \
        response_type *res = bpf_map_lookup_elem(&response_array_##id, &n); \
        if (!res) { \
            bpf_put_file(file); \
            bpf_task_release(task); \
            return NULL; \
        } \
        long err = bpf_dynptr_from_mem(res, sizeof(response_type), 0, &dynp); \
        bpf_map_update_elem(&request_array_##id, &n, req, BPF_ANY); \
        err = bpf_get_file_xattr(file, __get_dynamic_attr_##id(n), &dynp); \
        if (err < 0) { \
            bpf_put_file(file); \
            bpf_task_release(task); \
            return NULL; \
        } \
        bpf_put_file(file); \
        bpf_task_release(task); \
        return res; \
    }

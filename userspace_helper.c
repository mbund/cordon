//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define NUM_RINGS 16
#define PATH_MAX 4096

s32 pid;

#define DEFINE_USERSPACE(id, request_type, response_type) \
    struct context_##id { \
        __u32 lock; \
        __u64 pid_tgid; \
        struct bpf_stack_build_id stack[80]; \
        int stack_n; \
        unsigned char comm[TASK_COMM_LEN]; \
        unsigned char exe_path[PATH_MAX]; \
        __u32 n; \
        request_type value; \
    }; \
    struct { \
        __uint(type, BPF_MAP_TYPE_ARRAY); \
        __type(key, __u32); \
        __type(value, struct context_##id); \
        __uint(max_entries, NUM_RINGS); \
    } request_array_##id SEC(".maps"); \
    struct { \
        __uint(type, BPF_MAP_TYPE_ARRAY); \
        __type(key, __u32); \
        __type(value, response_type); \
        __uint(max_entries, NUM_RINGS); \
    } response_array_##id SEC(".maps"); \
    __u32 counter_##id = 0; \
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
    static __always_inline struct context_##id *userspace_blocking_reserve_##id() { \
        __u32 n = __sync_fetch_and_add(&counter_##id, 1) % NUM_RINGS; \
        struct context_##id *c = bpf_map_lookup_elem(&request_array_##id, &n); \
        if (!c) \
            return NULL; \
        if (__sync_val_compare_and_swap(&c->lock, 0, 1)) \
            return NULL; \
        c->n        = n; \
        c->pid_tgid = bpf_get_current_pid_tgid(); \
        struct task_struct *task = bpf_get_current_task_btf(); \
        c->stack_n = bpf_get_task_stack(task, c->stack, sizeof(c->stack), BPF_F_USER_STACK | BPF_F_USER_BUILD_ID); \
        bpf_get_current_comm(c->comm, sizeof(c->comm)); \
        struct file *exe_file = bpf_get_task_exe_file(task); \
        if (!exe_file) \
            return NULL; \
        bpf_path_d_path(&exe_file->f_path, (char *)c->exe_path, sizeof(c->exe_path)); \
        bpf_put_file(exe_file); \
        return c; \
    } \
    static __always_inline response_type *userspace_blocking_##id(struct context_##id *req) { \
        struct task_struct *task = bpf_task_from_pid(pid); \
        if (!task) { \
            req->lock = 0; \
            return NULL; \
        } \
        struct file *file = bpf_get_task_exe_file(task); \
        if (!file) { \
            bpf_task_release(task); \
            req->lock = 0; \
            return NULL; \
        } \
        response_type *res = bpf_map_lookup_elem(&response_array_##id, &req->n); \
        if (!res) { \
            bpf_put_file(file); \
            bpf_task_release(task); \
            req->lock = 0; \
            return NULL; \
        } \
        struct bpf_dynptr dynp; \
        long err = bpf_dynptr_from_mem(res, sizeof(response_type), 0, &dynp); \
        if (err < 0) { \
            bpf_printk("C n=%d err=%d", req->n, err); \
            bpf_put_file(file); \
            bpf_task_release(task); \
            req->lock = 0; \
            return NULL; \
        } \
        err = bpf_get_file_xattr(file, __get_dynamic_attr_##id(req->n), &dynp); \
        if (err < 0) { \
            bpf_printk("D n=%d err=%d", req->n, err); \
            bpf_put_file(file); \
            bpf_task_release(task); \
            req->lock = 0; \
            return NULL; \
        } \
        bpf_put_file(file); \
        bpf_task_release(task); \
        return res; \
    } \
    static __always_inline void userspace_blocking_end_##id(struct context_##id *req) { \
        req->lock = 0; \
    }

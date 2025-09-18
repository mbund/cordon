# cordon

An experimental interactive security sandbox for Linux.
Approve privileged actions before they run on any binary.

![demo](./docs/demo.gif)

> [!WARNING]
> This is heavily a work in progress and not ready for production.
> Do not use it to run untrusted software.

See the [related blog post](https://mbund.dev/posts/interactive-security-sandbox) for details.

Requires Linux v6.12 or higher.

## Development Notes

- libbpf section names
  - https://kernel.org/doc/html/v6.15/bpf/libbpf/program_types.html
- List of sleepable LSM hooks
  - https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/bpf_lsm.c#L286
- List of all LSM hook function signatures
  - https://github.com/torvalds/linux/blob/v6.15/include/linux/lsm_hook_defs.h
- File with comments explaining what each LSM hook does
  - https://github.com/torvalds/linux/blob/v6.15/security/security.c

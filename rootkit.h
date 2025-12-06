// SPDX-License-Identifier: GPL-2.0
#ifndef __ROOTKIT_H__
#define __ROOTKIT_H__

// Types - vmlinux.h provides these for BPF, define for userspace
#ifndef __VMLINUX_H__
#ifndef __u8
typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;
#endif
#endif

#define BPF_PROG_LOAD         5
#define BPF_PROG_GET_NEXT_ID  11

enum { ACTION_LOAD = 0, ACTION_UNLOAD = 1 };

struct event_data { __u8 action; };
struct call_ctx { __u64 uattr_ptr; __u32 start_id; };

#define RINGBUF_SIZE     (256 * 1024)
#define MAX_HIDDEN_PROGS 10240
#define MAX_CTX_ENTRIES  1024

#endif

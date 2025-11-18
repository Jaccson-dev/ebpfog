#!/usr/bin/env python3
import sys
import os
from bcc import BPF

def main():
    if os.geteuid() != 0:
        print("Error: Run as root")
        sys.exit(1)
    
    try:
        cflags = ["-Wno-address-space", "-Wno-duplicate-decl-specifier"]
        b = BPF(src_file="bpf_hook.c", cflags=cflags)
        b.attach_kprobe(event="__x64_sys_bpf", fn_name="trace_bpf_entry")
        b.attach_kretprobe(event="__x64_sys_bpf", fn_name="trace_bpf_exit")
        
        print("Monitoring BPF_PROG_GET_NEXT_ID syscalls (Ctrl+C to exit)...\n")
        b.trace_print()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

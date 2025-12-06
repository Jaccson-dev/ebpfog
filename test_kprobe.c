// Simple kprobe test loader
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(void)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    
    obj = bpf_object__open_file("test_kprobe.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }
    
    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }
    
    prog = bpf_object__find_program_by_name(obj, "test_kprobe");
    if (!prog) {
        fprintf(stderr, "Failed to find program\n");
        return 1;
    }
    
    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Failed to attach kprobe\n");
        return 1;
    }
    
    printf("Kprobe attached! Check trace_pipe output.\n");
    printf("Run 'sudo bpftool prog list' in another terminal to trigger it.\n");
    printf("Press Ctrl+C to exit...\n");
    
    sleep(60);
    
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}




#include "src/common_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

struct 
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 25); 
    __uint(pinning, LIBBPF_PIN_BY_NAME); 
} proc_info_buff SEC(".maps"); 
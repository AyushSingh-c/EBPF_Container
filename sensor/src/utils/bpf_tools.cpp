#include "src/utils/utils.h"
#include <unistd.h>
#include <cstring>
#include <iostream>
void utils::bpf::list_prog(struct bpf_object *obj)
{
    struct bpf_program *prog_temp;
    bpf_object__for_each_program(prog_temp, obj) 
    {
        const char *prog_name = bpf_program__name(prog_temp);
        printf("Program name: %s\n", prog_name);
    }
}

int utils::bpf::load_tracepoint_module(struct bpf_object *obj, std::string module_name, std::string submodule_name, std::string tracepoint_name)
{
    struct bpf_program *tracepoint_prog = bpf_object__find_program_by_name(obj, module_name.c_str());
    if (!tracepoint_prog) {
        fprintf(stderr, "Failed to find BPF program by title tracepoint/..\n");
        return -1;
    }

    int tracepoint_prog_fd;
    tracepoint_prog_fd = bpf_program__fd(tracepoint_prog);
    if (tracepoint_prog_fd < 0) {
        fprintf(stderr, "Failed to get BPF program file descriptor\n");
        return -1;
    }

    struct bpf_link *tracepoint_link = bpf_program__attach_tracepoint(tracepoint_prog, submodule_name.c_str(), tracepoint_name.c_str());
    if (libbpf_get_error(tracepoint_link)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return -1;
    }

    return 0;
}

void utils::bpf::unpin_maps(std::vector<std::string> maps_name)
{
    for (auto name : maps_name)
    {
        std::string ring_buff_path = "/sys/fs/bpf/" + name;
        int ring_buff_fd = bpf_obj_get(ring_buff_path.c_str());
        if (ring_buff_fd > 0) 
        {
            if (unlink(ring_buff_path.c_str()) == -1 || close(ring_buff_fd) == -1)
                std::cout << "Unable to close map" << std::endl;
        }
        else
            std::cout << "no map for u" << std::endl;
    }
}

struct bpf_object* utils::bpf::load_ebpf_obj(std::string filename)
{
    int err;

    struct bpf_object *obj = bpf_object__open_file(filename.c_str(), NULL);
    if (libbpf_get_error(obj)) {
        std::cout << "ERROR: opening BPF object file failed with filename: " << filename << std::endl;
        return obj;
    }

    err = bpf_object__load(obj);
    if (err) {
        std::cout << "ERROR: loading BPF object file failed with filename: " << filename << " with error: " << err << std::endl;
        return obj;
    }

    std::cout << "Listing the ebpf progs: " << std::endl;
    utils::bpf::list_prog(obj);
    return obj;
}
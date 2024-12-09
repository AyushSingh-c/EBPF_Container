#include "src/utils/utils.h"
#include <iostream>
#include <ftw.h>
#include <net/if.h>
#include <dirent.h>
#include <unistd.h>
#include <algorithm>
#include <sys/types.h>

namespace
{
    std::string get_path_from_dentry(process_info* info, pid_t pid)
    {
        std::string path = "";
        int starting_index = info->dentries_number - 1;
        for (int i = starting_index; i >= 0; i--)
        {
            if (info->dentries[i][0] == '\0' || info->dentries[i][0] == '/')
                continue;
            path += "/";
            for (int j = 0; j < info->dentry_sizes[i]; j++)
            {
                if (info->dentries[i][j] == '\0')
                    break;
                path += info->dentries[i][j];
            }
        }
        // std::cout << "dentry path: " << path << " and pid: " << pid << std::endl; 
        return path;
    }
}

std::atomic<bool> utils::ebpf_state_utils::running = true;

int utils::ebpf_state_utils::handle_proc_info(void *ctx, void *data, size_t size)
{
    process_info *info = (process_info *)data;
    unsigned int inode_test = info->ns_inode;

    std::string path = get_path_from_dentry(info, info->pid);

    if (path.find("/usr/bin/bash") == std::string::npos && 
        path.find("/usr/bin/dash") == std::string::npos &&
        path.find("/usr/bin/cat") == std::string::npos &&
        path.find("/usr/bin/sed") == std::string::npos)
        std::cout << "Process Info: pid -> " << info->pid << " ppid -> " << info->parent_pid << " path -> " << path << " namespace inode -> " << inode_test << std::endl;
    return 0;
}

void utils::ebpf_state_utils::start_ring_buff_polling(std::string ring_buff_path, Event_Handler handler)
{
    struct ring_buffer *rb = NULL;
    int ring_buff_fd = bpf_obj_get(ring_buff_path.c_str());
    if (ring_buff_fd < 0) 
    {
        perror("bpf_obj_get");
        return;
    }

    rb = ring_buffer__new(ring_buff_fd, handler, NULL, NULL);
    if (!rb) 
    {
        perror("ring_buffer__new");
        return;
    }

    while (running) 
    {
        int err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err < 0) 
        {
            perror("ring_buffer__poll");
            return;
        }
    }
    ring_buffer__free(rb);
    if (unlink(ring_buff_path.c_str()) == -1 || close(ring_buff_fd) == -1)
        std::cout << "Unable to close map" << std::endl;
}
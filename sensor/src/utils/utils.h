#include <atomic>
#include <string>
#include <vector>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "src/common_structs.h"

typedef int (*Event_Handler)(void *ctx, void *data, size_t size);

namespace utils
{
    class ebpf_state_utils
    {
    public:
        struct bpf_object *obj; 
        static std::atomic<bool> running;
        void init()
        {
            running = true;
            obj = NULL;
        }

        static int handle_proc_info(void *ctx, void *data, size_t size);

        static void start_ring_buff_polling(std::string ring_buff_path, Event_Handler handler);
    };
}

namespace utils::bpf
{
    void list_prog(struct bpf_object *obj);
    struct bpf_object* load_ebpf_obj(std::string filename);
    int load_tracepoint_module(struct bpf_object *obj, std::string module_name, std::string submodule_name, std::string tracepoint_name);
    void unpin_maps(std::vector<std::string> maps_name);
}

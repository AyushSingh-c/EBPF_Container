#include <string>
#include <iostream>
#include <optional>
#include <thread>
#include "src/utils/utils.h"

bool load_hooks(utils::ebpf_state_utils& state, std::string ebpf_obj_file)
{
	state.obj = utils::bpf::load_ebpf_obj(ebpf_obj_file);
    if (state.obj == NULL)
    {
        std::cout << "Unable to load bpf object" << std::endl;
        return false;
    }

    if (utils::bpf::load_tracepoint_module(state.obj, "handle_fork", "sched", "sched_process_fork") != 0)
    {
        std::cout << "Unable to load bpf handle_fork/sched/sched_process_fork module" << std::endl;
	    bpf_object__close(state.obj);
        return false;
    }

	if (utils::bpf::load_tracepoint_module(state.obj, "handle_exec", "sched", "sched_process_exec") != 0)
    {
        std::cout << "Unable to load bpf handle_fork/sched/sched_process_exec module" << std::endl;
	    bpf_object__close(state.obj);
        return false;
    }

    return true;
}

void join_optional_threads(std::optional<std::thread>& t)
{
	if (t->joinable()) 
	{
        t->join();
    }
}


int main(int argc, char* argv[])
{
    if (argc < 2) 
    {
        std::cerr << "Usage: " << argv[0] << " <ebpf_file_path>" << std::endl;
        return 1;
    }
    std::string file_path = argv[1];


	class utils::ebpf_state_utils state{};
	state.init();

    std::string input;
	std::optional<std::thread> proc_info_thread;

    if (!load_hooks(state, file_path))
	{
		std::cout << "Unable to load all the hooks. Exiting......." << std::endl;
		goto cleanup;
	}
	proc_info_thread.emplace(state.start_ring_buff_polling, "/sys/fs/bpf/proc_info_buff", state.handle_proc_info);

    std::cout << "Waiting for the break :)" << std::endl;
    std::getline(std::cin, input);
    state.running = false; 

	join_optional_threads(proc_info_thread);
cleanup:
    utils::bpf::unpin_maps(std::vector<std::string>{"proc_info_buff"});
    bpf_object__close(state.obj);	
    return 0;
}

#include "src/vmlinux.h"
#include "src/common_structs.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__attribute__((always_inline))
int get_dentry_kpath(struct dentry *dentry, struct dentry *mnt_dentry, process_info *event_kpath)
{
    struct dentry *d = dentry;
    struct dentry *mnt_d = mnt_dentry;
    struct dentry *d_parent;
    struct qstr dname;
    int err = 0;
    int i = 0;
    for (i = 0; i < KPATH_ENTRIES; ++i)
    {
        err = BPF_CORE_READ_INTO(&dname, d, d_name);
        if (err)
        {
            bpf_printk("get_path: BPF_CORE_READ_INTO error for d_name, %d\n", err);
            break;
        }
        int read_size = bpf_probe_read_kernel_str(event_kpath->dentries[i], KPATH_ENTRY_SIZE, dname.name);
        if (read_size < 0)
        {
            bpf_printk("get_path: bpf_probe_read_kernel error for name, %d\n", read_size);
            err = read_size;
            break;
        }
        event_kpath->dentry_sizes[i] = read_size - 1;
        err = BPF_CORE_READ_INTO(&d_parent, d, d_parent);
        if (err)
        {
            bpf_printk("get_path: BPF_CORE_READ_INTO error for d_parent %d\n", err);
            break;
        }
        if (!d_parent || d == d_parent)
        {
            ++i;
            break;
        }
        d = d_parent;
    }

    d_parent = NULL;

    if(mnt_d != NULL)
    {
        for ( ; i < KPATH_ENTRIES; ++i)
        {
            err = BPF_CORE_READ_INTO(&dname, mnt_d, d_name);
            if (err)
            {
                bpf_printk("get_path: BPF_CORE_READ_INTO error for d_name, %d\n", err);
                break;
            }
            int read_size = bpf_probe_read_kernel_str(event_kpath->dentries[i], KPATH_ENTRY_SIZE, dname.name);
            if (read_size < 0)
            {
                bpf_printk("get_path: bpf_probe_read_kernel error for name, %d\n", read_size);
                err = read_size;
                break;
            }
            event_kpath->dentry_sizes[i] = read_size - 1;
            err = BPF_CORE_READ_INTO(&d_parent, mnt_d, d_parent);
            if (err)
            {
                bpf_printk("get_path: BPF_CORE_READ_INTO error for d_parent %d\n", err);
                break;
            }
            if (!d_parent || mnt_d == d_parent)
            {
                ++i;
                break;
            }
            mnt_d = d_parent;
        }
    }
    event_kpath->dentries_number = i;
    return err;
}

__attribute__((always_inline))
int get_task_kpath(process_info *event_kpath, unsigned int kpath_type, struct task_struct *task)
{
    struct dentry *dentry = NULL;
    struct dentry *mnt_dentry = NULL;
    struct vfsmount *mnt_point = NULL;
    struct mount *mnt = NULL;
    int err = 0;

    if (kpath_type == kpath_type_process_path)
    {
        err = BPF_CORE_READ_INTO(&mnt_point, task, mm, exe_file, f_path.mnt);
        if (err)
        {
            bpf_printk("get_task_kpath: BPF_CORE_READ_INTO error for mnt_point, %d\n", err);
            mnt_point = NULL;
        }

        err = BPF_CORE_READ_INTO(&dentry, task, mm, exe_file, f_path.dentry);
    }
    else
    {
        err = BPF_CORE_READ_INTO(&mnt_point, task, fs, pwd.mnt);
        if (err)
        {
            bpf_printk("get_task_kpath: BPF_CORE_READ_INTO error for mnt_point, %d\n", err);
            mnt_point = NULL;
        }

        err = BPF_CORE_READ_INTO(&dentry, task, fs, pwd.dentry);
    }
    
    if (err)
    {
        bpf_printk("get_task_kpath: unable to get dentry, error %d\n", err);
        return err;
    }

    if(mnt_point != NULL)
    {
        mnt = container_of(mnt_point, struct mount, mnt);

        err = BPF_CORE_READ_INTO(&mnt_dentry, mnt, mnt_mountpoint);
        if (err)
        {
            bpf_printk("get_task_kpath: BPF_CORE_READ_INTO error for dentry, %d\n", err);
            mnt_dentry = NULL;
        }
    }

    return get_dentry_kpath(dentry, mnt_dentry, event_kpath);
}


static __always_inline void log_event(struct task_struct *task, pid_t parent_pid, pid_t child_pid) 
{
    if (task == NULL)
        return;

    process_info *proc_info = bpf_ringbuf_reserve(&proc_info_buff, sizeof(process_info), 0);
    if (proc_info == NULL)
    {
        bpf_printk("unable to get ring buff mem for sycall=fork, pid=%d for size=%d\n", child_pid, sizeof(process_info));
        return;
    }
    proc_info->pid = child_pid;
    proc_info->parent_pid = parent_pid;

    __builtin_memset(proc_info->full_path, 0, 512); // fix this

    if ( get_task_kpath(proc_info, kpath_type_process_path, task) || proc_info == NULL)
    {
        bpf_printk("unable to get process path for sycall=fork, pid=%d\n", child_pid);
        bpf_ringbuf_discard(proc_info, 0);
        return;
    }

    struct nsproxy *test_nsproxy;
    bpf_probe_read_kernel(&test_nsproxy, sizeof(test_nsproxy), &task->nsproxy);
    struct pid_namespace *pidns;
    bpf_probe_read_kernel(&pidns, sizeof(pidns), &test_nsproxy->pid_ns_for_children);
    
    if (pidns) 
    {
        bpf_probe_read_kernel(&proc_info->ns_inode, sizeof(proc_info->ns_inode), &pidns->ns.inum);   // Namespace inode number
    } 
    else 
    {
        proc_info->ns_inode = 0; // Invalid namespace
    }

    // bpf_printk("Process forked: Parent PID = %d, Child PID = %d, ns node from id = %u", parent_pid, child_pid, proc_info->ns_inode);
    bpf_ringbuf_submit(proc_info, 0);

}

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) 
{
    uint64_t parent_pid = ctx->parent_pid;
    uint64_t child_pid = ctx->child_pid;
    struct task_struct *parent_task = (struct task_struct *)bpf_get_current_task(); 
    log_event(parent_task, parent_pid, child_pid);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) 
{
    pid_t parent_pid = ctx->old_pid;
    pid_t child_pid = ctx->pid;
    struct task_struct *parent_task = (struct task_struct *)bpf_get_current_task(); 
    log_event(parent_task, parent_pid, child_pid);
    return 0;
}

char _license[] SEC("license") = "GPL";
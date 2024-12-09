

typedef unsigned char __u8;
typedef short unsigned int __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define MAX_BUF_SIZE 4096
#define MAX_PROCESS_PATH_LEN 4096
#define MAX_PROC_COUNT 4194304
#define KPATH_ENTRIES       (16)
#define KPATH_ENTRY_SIZE    (256)
#define MAX_CMDLINE_ARGS    (16)
#define SEPARATOR_SIZE      (1)

#define TASK_COMM_LEN 256

enum event_kpath_type
{
    kpath_type_process_path = 0,
    kpath_type_process_cwd = 1
};

typedef struct 
{
    __u64 pid;
    __u64 parent_pid;
    unsigned int ns_inode;
    union
    {
        char full_path[MAX_PROCESS_PATH_LEN];
        char dentries[KPATH_ENTRIES][KPATH_ENTRY_SIZE];
    };
    unsigned long dentry_sizes[KPATH_ENTRIES];
    unsigned int dentries_number;
} process_info;
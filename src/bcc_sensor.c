/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0
 */
#include <uapi/linux/limits.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/stat.h>
#include <uapi/linux/udp.h>

#include <linux/binfmts.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/kdev_t.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/path.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <linux/skbuff.h>

#include <net/sock.h>
#include <net/inet_sock.h>

#define CACHE_UDP

struct mnt_namespace {
    atomic_t count;
    struct ns_common ns;
};

struct mount {
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
    void *cb_args; 
} __randomize_layout;

enum event_type
{
    EVENT_PROCESS_ARG,
    EVENT_PROCESS_EXEC,
    EVENT_PROCESS_EXIT,
    EVENT_PROCESS_CLONE,
    EVENT_FILE_READ,
    EVENT_FILE_WRITE,
    EVENT_FILE_CREATE,
    EVENT_FILE_PATH,
    EVENT_FILE_MMAP,
    EVENT_FILE_TEST,
    EVENT_NET_CONNECT_PRE,
    EVENT_NET_CONNECT_ACCEPT,
    EVENT_NET_CONNECT_DNS_RESPONSE,
    EVENT_NET_CONNECT_WEB_PROXY,
    EVENT_FILE_DELETE,
};

#define IP_PROTO_UDP 17
#define IP_PROTO_TCP 6
#define DNS_RESP_PORT_NUM 53
#define DNS_RESP_MAXSIZE 512
#define PROXY_SERVER_MAX_LEN 100
#define DNS_SEGMENT_LEN 40
#define DNS_SEGMENT_FLAGS_START 0x01
#define DNS_SEGMENT_FLAGS_END 0x02

struct net_t
{
    u32  saddr;
    u32  daddr;
    u16  dport;
    u16  sport;
    u16  ipver;
    u16  protocol;
    u16  dns_flag;
    u32  saddr6[4];
    u32  daddr6[4];
    char dns[DNS_SEGMENT_LEN];
    u32   name_len;
};

struct mmap_args {
    u64 flags;
    u64 prot;
};

// Tells us the state for a probe point's data message
#define PP_NO_EXTRA_DATA 0
#define PP_ENTRY_POINT 1
#define PP_PATH_COMPONENT 2
#define PP_FINALIZED 3

struct data_t
{
    u64 event_time;
    u32 tid;
    u32 pid;
    u8 type;
    u8 state;
    u32 uid;
    u32 ppid;
    u64 inode;
    u32 device;
    u32 mnt_ns;
    union {
        struct mmap_args mmap_args;
        char fname[255];
        struct net_t net;
    };
    int retval;
    u64 start_time;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
BPF_HASH(last_start_time, u32, u64, 8192);
BPF_HASH(last_parent, u32, u32, 8192);
BPF_HASH(root_fs, u32, u64, 3); // stores last known root fs
#endif

BPF_PERF_OUTPUT(events);


static inline struct super_block * _sb_from_dentry(struct dentry *dentry)
{
    struct super_block *sb = NULL;
    // Can't get dentry info return NULL
    if (!dentry)
    {
        goto out;
    }
    // Try dentry inode before dentry's sb
    if (dentry->d_inode)
    {
        sb = dentry->d_inode->i_sb;
    }
    if (sb)
    {
        goto out;
    }
    // This might not exactly be the sb we are looking for
    sb = dentry->d_sb;

out:
    return sb;
}

static inline struct super_block * _sb_from_file(struct file *file)
{
    struct super_block *sb = NULL;

    if (!file)
    {
        goto out;
    }

    if (file->f_inode)
    {
        sb = file->f_inode->i_sb;
    }
    if (sb)
    {
        goto out;
    }
    sb = _sb_from_dentry(file->f_path.dentry);

out:
    return sb;
}

static inline bool __is_special_filesystem(struct super_block *sb)
{
    if (!sb) {
        return false;
    }

    switch (sb->s_magic)
    {
    // Special Kernel File Systems
    case CGROUP_SUPER_MAGIC:
#ifdef CGROUP2_SUPER_MAGIC
    case CGROUP2_SUPER_MAGIC:
#endif /* CGROUP2_SUPER_MAGIC */
    case SELINUX_MAGIC:
#ifdef SMACK_MAGIC
    case SMACK_MAGIC:
#endif /* SMACK_MAGIC */
    case SYSFS_MAGIC:
    case PROC_SUPER_MAGIC:
    case SOCKFS_MAGIC:
    case DEVPTS_SUPER_MAGIC:
    case FUTEXFS_SUPER_MAGIC:
    case ANON_INODE_FS_MAGIC:
    case DEBUGFS_MAGIC:
    case TRACEFS_MAGIC:
#ifdef BINDERFS_SUPER_MAGIC
    case BINDERFS_SUPER_MAGIC:
#endif /* BINDERFS_SUPER_MAGIC */
#ifdef BPF_FS_MAGIC
    case BPF_FS_MAGIC:
#endif /* BPF_FS_MAGIC */

        return true;

    default:
        return false;
    }

    return false;
}

static inline unsigned int __get_mnt_ns_id(struct task_struct *task)
{
    struct nsproxy *nsproxy;

    if (task && task->nsproxy)
    {
        return task->nsproxy->mnt_ns->ns.inum;
    }
    return 0;
}

static inline void __set_device_from_sb(struct data_t *data, struct super_block *sb)
{
    if (!data || !sb)
    {
        return;
    }

    data->device = new_encode_dev(sb->s_dev);
}

static inline void __set_device_from_file(struct data_t *data, struct file *file)
{
    struct super_block *sb = NULL;

    if (!data || !file)
    {
        return;
    }

    sb = _sb_from_file(file);
    if (!sb)
    {
        return;
    }
    __set_device_from_sb(data, sb);
}

// Assumed current context is what is valid!
static inline void __set_key_entry_data(struct data_t *data, struct file *file)
{
    struct inode *pinode = NULL;
    struct super_block *sb;
    u64 id; 

    data->event_time = bpf_ktime_get_ns();
    id = bpf_get_current_pid_tgid();
    data->tid = id & 0xffffffff;
    data->pid = id >> 32;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data->start_time = task->start_time;
    data->uid = __kuid_val(task->cred->uid);
    data->ppid = task->real_parent->tgid;
    data->mnt_ns = __get_mnt_ns_id(task);
#else
    u64 *last_start = last_start_time.lookup(&data->pid);
    if (last_start)
    {
        data->start_time = *last_start;
    }
    u32 *ppid = last_parent.lookup(&data->pid);
    if (ppid)
    {
        data->ppid = *ppid;
    }
#endif

    if (!file)
    {
        return;
    }
    bpf_probe_read(&pinode, sizeof(pinode), &(file->f_inode));
    if (!pinode)
    {
        return;
    }

    bpf_probe_read(&data->inode, sizeof(data->inode), &pinode->i_ino);
}

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read(data->fname, sizeof(data->fname), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    //const char *argp = NULL;
    void *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if(argp)
    {
        return __submit_arg(ctx, argp, data);
    }
    return 0;
}

#ifndef MAX_PATH_ITER
#define MAX_PATH_ITER 24
#endif
static inline int __do_file_path(struct pt_regs *ctx,
    struct dentry *dentry, struct vfsmount *mnt, struct data_t *data)
{
    struct mount *real_mount = NULL;
    struct mount *mnt_parent = NULL;
    struct dentry *mnt_root = NULL;
    struct dentry *new_mnt_root = NULL;
    struct dentry *parent_dentry = NULL;
    struct qstr   sp   = {};

    struct dentry *root_fs_dentry = NULL;
    struct vfsmount *root_fs_vfsmnt = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
    // We can ifdef this block to make this act more like either
    // d_absolute_path or __d_path
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task->fs)
    {
        // We can get root fs path from mnt_ns or task
        root_fs_vfsmnt = task->fs->root.mnt;
        root_fs_dentry = task->fs->root.dentry;
    }
#else
    u32 index = 0;
    struct dentry **t_dentry = root_fs.lookup(&index);
    if (t_dentry)
    {
      root_fs_dentry = *t_dentry;
    }
    index = 1;
    struct vfsmount **t_vfsmount = root_fs.lookup(&index);
    if (t_vfsmount)
    {
      root_fs_vfsmnt = *t_vfsmount;
    }
#endif

    mnt_root = mnt->mnt_root;

    // poorman's container_of
    real_mount = ((void *)mnt) - offsetof(struct mount, mnt);

    // compiler doesn't seem to mind accessing stuff without bpf_probe_read
    mnt_parent = real_mount->mnt_parent;

    /*
     * File Path Walking. This may not be completely accurate but
     * should hold for most cases. Paths for private mount namespaces might work.
     */
    data->state = PP_PATH_COMPONENT;
#pragma clang loop unroll(full)
    for (int i = 1; i < MAX_PATH_ITER; ++i) {
        if (dentry == root_fs_dentry)
        {
            goto out;
        }

        bpf_probe_read(&parent_dentry, sizeof(parent_dentry), &(dentry->d_parent));
        if (dentry == parent_dentry || dentry == mnt_root) {

            bpf_probe_read(&dentry, sizeof(struct dentry *), &(real_mount->mnt_mountpoint));
            real_mount = mnt_parent;
            bpf_probe_read(&mnt, sizeof(struct vfsmnt *), &(real_mount->mnt));
            mnt_root = mnt->mnt_root;
            if (mnt == root_fs_vfsmnt)
            {
                goto out;
            }

            // prefetch next real mount parent.
            mnt_parent = real_mount->mnt_parent;
            if (mnt_parent == real_mount)
            {
                goto out;
            }
        }
        else {
            bpf_probe_read(&sp, sizeof(sp), (void *)&(dentry->d_name));
            bpf_probe_read(&data->fname, sizeof(data->fname), sp.name);
            dentry = parent_dentry;
            events.perf_submit(ctx, data, sizeof(*data));
        }
    }
    
out:
    data->state = PP_FINALIZED;
    return 0;
}

static inline int __do_dentry_path(struct pt_regs *ctx, struct dentry *dentry, struct data_t *data)
{
    struct dentry *cd = NULL;
    struct dentry *pe = NULL;
    struct qstr sp = {};

    bpf_probe_read(&sp, sizeof(struct qstr), (void *)&(dentry->d_name));
    if (sp.name == NULL)
    {
        goto out;
    }
    bpf_probe_read(&data->fname, sizeof(data->fname), (void *)sp.name);

    bpf_probe_read(&pe, sizeof(pe), &(dentry->d_parent));
    bpf_probe_read(&cd, sizeof(cd), &(dentry));
    data->state = PP_PATH_COMPONENT;

#pragma unroll
    for (int i = 0; i < MAX_PATH_ITER; i++) {
        if (pe == cd || pe == NULL)
        {
            break;
        }
        bpf_probe_read(&sp, sizeof(struct qstr), (void *)&(cd->d_name));
        if((void *)sp.name != NULL)
        {
            bpf_probe_read(data->fname, sizeof(data->fname), (void *)sp.name);
            events.perf_submit(ctx, data, sizeof(*data));
        }

        bpf_probe_read(&cd, sizeof(cd), &(pe));
        bpf_probe_read(&pe, sizeof(pe), &(pe->d_parent));
    }

    data->fname[0] = '\0';
    events.perf_submit(ctx, data, sizeof(*data));

out:
    data->state = PP_FINALIZED;
    return 0;
}

#define MAXARG 30
int syscall__on_sys_execveat(struct pt_regs *ctx,
        int fd, const char __user *filename,
        const char __user *const __user *argv,
        const char __user *const __user *envp,
        int flags)
{
    struct data_t       data = {};

    __set_key_entry_data(&data, NULL);
    data.type       = EVENT_PROCESS_ARG;
    data.state = PP_ENTRY_POINT;


#pragma unroll
    for(int i = 0; i < MAXARG; i++)
    {
        if(submit_arg(ctx, (void *)&argv[i], &data) == 0)
        {
            goto out;
        }
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}
int syscall__on_sys_execve(struct pt_regs *ctx,
                  const char __user *filename,
                  const char __user *const __user *argv,
                  const char __user *const __user *envp)
{
    struct data_t       data = {};

    __set_key_entry_data(&data, NULL);
    data.type       = EVENT_PROCESS_ARG;
    data.state = PP_ENTRY_POINT;

#pragma unroll
    for(int i = 0; i < MAXARG; i++)
    {
        if(submit_arg(ctx, (void *)&argv[i], &data) == 0)
        {
            goto out;
        }
    }

    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

//Note that this can be called more than one from the same pid
int after_sys_execve(struct pt_regs *ctx)
{
    struct task_struct *task;
    struct data_t       data = {};
    u64 *start_time = NULL;
    u32 *ppid = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
    data.pid = bpf_get_current_pid_tgid() >> 32;
    start_time = last_start_time.lookup(&data.pid);
    if (start_time)
    {
        data.start_time = *start_time;
    }

    ppid = last_parent.lookup(&data.pid);
    if (ppid)
    {
        data.ppid = *ppid;
    }
#else
    task = (struct task_struct *)bpf_get_current_task();
    data.uid = __kuid_val(task->cred->uid);
    data.start_time = task->start_time;
    data.ppid = task->real_parent->tgid;
#endif
    data.tid = bpf_get_current_pid_tgid() & 0xffffffff;
    data.event_time = bpf_ktime_get_ns();
    data.state = PP_FINALIZED;
    data.type = EVENT_PROCESS_ARG;
    data.retval = PT_REGS_RC(ctx);

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
BPF_TABLE("lru_hash", u64, u32, file_write_cache, 16384);
BPF_TABLE("lru_hash", u64, u32, file_creat_cache, 16384);
#else
BPF_HASH(file_write_cache, u64, u32, 16384);
BPF_HASH(file_creat_cache, u64, u32, 16384);
#endif

// Only need this hook for kernels without lru_hash
int on_security_file_free(struct pt_regs *ctx, struct file *file)
{
    if (!file)
    {
        return 0;
    }
    u64 file_cache_key = (u64)file;
    
    file_write_cache.delete(&file_cache_key);
    file_creat_cache.delete(&file_cache_key);
    return 0;
}

int on_security_mmap_file(struct pt_regs *ctx,
        struct file *file, unsigned long prot, unsigned long flags)
{
    unsigned long exec_flags;
    struct data_t data = {};

    if (!file)
    {
        goto out;
    }
    if (!(prot & PROT_EXEC))
    {
        goto out;
    }

    exec_flags = flags & (MAP_DENYWRITE|MAP_EXECUTABLE);
    if (exec_flags == (MAP_DENYWRITE|MAP_EXECUTABLE))
    {
        data.type = EVENT_PROCESS_EXEC;
    }
    else
    {
        data.type = EVENT_FILE_MMAP;
    }

    // event specific data
    data.state = PP_ENTRY_POINT;
    __set_key_entry_data(&data, file);
    __set_device_from_file(&data, file);
    data.mmap_args.flags = flags;
    data.mmap_args.prot = prot;
    // submit initial event data
    events.perf_submit(ctx, &data, sizeof(data));

    // submit file path event data
    __do_file_path(ctx, file->f_path.dentry, file->f_path.mnt, &data);
    events.perf_submit(ctx, &data, sizeof(data));
out:
    return 0;
}


int trace_write_entry(struct pt_regs *ctx,
                      struct file *   file,
                      char __user *buf,
                      size_t       count)
{
    struct data_t data = {};
    struct super_block *sb = NULL;
    struct inode *inode = NULL;
    int mode;

    if (!file)
    {
        goto out;
    }

    sb = _sb_from_file(file);
    if (!sb)
    {
        goto out;
    }

    if (__is_special_filesystem(sb))
    {
        goto out;
    }

    bpf_probe_read(&inode, sizeof(inode), &(file->f_inode));
    if (!inode)
    {
        goto out;
    }
#if LINUX_VERSION_CODE >=KERNEL_VERSION(4, 8, 0)
    bpf_probe_read(&mode, sizeof(mode), &(inode->i_mode));
    if (!S_ISREG(mode))
    {
        goto out;
    }
#endif
    __set_key_entry_data(&data, file);
    __set_device_from_sb(&data, sb);

    u32 *cachep; 
    u64 file_cache_key = (u64)file;

    cachep = file_write_cache.lookup(&file_cache_key);
    if (cachep)
    {
        // if we really care about that multiple tasks 
        // these are likely threads or less likely inherited from a fork 
        if (*cachep == data.pid)
        {
            goto out;
        }
        file_write_cache.update(&file_cache_key, &data.pid);
        goto out;
    }
    else
    {
        file_write_cache.insert(&file_cache_key, &data.pid);
    }

    data.state = PP_ENTRY_POINT;
    data.type = EVENT_FILE_WRITE;
    events.perf_submit(ctx, &data, sizeof(data));

    __do_file_path(ctx, file->f_path.dentry, file->f_path.mnt, &data);
    events.perf_submit(ctx, &data, sizeof(data));
out:
    return 0;
}

struct file_data
{
    u64  device;
    u64  inode;
};

// This hash tracks the "observed" file-create events.  This will not be 100% accurate because we will report a
//  file create for any file the first time it is opened with WRITE|TRUNCATE (even if it already exists).  It
//  will however serve to de-dup some events.  (Ie.. If a program does frequent open/write/close.)
BPF_HASH(file_map, struct file_data, u32, 500);

// This hook may not be very accurate but at least tells us the intent
// to create the file if needed. So this will likely be written to next.
int on_security_file_open(struct pt_regs *ctx, struct file *file)
{
    struct data_t data = {};
    struct super_block *sb = NULL;
    struct inode *inode = NULL;
    int mode;

    if (!file)
    {
        goto out;
    }
    if (!(file->f_flags & (O_CREAT|O_TRUNC)))
    {
        goto out;
    }

    sb = _sb_from_file(file);
    if (!sb)
    {
        goto out;
    }

    if (__is_special_filesystem(sb))
    {
        goto out;
    }

    bpf_probe_read(&inode, sizeof(inode), &(file->f_inode));
    if (!inode)
    {
        goto out;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
    bpf_probe_read(&mode, sizeof(mode), &(inode->i_mode));
    if (!S_ISREG(mode))
    {
        goto out;
    }
#endif
    __set_key_entry_data(&data, file);
    __set_device_from_sb(&data, sb);

    u32 *cachep;
    u64 file_cache_key = (u64)file;

    struct file_data key = {
        .device = data.device,
        .inode  = data.inode
    };

    // If this is already tracked skip the event.  Otherwise add it to the tracking table.
    u32 *file_exists = file_map.lookup(&key);
    if (file_exists)
    {
        goto out;
    }
    else
    {
        file_map.update(&key, &data.pid);
    }



    cachep = file_creat_cache.lookup(&file_cache_key);
    if (cachep)
    {
        if (*cachep == data.pid)
        {
            goto out;
        }
        file_creat_cache.update(&file_cache_key, &data.pid);
        goto out;
    }
    else
    {
        file_creat_cache.insert(&file_cache_key, &data.pid);
    }

    data.state = PP_ENTRY_POINT;
    data.type = EVENT_FILE_CREATE;
    events.perf_submit(ctx, &data, sizeof(data));

    __do_file_path(ctx, file->f_path.dentry, file->f_path.mnt, &data);

    events.perf_submit(ctx, &data, sizeof(data));

out:
    return 0;
}

int on_security_inode_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    struct data_t data = {};
    struct super_block *sb    = NULL;
    struct inode       *inode = NULL;
    int                mode;

    if (!dentry)
    {
        goto out;
    }

    sb = _sb_from_dentry(dentry);
    if (!sb)
    {
        goto out;
    }

    if (__is_special_filesystem(sb))
    {
        goto out;
    }

    __set_key_entry_data(&data, NULL);

    bpf_probe_read(&inode, sizeof(inode), &(dentry->d_inode));
    if (inode)
    {
        bpf_probe_read(&data.inode, sizeof(data.inode), &inode->i_ino);
    }

    __set_device_from_sb(&data, sb);

    // Delete the file from the tracking so that it will be reported the next time it is created.
    struct file_data key = {
        .device = data.device,
        .inode  = data.inode
    };

    file_map.delete(&key);

    data.state = PP_ENTRY_POINT;
    data.type  = EVENT_FILE_DELETE;
    events.perf_submit(ctx, &data, sizeof(data));

    __do_dentry_path(ctx, dentry, &data);

    events.perf_submit(ctx, &data, sizeof(data));

out:
    return 0;
}

int on_wake_up_new_task(struct pt_regs *ctx, struct task_struct *task)
{
    struct inode *pinode = NULL;
    struct data_t data = {};
    struct file *exe_file = NULL;
    if (!task)
    {
        goto out;
    }

    if (task->tgid != task->pid)
    {
        goto out;
    }

    data.event_time = bpf_ktime_get_ns();
    data.type = EVENT_PROCESS_CLONE;
    data.tid = task->pid;
    data.pid = task->tgid;
    data.start_time = task->start_time;
    data.ppid = task->real_parent->tgid;
    data.state = PP_NO_EXTRA_DATA;
    data.uid = __kuid_val(task->real_parent->cred->uid);
    data.mnt_ns = __get_mnt_ns_id(task);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
    // Store last reported start_time where ever we can grab the task struct
    // For older kernels we could probe when tasks are scheduled to wake
    // to cache more tasks.
    u64 parent_start_time = task->real_parent->start_time;
    last_start_time.update(&data.ppid, &parent_start_time);
    last_parent.update(&data.pid, &data.ppid);
    last_start_time.update(&data.pid, &data.start_time);
    last_parent.update(&data.pid, &data.ppid);

    // Poorman's method for storing root fs path data.
    // This is to prevent us from iterating past '/'
    u32 index;
    struct dentry *root_fs_dentry = task->fs->root.dentry;
    struct vfsmount *root_fs_vfsmount = task->fs->root.mnt;
    index = 0;
    root_fs.update(&index, &root_fs_dentry);
    index += 1;
    root_fs.update(&index, &root_fs_vfsmount);
#endif

    // Get this in case it's a non-standard process
    bpf_get_current_comm(&data.fname, TASK_COMM_LEN);
    if ((task->flags & PF_KTHREAD) || !task->mm)
    {
        events.perf_submit(ctx, &data, sizeof(data));
        goto out;
    }

    exe_file = task->mm->exe_file;
    if (!exe_file)
    {
        events.perf_submit(ctx, &data, sizeof(data));
        goto out;
    }
    bpf_probe_read(&pinode, sizeof(pinode), &(exe_file->f_inode));
    if (!pinode)
    {
        events.perf_submit(ctx, &data, sizeof(data));
        goto out;
    }
    bpf_probe_read(&data.inode, sizeof(data.inode), &pinode->i_ino);
    __set_device_from_file(&data, exe_file);

    data.state = PP_ENTRY_POINT;

    events.perf_submit(ctx, &data, sizeof(data));
    __do_file_path(ctx, exe_file->f_path.dentry, exe_file->f_path.mnt, &data);
    events.perf_submit(ctx, &data, sizeof(data));

out:
    return 0;
}

#ifdef CACHE_UDP
struct ip_key {
    uint32_t pid;
    uint64_t start_time;
    uint16_t dport;
    uint16_t sport;
    uint32_t daddr;
    uint32_t saddr;
};
struct ip6_key {
    uint32_t pid;
    uint64_t start_time;
    uint16_t dport;
    uint16_t sport;
    uint32_t daddr6[4];
    uint32_t saddr6[4];
};
#define FLOW_TX 0x01
#define FLOW_RX 0x02
struct ip_entry {
    u8 flow;
};
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
// UDP Burst cache
BPF_TABLE("hash", u32, struct ip_key, ip_cache, 8192);
BPF_TABLE("hash", u32, struct ip6_key, ip6_cache, 8192);
#else
BPF_TABLE("lru_hash", struct ip_key, struct ip_entry, ip_cache, 8192);
BPF_TABLE("lru_hash", struct ip6_key, struct ip_entry, ip6_cache, 8192);
#endif

static inline bool has_ip_cache(struct ip_key *ip_key, u8 flow)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
    struct ip_key *ip_entry = ip_cache.lookup(&ip_key->pid);
    if (ip_entry)
    {
        if (ip_entry->dport == ip_key->dport &&
            ip_entry->sport == ip_key->sport &&
            ip_entry->daddr == ip_key->daddr &&
            ip_entry->saddr == ip_key->saddr)
        {
            return true;
        }
        else
        {
            // Update entry
            ip_cache.update(&ip_key->pid, ip_key);
        }
    }
    else
    {
        ip_cache.insert(&ip_key->pid, ip_key);
    }
#else
    struct ip_entry *ip_entry = ip_cache.lookup(ip_key);
    if (ip_entry)
    {
        if ((ip_entry->flow & flow))
        {
            return true;
        }
        // Updates map entry
        ip_entry->flow |= flow;
    }
    else
    {
        struct ip_entry new_entry = {};
        new_entry.flow = flow;
        ip_cache.insert(ip_key, &new_entry);
    }
#endif
    return false;

}

static inline bool has_ip6_cache(struct ip6_key *ip6_key, u8 flow)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
    struct ip6_key *ip_entry = ip6_cache.lookup(&ip6_key->pid);
    if (ip_entry)
    {
        if (ip_entry->dport == ip6_key->dport &&
            ip_entry->sport == ip6_key->sport &&
            ip_entry->daddr6[0] == ip6_key->daddr6[0] &&
            ip_entry->daddr6[1] == ip6_key->daddr6[1] &&
            ip_entry->daddr6[2] == ip6_key->daddr6[2] &&
            ip_entry->daddr6[3] == ip6_key->daddr6[3] &&
            ip_entry->saddr6[0] == ip6_key->saddr6[0] &&
            ip_entry->saddr6[1] == ip6_key->saddr6[1] &&
            ip_entry->saddr6[2] == ip6_key->saddr6[2] &&
            ip_entry->saddr6[3] == ip6_key->saddr6[3])
        {
            return true;
        }
        else
        {
            // Update entry
            ip6_cache.update(&ip6_key->pid, ip6_key);
        }
    }
    else
    {
        ip6_cache.insert(&ip6_key->pid, ip6_key);
    }
#else
    struct ip_entry *ip_entry = ip6_cache.lookup(ip6_key);
    if (ip_entry)
    {
        if ((ip_entry->flow & flow))
        {
            return true;
        }
        // Updates map entry
        ip_entry->flow |= flow;
    }
    else
    {
        struct ip_entry new_entry = {};
        new_entry.flow = flow;
        ip6_cache.insert(ip6_key, &new_entry);
    }
#endif
    return false;
}
#endif /* CACHE_UDP */

int on_security_task_free(struct pt_regs *ctx, struct task_struct *task)
{
    struct data_t data = {};
    if (!task)
    {
        goto out;
    }
    if (task->tgid != task->pid)
    {
        goto out;
    }

    data.event_time = bpf_ktime_get_ns();
    data.type = EVENT_PROCESS_EXIT;
    data.tid = task->pid;
    data.pid = task->tgid;
    data.start_time = task->start_time;
    if (task->real_parent)
    {
        data.ppid = task->real_parent->tgid;
    }
    events.perf_submit(ctx, &data, sizeof(data));
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
    last_start_time.delete(&data.pid);
    last_parent.delete(&data.pid);
#ifdef CACHE_UDP
    // Remove burst cache entries
    ip_cache.delete(&data.pid);
    ip6_cache.delete(&data.pid);
#endif /* CACHE_UDP */
#endif
out:
    return 0;
}

BPF_HASH(currsock, u64, struct sock *);
BPF_HASH(currsock2, u64, struct msghdr *);
BPF_HASH(currsock3, u64, struct sock *);

int trace_connect_v4_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 id = bpf_get_current_pid_tgid();
    currsock.update(&id, &sk);
    return 0;
}

int trace_connect_v6_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 id = bpf_get_current_pid_tgid();
    currsock.update(&id, &sk);
    return 0;
}

static int trace_connect_return(struct pt_regs *ctx, short ipver)
{
    u64 id   = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int ret = PT_REGS_RC(ctx);
    if(ret != 0)
    {
        currsock.delete(&id);
        return 0;
    }

    struct sock **skpp;
    skpp = currsock.lookup(&id);
    if(skpp == 0)
    {
        return 0;
    }

    struct data_t data  = {};
    struct sock * skp   = *skpp;
    u16           dport = skp->__sk_common.skc_dport;

    __set_key_entry_data(&data, NULL);
    data.type         = EVENT_NET_CONNECT_PRE;
    data.net.protocol = IP_PROTO_TCP;
    data.net.dport    = dport; // cbdaemon expects network order

    struct inet_sock *sockp = (struct inet_sock *)skp;
    data.net.sport          = sockp->inet_sport;


    if(ipver == 4)
    {
        data.net.ipver = AF_INET;
        data.net.saddr = skp->__sk_common.skc_rcv_saddr;
        data.net.daddr = skp->__sk_common.skc_daddr;

        events.perf_submit(ctx, &data, sizeof(data));
    }
    else
    {
        data.net.ipver = AF_INET6;
        bpf_probe_read(&data.net.saddr6,
                       sizeof(data.net.saddr6),
                       skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data.net.daddr6,
                       sizeof(data.net.daddr6),
                       skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

        events.perf_submit(ctx, &data, sizeof(data));
    }

    currsock.delete(&id);
    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 6);
}

static inline bool check_family(struct sock *sk, u16 expected_family)
{
    u16 family = sk->__sk_common.skc_family;
    return family == expected_family;
}

int trace_skb_recv_udp(struct pt_regs *ctx)
{
    u64 id   = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    struct sk_buff *skb = (struct sk_buff *)PT_REGS_RC(ctx);
    if(skb == NULL)
    {
        return 0;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
    // Older kernels we probe __skb_recv_datagram which can be used by
    // other protocols. We filter by sk_family or skb->protocol
    if (!skb->sk)
    {
        return 0;
    }
    if (!(skb->sk->sk_family == AF_INET ||
          skb->sk->sk_family == AF_INET6))
    {
        return 0;
    }
#endif
    struct udphdr *udphdr = NULL;
    struct iphdr *iphdr = NULL;

    iphdr = (struct iphdr *)(skb->head + skb->network_header);

    uint8_t version = 0;

    bpf_probe_read(&version, 1, ((u8 *)&iphdr->tos) - 1);

    struct data_t data = {};

    data.type         = EVENT_NET_CONNECT_ACCEPT;
    __set_key_entry_data(&data, NULL);
    
    data.net.protocol = IP_PROTO_UDP;

    // Before the bitfield read access is directly available in bcc:
    //  - use next struct member with a byte offset to copy area of bitfield containing the version info
    //  - use masks and shift based on endianness to get the IP version

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    version = (version & 0xF0);
    version = version >> 4;
#else
    version = (version & 0x0F);
#endif

    udphdr = (struct udphdr *)(skb->head + skb->transport_header);
    data.net.dport = udphdr->dest;
    data.net.sport = udphdr->source;

    if (version == 4)
    {
        data.net.ipver = AF_INET;
        data.net.saddr = iphdr->saddr;
        data.net.daddr = iphdr->daddr;

#ifdef CACHE_UDP
        struct ip_key ip_key = {};
        ip_key.pid = data.pid;
        ip_key.start_time = data.start_time;
        bpf_probe_read(&ip_key.dport, sizeof(data.net.dport), &data.net.dport);
        bpf_probe_read(&ip_key.sport, sizeof(data.net.sport), &data.net.sport);
        bpf_probe_read(&ip_key.daddr, sizeof(data.net.daddr), &data.net.daddr);
        bpf_probe_read(&ip_key.saddr, sizeof(data.net.saddr), &data.net.saddr);
        if (has_ip_cache(&ip_key, FLOW_RX))
        {
            return 0;
        }
#endif /* CACHE_UDP */
    }
    else
    {
        // Why IPv6 address/port is read in a differen way than IPv4:
        //  - BPF C compiled to BPF instructions don't always do what we expect
        //  - especially when accessing members of a struct containing bitfields

        data.net.ipver = AF_INET6;
        struct ipv6hdr *ipv6hdr = (struct ipv6hdr *)iphdr;
        bpf_probe_read(data.net.saddr6, sizeof(uint32_t) * 4, &ipv6hdr->saddr.s6_addr32);
        bpf_probe_read(data.net.daddr6, sizeof(uint32_t) * 4, &ipv6hdr->daddr.s6_addr32);

#ifdef CACHE_UDP
        struct ip6_key ip_key = {};
        ip_key.pid = data.pid;
        ip_key.start_time = data.start_time;
        bpf_probe_read(&ip_key.dport, sizeof(data.net.dport), &data.net.dport);
        bpf_probe_read(&ip_key.sport, sizeof(data.net.sport), &data.net.sport);
        bpf_probe_read(ip_key.daddr6, sizeof(data.net.daddr6), &ipv6hdr->daddr.s6_addr32);
        bpf_probe_read(ip_key.saddr6, sizeof(data.net.saddr6), &ipv6hdr->saddr.s6_addr32);
        if (has_ip6_cache(&ip_key, FLOW_RX))
        {
            return 0;
        }
#endif /* CACHE_UDP */
    }

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}


int trace_accept_return(struct pt_regs *ctx)
{
    u64 id   = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if(newsk == NULL)
    {
        return 0;
    }

    struct data_t data = {};

    __set_key_entry_data(&data, NULL);
    data.type = EVENT_NET_CONNECT_ACCEPT;


    if(check_family(newsk, AF_INET))
    {
        data.net.ipver = AF_INET;

        data.net.protocol = IP_PROTO_TCP;
        data.net.saddr    = newsk->__sk_common.skc_rcv_saddr;
        data.net.daddr    = newsk->__sk_common.skc_daddr;

        data.net.sport = newsk->__sk_common.skc_num; // host order sport
        data.net.dport = newsk->__sk_common.skc_dport; // network order dport

        if(data.net.saddr != 0 && data.net.daddr != 0 && data.net.sport != 0 &&
           data.net.dport != 0)
        {
            events.perf_submit(ctx, &data, sizeof(data));
        }
    }
    else if(check_family(newsk, AF_INET6))
    {
        data.net.ipver = AF_INET6;

        bpf_probe_read(&data.net.saddr6,
                       sizeof(data.net.saddr6),
                       newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data.net.daddr6,
                       sizeof(data.net.daddr6),
                       newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

        data.net.sport = newsk->__sk_common.skc_num;
        u16 dport      = newsk->__sk_common.skc_dport;
        data.net.dport = dport;

        events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}


int trace_udp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg,
                             size_t length,
                             int noblock,
                             int flags)
{
    u64            pid;

    pid = bpf_get_current_pid_tgid();
    if (flags != MSG_PEEK)
    {
        currsock2.update(&pid, &msg);
        currsock3.update(&pid, &sk);
    }

    return 0;
}

int trace_udp_recvmsg_return(struct pt_regs *ctx,
                             struct sock *   sk,
                             struct msghdr * msg)
{
    int ret = PT_REGS_RC(ctx);
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    struct msghdr **msgpp; // for DNS receive probe

    msgpp = currsock2.lookup(&id);
    if(msgpp == 0)
    {
        return 0; // missed entry
    }

    struct sock **skpp;
    skpp = currsock3.lookup(&id);
    if(skpp == 0)
    {
        return 0;
    }

    if(ret <= 0)
    {
        currsock2.delete(&id);
        return 0;
    }

    struct data_t data = {};
    __set_key_entry_data(&data, NULL);
    data.type         = EVENT_NET_CONNECT_DNS_RESPONSE;
    data.net.protocol = IP_PROTO_UDP;

    struct sock *skp = *skpp;
    data.net.ipver   = skp->__sk_common.skc_family;

    // Send DNS info if port is DNS
    struct msghdr *msgp = *msgpp;

    const char __user *dns;
    dns = (msgp->msg_iter).iov->iov_base;

    u16 dport     = (((struct sockaddr_in *)(msgp->msg_name))->sin_port);
    u16 len       = ret;
    data.net.name_len = ret;

    if(DNS_RESP_PORT_NUM == ntohs(dport))
    {
#pragma unroll
        for(int i = 1; i <= (DNS_RESP_MAXSIZE / DNS_SEGMENT_LEN) + 1; ++i)
        {
            if(len > 0 && len < DNS_RESP_MAXSIZE)
            {
                data.net.dns_flag = 0;
                bpf_probe_read(&data.net.dns, DNS_SEGMENT_LEN, dns);
                if(i == 1) data.net.dns_flag = DNS_SEGMENT_FLAGS_START;
                if(len <= 40) data.net.dns_flag |= DNS_SEGMENT_FLAGS_END;

                events.perf_submit(ctx, &data, sizeof(data));
                len = len - DNS_SEGMENT_LEN;
                dns = dns + DNS_SEGMENT_LEN;
            }
            else
            {
                break;
            }
        }
    }

    currsock2.delete(&id);
    currsock3.delete(&id);
    return 0;
}

int trace_udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg)
{
    u64 id;

    id = bpf_get_current_pid_tgid();
    currsock3.update(&id, &sk);
    return 0;
}

int trace_udp_sendmsg_return(struct pt_regs *ctx,
                             struct sock *   sk,
                             struct msghdr * msg)
{
    int ret = PT_REGS_RC(ctx);
    u64 id = bpf_get_current_pid_tgid();

    struct sock **skpp;
    skpp = currsock3.lookup(&id);
    if(skpp == 0)
    {
        return 0;
    }

    if(ret <= 0)
    {
        currsock3.delete(&id);
        return 0;
    }

    struct data_t data = {};
    __set_key_entry_data(&data, NULL);
    data.type         = EVENT_NET_CONNECT_PRE;
    data.net.protocol = IP_PROTO_UDP;

    // get ip version
    struct sock *skp = *skpp;
    data.net.ipver   = skp->__sk_common.skc_family;

    if(data.net.ipver == AF_INET)
    {
        data.net.daddr = skp->__sk_common.skc_daddr;
        data.net.dport = skp->__sk_common.skc_dport; // already network order

        data.net.saddr = skp->__sk_common.skc_rcv_saddr;
        data.net.sport = skp->__sk_common.skc_num; // host order sport

#ifdef CACHE_UDP
        struct ip_key ip_key = {};
        ip_key.pid = data.pid;
        ip_key.start_time = data.start_time;
        bpf_probe_read(&ip_key.dport, sizeof(data.net.dport), &data.net.dport);
        bpf_probe_read(&ip_key.sport, sizeof(data.net.sport), &data.net.sport);
        bpf_probe_read(&ip_key.daddr, sizeof(data.net.daddr), &data.net.daddr);
        bpf_probe_read(&ip_key.saddr, sizeof(data.net.saddr), &data.net.saddr);

        if (has_ip_cache(&ip_key, FLOW_TX))
        {
            goto out;
        }
#endif /* CACHE_UDP */
    }
    else
    {
        data.net.dport = skp->__sk_common.skc_dport;
        bpf_probe_read(&data.net.daddr6,
                       sizeof(data.net.daddr6),
                       &(skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32));
        bpf_probe_read(&data.net.saddr6,
                       sizeof(data.net.saddr6),
                       &(skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32));
        data.net.sport = skp->__sk_common.skc_num; // host order sport

#ifdef CACHE_UDP
        struct ip6_key ip_key = {};
        ip_key.pid = data.pid;
        ip_key.start_time = data.start_time;
        bpf_probe_read(&ip_key.dport, sizeof(data.net.dport), &data.net.dport);
        bpf_probe_read(&ip_key.sport, sizeof(data.net.sport), &data.net.sport);
        bpf_probe_read(ip_key.daddr6, sizeof(data.net.daddr6),
                       &(skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32));
        bpf_probe_read(ip_key.saddr6, sizeof(data.net.saddr6),
                       &(skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32));
        if (has_ip6_cache(&ip_key, FLOW_TX))
        {
            goto out;
        }
#endif /* CACHE_UDP */
    }
    events.perf_submit(ctx, &data, sizeof(data));

out:
    currsock3.delete(&id);
    return 0;
}


int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg)
{
    struct data_t data = {};
    int cmd    = 0;
    int offset = 0;

    // filter proxy traffic
    const char __user *p       = (msg->msg_iter).iov->iov_base;
    __kernel_size_t    cmd_len = (msg->msg_iter).iov->iov_len;

    if((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T') && (p[4] != '/'))
    {
        cmd    = 0;
        offset = 3;
        goto CATCH;
    }
    if((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T') && (p[4] != '/'))
    {
        cmd    = 1;
        offset = 3;
        goto CATCH;
    }
    if((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T') &&
       (p[5] != '/'))
    {
        cmd    = 2;
        offset = 4;
        goto CATCH;
    }
    if((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') &&
       (p[4] == 'T') && (p[5] == 'E') && (p[7] != '/'))
    {
        cmd    = 3;
        offset = 6;
        goto CATCH;
    }
    if((p[0] == 'C') && (p[1] == 'O') && (p[2] == 'N') && (p[3] == 'N') &&
       (p[4] == 'E') && (p[5] == 'C') && (p[6] == 'T') && (p[8] != '/'))
    {
        cmd    = 4;
        offset = 7;
        goto CATCH;
    }
    return 0;

CATCH:
    data.type = EVENT_NET_CONNECT_WEB_PROXY;
    __set_key_entry_data(&data, NULL);

    data.net.name_len = cmd_len;

    // TODO: calculate real url length
    int len = PROXY_SERVER_MAX_LEN;

    if(sk->sk_family == AF_INET)
    {
        data.net.ipver = AF_INET;

        data.net.saddr = sk->__sk_common.skc_rcv_saddr;
        data.net.daddr = sk->__sk_common.skc_daddr;

        data.net.sport = sk->__sk_common.skc_num; // host order sport
        u16 dport      = sk->__sk_common.skc_dport;
        data.net.dport = ntohs(dport); // host order dport
    }
    else
    {
        data.net.ipver = AF_INET6;
        bpf_probe_read(&data.net.saddr6,
                       sizeof(data.net.saddr6),
                       sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data.net.daddr6,
                       sizeof(data.net.daddr6),
                       sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data.net.sport = sk->__sk_common.skc_num; // host order sport
        u16 dport      = sk->__sk_common.skc_dport;
        data.net.dport = ntohs(dport); // host order dport
    }

    p = p + offset + 1;
#pragma unroll
    for(int i = 1; i <= (PROXY_SERVER_MAX_LEN / DNS_SEGMENT_LEN) + 1; ++i)
    {
        if(len > 0 && len < DNS_RESP_MAXSIZE)
        {
            data.net.dns_flag = 0;
            bpf_probe_read(&data.net.dns, DNS_SEGMENT_LEN, p);
            if(i == 1) data.net.dns_flag = DNS_SEGMENT_FLAGS_START;
            if(len <= 40) data.net.dns_flag |= DNS_SEGMENT_FLAGS_END;

            events.perf_submit(ctx, &data, sizeof(data));
            len = len - DNS_SEGMENT_LEN;
            p   = p + DNS_SEGMENT_LEN;
        }
        else
        {
            break;
        }
    }

    return 0;
}

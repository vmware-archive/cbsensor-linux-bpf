/*
 * Copyright 2019-2021 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0
 */

// Struct randomization causes issues on 4.13 and some early versions of 4.14
// These are redefined to work around this, per:
// https://lists.iovisor.org/g/iovisor-dev/topic/21386300#1239
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#ifdef randomized_struct_fields_start
#undef randomized_struct_fields_start
#endif
#define randomized_struct_fields_start  struct {

#ifdef randomized_struct_fields_end
#undef randomized_struct_fields_end
#endif
#define randomized_struct_fields_end    };
#endif

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "vmw_bcc_bpfsensor"
#endif

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

// Create BPF_LRU if it does not exist.
// Support for lru hashes begins with 4.10, so a regular hash table must be used on earlier
// kernels (https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#tables-aka-maps)
// This follows the form for other BPF_XXXX macros, so should work if it is ever added
#ifndef BPF_LRU
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#define BPF_LRU1(_name) \
    BPF_TABLE("lru_hash", u64, u64, _name, 10240)
#define BPF_LRU2(_name, _key_type) \
	BPF_TABLE("lru_hash", _key_type, u64, _name, 10240)
#define BPF_LRU3(_name, _key_type, _leaf_type) \
	BPF_TABLE("lru_hash", _key_type, _leaf_type, _name, 10240)
// helper for default-variable macro function
#define BPF_LRUX(_1, _2, _3, NAME, ...) NAME

// Define a hash function, some arguments optional
// BPF_LRU(name, key_type=u64, leaf_type=u64, size=10240)
#define BPF_LRU(...) \
	BPF_LRUX(__VA_ARGS__, BPF_LRU3, BPF_LRU2, BPF_LRU1)(__VA_ARGS__)
#else
#define BPF_LRU BPF_HASH
#endif
#endif

#ifndef PT_REGS_RC
#define PT_REGS_RC(x) ((x)->ax)
#endif

#ifndef bpf_probe_read_str
// Note that these functions are not 100% compatible.  The read_str function returns the number of bytes read,
//   while the old version returns 0 on success.  Some of the logic we use does depend on the non-zero result
//   (described later).
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#define bpf_probe_read_str bpf_probe_read
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#define FALLBACK_FIELD_TYPE(A, B) A
#else
#define FALLBACK_FIELD_TYPE(A, B) B
#endif

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

enum event_type {
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
	EVENT_FILE_CLOSE,
	EVENT_FILE_OPEN
};

#define DNS_RESP_PORT_NUM 53
#define DNS_RESP_MAXSIZE 512
#define PROXY_SERVER_MAX_LEN 100
#define DNS_SEGMENT_LEN 40
#define DNS_SEGMENT_FLAGS_START 0x01
#define DNS_SEGMENT_FLAGS_END 0x02

struct net_t {
	u32 __local_addr; // This is deprecated, but left here to be backwards compatible
	u32 __remote_addr; // This is deprecated, but left here to be backwards compatible
	u16 remote_port;
	u16 local_port;
	u16 ipver;
	u16 protocol;
	u16 dns_flag;
	union {
		u32 local_addr;
		u32 local_addr6[4];
	};
	union {
		u32 remote_addr;
		u32 remote_addr6[4];
	};
	char dns[DNS_SEGMENT_LEN];
	u32 name_len;
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
#define PP_APPEND 4
#define PP_DEBUG 5

#define MAX_FNAME 255L

struct data_t {
	u64 event_time; // Time the event collection started.  (Same across message parts.)
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
		char fname[MAX_FNAME];
		struct net_t net;
	};
	int retval;
	u64 start_time;
    u64 event_submit_time; // Time we submit the event to bpf.  (Unique for each event.)
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
BPF_HASH(last_start_time, u32, u64, 8192);
BPF_HASH(last_parent, u32, u32, 8192);
BPF_HASH(root_fs, u32, void *, 3); // stores last known root fs
#endif

BPF_PERF_OUTPUT(events);

static void send_event(struct pt_regs *ctx, struct data_t *data)
{
    data->event_submit_time = bpf_ktime_get_ns();
    events.perf_submit(ctx, data, sizeof(struct data_t));
}

static inline struct super_block *_sb_from_dentry(struct dentry *dentry)
{
	struct super_block *sb = NULL;
	// Can't get dentry info return NULL
	if (!dentry) {
		goto out;
	}
	// Try dentry inode before dentry's sb
	if (dentry->d_inode) {
		sb = dentry->d_inode->i_sb;
	}
	if (sb) {
		goto out;
	}
	// This might not exactly be the sb we are looking for
	sb = dentry->d_sb;

out:
	return sb;
}

static inline struct super_block *_sb_from_file(struct file *file)
{
	struct super_block *sb = NULL;

	if (!file) {
		goto out;
	}

	if (file->f_inode) {
		sb = file->f_inode->i_sb;
	}
	if (sb) {
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

	switch (sb->s_magic) {
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

	if (task && task->nsproxy) {
		return task->nsproxy->mnt_ns->ns.inum;
	}
	return 0;
}

static inline void __set_device_from_sb(struct data_t *data,
					struct super_block *sb)
{
	if (data) {
		data->device = 0;
	}

	if (!data || !sb) {
		return;
	}

	data->device = new_encode_dev(sb->s_dev);
}

static inline void __set_device_from_file(struct data_t *data,
					  struct file *file)
{
	struct super_block *sb = NULL;

	if (data) {
		data->device = 0;
	}

	if (!data || !file) {
		return;
	}

	sb = _sb_from_file(file);
	if (!sb) {
		return;
	}
	__set_device_from_sb(data, sb);
}

static inline void __set_inode_from_file(struct data_t *data, struct file *file)
{
	struct inode *pinode = NULL;

	if (data) {
		data->inode = 0;
	}

	if (!data || !file) {
		return;
	}

	bpf_probe_read(&pinode, sizeof(pinode), &(file->f_inode));
	if (!pinode) {
		return;
	}

	bpf_probe_read(&data->inode, sizeof(data->inode), &pinode->i_ino);
}

// Assumed current context is what is valid!
static inline void __set_key_entry_data(struct data_t *data, struct file *file)
{
	u64 id;

	data->event_time = bpf_ktime_get_ns();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	data->tid = task->pid;
	data->pid = task->tgid;
	data->start_time = task->start_time;
	data->uid = __kuid_val(task->cred->uid);
	data->ppid = task->real_parent->tgid;
	data->mnt_ns = __get_mnt_ns_id(task);
#else
	id = bpf_get_current_pid_tgid();
	data->tid = id & 0xffffffff;
	data->pid = id >> 32;

	u64 *last_start = last_start_time.lookup(&data->pid);
	if (last_start) {
		data->start_time = *last_start;
	}
	u32 *ppid = last_parent.lookup(&data->pid);
	if (ppid) {
		data->ppid = *ppid;
	}
#endif

	__set_inode_from_file(data, file);
}

static u8 __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
	// Note: On some kernels bpf_probe_read_str does not exist.  In this case it is
	//  substituted by bpf_probe_read.  The return value for these two cases mean something
	//  different, but that is OK for our logic.
	// Note: On older kernel this may read past the actual arg list into the env.
	u8 result = bpf_probe_read_str(data->fname, MAX_FNAME, ptr);
    send_event(ctx, data);
	return result;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#define MAXARG 30
#else
#define MAXARG 20
#endif

// PSCLNX-6764 - Improve EXEC event performance
//  This logic should be refactored to write the multiple args into a single
//  event buffer instead of one event per arg.
static void submit_all_args(struct pt_regs *ctx,
			    const char __user *const __user *_argv,
			    struct data_t *data)
{
	void *argp = NULL;
	void *next_argp = NULL;
	int index = 0;

#pragma unroll
	for (int i = 0; i < MAXARG; i++) {
		if (next_argp) {
			// If there is more data to read in this arg, we tell the collector
			//  to continue with the previous arg (and not add a ' ').
			data->state = PP_APPEND;
			argp = next_argp;
			next_argp = NULL;
		} else {
			// This is a new arg
			data->state = PP_ENTRY_POINT;
			bpf_probe_read(&argp, sizeof(argp), &_argv[index++]);
		}
		if (!argp) {
			// We have reached the last arg so bail out
			goto out;
		}

		// Read the arg data and send an event.  We expect the result to be the bytes sent
		//  in the event.  On older kernels, this may be 0 which is OK.  It just means that
		//  we will always truncate the arg.
		u8 bytes_written = __submit_arg(ctx, argp, data);
		next_argp = NULL;

		if (bytes_written == MAX_FNAME) {
			// If we have filled the buffer exactly, it means that there is additional
			//  data for this arg.
			// Advance the read pointer by the bytes written (minus the null terminator)
			next_argp = argp + bytes_written - 1;
		}
	}

	// handle truncated argument list
	char ellipsis[] = "...";
	__submit_arg(ctx, (void *)ellipsis, data);

out:
	return;
}

#ifndef MAX_PATH_ITER
#define MAX_PATH_ITER 24
#endif
static inline int __do_file_path(struct pt_regs *ctx, struct dentry *dentry,
				 struct vfsmount *mnt, struct data_t *data)
{
	struct mount *real_mount = NULL;
	struct mount *mnt_parent = NULL;
	struct dentry *mnt_root = NULL;
	struct dentry *new_mnt_root = NULL;
	struct dentry *parent_dentry = NULL;
	struct qstr sp = {};

	struct dentry *root_fs_dentry = NULL;
	struct vfsmount *root_fs_vfsmnt = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	// We can ifdef this block to make this act more like either
	// d_absolute_path or __d_path
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (task->fs) {
		// We can get root fs path from mnt_ns or task
		root_fs_vfsmnt = task->fs->root.mnt;
		root_fs_dentry = task->fs->root.dentry;
	}
#else
	u32 index = 0;
	struct dentry **t_dentry = (struct dentry **)root_fs.lookup(&index);
	if (t_dentry) {
		root_fs_dentry = *t_dentry;
	}
	index = 1;
	struct vfsmount **t_vfsmount =
		(struct vfsmount **)root_fs.lookup(&index);
	if (t_vfsmount) {
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
		if (dentry == root_fs_dentry) {
			goto out;
		}

		bpf_probe_read(&parent_dentry, sizeof(parent_dentry),
			       &(dentry->d_parent));
		if (dentry == parent_dentry || dentry == mnt_root) {
			bpf_probe_read(&dentry, sizeof(struct dentry *),
				       &(real_mount->mnt_mountpoint));
			real_mount = mnt_parent;
			bpf_probe_read(&mnt, sizeof(struct vfsmnt *),
				       &(real_mount->mnt));
			mnt_root = mnt->mnt_root;
			if (mnt == root_fs_vfsmnt) {
				goto out;
			}

			// prefetch next real mount parent.
			mnt_parent = real_mount->mnt_parent;
			if (mnt_parent == real_mount) {
				goto out;
			}
		} else {
			bpf_probe_read(&sp, sizeof(sp),
				       (void *)&(dentry->d_name));
			bpf_probe_read(&data->fname, sizeof(data->fname),
				       sp.name);
			dentry = parent_dentry;
			send_event(ctx, data);
		}
	}

out:
	data->state = PP_FINALIZED;
	return 0;
}

static inline int __do_dentry_path(struct pt_regs *ctx, struct dentry *dentry,
				   struct data_t *data)
{
	struct dentry *current_dentry = NULL;
	struct dentry *parent_dentry = NULL;
	struct qstr sp = {};

	struct dentry *root_fs_dentry = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (task->fs) {
		root_fs_dentry = task->fs->root.dentry;
	}
#else
	u32 index = 0;
	struct dentry **t_dentry = (struct dentry **)root_fs.lookup(&index);
	if (t_dentry) {
		root_fs_dentry = *t_dentry;
	}
#endif
	bpf_probe_read(&sp, sizeof(struct qstr), (void *)&(dentry->d_name));
	if (sp.name == NULL) {
		goto out;
	}
	bpf_probe_read(&data->fname, sizeof(data->fname), (void *)sp.name);

	bpf_probe_read(&parent_dentry, sizeof(parent_dentry),
		       &(dentry->d_parent));
	bpf_probe_read(&current_dentry, sizeof(current_dentry), &(dentry));
	data->state = PP_PATH_COMPONENT;

#pragma unroll
	for (int i = 0; i < MAX_PATH_ITER; i++) {
		if (dentry == root_fs_dentry) {
			goto out;
		}

		if (parent_dentry == current_dentry || parent_dentry == NULL) {
			break;
		}
		bpf_probe_read(&sp, sizeof(struct qstr),
			       (void *)&(current_dentry->d_name));
		if ((void *)sp.name != NULL) {
			bpf_probe_read(data->fname, sizeof(data->fname),
				       (void *)sp.name);
			send_event(ctx, data);
		}

		bpf_probe_read(&current_dentry, sizeof(current_dentry),
			       &(parent_dentry));
		bpf_probe_read(&parent_dentry, sizeof(parent_dentry),
			       &(parent_dentry->d_parent));
	}

	data->fname[0] = '\0';
	send_event(ctx, data);

out:
	data->state = PP_FINALIZED;
	return 0;
}

int syscall__on_sys_execveat(struct pt_regs *ctx, int fd,
			     const char __user *filename,
			     const char __user *const __user *argv,
			     const char __user *const __user *envp, int flags)
{
	struct data_t data = {};

	__set_key_entry_data(&data, NULL);
	data.type = EVENT_PROCESS_ARG;
	data.state = PP_ENTRY_POINT;

	submit_all_args(ctx, argv, &data);

	return 0;
}
int syscall__on_sys_execve(struct pt_regs *ctx, const char __user *filename,
			   const char __user *const __user *argv,
			   const char __user *const __user *envp)
{
	struct data_t data = {};

	__set_key_entry_data(&data, NULL);
	data.type = EVENT_PROCESS_ARG;
	data.state = PP_ENTRY_POINT;

	submit_all_args(ctx, argv, &data);

	return 0;
}

//Note that this can be called more than one from the same pid
int after_sys_execve(struct pt_regs *ctx)
{
	struct data_t data = {};

	__set_key_entry_data(&data, NULL);
	data.event_time = bpf_ktime_get_ns();
	data.state = PP_FINALIZED;
	data.type = EVENT_PROCESS_ARG;
	data.retval = PT_REGS_RC(ctx);

	send_event(ctx, &data);

	return 0;
}

struct file_data {
	u64 pid;
	u64 device;
	u64 inode;
};

// This hash tracks the "observed" file-create events.  This will not be 100% accurate because we will report a
//  file create for any file the first time it is opened with WRITE|TRUNCATE (even if it already exists).  It
//  will however serve to de-dup some events.  (Ie.. If a program does frequent open/write/close.)
BPF_LRU(file_map, struct file_data, u32);

// Older kernels do not support the struct fields so allow for fallback
BPF_LRU(file_write_cache, u64, FALLBACK_FIELD_TYPE(struct file_data, u32));
BPF_LRU(file_creat_cache, u64, u32);

// Only need this hook for kernels without lru_hash
int on_security_file_free(struct pt_regs *ctx, struct file *file)
{
	if (!file) {
		return 0;
	}
	u64 file_cache_key = (u64)file;

	void *cachep = file_write_cache.lookup(&file_cache_key);
	if (cachep) {
		struct data_t data = {};
		__set_key_entry_data(&data, NULL);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
		data.device = ((struct file_data *)cachep)->device;
		data.inode = ((struct file_data *)cachep)->inode;
#else
		data.device = 0;
		data.inode = 0;
		__set_device_from_file(&data, file);
		__set_inode_from_file(&data, file);
#endif

		data.state = PP_ENTRY_POINT;
		data.type = EVENT_FILE_CLOSE;
		send_event(ctx, &data);

		__do_file_path(ctx, file->f_path.dentry, file->f_path.mnt,
			       &data);
		send_event(ctx, &data);
	}

	file_write_cache.delete(&file_cache_key);
	file_creat_cache.delete(&file_cache_key);
	return 0;
}

int on_security_mmap_file(struct pt_regs *ctx, struct file *file,
			  unsigned long prot, unsigned long flags)
{
	unsigned long exec_flags;
	struct data_t data = {};

	if (!file) {
		goto out;
	}
	if (!(prot & PROT_EXEC)) {
		goto out;
	}

	exec_flags = flags & (MAP_DENYWRITE | MAP_EXECUTABLE);
	if (exec_flags == (MAP_DENYWRITE | MAP_EXECUTABLE)) {
		data.type = EVENT_PROCESS_EXEC;
	} else {
		data.type = EVENT_FILE_MMAP;
	}

	// event specific data
	data.state = PP_ENTRY_POINT;
	__set_key_entry_data(&data, file);
	__set_device_from_file(&data, file);
	data.mmap_args.flags = flags;
	data.mmap_args.prot = prot;
	// submit initial event data
	send_event(ctx, &data);

	// submit file path event data
	__do_file_path(ctx, file->f_path.dentry, file->f_path.mnt, &data);
	send_event(ctx, &data);
out:
	return 0;
}

static inline int __trace_write_entry(struct pt_regs *ctx, struct file *file,
				      char __user *buf, size_t count)
{
	struct data_t data = {};
	struct super_block *sb = NULL;
	struct inode *inode = NULL;
	int mode;

	if (!file) {
		goto out;
	}

	sb = _sb_from_file(file);
	if (!sb) {
		goto out;
	}

	if (__is_special_filesystem(sb)) {
		goto out;
	}

	bpf_probe_read(&inode, sizeof(inode), &(file->f_inode));
	if (!inode) {
		goto out;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	bpf_probe_read(&mode, sizeof(mode), &(inode->i_mode));
	if (!S_ISREG(mode)) {
		goto out;
	}
#endif
	__set_key_entry_data(&data, file);
	__set_device_from_sb(&data, sb);

	u64 file_cache_key = (u64)file;

	void *cachep = file_write_cache.lookup(&file_cache_key);
	if (cachep) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
		struct file_data cache_data = *((struct file_data *)cachep);
		pid_t pid = cache_data.pid;
		cache_data.pid = data.pid;
#else
		u32 cache_data = *(u32 *)cachep;
		pid_t pid = cache_data;
		cache_data = data.pid;
#endif

		// if we really care about that multiple tasks
		// these are likely threads or less likely inherited from a fork
		if (pid == data.pid) {
			goto out;
		}

		file_write_cache.update(&file_cache_key, &cache_data);
		goto out;
	} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
		struct file_data cache_data = { .pid = data.pid,
						.device = data.device,
						.inode = data.inode };
#else
		u32 cache_data = data.pid;
#endif
		file_write_cache.insert(&file_cache_key, &cache_data);
	}

	data.state = PP_ENTRY_POINT;
	data.type = EVENT_FILE_WRITE;
	send_event(ctx, &data);

	__do_file_path(ctx, file->f_path.dentry, file->f_path.mnt, &data);
	send_event(ctx, &data);
out:
	return 0;
}

int trace_write_entry(struct pt_regs *ctx, struct file *file, char __user *buf,
		      size_t count)
{
	return (__trace_write_entry(ctx, file, buf, count));
}

// This is mainly for kernel > 5.8.0
int trace_write_kentry(struct pt_regs *ctx, struct file *file, const void *buf,
		       size_t count)
{
	return (__trace_write_entry(ctx, file, (char *)buf, count));
}

// This hook may not be very accurate but at least tells us the intent
// to create the file if needed. So this will likely be written to next.
int on_security_file_open(struct pt_regs *ctx, struct file *file)
{
	struct data_t data = {};
	struct super_block *sb = NULL;
	struct inode *inode = NULL;
	int mode;

	if (!file) {
		goto out;
	}

	if ((file->f_flags & (O_CREAT | O_TRUNC))) {
		data.type = EVENT_FILE_CREATE;
	}
	else if (!(file->f_flags & (O_RDWR | O_WRONLY))) {
		data.type = EVENT_FILE_OPEN;
	}
	else {
		goto out;
	}

	sb = _sb_from_file(file);
	if (!sb) {
		goto out;
	}

	if (__is_special_filesystem(sb)) {
		goto out;
	}

	bpf_probe_read(&inode, sizeof(inode), &(file->f_inode));
	if (!inode) {
		goto out;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	bpf_probe_read(&mode, sizeof(mode), &(inode->i_mode));
	if (!S_ISREG(mode)) {
		goto out;
	}
#endif
	__set_key_entry_data(&data, file);
	__set_device_from_sb(&data, sb);

	u32 *cachep;
	u64 file_cache_key = (u64)file;

	struct file_data key = { .device = data.device, .inode = data.inode };

	// If this is a create event and is already tracked, skip the event.
	// Otherwise add it to the tracking table.
	// Skip this behavior if this is an open event.
	u32 *file_exists = file_map.lookup(&key);
	if (data.type == EVENT_FILE_CREATE) {
		if(file_exists) {
			goto out;
		}

		file_map.update(&key, &data.pid);
		cachep = file_creat_cache.lookup(&file_cache_key);
		if(cachep) {
			if(*cachep == data.pid) {
				goto out;
			}
			file_creat_cache.update(&file_cache_key, &data.pid);
			goto out;
		}
		else {
			file_creat_cache.insert(&file_cache_key, &data.pid);
		}
	}

	data.state = PP_ENTRY_POINT;
	send_event(ctx, &data);

	__do_file_path(ctx, file->f_path.dentry, file->f_path.mnt, &data);

	send_event(ctx, &data);

out:
	return 0;
}

int on_security_inode_unlink(struct pt_regs *ctx, struct inode *dir,
			     struct dentry *dentry)
{
	struct data_t data = {};
	struct super_block *sb = NULL;
	struct inode *inode = NULL;
	int mode;

	if (!dentry) {
		goto out;
	}

	sb = _sb_from_dentry(dentry);
	if (!sb) {
		goto out;
	}

	if (__is_special_filesystem(sb)) {
		goto out;
	}

	__set_key_entry_data(&data, NULL);

	bpf_probe_read(&inode, sizeof(inode), &(dentry->d_inode));
	if (inode) {
		bpf_probe_read(&data.inode, sizeof(data.inode), &inode->i_ino);
	}

	__set_device_from_sb(&data, sb);

	// Delete the file from the tracking so that it will be reported the next time it is created.
	struct file_data key = { .device = data.device, .inode = data.inode };

	file_map.delete(&key);

	data.state = PP_ENTRY_POINT;
	data.type = EVENT_FILE_DELETE;
	send_event(ctx, &data);

	__do_dentry_path(ctx, dentry, &data);

	send_event(ctx, &data);

out:
	return 0;
}

int on_security_inode_rename(struct pt_regs *ctx,
			     struct inode *old_dir, struct dentry *old_dentry,
			     struct inode *new_dir, struct dentry *new_dentry,
			     unsigned int flags)
{
	struct data_t data = {};
	struct super_block *old_sb = NULL;
	struct super_block *new_sb = NULL;
	struct inode *inode = NULL;

	old_sb = _sb_from_dentry(old_dentry);
	if (!old_sb || __is_special_filesystem(old_sb)) {
		goto out;
	}

    // Send the delete event for the path where the file is being moved from
	__set_key_entry_data(&data, NULL);

	data.state = PP_ENTRY_POINT;
	data.type = EVENT_FILE_DELETE;
	bpf_probe_read(&inode, sizeof(inode), &(old_dentry->d_inode));
	if (inode) {
		bpf_probe_read(&data.inode, sizeof(data.inode), &inode->i_ino);
	}

	struct file_data old_key = { .device = data.device, .inode = data.inode };
	file_map.delete(&old_key);

	__set_device_from_sb(&data, old_sb);
	send_event(ctx, &data);
	__do_dentry_path(ctx, old_dentry, &data);
	send_event(ctx, &data);

    // If the target destination already exists,
    // send a delete event for the file that will be overwritten
    if (new_dentry && new_dentry->d_inode != NULL)
    {
        new_sb = _sb_from_dentry(new_dentry);
        if (new_sb &&  !__is_special_filesystem(new_sb))
        {
            __set_key_entry_data(&data, NULL);

            data.state = PP_ENTRY_POINT;
            data.type = EVENT_FILE_DELETE;
            bpf_probe_read(&inode, sizeof(inode), &(new_dentry->d_inode));
            if (inode) {
                bpf_probe_read(&data.inode, sizeof(data.inode), &inode->i_ino);
            }

            struct file_data new_key = { .device = data.device, .inode = data.inode };
            file_map.delete(&new_key);

            __set_device_from_sb(&data, new_sb);
            send_event(ctx, &data);
            __do_dentry_path(ctx, new_dentry, &data);
            send_event(ctx, &data);
        }
    }

    // Send the create event for the path where the file is being moved to
    // (the path will be the one reported in the new dentry, but the inode
    // will persist and be the one from the old dentry)
	inode = NULL;
	data.state = PP_ENTRY_POINT;
	data.type = EVENT_FILE_CREATE;
	bpf_probe_read(&inode, sizeof(inode), &(old_dentry->d_inode));
	if (inode) {
		bpf_probe_read(&data.inode, sizeof(data.inode), &inode->i_ino);
	}
    __set_device_from_sb(&data, new_sb ? new_sb : old_sb);
	send_event(ctx, &data);
	__do_dentry_path(ctx, new_dentry, &data);
	send_event(ctx, &data);

out:
	return 0;
}

int on_wake_up_new_task(struct pt_regs *ctx, struct task_struct *task)
{
	struct inode *pinode = NULL;
	struct data_t data = {};
	struct file *exe_file = NULL;
	if (!task) {
		goto out;
	}

	if (task->tgid != task->pid) {
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
	root_fs.update(&index, (void *)&root_fs_dentry);
	index += 1;
	root_fs.update(&index, (void *)&root_fs_vfsmount);
#endif

	// Get this in case it's a non-standard process
	bpf_get_current_comm(&data.fname, TASK_COMM_LEN);
	if ((task->flags & PF_KTHREAD) || !task->mm) {
		send_event(ctx, &data);
		goto out;
	}

	exe_file = task->mm->exe_file;
	if (!exe_file) {
		send_event(ctx, &data);
		goto out;
	}
	bpf_probe_read(&pinode, sizeof(pinode), &(exe_file->f_inode));
	if (!pinode) {
		send_event(ctx, &data);
		goto out;
	}
	bpf_probe_read(&data.inode, sizeof(data.inode), &pinode->i_ino);
	__set_device_from_file(&data, exe_file);

	data.state = PP_ENTRY_POINT;

	send_event(ctx, &data);
	__do_file_path(ctx, exe_file->f_path.dentry, exe_file->f_path.mnt,
		       &data);
	send_event(ctx, &data);

out:
	return 0;
}

#ifdef CACHE_UDP
struct ip_key {
	uint32_t pid;
	uint64_t start_time;
	uint16_t remote_port;
	uint16_t local_port;
	uint32_t remote_addr;
	uint32_t local_addr;
};
struct ip6_key {
	uint32_t pid;
	uint64_t start_time;
	uint16_t remote_port;
	uint16_t local_port;
	uint32_t remote_addr6[4];
	uint32_t local_addr6[4];
};
#define FLOW_TX 0x01
#define FLOW_RX 0x02
struct ip_entry {
	u8 flow;
};

BPF_LRU(ip_cache, FALLBACK_FIELD_TYPE(struct ip_key, u32),
	FALLBACK_FIELD_TYPE(struct ip_entry, struct ip_key));
BPF_LRU(ip6_cache, FALLBACK_FIELD_TYPE(struct ip6_key, u32),
	FALLBACK_FIELD_TYPE(struct ip_entry, struct ip6_key));

static inline bool has_ip_cache(struct ip_key *ip_key, u8 flow)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	struct ip_key *ip_entry = ip_cache.lookup(&ip_key->pid);
	if (ip_entry) {
		if (ip_entry->remote_port == ip_key->remote_port &&
		    ip_entry->local_port == ip_key->local_port &&
		    ip_entry->remote_addr == ip_key->remote_addr &&
		    ip_entry->local_addr == ip_key->local_addr) {
			return true;
		} else {
			// Update entry
			ip_cache.update(&ip_key->pid, ip_key);
		}
	} else {
		ip_cache.insert(&ip_key->pid, ip_key);
	}
#else
	struct ip_entry *ip_entry = ip_cache.lookup(ip_key);
	if (ip_entry) {
		if ((ip_entry->flow & flow)) {
			return true;
		}
		// Updates map entry
		ip_entry->flow |= flow;
	} else {
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
	if (ip_entry) {
		if (ip_entry->remote_port == ip6_key->remote_port &&
		    ip_entry->local_port == ip6_key->local_port &&
		    ip_entry->remote_addr6[0] == ip6_key->remote_addr6[0] &&
		    ip_entry->remote_addr6[1] == ip6_key->remote_addr6[1] &&
		    ip_entry->remote_addr6[2] == ip6_key->remote_addr6[2] &&
		    ip_entry->remote_addr6[3] == ip6_key->remote_addr6[3] &&
		    ip_entry->local_addr6[0] == ip6_key->local_addr6[0] &&
		    ip_entry->local_addr6[1] == ip6_key->local_addr6[1] &&
		    ip_entry->local_addr6[2] == ip6_key->local_addr6[2] &&
		    ip_entry->local_addr6[3] == ip6_key->local_addr6[3]) {
			return true;
		} else {
			// Update entry
			ip6_cache.update(&ip6_key->pid, ip6_key);
		}
	} else {
		ip6_cache.insert(&ip6_key->pid, ip6_key);
	}
#else
	struct ip_entry *ip_entry = ip6_cache.lookup(ip6_key);
	if (ip_entry) {
		if ((ip_entry->flow & flow)) {
			return true;
		}
		// Updates map entry
		ip_entry->flow |= flow;
	} else {
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
	if (!task) {
		goto out;
	}
	if (task->tgid != task->pid) {
		goto out;
	}

	data.event_time = bpf_ktime_get_ns();
	data.type = EVENT_PROCESS_EXIT;
	data.tid = task->pid;
	data.pid = task->tgid;
	data.start_time = task->start_time;
	if (task->real_parent) {
		data.ppid = task->real_parent->tgid;
	}
	send_event(ctx, &data);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	last_start_time.delete(&data.pid);
	last_parent.delete(&data.pid);
#ifdef CACHE_UDP
	// Remove burst cache entries
	//  We only need to do this for older kernels that do not have an LRU
	ip_cache.delete(&data.pid);
	ip6_cache.delete(&data.pid);
#endif /* CACHE_UDP */
#endif
out:
	return 0;
}

BPF_LRU(currsock, u64, struct sock *);
BPF_LRU(currsock2, u64, struct msghdr *);
BPF_LRU(currsock3, u64, struct sock *);

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

static inline bool check_family(struct sock *sk, u16 expected_family)
{
	u16 family = sk->__sk_common.skc_family;
	return family == expected_family;
}

static int trace_connect_return(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	int ret = PT_REGS_RC(ctx);
	if (ret != 0) {
		currsock.delete(&id);
		return 0;
	}

	struct sock **skpp;
	skpp = currsock.lookup(&id);
	if (skpp == 0) {
		return 0;
	}

	struct data_t data = {};
	struct sock *skp = *skpp;
	u16 dport = skp->__sk_common.skc_dport;

	__set_key_entry_data(&data, NULL);
	data.type = EVENT_NET_CONNECT_PRE;
	data.net.protocol = IPPROTO_TCP;
	data.net.remote_port = dport;

	struct inet_sock *sockp = (struct inet_sock *)skp;
	data.net.local_port = sockp->inet_sport;

	if (check_family(skp, AF_INET)) {
		data.net.ipver = AF_INET;
		data.net.__local_addr = data.net.local_addr =
			skp->__sk_common.skc_rcv_saddr;
		data.net.__remote_addr = data.net.remote_addr =
			skp->__sk_common.skc_daddr;

		send_event(ctx, &data);
	} else if (check_family(skp, AF_INET6)) {
		data.net.ipver = AF_INET6;
		bpf_probe_read(
			&data.net.local_addr6, sizeof(data.net.local_addr6),
			skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read(&data.net.remote_addr6,
			       sizeof(data.net.remote_addr6),
			       skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

		send_event(ctx, &data);
	}

	currsock.delete(&id);
	return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
	return trace_connect_return(ctx);
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
	return trace_connect_return(ctx);
}

int trace_skb_recv_udp(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;

	struct sk_buff *skb = (struct sk_buff *)PT_REGS_RC(ctx);
	if (skb == NULL) {
		return 0;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	// Older kernels we probe __skb_recv_datagram which can be used by
	// other protocols. We filter by sk_family or skb->protocol
	if (!skb->sk) {
		return 0;
	}
	if (!(skb->sk->sk_family == AF_INET ||
	      skb->sk->sk_family == AF_INET6)) {
		return 0;
	}
#endif
	struct udphdr *udphdr = NULL;

	// Get a pointer to the network header and the header length.
	//  We use the header length to decide if this is IPv4 or IPv6
	void *hdr = (struct iphdr *)(skb->head + skb->network_header);
	u32 hdr_len = skb->transport_header - skb->network_header;

	struct data_t data = {};

	data.type = EVENT_NET_CONNECT_ACCEPT;
	__set_key_entry_data(&data, NULL);

	data.net.protocol = IPPROTO_UDP;

	udphdr = (struct udphdr *)(skb->head + skb->transport_header);
	data.net.remote_port = udphdr->source;
	data.net.local_port = udphdr->dest;

	if (hdr_len == sizeof(struct iphdr)) {
		struct iphdr *iphdr = (struct iphdr *)hdr;

		data.net.ipver = AF_INET;
		data.net.__local_addr = data.net.local_addr = iphdr->daddr;
		data.net.__remote_addr = data.net.remote_addr = iphdr->saddr;

#ifdef CACHE_UDP
		struct ip_key ip_key = {};
		ip_key.pid = data.pid;
		ip_key.start_time = data.start_time;
		ip_key.remote_port =
			0; // Ignore the remote port for incoming connections
		bpf_probe_read(&ip_key.local_port, sizeof(data.net.local_port),
			       &data.net.local_port);
		bpf_probe_read(&ip_key.remote_addr,
			       sizeof(data.net.remote_addr),
			       &data.net.remote_addr);
		bpf_probe_read(&ip_key.local_addr, sizeof(data.net.local_addr),
			       &data.net.local_addr);
		if (has_ip_cache(&ip_key, FLOW_RX)) {
			return 0;
		}
#endif /* CACHE_UDP */
	} else if (hdr_len == sizeof(struct ipv6hdr)) {
		// Why IPv6 address/port is read in a differen way than IPv4:
		//  - BPF C compiled to BPF instructions don't always do what we expect
		//  - especially when accessing members of a struct containing bitfields
		struct ipv6hdr *ipv6hdr = (struct ipv6hdr *)hdr;

		data.net.ipver = AF_INET6;
		bpf_probe_read(data.net.local_addr6, sizeof(uint32_t) * 4,
			       &ipv6hdr->daddr.s6_addr32);
		bpf_probe_read(data.net.remote_addr6, sizeof(uint32_t) * 4,
			       &ipv6hdr->saddr.s6_addr32);

#ifdef CACHE_UDP
		struct ip6_key ip_key = {};
		ip_key.pid = data.pid;
		ip_key.start_time = data.start_time;
		ip_key.remote_port =
			0; // Ignore the remote port for incoming connections
		bpf_probe_read(&ip_key.local_port, sizeof(data.net.local_port),
			       &data.net.local_port);
		bpf_probe_read(ip_key.remote_addr6,
			       sizeof(data.net.remote_addr6),
			       &ipv6hdr->daddr.s6_addr32);
		bpf_probe_read(ip_key.local_addr6, sizeof(data.net.local_addr6),
			       &ipv6hdr->saddr.s6_addr32);
		if (has_ip6_cache(&ip_key, FLOW_RX)) {
			return 0;
		}
#endif /* CACHE_UDP */
	} else {
	    return 0;
	}

	send_event(ctx, &data);

	return 0;
}

int trace_accept_return(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;

	struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
	if (newsk == NULL) {
		return 0;
	}

	struct data_t data = {};

	__set_key_entry_data(&data, NULL);
	data.type = EVENT_NET_CONNECT_ACCEPT;
	data.net.protocol = IPPROTO_TCP;

	data.net.ipver = newsk->__sk_common.skc_family;
	bpf_probe_read(&data.net.local_port, sizeof(newsk->__sk_common.skc_num),
		       &newsk->__sk_common.skc_num);
	data.net.local_port = htons(data.net.local_port);
	data.net.remote_port =
		newsk->__sk_common.skc_dport; // network order dport

	if (check_family(newsk, AF_INET)) {
		data.net.__local_addr = data.net.local_addr =
			newsk->__sk_common.skc_rcv_saddr;
		data.net.__remote_addr = data.net.remote_addr =
			newsk->__sk_common.skc_daddr;

		if (data.net.local_addr != 0 && data.net.remote_addr != 0 &&
		    data.net.local_port != 0 && data.net.remote_port != 0) {
			send_event(ctx, &data);
		}
	} else if (check_family(newsk, AF_INET6)) {
		bpf_probe_read(
			&data.net.local_addr6, sizeof(data.net.local_addr6),
			newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read(&data.net.remote_addr6,
			       sizeof(data.net.remote_addr6),
			       newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

		send_event(ctx, &data);
	}
	return 0;
}

int trace_udp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg,
		      size_t length, int noblock, int flags)
{
	u64 pid;

	pid = bpf_get_current_pid_tgid();
	if (flags != MSG_PEEK) {
		currsock2.update(&pid, &msg);
		currsock3.update(&pid, &sk);
	}

	return 0;
}

int trace_udp_recvmsg_return(struct pt_regs *ctx, struct sock *sk,
			     struct msghdr *msg)
{
	int ret = PT_REGS_RC(ctx);
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;

	struct msghdr **msgpp; // for DNS receive probe

	msgpp = currsock2.lookup(&id);
	if (msgpp == 0) {
		return 0; // missed entry
	}

	struct sock **skpp;
	skpp = currsock3.lookup(&id);
	if (skpp == 0) {
		return 0;
	}

	if (ret <= 0) {
		currsock2.delete(&id);
		return 0;
	}

	struct data_t data = {};
	__set_key_entry_data(&data, NULL);
	data.type = EVENT_NET_CONNECT_DNS_RESPONSE;
	data.net.protocol = IPPROTO_UDP;

	struct sock *skp = *skpp;
	data.net.ipver = skp->__sk_common.skc_family;

	// Send DNS info if port is DNS
	struct msghdr *msgp = *msgpp;

	const char __user *dns;
	dns = (msgp->msg_iter).iov->iov_base;

	u16 dport = (((struct sockaddr_in *)(msgp->msg_name))->sin_port);
	u16 len = ret;
	data.net.name_len = ret;

	if (DNS_RESP_PORT_NUM == ntohs(dport)) {
#pragma unroll
		for (int i = 1; i <= (DNS_RESP_MAXSIZE / DNS_SEGMENT_LEN) + 1;
		     ++i) {
			if (len > 0 && len < DNS_RESP_MAXSIZE) {
				data.net.dns_flag = 0;
				bpf_probe_read(&data.net.dns, DNS_SEGMENT_LEN,
					       dns);
				if (i == 1)
					data.net.dns_flag =
						DNS_SEGMENT_FLAGS_START;
				if (len <= 40)
					data.net.dns_flag |=
						DNS_SEGMENT_FLAGS_END;

				send_event(ctx, &data);
				len = len - DNS_SEGMENT_LEN;
				dns = dns + DNS_SEGMENT_LEN;
			} else {
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

int trace_udp_sendmsg_return(struct pt_regs *ctx, struct sock *sk,
			     struct msghdr *msg)
{
	int ret = PT_REGS_RC(ctx);
	u64 id = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = currsock3.lookup(&id);
	if (skpp == 0) {
		return 0;
	}

	if (ret <= 0) {
		currsock3.delete(&id);
		return 0;
	}

	struct data_t data = {};
	__set_key_entry_data(&data, NULL);
	data.type = EVENT_NET_CONNECT_PRE;
	data.net.protocol = IPPROTO_UDP;

	// get ip version
	struct sock *skp = *skpp;

	data.net.ipver = skp->__sk_common.skc_family;
	bpf_probe_read(&data.net.local_port, sizeof(skp->__sk_common.skc_num),
		       &skp->__sk_common.skc_num);
	data.net.local_port = htons(data.net.local_port);
	data.net.remote_port =
		skp->__sk_common.skc_dport; // already network order

	if (check_family(skp, AF_INET)) {
		data.net.__remote_addr = data.net.remote_addr =
			skp->__sk_common.skc_daddr;
		data.net.__local_addr = data.net.local_addr =
			skp->__sk_common.skc_rcv_saddr;

#ifdef CACHE_UDP
		struct ip_key ip_key = {};
		ip_key.pid = data.pid;
		ip_key.start_time = data.start_time;
		bpf_probe_read(&ip_key.remote_port,
			       sizeof(data.net.remote_port),
			       &data.net.remote_port);
		ip_key.local_port =
			0; // Ignore the local port for outgoing connections
		bpf_probe_read(&ip_key.remote_addr,
			       sizeof(data.net.remote_addr),
			       &data.net.remote_addr);
		bpf_probe_read(&ip_key.local_addr, sizeof(data.net.local_addr),
			       &data.net.local_addr);

		if (has_ip_cache(&ip_key, FLOW_TX)) {
			goto out;
		}
#endif /* CACHE_UDP */
	} else if (check_family(skp, AF_INET6)) {
		bpf_probe_read(
			&data.net.remote_addr6, sizeof(data.net.remote_addr6),
			&(skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32));
		bpf_probe_read(
			&data.net.local_addr6, sizeof(data.net.local_addr6),
			&(skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32));

#ifdef CACHE_UDP
		struct ip6_key ip_key = {};
		ip_key.pid = data.pid;
		ip_key.start_time = data.start_time;
		bpf_probe_read(&ip_key.remote_port,
			       sizeof(data.net.remote_port),
			       &data.net.remote_port);
		ip_key.local_port =
			0; // Ignore the local port for outgoing connections
		bpf_probe_read(
			ip_key.remote_addr6, sizeof(data.net.remote_addr6),
			&(skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32));
		bpf_probe_read(
			ip_key.local_addr6, sizeof(data.net.local_addr6),
			&(skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32));
		if (has_ip6_cache(&ip_key, FLOW_TX)) {
			goto out;
		}
#endif /* CACHE_UDP */
	}
	send_event(ctx, &data);

out:
	currsock3.delete(&id);
	return 0;
}

int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg)
{
	struct data_t data = {};
	int cmd = 0;
	int offset = 0;

	// filter proxy traffic
	const char __user *p = (msg->msg_iter).iov->iov_base;
	__kernel_size_t cmd_len = (msg->msg_iter).iov->iov_len;

	if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T') && (p[4] != '/')) {
		cmd = 0;
		offset = 3;
		goto CATCH;
	}
	if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T') && (p[4] != '/')) {
		cmd = 1;
		offset = 3;
		goto CATCH;
	}
	if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T') &&
	    (p[5] != '/')) {
		cmd = 2;
		offset = 4;
		goto CATCH;
	}
	if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') &&
	    (p[4] == 'T') && (p[5] == 'E') && (p[7] != '/')) {
		cmd = 3;
		offset = 6;
		goto CATCH;
	}
	if ((p[0] == 'C') && (p[1] == 'O') && (p[2] == 'N') && (p[3] == 'N') &&
	    (p[4] == 'E') && (p[5] == 'C') && (p[6] == 'T') && (p[8] != '/')) {
		cmd = 4;
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

	data.net.ipver = sk->__sk_common.skc_family;
	bpf_probe_read(&data.net.local_port, sizeof(sk->__sk_common.skc_num),
		       &sk->__sk_common.skc_num);
	data.net.local_port = htons(data.net.local_port);
	data.net.remote_port = sk->__sk_common.skc_dport;

	if (check_family(sk, AF_INET)) {
		data.net.__local_addr = data.net.local_addr =
			sk->__sk_common.skc_rcv_saddr;
		data.net.__remote_addr = data.net.remote_addr =
			sk->__sk_common.skc_daddr;
	} else if (check_family(sk, AF_INET6)) {
		bpf_probe_read(
			&data.net.local_addr6, sizeof(data.net.local_addr6),
			sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read(&data.net.remote_addr6,
			       sizeof(data.net.remote_addr6),
			       sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	p = p + offset + 1;
#pragma unroll
	for (int i = 1; i <= (PROXY_SERVER_MAX_LEN / DNS_SEGMENT_LEN) + 1;
	     ++i) {
		if (len > 0 && len < DNS_RESP_MAXSIZE) {
			data.net.dns_flag = 0;
			bpf_probe_read(&data.net.dns, DNS_SEGMENT_LEN, p);
			if (i == 1)
				data.net.dns_flag = DNS_SEGMENT_FLAGS_START;
			if (len <= 40)
				data.net.dns_flag |= DNS_SEGMENT_FLAGS_END;

			send_event(ctx, &data);
			len = len - DNS_SEGMENT_LEN;
			p = p + DNS_SEGMENT_LEN;
		} else {
			break;
		}
	}

	return 0;
}

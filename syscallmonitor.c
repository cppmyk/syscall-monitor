#include <linux/fcntl.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/linkage.h>
#include <linux/limits.h>
#include <linux/namei.h>

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) ((a)*65536 + (b)*256 + (c))
#endif // KERNEL_VERSION

#if defined(CONFIG_X86_64) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)

#define MAX_PATH 512
#define MAX_INSTRUCTION_LENGTH 16 + MAX_PATH + NAME_MAX
#define MAX_LOG_ENTRIES 64

#define MAX_BUF_OFFSET 8

#define PROCFS_NAME "syscallmonitor"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define HAVE_PROC_OPS
#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)

static struct proc_dir_entry *proc_entry;

static bool logging = true;
static int syscall_level = 1;

static bool unload = true;
module_param(unload, bool, 0);

static DEFINE_MUTEX(log_entries_mutex);
static LIST_HEAD(log_entries_list);
static size_t log_entries_list_size = 0;

/*
 * A structure that represents log entry in proc file.
 */
struct log_entry {
  char *exec_file_path;
  char *syscall_target_file_path;
  struct list_head head;
};

/*
 * A function that allocates and fills log_entry memory.
 *
 * @param exec_file_path. An executable file path.
 * @param target_file_path. A syscall target file path.
 *
 * @return. A pointer to log_entry object.
 */
static struct log_entry *allocate_log_entry(char *exec_file_path,
              char *target_file_path)
{
  struct log_entry *entry = kmalloc(sizeof(struct log_entry), GFP_KERNEL);

  entry->exec_file_path = exec_file_path;
  entry->syscall_target_file_path = target_file_path;

  return entry;
}

/*
 * A function that frees log_entry memory (including internal variables).
 *
 * @param entry. Log entry.
 */
static void free_log_entry(struct log_entry *entry)
{
  if (!entry) {
    return;
  }

  kfree(entry->exec_file_path);
  kfree(entry->syscall_target_file_path);
  kfree(entry);
}

/*
 * A function that erases first element (head) from linked lints data structure
 * that contans log entries.
 */
static void erase_log_entries_head(void)
{
  struct log_entry *entry_to_remove;

  if (log_entries_list_size == 0) {
    return;
  }

  entry_to_remove =
    list_entry(log_entries_list.next, struct log_entry, head);
  list_del(log_entries_list.next);
  free_log_entry(entry_to_remove);
  --log_entries_list_size;
}

/*
 * A function that adds log entry to the log_entries_list and removes oldest
 * entry if size > MAX_LOG_ENTRIES.
 *
 * @param entry. Log entry.
 */
static void add_log_entry(struct log_entry *entry)
{
  if (!entry) {
    return;
  }

  list_add_tail(&entry->head, &log_entries_list);
  ++log_entries_list_size;

  if (log_entries_list_size > MAX_LOG_ENTRIES) {
    erase_log_entries_head();
  }
}

/*
 * A function that erases all elements from a linked list data structure
 * at once.
 */
static void clear_log_entries(void)
{
  while (log_entries_list_size) {
    erase_log_entries_head();
  }
}

/*
 * A structure that wraps rb_node field and char* field.
 * This structure is defined for being a real node of a red-black tree data
 * structure as rb tree is intrusive in linux kernel.
 */
struct rb_node_wrapper {
  struct rb_node node;
  char *exec_file;
};

static DEFINE_MUTEX(exec_files_mutex);
static struct rb_root exec_files_rbtree_root = RB_ROOT;

/*
 * A function that searches for a specific executable file name in a red-black
 * tree data structure.
 *
 * @param root. A root node of rb tree.
 * @param desired_exec_file. The executable file name that has to be searched.
 *
 * @return. A pointer to a found node containing the desired executable file
 * name or NULL otherwise.
 */
static struct rb_node_wrapper *search_in_rbtree(struct rb_root *root,
            const char *desired_exec_file)
{
  struct rb_node *node = root->rb_node;

  while (node) {
    struct rb_node_wrapper *curr =
      rb_entry(node, struct rb_node_wrapper, node);
    int result = strcmp(desired_exec_file, curr->exec_file);

    if (result < 0)
      node = node->rb_left;
    else if (result > 0)
      node = node->rb_right;
    else
      return curr;
  }

  return NULL;
}

/*
 * A function that inserts a new node into a red-black tree data structure.
 *
 * @param root. A root node of rb tree.
 * @param wrapper_entry. A pointer to a new node that has to be inserted.
 *
 * @return. true on success or false otherwise.
 */
static bool insert_to_rbtree(struct rb_root *root,
           struct rb_node_wrapper *wrapper_entry)
{
  struct rb_node **new = &(root->rb_node), *parent = NULL;

  while (*new) {
    struct rb_node_wrapper *curr =
      rb_entry(*new, struct rb_node_wrapper, node);
    int result = strcmp(wrapper_entry->exec_file, curr->exec_file);

    parent = *new;
    if (result < 0)
      new = &((*new)->rb_left);
    else if (result > 0)
      new = &((*new)->rb_right);
    else
      return false;
  }

  rb_link_node(&wrapper_entry->node, parent, new);
  rb_insert_color(&wrapper_entry->node, root);

  return true;
}

/*
 * A function that erases a node from a red-black tree data structure.
 *
 * @param root. A root node of rb tree.
 * @param wrapper_entry. A pointer to a new node that has to be inserted.
 */
static void erase_from_rbtree(struct rb_root *root,
            struct rb_node_wrapper *wrapper_entry)
{
  rb_erase(&wrapper_entry->node, root);
  kfree(wrapper_entry->exec_file);
  kfree(wrapper_entry);
}

/*
 * A function that erases all elements from a red-black tree data structure
 * at once.
 *
 * @param root. A root node of rb tree.
 */
static void clear_rbtree(struct rb_root *root)
{
  while (root->rb_node) {
    erase_from_rbtree(root, rb_entry(root->rb_node,
             struct rb_node_wrapper, node));
  }
}

/*
 * A function that resolves a syscall name into a syscall address.
 *
 * @param syscall_name. The syscall name.
 *
 * @return. The syscall address.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long lookup_name(const char *syscall_name)
{
  struct kprobe kp = { .symbol_name = syscall_name };
  unsigned long syscall_address;

  if (register_kprobe(&kp) < 0) {
    return 0;
  }
  syscall_address = (unsigned long)kp.addr;
  unregister_kprobe(&kp);
  return syscall_address;
}
#else
static unsigned long lookup_name(const char *syscall_name)
{
  return kallsyms_lookup_name(syscall_name);
}
#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *
ftrace_get_regs(struct ftrace_regs *fregs)
{
  return fregs;
}
#endif // LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)

/*
 * A structure that represents a hook entry.
 */
struct ftrace_hook {
  const char *name;
  void *function;
  void *original;
  unsigned long address;
  struct ftrace_ops ops;
};

/*
 * A function that searches for a syscall address and saves it at hook entry.
 *
 * @param hook. The hook entry to save at.
 *
 * @return. 0 on success, -ENOENT otherwise.
 */
static int resolve_hook_address(struct ftrace_hook *hook)
{
  hook->address = lookup_name(hook->name);

  if (!hook->address) {
    return -ENOENT;
  }

  *((unsigned long *)hook->original) = hook->address;
  return 0;
}

/*
 * A function that is a callback. It puts a hook address into a rip register.
 */
static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip,
         struct ftrace_ops *ops,
         struct ftrace_regs *fregs)
{
  struct pt_regs *regs = ftrace_get_regs(fregs);
  struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

  if (!within_module(parent_ip, THIS_MODULE)) {
    regs->ip = (unsigned long)hook->function;
  }
}

/*
 * A function that removes a specific hook from hooks table.
 *
 * @param hook. The specific hook to remove.
 */
static void remove_hook(struct ftrace_hook *hook)
{
  unregister_ftrace_function(&hook->ops);
  ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

/*
 * A function that installs a specific hook at hooks table.
 *
 * @param hook. The specific hook to install.
 *
 * @return. 0 on success, any error code otherwise.
 */
static int install_hook(struct ftrace_hook *hook)
{
  int err;

  err = resolve_hook_address(hook);
  if (err) {
    return err;
  }

  hook->ops.func = ftrace_thunk;
  hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |
        FTRACE_OPS_FL_IPMODIFY;

  err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
  if (err) {
    return err;
  }

  err = register_ftrace_function(&hook->ops);
  if (err) {
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    return err;
  }

  return 0;
}

/*
 * A function that removes hooks range(from 1st hook up to count hook)
 * from hooks table.
 *
 * @param hooks. Hooks range to remove.
 */
static void remove_hooks_range_from_begin(struct ftrace_hook *hooks,
            size_t count)
{
  size_t i;

  for (i = 0; i < count; ++i) {
    remove_hook(&hooks[i]);
  }
}

/*
 * A function that installs hooks range(from 1st hook up to count hook)
 * at hooks table. On a failure while installing a hook from the range,
 * the entire installed hooks are removed.
 *
 * @param hooks. Hooks range to install.
 *
 * @return. 0 on success, any error code otherwise.
 */
static int install_hooks_range_from_begin(struct ftrace_hook *hooks,
            size_t count)
{
  int err;
  size_t i;

  for (i = 0; i < count; ++i) {
    err = install_hook(&hooks[i]);
    if (err) {
      goto error;
    }
  }
  return 0;

error:
  remove_hooks_range_from_begin(hooks, i + 1);
  return err;
}

/*
 * A function that removes one of hooks ranges depending on a required
 * syscall level.
 *
 * @param hooks. A pointer to the 1st hook at hooks table.
 * @param level. Required syscall level to remove.
 */
static void remove_hooks(struct ftrace_hook *hooks, int level)
{
  if (level == 1) {
    remove_hooks_range_from_begin(hooks, 7);
  } else if (level == 2) {
    remove_hooks_range_from_begin(hooks, 14);
  } else if (level == 3) {
    remove_hooks_range_from_begin(hooks, 18);
  }
}

/*
 * A function that installs one of hooks ranges depending on a required
 * syscall level.
 *
 * @param hooks. A pointer to the 1st hook at hooks table.
 * @param level. Required syscall level to install.
 *
 * @return. 0 on success, any error code otherwise.
 */
static int install_hooks(struct ftrace_hook *hooks, int level)
{
  if (level == 1) {
    return install_hooks_range_from_begin(hooks, 7);
  } else if (level == 2) {
    return install_hooks_range_from_begin(hooks, 14);
  } else if (level == 3) {
    return install_hooks_range_from_begin(hooks, 18);
  }
  return -1;
}

/*
 * Pointers to real syscalls.
 */
static asmlinkage int (*real_sys_open)(struct pt_regs *);
static asmlinkage int (*real_sys_openat)(struct pt_regs *);
static asmlinkage ssize_t (*real_sys_write)(struct pt_regs *);
static asmlinkage ssize_t (*real_sys_writev)(struct pt_regs *);
static asmlinkage ssize_t (*real_sys_pwrite64)(struct pt_regs *);
static asmlinkage ssize_t (*real_sys_pwritev)(struct pt_regs *);
static asmlinkage ssize_t (*real_sys_pwritev2)(struct pt_regs *);
static asmlinkage int (*real_sys_chown)(struct pt_regs *);
static asmlinkage int (*real_sys_lchown)(struct pt_regs *);
static asmlinkage int (*real_sys_fchown)(struct pt_regs *);
static asmlinkage int (*real_sys_fchownat)(struct pt_regs *);
static asmlinkage int (*real_sys_chmod)(struct pt_regs *);
static asmlinkage int (*real_sys_fchmod)(struct pt_regs *);
static asmlinkage int (*real_sys_fchmodat)(struct pt_regs *);
static asmlinkage pid_t (*real_sys_fork)(struct pt_regs *);
static asmlinkage pid_t (*real_sys_vfork)(struct pt_regs *);
static asmlinkage int (*real_sys_execve)(struct pt_regs *);
static asmlinkage int (*real_sys_execveat)(struct pt_regs *);

static bool file_exists(const char *);

/*
 * A function that searches for the source directory for a given
 * executable file name.
 *
 * @file_path. A pointer to a buffer where to store the source directory
 * with executable file name.
 * @file_name. A file name which to search for the source directory for.
 */
static void find_path_to_exec_file(char *file_path, const char *file_name)
{
  const char *path[] = { "/usr/local/sbin/", "/usr/local/bin/",
             "/usr/sbin/",     "/usr/bin/",
             "/sbin/",     "/bin/",
             "/usr/games/",    "/usr/local/games/" };
  size_t i;

  for (i = 0; i < ARRAY_SIZE(path); ++i) {
    memset(file_path, 0, NAME_MAX);
    sprintf(file_path, "%s%s", path[i], file_name);

    if (file_exists(file_path)) {
      return;
    }
  }
  sprintf(file_path,
    "not found executable file(from nonstandard bin-directory)");
}

/*
 * A function that searches for the source directory for a given file name.
 *
 * @param file_path. A pointer to a buffer where to store the source directory
 * with file name.
 * @param dfd. Source directory descriptor.
 * @param fn_address. A pointer to a file name.
 */
static void find_path_to_target_file(char *file_path, unsigned long dfd,
             unsigned long fn_address)
{
  struct path target_path;
  char *buf, *buf_offset;

  if (!user_path_at(dfd, (char *)fn_address, LOOKUP_FOLLOW,
        &target_path)) {
    path_put(&target_path);

    buf = kmalloc_array(MAX_PATH + NAME_MAX + MAX_BUF_OFFSET,
            sizeof(char), GFP_KERNEL);
    buf_offset = d_path(&target_path, buf,
            MAX_PATH + NAME_MAX + MAX_BUF_OFFSET);

    memcpy(file_path, buf_offset, MAX_PATH + NAME_MAX);
    kfree(buf);
  }
}

/*
 * A function that checks whether file_path points to /var/log/kern.log
 * or /proc/syscallmonitor.
 *
 * @param file_path. A path to a file to check.
 *
 * @return. true if it is, false otherwise.
 */
static bool is_kernel_or_procfs_log(const char *file_path)
{
  return (strncmp(file_path, "/var/log/kern.log", 17) == 0) ||
         (strncmp(file_path, "/proc/syscallmonitor", 20) == 0);
}

/*
 * A hook for open syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage int hook_sys_open(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path,
    *target_file_path = kmalloc_array(MAX_PATH + NAME_MAX,
              sizeof(char), GFP_KERNEL);
  long err = strncpy_from_user(target_file_path, (char *)regs->di,
             MAX_PATH + NAME_MAX);

  if (err < 1) {
    kfree(target_file_path);
    return -EFAULT;
  }

  exec_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  find_path_to_exec_file(exec_file_path, current->comm);

  entry = allocate_log_entry(exec_file_path, target_file_path);
  mutex_lock(&log_entries_mutex);
  add_log_entry(entry);
  mutex_unlock(&log_entries_mutex);

  return real_sys_open(regs);
}

/*
 * A hook for openat syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage int hook_sys_openat(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path,
    *target_file_path = kmalloc_array(MAX_PATH + NAME_MAX,
              sizeof(char), GFP_KERNEL);
  long err = strncpy_from_user(target_file_path, (char *)regs->si,
             MAX_PATH + NAME_MAX);

  if (err < 1) {
    kfree(target_file_path);
    return -EFAULT;
  }

  exec_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  find_path_to_exec_file(exec_file_path, current->comm);

  if (target_file_path[0] != '/') {
    find_path_to_target_file(target_file_path, regs->di, regs->si);
  }

  entry = allocate_log_entry(exec_file_path, target_file_path);
  mutex_lock(&log_entries_mutex);
  add_log_entry(entry);
  mutex_unlock(&log_entries_mutex);

  return real_sys_openat(regs);
}

/*
 * A hook for write syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage ssize_t hook_sys_write(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path, *target_file_path, *buf, *buf_offset;
  struct fd f = fdget(regs->di);

  if (!f.file) {
    return -ENOENT;
  }

  target_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  buf = kmalloc_array(MAX_PATH + NAME_MAX + MAX_BUF_OFFSET, sizeof(char),
          GFP_KERNEL);
  buf_offset = d_path(&f.file->f_path, buf,
          MAX_PATH + NAME_MAX + MAX_BUF_OFFSET);
  memcpy(target_file_path, buf_offset, MAX_PATH + NAME_MAX);

  kfree(buf);

  if (!is_kernel_or_procfs_log(target_file_path)) {
    exec_file_path = kmalloc_array(MAX_PATH + NAME_MAX,
                 sizeof(char), GFP_KERNEL);
    find_path_to_exec_file(exec_file_path, current->comm);

    entry = allocate_log_entry(exec_file_path, target_file_path);

    mutex_lock(&log_entries_mutex);
    add_log_entry(entry);
    mutex_unlock(&log_entries_mutex);
  } else {
    kfree(target_file_path);
  }

  return real_sys_write(regs);
}

/*
 * A hook for writev syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage ssize_t hook_sys_writev(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path, *target_file_path, *buf, *buf_offset;
  struct fd f = fdget(regs->di);

  if (!f.file) {
    return -ENOENT;
  }

  target_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  buf = kmalloc_array(MAX_PATH + NAME_MAX + MAX_BUF_OFFSET, sizeof(char),
          GFP_KERNEL);
  buf_offset = d_path(&f.file->f_path, buf,
          MAX_PATH + NAME_MAX + MAX_BUF_OFFSET);
  memcpy(target_file_path, buf_offset, MAX_PATH + NAME_MAX);

  kfree(buf);

  if (!is_kernel_or_procfs_log(target_file_path)) {
    exec_file_path = kmalloc_array(MAX_PATH + NAME_MAX,
                 sizeof(char), GFP_KERNEL);
    find_path_to_exec_file(exec_file_path, current->comm);

    entry = allocate_log_entry(exec_file_path, target_file_path);

    mutex_lock(&log_entries_mutex);
    add_log_entry(entry);
    mutex_unlock(&log_entries_mutex);
  } else {
    kfree(target_file_path);
  }

  return real_sys_writev(regs);
}

/*
 * A hook for pwrite64 syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage ssize_t hook_sys_pwrite64(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path, *target_file_path, *buf, *buf_offset;
  struct fd f = fdget(regs->di);

  if (!f.file) {
    return -ENOENT;
  }

  target_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  buf = kmalloc_array(MAX_PATH + NAME_MAX + MAX_BUF_OFFSET, sizeof(char),
          GFP_KERNEL);
  buf_offset = d_path(&f.file->f_path, buf,
          MAX_PATH + NAME_MAX + MAX_BUF_OFFSET);
  memcpy(target_file_path, buf_offset, MAX_PATH + NAME_MAX);

  kfree(buf);

  if (!is_kernel_or_procfs_log(target_file_path)) {
    exec_file_path = kmalloc_array(MAX_PATH + NAME_MAX,
                 sizeof(char), GFP_KERNEL);
    find_path_to_exec_file(exec_file_path, current->comm);

    entry = allocate_log_entry(exec_file_path, target_file_path);

    mutex_lock(&log_entries_mutex);
    add_log_entry(entry);
    mutex_unlock(&log_entries_mutex);
  } else {
    kfree(target_file_path);
  }

  return real_sys_pwrite64(regs);
}

/*
 * A hook for pwritev syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage ssize_t hook_sys_pwritev(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path, *target_file_path, *buf, *buf_offset;
  struct fd f = fdget(regs->di);

  if (!f.file) {
    return -ENOENT;
  }

  target_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  buf = kmalloc_array(MAX_PATH + NAME_MAX + MAX_BUF_OFFSET, sizeof(char),
          GFP_KERNEL);
  buf_offset = d_path(&f.file->f_path, buf,
          MAX_PATH + NAME_MAX + MAX_BUF_OFFSET);
  memcpy(target_file_path, buf_offset, MAX_PATH + NAME_MAX);

  kfree(buf);

  if (!is_kernel_or_procfs_log(target_file_path)) {
    exec_file_path = kmalloc_array(MAX_PATH + NAME_MAX,
                 sizeof(char), GFP_KERNEL);
    find_path_to_exec_file(exec_file_path, current->comm);

    entry = allocate_log_entry(exec_file_path, target_file_path);

    mutex_lock(&log_entries_mutex);
    add_log_entry(entry);
    mutex_unlock(&log_entries_mutex);
  } else {
    kfree(target_file_path);
  }

  return real_sys_pwritev(regs);
}

/*
 * A hook for pwritev2 syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage ssize_t hook_sys_pwritev2(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path, *target_file_path, *buf, *buf_offset;
  struct fd f = fdget(regs->di);

  if (!f.file) {
    return -ENOENT;
  }

  target_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  buf = kmalloc_array(MAX_PATH + NAME_MAX + MAX_BUF_OFFSET, sizeof(char),
          GFP_KERNEL);
  buf_offset = d_path(&f.file->f_path, buf,
          MAX_PATH + NAME_MAX + MAX_BUF_OFFSET);
  memcpy(target_file_path, buf_offset, MAX_PATH + NAME_MAX);

  kfree(buf);

  if (!is_kernel_or_procfs_log(target_file_path)) {
    exec_file_path = kmalloc_array(MAX_PATH + NAME_MAX,
                 sizeof(char), GFP_KERNEL);
    find_path_to_exec_file(exec_file_path, current->comm);

    entry = allocate_log_entry(exec_file_path, target_file_path);

    mutex_lock(&log_entries_mutex);
    add_log_entry(entry);
    mutex_unlock(&log_entries_mutex);
  } else {
    kfree(target_file_path);
  }

  return real_sys_pwritev2(regs);
}

/*
 * A hook for chown syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage int hook_sys_chown(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path,
    *target_file_path = kmalloc_array(MAX_PATH + NAME_MAX,
              sizeof(char), GFP_KERNEL);
  long err = strncpy_from_user(target_file_path, (char *)regs->di,
             MAX_PATH + NAME_MAX);

  if (err < 1) {
    kfree(target_file_path);
    return -EFAULT;
  }

  exec_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  find_path_to_exec_file(exec_file_path, current->comm);

  entry = allocate_log_entry(exec_file_path, target_file_path);
  mutex_lock(&log_entries_mutex);
  add_log_entry(entry);
  mutex_unlock(&log_entries_mutex);

  return real_sys_chown(regs);
}

/*
 * A hook for lchown syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage int hook_sys_lchown(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path,
    *target_file_path = kmalloc_array(MAX_PATH + NAME_MAX,
              sizeof(char), GFP_KERNEL);
  long err = strncpy_from_user(target_file_path, (char *)regs->di,
             MAX_PATH + NAME_MAX);

  if (err < 1) {
    kfree(target_file_path);
    return -EFAULT;
  }

  exec_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  find_path_to_exec_file(exec_file_path, current->comm);

  entry = allocate_log_entry(exec_file_path, target_file_path);
  mutex_lock(&log_entries_mutex);
  add_log_entry(entry);
  mutex_unlock(&log_entries_mutex);

  return real_sys_lchown(regs);
}

/*
 * A hook for fchown syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage int hook_sys_fchown(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path, *target_file_path, *buf, *buf_offset;
  struct fd f = fdget(regs->di);

  if (!f.file) {
    return -ENOENT;
  }

  exec_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  find_path_to_exec_file(exec_file_path, current->comm);

  target_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  buf = kmalloc_array(MAX_PATH + NAME_MAX + MAX_BUF_OFFSET, sizeof(char),
          GFP_KERNEL);
  buf_offset = d_path(&f.file->f_path, buf,
          MAX_PATH + NAME_MAX + MAX_BUF_OFFSET);
  memcpy(target_file_path, buf_offset, MAX_PATH + NAME_MAX);

  kfree(buf);

  entry = allocate_log_entry(exec_file_path, target_file_path);
  mutex_lock(&log_entries_mutex);
  add_log_entry(entry);
  mutex_unlock(&log_entries_mutex);

  return real_sys_fchown(regs);
}

/*
 * A hook for fchownat syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage int hook_sys_fchownat(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path,
    *target_file_path = kmalloc_array(MAX_PATH + NAME_MAX,
              sizeof(char), GFP_KERNEL);
  long err = strncpy_from_user(target_file_path, (char *)regs->si,
             MAX_PATH + NAME_MAX);

  if (err < 1) {
    kfree(target_file_path);
    return -EFAULT;
  }

  exec_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  find_path_to_exec_file(exec_file_path, current->comm);

  if (target_file_path[0] != '/') {
    find_path_to_target_file(target_file_path, regs->di, regs->si);
  }

  entry = allocate_log_entry(exec_file_path, target_file_path);
  mutex_lock(&log_entries_mutex);
  add_log_entry(entry);
  mutex_unlock(&log_entries_mutex);

  return real_sys_fchownat(regs);
}

/*
 * A hook for chmod syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage int hook_sys_chmod(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path,
    *target_file_path = kmalloc_array(MAX_PATH + NAME_MAX,
              sizeof(char), GFP_KERNEL);
  long err = strncpy_from_user(target_file_path, (char *)regs->di,
             MAX_PATH + NAME_MAX);

  if (err < 1) {
    kfree(target_file_path);
    return -EFAULT;
  }

  exec_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  find_path_to_exec_file(exec_file_path, current->comm);

  entry = allocate_log_entry(exec_file_path, target_file_path);
  mutex_lock(&log_entries_mutex);
  add_log_entry(entry);
  mutex_unlock(&log_entries_mutex);

  return real_sys_chmod(regs);
}

/*
 * A hook for fchmod syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage int hook_sys_fchmod(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path, *target_file_path, *buf, *buf_offset;
  struct fd f = fdget(regs->di);

  if (!f.file) {
    return -ENOENT;
  }

  exec_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  find_path_to_exec_file(exec_file_path, current->comm);

  target_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  buf = kmalloc_array(MAX_PATH + NAME_MAX + MAX_BUF_OFFSET, sizeof(char),
          GFP_KERNEL);
  buf_offset = d_path(&f.file->f_path, buf,
          MAX_PATH + NAME_MAX + MAX_BUF_OFFSET);
  memcpy(target_file_path, buf_offset, MAX_PATH + NAME_MAX);

  kfree(buf);

  entry = allocate_log_entry(exec_file_path, target_file_path);
  mutex_lock(&log_entries_mutex);
  add_log_entry(entry);
  mutex_unlock(&log_entries_mutex);

  return real_sys_fchmod(regs);
}

/*
 * A hook for fchmodat syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage int hook_sys_fchmodat(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path,
    *target_file_path = kmalloc_array(MAX_PATH + NAME_MAX,
              sizeof(char), GFP_KERNEL);
  long err = strncpy_from_user(target_file_path, (char *)regs->si,
             MAX_PATH + NAME_MAX);

  if (err < 1) {
    kfree(target_file_path);
    return -EFAULT;
  }

  exec_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  find_path_to_exec_file(exec_file_path, current->comm);

  if (target_file_path[0] != '/') {
    find_path_to_target_file(target_file_path, regs->di, regs->si);
  }

  entry = allocate_log_entry(exec_file_path, target_file_path);
  mutex_lock(&log_entries_mutex);
  add_log_entry(entry);
  mutex_unlock(&log_entries_mutex);

  return real_sys_fchmodat(regs);
}

/*
 * A hook for fork syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage pid_t hook_sys_fork(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path, *target_exec_file_path;

  exec_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  find_path_to_exec_file(exec_file_path, current->comm);

  target_exec_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  memcpy(target_exec_file_path, exec_file_path, MAX_PATH + NAME_MAX);

  entry = allocate_log_entry(exec_file_path, target_exec_file_path);
  mutex_lock(&log_entries_mutex);
  add_log_entry(entry);
  mutex_unlock(&log_entries_mutex);

  mutex_lock(&exec_files_mutex);
  if (search_in_rbtree(&exec_files_rbtree_root, target_exec_file_path)) {
    mutex_unlock(&exec_files_mutex);
    return -EFAULT;
  }
  mutex_unlock(&exec_files_mutex);

  return real_sys_fork(regs);
}

/*
 * A hook for vfork syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage pid_t hook_sys_vfork(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path, *target_exec_file_path;

  exec_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  find_path_to_exec_file(exec_file_path, current->comm);

  target_exec_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  memcpy(target_exec_file_path, exec_file_path, MAX_PATH + NAME_MAX);

  entry = allocate_log_entry(exec_file_path, target_exec_file_path);
  mutex_lock(&log_entries_mutex);
  add_log_entry(entry);
  mutex_unlock(&log_entries_mutex);

  mutex_lock(&exec_files_mutex);
  if (search_in_rbtree(&exec_files_rbtree_root, target_exec_file_path)) {
    mutex_unlock(&exec_files_mutex);
    return -EFAULT;
  }
  mutex_unlock(&exec_files_mutex);

  return real_sys_vfork(regs);
}

/*
 * A hook for execve syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage int hook_sys_execve(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path, *target_exec_file_path =
              kmalloc_array(MAX_PATH + NAME_MAX,
                sizeof(char), GFP_KERNEL);
  long err = strncpy_from_user(target_exec_file_path, (char *)regs->di,
             MAX_PATH + NAME_MAX);

  if (err < 1) {
    kfree(target_exec_file_path);
    return -EFAULT;
  }

  exec_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  find_path_to_exec_file(exec_file_path, current->comm);

  entry = allocate_log_entry(exec_file_path, target_exec_file_path);
  mutex_lock(&log_entries_mutex);
  add_log_entry(entry);
  mutex_unlock(&log_entries_mutex);

  mutex_lock(&exec_files_mutex);
  if (search_in_rbtree(&exec_files_rbtree_root, target_exec_file_path)) {
    mutex_unlock(&exec_files_mutex);
    return -EFAULT;
  }
  mutex_unlock(&exec_files_mutex);

  return real_sys_execve(regs);
}

/*
 * A hook for execveat syscall.
 *
 * @regs. A representation of registers(x86_64) for a real syscall.
 *
 * @return. Returned value of the real syscall.
 */
static asmlinkage int hook_sys_execveat(struct pt_regs *regs)
{
  struct log_entry *entry;
  char *exec_file_path, *target_exec_file_path =
              kmalloc_array(MAX_PATH + NAME_MAX,
                sizeof(char), GFP_KERNEL);
  long err = strncpy_from_user(target_exec_file_path, (char *)regs->si,
             MAX_PATH + NAME_MAX);

  if (err < 1) {
    kfree(target_exec_file_path);
    return -EFAULT;
  }

  exec_file_path =
    kmalloc_array(MAX_PATH + NAME_MAX, sizeof(char), GFP_KERNEL);
  find_path_to_exec_file(exec_file_path, current->comm);

  if (target_exec_file_path[0] != '/') {
    find_path_to_target_file(target_exec_file_path, regs->di,
           regs->si);
  }

  entry = allocate_log_entry(exec_file_path, target_exec_file_path);
  mutex_lock(&log_entries_mutex);
  add_log_entry(entry);
  mutex_unlock(&log_entries_mutex);

  mutex_lock(&exec_files_mutex);
  if (search_in_rbtree(&exec_files_rbtree_root, target_exec_file_path)) {
    mutex_unlock(&exec_files_mutex);
    return -EFAULT;
  }
  mutex_unlock(&exec_files_mutex);

  return real_sys_execveat(regs);
}

#define SYSCALL_NAME(name) ("__x64_" name)
#define HOOK(_name, _function, _original)                             \
  {                                                             \
    .name = SYSCALL_NAME(_name), .function = (_function), \
    .original = (_original)                               \
  }

static DEFINE_MUTEX(hooks_mutex);

/*
 * Hooks table.
 */
static struct ftrace_hook sys_calls_hooks[] = {
  /*
   * 1st level of system calls. Amount: 7. Index range: 0-6.
   */
  HOOK("sys_open", hook_sys_open, &real_sys_open),
  HOOK("sys_openat", hook_sys_openat, &real_sys_openat),
  HOOK("sys_write", hook_sys_write, &real_sys_write),
  HOOK("sys_writev", hook_sys_writev, &real_sys_writev),
  HOOK("sys_pwrite64", hook_sys_pwrite64, &real_sys_pwrite64),
  HOOK("sys_pwritev", hook_sys_pwritev, &real_sys_pwritev),
  HOOK("sys_pwritev2", hook_sys_pwritev2, &real_sys_pwritev2),
  /*
   * 2nd level of system calls. Amount: 7 + 7. Index range: 0-13.
   */
  HOOK("sys_chown", hook_sys_chown, &real_sys_chown),
  HOOK("sys_lchown", hook_sys_lchown, &real_sys_lchown),
  HOOK("sys_fchown", hook_sys_fchown, &real_sys_fchown),
  HOOK("sys_fchownat", hook_sys_fchownat, &real_sys_fchownat),
  HOOK("sys_chmod", hook_sys_chmod, &real_sys_chmod),
  HOOK("sys_fchmod", hook_sys_fchmod, &real_sys_fchmod),
  HOOK("sys_fchmodat", hook_sys_fchmodat, &real_sys_fchmodat),
  /*
   * 3rd level of system calls. Amount: 7 + 7 + 4. Index range: 0-17.
   */
  HOOK("sys_fork", hook_sys_fork, &real_sys_fork),
  HOOK("sys_vfork", hook_sys_vfork, &real_sys_vfork),
  HOOK("sys_execve", hook_sys_execve, &real_sys_execve),
  HOOK("sys_execveat", hook_sys_execveat, &real_sys_execveat)
};

/*
 * A function that checks if a file exists and if it's not a directory.
 *
 * @param path. Path to the possible file location.
 *
 * @return. true on success or false otherwise.
 */
static bool file_exists(const char *path)
{
  struct file *file = filp_open(path, O_RDONLY, 0);
  if (IS_ERR(file) || file == NULL) {
    return false;
  } else if (S_ISDIR(file->f_inode->i_mode)) {
    filp_close(file, NULL);
    return false;
  }
  filp_close(file, NULL);

  return true;
}

/*
 * A function that looks for a character in a char array.
 *
 * @param str. Source to search.
 * @param c. Character to find.
 *
 * @return. First character entry position on success or str size otherwise.
 */
static size_t find_char(const char *str, char c)
{
  size_t str_length, pos;
  int i;

  str_length = strlen(str);
  pos = 0;

  for (i = 0; i < str_length; ++i) {
    if (str[i] == c) {
      return pos;
    }
    ++pos;
  }

  return str_length;
}

enum command {
  cmd_unknown,
  cmd_startlogging,
  cmd_stoplogging,
  cmd_setsyscalllevel,
  cmd_block,
  cmd_unblock
};

/*
 * A function that parses input character array and divides a command from it.
 *
 * @param input. User input with command on first place.
 *
 * @return. Command enum.
 */
static enum command parse_command(const char *input)
{
  enum command cmd;

  if (!strncmp(input, "startlogging", 12)) {
    cmd = cmd_startlogging;
  } else if (!strncmp(input, "stoplogging", 11)) {
    cmd = cmd_stoplogging;
  } else if (!strncmp(input, "setsyscalllevel", 15)) {
    cmd = cmd_setsyscalllevel;
  } else if (!strncmp(input, "block", 5)) {
    cmd = cmd_block;
  } else if (!strncmp(input, "unblock", 7)) {
    cmd = cmd_unblock;
  } else {
    cmd = cmd_unknown;
  }

  return cmd;
}

/*
 * A function that processes 'startlogging' command.
 */
static void process_startlogging(void)
{
  mutex_lock(&hooks_mutex);
  if (!logging) {
    int err = install_hooks(sys_calls_hooks, syscall_level);

    if (err) {
      pr_alert("System calls hooks not installed.\n");
    } else {
      logging = true;
      pr_info("Logging started.\n");
    }
  }
  mutex_unlock(&hooks_mutex);
}

/*
 * A function that processes 'stoplogging' command.
 */
static void process_stoplogging(void)
{
  mutex_lock(&hooks_mutex);
  if (logging) {
    remove_hooks(sys_calls_hooks, syscall_level);

    logging = false;
    pr_info("Logging stopped.\n");
  }
  mutex_unlock(&hooks_mutex);
}

/*
 * A function that processes 'setsyscalllevel' command.
 *
 * @param level_str. New syscall level in string format.
 */
static void process_setsyscalllevel(const char *level_str)
{
  int level, result, err;

  result = kstrtoint(level_str, 10, &level);
  if (result != 0) {
    pr_debug("kstrtoint failed with error %d", result);
    return;
  }

  if (syscall_level == level) {
    pr_info("Syscall level is already set to %d!\n", syscall_level);
    return;
  }

  if (level == 1 || level == 2 || level == 3) {
    mutex_lock(&hooks_mutex);
    remove_hooks(sys_calls_hooks, syscall_level);

    syscall_level = level;

    err = install_hooks(sys_calls_hooks, syscall_level);

    if (err) {
      logging = false;
      pr_alert("System calls hooks not installed.\n");
    } else {
      logging = true;
      pr_info("Syscall level changed to %d.\n",
        syscall_level);
    }
    mutex_unlock(&hooks_mutex);
  } else {
    pr_info("Unsupported operation. Unable to set syscall level to %d!\n",
      level);
  }
}

/*
 * A function that processes 'block' command.
 *
 * @param path. Path to the process to be blocked.
 */
static void process_block(const char *path)
{
  struct rb_node_wrapper *node;
  size_t path_length;

  if (!file_exists(path)) {
    pr_info("Error. File %s doesn't exist!\n", path);
    return;
  }

  mutex_lock(&exec_files_mutex);

  if (search_in_rbtree(&exec_files_rbtree_root, path)) {
    pr_info("Path %s is already blocked.\n", path);
    mutex_unlock(&exec_files_mutex);
    return;
  }

  node = kmalloc(sizeof(struct rb_node_wrapper), GFP_KERNEL);

  path_length = strlen(path) + 1;

  node->exec_file = kmalloc_array(path_length, sizeof(char), GFP_KERNEL);
  memcpy(node->exec_file, path, path_length);

  insert_to_rbtree(&exec_files_rbtree_root, node);

  pr_info("Success! File %s blocked!\n", path);
  mutex_unlock(&exec_files_mutex);
}

/*
 * A function that processes 'unblock' command.
 *
 * @param path. Path to the process to be unblocked.
 */
static void process_unblock(const char *path)
{
  struct rb_node_wrapper *node;

  mutex_lock(&exec_files_mutex);
  node = search_in_rbtree(&exec_files_rbtree_root, path);
  if (!node) {
    pr_info("Path %s is not blocked.\n", path);
    return;
  }

  erase_from_rbtree(&exec_files_rbtree_root, node);

  pr_info("Success! File %s unblocked!", path);
  mutex_unlock(&exec_files_mutex);
}

/*
 * A function that processes commands.
 *
 * @param cmd. Command.
 * @param args. Args to the command.
 */
static void process_command(enum command cmd, const char *args)
{
  // pr_info("Processing command... Cmd: %d, args: %s.\n", cmd, args);

  switch (cmd) {
  case cmd_startlogging:
    process_startlogging();
    return;
  case cmd_stoplogging:
    process_stoplogging();
    return;
  case cmd_setsyscalllevel:
    process_setsyscalllevel(args);
    return;
  case cmd_block:
    process_block(args);
    return;
  case cmd_unblock:
    process_unblock(args);
    return;
  case cmd_unknown:
    pr_info("Unknown command. Unable to process.\n");
    return;
  }
}

static ssize_t procfile_write(struct file *file, const char __user *buff,
            size_t length, loff_t *offset)
{
  char buffer[MAX_INSTRUCTION_LENGTH + 1];
  char *args;
  enum command cmd;
  size_t space_pos;

  if (length > MAX_INSTRUCTION_LENGTH) {
    pr_info("Buffer size exceeded!\n");
    return -EIO;
  }
  if (length == 0) {
    pr_info("Empty input.\n");
    return -EIO;
  }
  if (copy_from_user(buffer, buff, length)) {
    pr_info("Not enought RAM!\n");
    return -EFAULT;
  }

  buffer[length - 1] = '\0';
  space_pos = find_char(buffer, ' ');

  cmd = parse_command(buffer);
  // pr_info("Command processed: %d.\n", cmd);

  args = buffer + space_pos + 1;
  // pr_info("Args processed: %s.\n", args);
  process_command(cmd, args);

  return length;
}

static void *seq_start(struct seq_file *s, loff_t *pos)
{
  struct list_head *head;

  head = seq_list_start(&log_entries_list, *pos);
  if (head) {
    mutex_lock(&log_entries_mutex);
  } else {
    mutex_unlock(&log_entries_mutex);
  }

  return head;
}

static void *seq_next(struct seq_file *s, void *v, loff_t *pos)
{
  return seq_list_next(v, &log_entries_list, pos);
}

static void seq_stop(struct seq_file *s, void *v)
{
  // Nothing
}

static int seq_show(struct seq_file *s, void *v)
{
  struct log_entry *entry;

  entry = list_entry(v, struct log_entry, head);
  seq_printf(s, "Exec: %s. Syscall target: %s.\n", entry->exec_file_path,
       entry->syscall_target_file_path);
  return 0;
}

static struct seq_operations my_seq_ops = {
  .start = seq_start,
  .next = seq_next,
  .stop = seq_stop,
  .show = seq_show,
};

static int procfile_open(struct inode *inode, struct file *file)
{
  pr_debug("Procfile opened!\n");
  return seq_open(file, &my_seq_ops);
};

#ifdef HAVE_PROC_OPS
static const struct proc_ops proc_file_fops = {
  .proc_open = procfile_open,
  .proc_write = procfile_write,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = seq_release,
};
#else
static const struct file_operations proc_file_fops = {
  .open = procfile_open,
  .write = procfile_write,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = seq_release,
};
#endif // HAVE_PROC_OPS
#endif // defined(CONFIG_X86_64) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)

/*
 * A function that serves to initialize the module.
 * It is launched once when the module is insmod'ed.
 *
 * @return. 0 on success, any error code otherwise.
 */
static int init_mod(void)
{
#if !defined(CONFIG_X86_64) || LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
  pr_info("The arch has to be x86-64 and the kernel version has to be >= 4.4.0.\n");
  return EPERM;
#else
  int err = install_hooks(sys_calls_hooks, syscall_level);
  if (err) {
    pr_alert("System calls hooks not installed.\n");
    return err;
  }

  if (!unload) {
    try_module_get(THIS_MODULE);
  }

  proc_entry = proc_create(PROCFS_NAME, 0644, NULL, &proc_file_fops);
  if (!proc_entry) {
    proc_remove(proc_entry);
    pr_alert("Could not initialize /proc/%s\n", PROCFS_NAME);
    return -ENOMEM;
  }

  pr_info("Module loaded");

  return 0;
#endif // !defined(CONFIG_X86_64) || LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
}

/*
 * A function that serves to clean up the memory used by the module.
 * It is launched once when the module is rmmod'ed.
 */
static void exit_mod(void)
{
#if defined(CONFIG_X86_64) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
  mutex_lock(&exec_files_mutex);
  mutex_lock(&log_entries_mutex);
  mutex_lock(&hooks_mutex);

  proc_remove(proc_entry);

  clear_rbtree(&exec_files_rbtree_root);
  clear_log_entries();

  remove_hooks(sys_calls_hooks, syscall_level);

  pr_info("Module unloaded");
#endif // defined(CONFIG_X86_64) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
}

module_init(init_mod);
module_exit(exit_mod);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(
  "Loadable kernel module(LKM) for monitoring of certain system calls.");
MODULE_VERSION("1.0");

#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#define MAX_PATH_LENGTH 128
#define MAX_FILE_NAME_LENGTH 32
#define MAX_INSTRUCTION_LENGTH 16 + MAX_PATH_LENGTH + MAX_FILE_NAME_LENGTH

#define PROCFS_NAME "syscallmonitor"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define HAVE_PROC_OPS
#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)

static struct proc_dir_entry *proc_entry;

static bool logging = true;
static int syscall_level = 1;

static bool unload = true;
module_param(unload, bool, 0);

/*
 * A structure that wraps rb_node field and char[] field.
 * This structure is defined for being a real node of a red-black tree data
 * structure as rb tree is intrusive in linux kernel.
 */
struct rb_node_wrapper {
  struct rb_node node;
  char *exec_file;
};

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
                                                const char *desired_exec_file) {
  struct rb_node *node = root->rb_node;

  while (node) {
    struct rb_node_wrapper *curr = rb_entry(node, struct rb_node_wrapper, node);
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
 * @return. 0 on success or -1 otherwise.
 */
static int insert_to_rbtree(struct rb_root *root,
                            struct rb_node_wrapper *wrapper_entry) {
  struct rb_node **new = &(root->rb_node), *parent = NULL;

  while (*new) {
    struct rb_node_wrapper *curr = rb_entry(*new, struct rb_node_wrapper, node);
    int result = strcmp(wrapper_entry->exec_file, curr->exec_file);

    parent = *new;
    if (result < 0)
      new = &((*new)->rb_left);
    else if (result > 0)
      new = &((*new)->rb_right);
    else
      return -1;
  }

  rb_link_node(&wrapper_entry->node, parent, new);
  rb_insert_color(&wrapper_entry->node, root);

  return 0;
}

/*
 * A function that erases a node from a red-black tree data structure.
 *
 * @param root. A root node of rb tree.
 * @param wrapper_entry. A pointer to a new node that has to be inserted.
 */
static void erase_from_rbtree(struct rb_root *root,
                              struct rb_node_wrapper *wrapper_entry) {
  rb_erase(&wrapper_entry->node, root);
  kfree(wrapper_entry->exec_file);
  kfree(wrapper_entry);
}

/*
 * A function that checks if a file exists and if it's not a directory.
 *
 * @param path. Path to the possible file location.
 *
 * @return. true on success or false otherwise.
 */
static bool file_exists(const char *path) {
  struct file *file = filp_open(path, O_RDONLY, 0);
  if (IS_ERR(file) || S_ISDIR(file->f_inode->i_mode) || file == NULL) {
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
static size_t find_char(const char *str, char c) {
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
static enum command parse_command(const char *input) {
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
static void process_startlogging(void) {
  logging = true;
  pr_info("Logging started.\n");
}

/*
 * A function that processes 'stoplogging' command.
 */
static void process_stoplogging(void) {
  logging = false;
  pr_info("Logging stopped.\n");
}

/*
 * A function that processes 'setsyscalllevel' command.
 *
 * @param level_str. New syscall level in string format.
 */
static void process_setsyscalllevel(const char *level_str) {
  int level;

  kstrtoint(level_str, 10, &level);

  if (syscall_level == level) {
    pr_info("Syscall level is already set to %d!\n", syscall_level);
    return;
  }

  if (level == 1 || level == 2 || level == 3) {
    syscall_level = level;
    pr_info("Syscall level changed to %d.\n", syscall_level);
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
static void process_block(const char *path) {
  struct rb_node_wrapper *node;
  size_t path_length;

  if (!file_exists(path)) {
    pr_info("Error. File %s doesn't exist!\n", path);
    return;
  }

  if (search_in_rbtree(&exec_files_rbtree_root, path)) {
    pr_info("Path %s is already blocked.\n", path);
    return;
  }

  node = kmalloc(sizeof(struct rb_node_wrapper), GFP_KERNEL);

  path_length = strlen(path) + 1;

  node->exec_file = kmalloc_array(path_length, sizeof(char), GFP_KERNEL);
  memcpy(node->exec_file, path, path_length);

  insert_to_rbtree(&exec_files_rbtree_root, node);

  pr_info("Success! File %s blocked!\n", path);
}

/* A function that processes 'unblock' command.
 *
 * @param path. Path to the process to be unblocked.
 */
static void process_unblock(const char *path) {
  struct rb_node_wrapper *node =
      search_in_rbtree(&exec_files_rbtree_root, path);
  if (!node) {
    pr_info("Path %s is not blocked.\n", path);
    return;
  }

  erase_from_rbtree(&exec_files_rbtree_root, node);

  pr_info("Success! File %s unblocked!", path);
}

/* A function that processes commands.
 *
 * @param cmd. Command.
 * @param args. Args to the command.
 */
static void process_command(enum command cmd, const char *args) {
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
                              size_t len, loff_t *off) {
  char buffer[MAX_INSTRUCTION_LENGTH + 1];
  char *args;
  enum command cmd;
  size_t space_pos;

  if (len > MAX_INSTRUCTION_LENGTH) {
    pr_info("Buffer size exceeded!\n");
    return -EIO;
  }
  if (len == 0) {
    pr_info("Empty input.\n");
    return -EIO;
  }
  if (copy_from_user(buffer, buff, len)) {
    pr_info("Not enought RAM!\n");
    return -EFAULT;
  }

  buffer[len - 1] = '\0';
  space_pos = find_char(buffer, ' ');

  cmd = parse_command(buffer);
  // pr_info("Command processed: %d.\n", cmd);

  args = buffer + space_pos + 1;
  // pr_info("Args processed: %s.\n", args);
  process_command(cmd, args);

  return len;
}

#ifdef HAVE_PROC_OPS
static const struct proc_ops proc_file_fops = {
    .proc_write = procfile_write,
};
#else
static const struct file_operations proc_file_fops = {
    .write = procfile_write,
};
#endif // HAVE_PROC_OPS

static int init_mod(void) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
  pr_info(
      "The current kernel version is less than 4.4.0. LKM features will not "
      "be applied.\n");
  return EPERM;
#else
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
#endif // LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
}

static void exit_mod(void) {
  proc_remove(proc_entry);

  // TODO Free rbtree memory

  pr_info("Module unloaded");
}

module_init(init_mod);
module_exit(exit_mod);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(""); // fill later
MODULE_DESCRIPTION("Loadable kernel module for system call monitoring.");
MODULE_VERSION("1.0");

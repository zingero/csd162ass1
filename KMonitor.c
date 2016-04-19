#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/delay.h> 
#include <linux/sched.h>
#include <linux/version.h>

// Write Protect Bit (CR0:16)
#define CR0_WP 0x00010000 

MODULE_LICENSE("GPL");

void **syscall_table;

unsigned long **find_sys_call_table(void);

long (*original_open_call)(const char *, int, int);
long (*original_read_call)(const char *, int, int);
long (*original_write_call)(const char *, int, int);
long (*original_listen_call)(const char *, int, int);
long (*original_connect_call)(const char *, int, int);
long (*original_mount_call)(const char *, int, int);

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
    printk(KERN_DEBUG "HIJACKED: open\n");
    return original_open_call(filename, flags, mode);
}

int my_sys_read(const char *filename, int flags, int mode)
{
    printk(KERN_DEBUG "HIJACKED: read\n");
    return original_read_call(filename, flags, mode);
}

int my_sys_write(const char *filename, int flags, int mode)
{
    printk(KERN_DEBUG "HIJACKED: write\n");
    return original_write_call(filename, flags, mode);
}

int my_sys_listen(const char *filename, int flags, int mode)
{
    printk(KERN_DEBUG "HIJACKED: listen\n");
    return original_listen_call(filename, flags, mode);
}

int my_sys_connect(const char *filename, int flags, int mode)
{
    printk(KERN_DEBUG "HIJACKED: connect\n");
    return original_connect_call(filename, flags, mode);
}

int my_sys_mount(const char *filename, int flags, int mode)
{
    printk(KERN_DEBUG "HIJACKED: mount\n");
    return original_mount_call(filename, flags, mode);
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

    original_open_call = syscall_table[__NR_open];
    original_read_call = syscall_table[__NR_read];
    original_write_call = syscall_table[__NR_write];
    original_listen_call = syscall_table[__NR_listen];
    original_connect_call = syscall_table[__NR_connect];
    original_mount_call = syscall_table[__NR_mount];

    syscall_table[__NR_open] = my_sys_open;
    printk(KERN_DEBUG "Hijacked open\n");
    syscall_table[__NR_read] = my_sys_read;
    printk(KERN_DEBUG "Hijacked read\n");
    syscall_table[__NR_write] = my_sys_write;
    printk(KERN_DEBUG "Hijacked write\n");
    syscall_table[__NR_listen] = my_sys_listen;
    printk(KERN_DEBUG "Hijacked listen\n");
    syscall_table[__NR_connect] = my_sys_connect;
    printk(KERN_DEBUG "Hijacked connect\n");
    syscall_table[__NR_mount] = my_sys_mount;
    printk(KERN_DEBUG "Hijacked mount\n");
    write_cr0(cr0);
    return 0;
}

static void __exit syscall_release(void)
{
    unsigned long cr0;

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
}

module_init(syscall_init);
module_exit(syscall_release);

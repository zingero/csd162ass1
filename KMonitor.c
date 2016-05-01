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
#include <linux/file.h>
#include <linux/times.h>
#include <linux/timekeeping.h>
#include <linux/rtc.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <net/inet_sock.h>

#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <asm/uaccess.h>
#include <linux/string.h>

// Write Protect Bit (CR0:16)
#define CR0_WP 0x00010000 

#define MAX_EVENTS 10
#define BUF_SIZE 128

static char msg[128];
static int len = 0;
static int len_check = 1;

void **syscall_table;

spinlock_t lock;

unsigned long **find_sys_call_table(void);

long (*original_open_call)(const char *, int, int);
long (*original_read_call)(unsigned int, char *, size_t);
long (*original_write_call)(unsigned int, const char *, size_t);
long (*original_listen_call)(int, int);
long (*original_accept_call)(int, struct sockaddr *, int *);
long (*original_mount_call)(char *, char *, char *, unsigned long, void *);

/* monitoring flags */
int file_monitoring = 1;
int net_monitoring = 0;
int mount_monitoring = 0;

/*MAX_EVENTS stands for the maximum number of elements Queue can hold.
  num_of_events stands for the current size of the Queue.
  events is the array of elements. 
 */
int num_of_events = 0;
char events[MAX_EVENTS][BUF_SIZE];

struct rtc_time tm;
struct timeval time;
unsigned long local_time;

void get_time(void)
{
	do_gettimeofday(&time);
	local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
	rtc_time_to_tm(local_time, &tm);
}

void dequeue(void)
{
    int i;
    char empty_string[128] = {'\0'};
    if(num_of_events == 0)
    {
	    return;
    }
    else
    {
    	for(i = 1 ; i < MAX_EVENTS ; ++i)
    	{
    		strcpy(events[i-1], events[i]);
    	}
	    num_of_events--;
    	strcpy(events[num_of_events], empty_string);
    }
}

void enqueue(char *event)
{
    if(num_of_events == MAX_EVENTS)
    {
		dequeue();
    }
    strcpy(events[num_of_events], event);
    num_of_events++;
}

/* our system calls. executing by demand and returning the defined data. */
int my_sys_open(const char *filename, int flags, int mode)
{
    if(file_monitoring)
    {
		char temp[128]; // we need this array only to get the path.
    	// spin_lock(&lock);
    	char str[128];
    	get_time();
		if(filename != 0)
		{
		    sprintf(str, "%04d.%02d.%02d %02d:%02d:%02d, open %s %d %s\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, 
		    	filename, current->pid,	d_path(&(current->mm->exe_file->f_path), temp, 128));
		    printk(KERN_INFO "%s", str);
		    enqueue(str);
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
		char temp[100]; // we need this array only to get the paths
        char *filename = 0;
		get_time();
        
        spin_lock(&lock);
        filename = d_path(&(fget(fd)->f_path), temp, 100);
        if(filename != 0)
        {
            printk(KERN_INFO "%04d.%02d.%02d %02d:%02d:%02d, read %s %d %s %d \n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, filename, current->pid, d_path(&(current->mm->exe_file->f_path), temp, 100), (int)count);
        }
        else
        {
          printk(KERN_DEBUG "read: file name is null.\n");
        }
        spin_unlock(&lock);
    }
    return original_read_call(fd, buf, count);
}

int my_sys_write(unsigned int fd, const char * buf, size_t count)
{
    if(file_monitoring)  
    {
		char temp [128]; // we need this array only to get the paths
		char tmp[128]; // we need this array only to get the paths
        char *filename = 0;
		struct file *file;
    	get_time();
        spin_lock(&lock);
        
        file = fget(fd);
        filename = d_path(&(file->f_path), tmp, 128);
		fput(file);

        if(filename != 0)
        {
            printk(KERN_INFO "%04d.%02d.%02d %02d:%02d:%02d, write %s %d %s\n",
             					tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
             					filename, current->pid, d_path(&(current->mm->exe_file->f_path), temp, 128));
        }
        else
        {
          printk(KERN_DEBUG "write: file name is null.\n");
        }
        spin_unlock(&lock);
    }
    return original_write_call(fd, buf, count);
}

int my_sys_listen(int fd, int backlog)
{
    if(net_monitoring)
    {
    	struct file * struct_file;
    	struct socket *socket;
		int port = 0;
		// int ip = 0;	
		struct sock *sk;
		char temp[128];
		// struct inet_sock *inet;
    	get_time();

		struct_file = (current->files->fdt->fd[fd]);
    	socket = (struct socket*) struct_file->private_data;
		if(socket)
		{ 
		 	sk = socket->sk;
		 	if(sk)
		 	{
		   		port = (le16_to_cpu((sk->__sk_common.skc_portpair)>>16));
		   		printk(KERN_INFO "%04d.%02d.%02d %02d:%02d:%02d, listen %pI4:%d %d %s\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
		   											 (&(sk->__sk_common.skc_addrpair)), port, current->pid, d_path(&(current->mm->exe_file->f_path), temp, 128));
		   	}
	    	else
	    	{
	    		printk(KERN_DEBUG "wrong socket type\n");
	    	}
		}
		else
		{
	    	printk(KERN_DEBUG "socket is null\n");	
	    }
    }
    return original_listen_call(fd, backlog);
}

int my_sys_accept(int fd, struct sockaddr * uservaddr, int * addrlen)
{
	struct file *struct_file;
    struct socket *socket;
    struct sock *sk;
    // int pflag;
    int new_fd = 0;
    // char* pname, *p;
	char temp[128];
    if(net_monitoring)
    {
    	printk(KERN_INFO "MY SYS ACCEPT STARTS\n");
    	get_time();
	    // pflag = 0;

	    new_fd = original_accept_call(fd, uservaddr, addrlen);
	    struct_file = (current->files->fdt->fd[new_fd]);
	    socket = (struct socket*) struct_file->private_data;
	    sk = socket->sk;
		printk(KERN_INFO "%04d.%02d.%02d %02d:%02d:%02d, accept %d %s %pI4 %d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, current->pid, d_path(&(current->mm->exe_file->f_path), temp, 128), (&(sk->__sk_common.skc_addrpair)), (le16_to_cpu((sk->__sk_common.skc_portpair)>>16)));
    }
    printk(KERN_INFO "MY SYS ACCEPT ENDS\n");
    return new_fd;
}

int my_sys_mount(char * dev_name, char * dir_name, char * type, unsigned long flags, void * data)
{
    if(mount_monitoring)
    {
		char temp[100];
		get_time();
		spin_lock(&lock);
		printk(KERN_DEBUG "%04d.%02d.%02d %02d:%02d:%02d, %s %s %s %d %s\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, dev_name, type, dir_name, current->pid, d_path(&(current->mm->exe_file->f_path), temp, 100));
    	spin_unlock(&lock);
    }
    return original_mount_call(dev_name, dir_name, type, flags, data);
}

int fops_open(struct inode * sp_inode, struct file *sp_file)
{
	// printk(KERN_INFO "proc called open\n");
	return 0;
}
int fops_release(struct inode *sp_indoe, struct file *sp_file)
{
	// printk(KERN_INFO "proc called release\n");
	return 0;
}

void print_events(void)
{
	int i = 0;
	for(; i < num_of_events ; ++i)
	{
		printk(KERN_INFO "%s\n", events[i]);
	}
}

void print_conf(void)
{
	if(file_monitoring)
		printk(KERN_INFO "File Monitoring - Enabled\n");
	else
		printk(KERN_INFO "File Monitoring - Disabled\n");
	if(net_monitoring)
		printk(KERN_INFO "Net Monitoring - Enabled\n");
	else
		printk(KERN_INFO "Net Monitoring - Disabled\n");
	if(mount_monitoring)
		printk(KERN_INFO "Mount Monitoring - Enabled\n");
	else
		printk(KERN_INFO "Mount Monitoring - Disabled\n");
}

ssize_t fops_read(struct file *sp_file,char __user *buf, size_t size, loff_t *offset)
{
	if (len_check)
	 len_check = 0;
	else 
	{
	 	len_check = 1;
	 	return 0;
	}

	copy_to_user(buf,msg,len);
	printk(KERN_INFO "KMonitor - Last Events:\n");
	print_events();
	printk(KERN_INFO "KMonitor Current Configuration:\n");
	print_conf();
	return len;
}

/* write controling: parsing user preferences and LKM definition*/
ssize_t fops_write(struct file *sp_file,const char __user *buf, size_t size, loff_t *offset)
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
.open = fops_open,
.read = fops_read,
.write = fops_write,
.release = fops_release
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
    original_accept_call = syscall_table[__NR_accept];	
    original_mount_call = syscall_table[__NR_mount];
    syscall_table[__NR_open] = my_sys_open;
    syscall_table[__NR_read] = my_sys_read;
    syscall_table[__NR_write] = my_sys_write;
    syscall_table[__NR_listen] = my_sys_listen;
    syscall_table[__NR_accept] = my_sys_accept;
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
    syscall_table[__NR_accept] = original_accept_call;
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


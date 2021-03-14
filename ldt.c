/* TIL linux has modify_ldt */

#ifdef linux
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <asm/ldt.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "mmap.h"


/*
 * Useless use of ldt
 *
 * A 16 bit segment selector is [Index][TI][RPL]
 * which specify if it's from the LDT (TI=1) or GDT (TI=0)
 * and which RPL to limit CPL. Also TI means table indicator.
 *
 * A segment selector in the GDT of index 0 is a null segment selector,
 * index=0 in the LDT works.
 *
 * Loading CS or SS with a null segment selector generates a #GP. The rest is
 * fine.
 */

unsigned int read_ldt()
{
    int ret;
    __asm__ volatile("sldt %0\n": "=m" (ret): /* no input */);

    return ret;
}

int main(int argc, char **argv)
{
    // 64 bits ignores segment selectors but FS/GS
    int ret;

    struct user_desc ldt = {
	// so [IDX=0][1][11] => this ldt entry is pointed to by segment 7 
        // and also 4, 5, 6 - because a higher RPL is just ignored
        .entry_number = 0,
        // This is a 32 bits address - on 64 bits it's going
        // to load just the lower 32 bits and segfault on access
        // so we also need to map something from lower space first
        .base_addr = (unsigned long) get_low_page(),
        .limit = (unsigned int) -1,
        .seg_32bit = 1,
        .read_exec_only = 0, /* Data segment */
        .limit_in_pages = 0,
        .seg_not_present = 0,
        .useable = 1
    };

    printf("LDT before is %x\n", read_ldt());

    ret = syscall(__NR_modify_ldt, 1, &ldt, sizeof(struct user_desc));
    if (ret) {
        printf("modify: %d\n", ret);
        exit(1);
    }

    printf("LDT after is %x\n", read_ldt());

    // segment selector in 64 is ignored but for gs/fs
    __asm__("movl $4, %eax\nmovl %eax, %gs\n");
    __asm__("mov %%gs:(0), %0\n": "=r" (ret));

    printf("Eax = %x, ldt base=%x, ldt base value=%x\n", ret, ldt.base_addr,
		*((int *) (long) ldt.base_addr));

    if (argc == 1) {
	    execve("./ldt", (char *[]){"./ldt", "test", NULL}, NULL);
    }

    exit(0);
}
#else
int main(void)
{
}
#endif


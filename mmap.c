#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>

void *get_low_page(void)
{
    // On linux min address you can get from mmap is mmap_min_addr
    // cat /proc/sys/vm/mmap_min_addr
    int *p = mmap((void *) 65536, 4096, PROT_READ|PROT_WRITE,
		MAP_ANONYMOUS|MAP_FIXED|MAP_PRIVATE, -1, 0);

    if (p == (void *) -1) {
        perror("mmap");
        exit(1);
    }

    *p = 0xfeedfeed;
    return p;
}

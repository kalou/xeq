#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

volatile unsigned long time_read(char *addr)
{
    unsigned long first, second;

    __asm__("cpuid\n"
            "rdtsc\n" //serialized by cpuid
            "mov %%rax, %0\n"
            "testq $0, (%2)\n" // Read addr
            "jz 1f\n"
            "inc %%rax\n"
            "1:\n"
            "rdtscp\n" // serialized by p
            "mov %%rax, %1\n": "=r"(first), "=r"(second): "r"(addr):
                            "rax", "rdx", "rcx");

    if (first > second)
        return (-1ULL) - first + second;
    return second - first;
}

void flush_cache(void *addr)
{
    __asm__("clflush (%0)" : /* no out */ : "r"(addr) :);
}

static int cold_threshold = 150;
//static int cache_line_size = 64;

int cache_hot(void *addr)
{
    return (time_read(addr) <= cold_threshold);
}

void learn_cache_params(void)
{
    char *arr = malloc(4096);
    int total = 0, hot_total = 0;

#define LEARNING_CYCLES 2000
    /* Estimate cache-cold times */
    for (int i = 0; i < LEARNING_CYCLES; i++) {
        flush_cache(arr);
        total += time_read(arr);
        hot_total += time_read(arr);
    }

    printf("avg cold time is %d, avg hot %d (total %d, hot total %d)\n",
            total/LEARNING_CYCLES, hot_total/LEARNING_CYCLES, total, hot_total);

    // Naive threshold set half-way between hot and cold
    cold_threshold = (total + hot_total) / (2 * LEARNING_CYCLES);
    printf("set cold threshold to %d\n", cold_threshold);
}

int main(int argc, const char **argv)
{
    learn_cache_params();
    exit(0);
}

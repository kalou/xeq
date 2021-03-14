#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdio.h>

/*

Various x86 hacks to inspect virtualized things and execution quality

Note that since UMIP, these don't really work anymore

=== What is UMIP?

User-Mode Instruction Prevention (UMIP) is a security feature present in
new Intel Processors. If enabled, it prevents the execution of certain
instructions if the Current Privilege Level (CPL) is greater than 0. If
these instructions were executed while in CPL > 0, user space applications
could have access to system-wide settings such as the global and local
descriptor tables, the segment selectors to the current task state and the
local descriptor table. Hiding these system resources reduces the tools
available to craft privilege escalation attacks such as [8].

These are the instructions covered by UMIP:
* SGDT - Store Global Descriptor Table
* SIDT - Store Interrupt Descriptor Table
* SLDT - Store Local Descriptor Table
* SMSW - Store Machine Status Word
* STR - Store Task Register

If any of these instructions is executed with CPL > 0, a general protection
exception is issued when UMIP is enabled.

*/

struct _3_regs {
    int eax;
    int ecx;
    int edx;
};

struct _3_regs rdtscp()
{
    long edx, eax, ecx;
    __asm__ volatile("rdtscp": "=d" (edx), "=a" (eax), "=c" (ecx));

    return (struct _3_regs) {
        .eax = eax,
        .ecx = ecx,
        .edx = edx
    };
}

struct _2_regs {
    int eax;
    int edx;
};

/* Read performance counters if CR4.PCE=1 */
struct _2_regs rdpmc(int n)
{
    int edx, eax;
    __asm__ volatile("rdpmc\n":
            "=d" (edx), "=a" (eax) : "c" (n));

    return (struct _2_regs) {
        .eax = eax,
        .edx = edx
    };
}

struct _2_regs rdtsc()
{
    int edx, eax;
    __asm__ volatile("rdtsc\n": "=d" (edx), "=a" (eax));

    return (struct _2_regs) {
        .eax = eax,
        .edx = edx
    };
}

#ifdef linux
#define getcpu() syscall(__NR_getcpu)
#else
static int getcpu()
{
    return -1;
}
#endif

/* Identify CPU with local APIC id in CPUID. Can be virtualized,
 * APIC id is not super specified (0->n?)
 */
unsigned int cpuid_cpu()
{
    int ebx = 0;
    // Linux has a syscall for that (getcpu)

    __asm__ volatile("cpuid\n"
             "shrl $24, %%ebx\n":
             "=b" (ebx) : "a" (1) :
             "rcx", "rdx");

    return ebx;
}

/* RDTSCP gives processor id stored in the IA32_TSC_AUX MSR configured
 * by OS. On virtualized, it will give the host MSR value?
 * xen/osx seem to have 0
 * linux on linux should have numa<<something+core_id
 */
unsigned int rdtscp_cpu()
{
    struct _3_regs tscp = rdtscp();

    return tscp.ecx;
}

/* Modern CPUs have RDPID I couldn't test this */
unsigned int rdpid()
{
    int eax;
    __asm__ volatile(".byte 0xf3,0x0f,0xc7,0xf8\n": "=a" (eax));
    //__asm__ volatile("rdpid %%rax\n": "=a" (eax) ::);

    return eax;
}

unsigned int (*get_cpu)(void) = cpuid_cpu;



/* Read CR0 */
unsigned int read_msw()
{
    int ret;
    __asm__ volatile("smsw %%rax\n": "=a" (ret) : /* no input */);

    return ret;
}

/* Returns eflags */
unsigned int eflags()
{
    int ret;

    __asm__ volatile("pushf\npop %%rax\n": "=a" (ret) : /* no input */);

    return ret;
}

#define iopl() ((eflags() >> 12) & 3)

struct dt {
    unsigned short limit;
    long  base;
} __attribute__((packed));

/* Read IDT: Assuming this will always have one hardware address
 * per real physical processor, using that to map execution on host
 * processors. This could be inaccurate. */
struct dt read_idt()
{
    struct dt ret;
    __asm__ volatile("sidtq %0\n": "=m" (ret): /* no input */);

    return ret;
}

long idt_base(void)
{
    return read_idt().base;
}

/* Read GDT */
struct dt read_gdt()
{
    struct dt ret;
    __asm__ volatile("sgdt %0\n": "=m" (ret): /* no input */);

    return ret;
}

long gdt_base()
{
    return read_gdt().base;
}

/* Read LDT, set per-"mm" (task) */
/* Linux has no LDT unless custom set - OSX has an LDT (here at 0x30) */
long read_ldt()
{
    long ret = 0;
    __asm__ volatile("sldt %0\n": "=r" (ret): /* no input */);

    return ret;
}

/* Read TR: linux uses only two task registers, we'll see the
 * one for userspace at 0x40, OSX also uses 0x40 */
long read_tr()
{
    long ret = 0;
    __asm__ volatile("str %0\n": "=r" (ret): /* no input */);

    return ret;
}

long usec_diff(struct timespec *start, struct timespec *stop)
{
    struct timespec res;

    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        res.tv_sec = stop->tv_sec - start->tv_sec - 1;
        res.tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        res.tv_sec = stop->tv_sec - start->tv_sec;
        res.tv_nsec = stop->tv_nsec - start->tv_nsec;
    }

    return res.tv_sec * 1000000 + res.tv_nsec / 1000;
}

struct myperf {
    long cpu_time;  /* nsec */
    long wall_time; /* nsec */
    int  corecount[255];
    int  result;
};

/*
 Measure wall time and actual cpu scheduled time in usec
 for a function call.
*/
struct myperf timef(void (*f)(struct myperf*)) {
    struct timespec res;
    struct timespec cpu_start, cpu_end;
    struct timespec wall_start, wall_end;
    struct myperf result;

    memset(result.corecount, 0, sizeof(result.corecount));

    clock_getres(CLOCK_MONOTONIC_RAW, &res);
    if ((res.tv_sec * 1000000000L + res.tv_nsec) > 1000) {
        printf("WARNING: clock resolution is >1 usec\n");
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &wall_start);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_start);
    f(&result);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_end);
    clock_gettime(CLOCK_MONOTONIC_RAW, &wall_end);

    result.cpu_time = usec_diff(&cpu_start, &cpu_end);
    result.wall_time = usec_diff(&wall_start, &wall_end);
 
    return result;
}

static inline void count_core(struct myperf *p)
{
    p->corecount[get_cpu() & 0xff]++;
}

void sleep_one(struct myperf *p)
{
    int x = 0;
    struct timespec wall_start, wall_now;

    clock_gettime(CLOCK_MONOTONIC_RAW, &wall_start);

    do {
        x += 388375;
        x ^= (x << 24);
        x /= 3333;
        count_core(p);
        clock_gettime(CLOCK_MONOTONIC_RAW, &wall_now);
    } while(usec_diff(&wall_start, &wall_now) < 5 * 1000000);
}

int print_cpumap(struct myperf *p)
{
    int i, cnt = 0;
    printf("Executions on cores:\n");
    for (i = 0; i < 255; i++) {
        if (p->corecount[i]) {
            cnt++;
            printf("\tcore#%d: %d\n", i, p->corecount[i]);
        }
    }

    return cnt;
}

int fs_read_int(const char *file)
{
    char buf[128];
    int fd;

    fd = open(file, O_RDONLY);
    if (fd < 0) {
        perror("checking cgroup config");
        return -1;
    }

    if (read(fd, buf, 128) < 0) {
        perror("read");
        close(fd);
        return -1;
    }

    return atoi(buf);
}

struct cfs_quota {
    int period;
    int quota;
};

struct cfs_quota get_quota() {
    return (struct cfs_quota) {
        .period = fs_read_int("/sys/fs/cgroup/cpuacct/cpu.cfs_period_us"),
        .quota = fs_read_int("/sys/fs/cgroup/cpuacct/cpu.cfs_quota_us"),
    };
}

void show_cpumap()
{
    unsigned long task, last_task = 0;

    printf("Looping on cores:\n");
    for (;;) {
        task = read_gdt().base;
        if (task != last_task) {
            printf("TR %lx\n", task);
            last_task = task;
        }
    }
}

void decode_cr0(int cr0)
{
    struct flagdesc {
        char *name;
        char  pos;
    } flags[] = {
        { .name = "pg", .pos = 31 },
        { .name = "cd", .pos = 30 },
        { .name = "nw", .pos = 29 },
        { .name = "am", .pos = 18 },
        { .name = "wp", .pos = 16 },
        { .name = "ne", .pos = 5 },
        { .name = "et", .pos = 4 },
        { .name = "ts", .pos = 3 },
        { .name = "em", .pos = 2 },
        { .name = "mp", .pos = 1 },
        { .name = "pe", .pos = 0 }
    };
    struct flagdesc *p = flags;

    do {
        if (cr0 & (1 << p->pos))
            printf("%s ", p->name);
        p++;
    } while(p->pos);
    printf("\n");
}

// Attempt to estimate our scheduling timeline in some unknown
// environment. We'll record cpu usage and try to notice when
// we get rescheduled on new CPUs.
//
// Wall t0                           t1
// CPU0 R[2*c_g()]RRRRRRRRRRRRRRRRRmmmmm..
// CPU1                               ..wwwwwwR[2*clock_gettime()]RRRRRR.....
// Cpu  c0              c1           c1
//
// scheduled time (R) on first probe is c1-c0 (clock_gettime PROCESS_CPU taken
// as soon a cpu switch is detected)
// migration (pushed out of cpu0)
// waiting on runqueue : well we can't really get that with syscalls.
// wait time between two cpu probes is (t1 - t0) - R
// if run time is too short, it's probably not accurate

struct cpu_slice {
    struct timespec wall_end; // for % usage estimate we use real time
                           // of approx. when we ended benchmarking on
                           // this core.
    struct timespec cpu_end; // for % usage estimate we use CPU time
                           // of approx. when we ended benchmarking on
                           // this core.
    long   nr_loops;       // estimate work done on CPU
    long   idt;            // try to map it to host//hardware
    long   gdt;            // try to map it to host//hardware
    int    cpuid;          // also try to compare to reported cpuid core
    int    core_id;        // also try to compare to guest//local view
};

// %used    work    idt     cpuid core_id(linux)
// 97.98    129999  0xce34  0     0
// 87.98    109999  0xfe34  1     1
// 97.98    129999  0xce34  0     0
// 97.98    129999  0xfe34  1     1

void nn_stat(int nr_samples)
{
    struct cpu_slice *samples = calloc(nr_samples, sizeof(struct cpu_slice));


    /*
    clock_gettime(CLOCK_MONOTONIC_RAW, &prev.wall_end);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &prev.cpu_end);
    prev.idt = idt_base();
    prev.gdt = gdt_base();
    prev.cpuid = cpuid_cpu();
    prev.core_id = getcpu();
    */

    for(int i = 0; i < nr_samples; i++) {
        struct cpu_slice cur = samples[i];
        struct cpu_slice prev = samples[i-1 > 0 ? i-1 : 0];

        cur.nr_loops = 0;
        do {
            cur.idt = idt_base();
            cur.gdt = gdt_base();
            cur.cpuid = cpuid_cpu();
            cur.core_id = getcpu();
            cur.nr_loops++;
        } while(cur.idt == prev.idt &&
                cur.gdt == prev.gdt &&
                cur.cpuid == prev.cpuid &&
                cur.core_id == prev.core_id &&
                cur.nr_loops % 500000);

        // Update current wall/cpu clock from times to times
        clock_gettime(CLOCK_MONOTONIC_RAW, &cur.wall_end);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cur.cpu_end);

        // If past one second on this sample or first sample
        // switch to next
        // if (i == 0 || time...)
    }

    /*
        printf("%.02f%%\tloops=%04ld\tgdt=%lx\tidt=%lx\tc=%d, %d\n",
                (float) 100 * usec_diff(&prev.cpu_end, &cur.cpu_end) /
                        usec_diff(&prev.wall_end, &cur.wall_end),
                        cur.nr_loops / (1024),
			cur.gdt,
                        cur.idt,
                        cur.cpuid,
#ifdef linux
                        cur.core_id
#else
                        -1
#endif
              );
        memcpy(&prev, &cur, sizeof(struct cpu_slice));

	// Ignore time spent doing the above
        clock_gettime(CLOCK_MONOTONIC_RAW, &cur.wall_end);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cur.cpu_end);
    }
    */
}

int main(void)
{
    struct rusage r;
    struct cfs_quota me = get_quota();

    struct _2_regs rd = rdtsc();
    printf("rdtsc %x:%x\n", rd.edx, rd.eax);

    struct myperf some = timef(sleep_one);

    getrusage(RUSAGE_SELF, &r);

    if (iopl() != 0) {
        printf("Weird system where IOPL is %d\n", iopl());
    }

    decode_cr0(read_msw());

    rd = rdtsc();
    printf("rdtsc %x:%x\n", rd.edx, rd.eax);
    rd = rdtsc();
    printf("rdtsc %x:%x\n", rd.edx, rd.eax);

    struct dt idt = read_idt();
    printf("IDT at: %lx, limit %d\n", idt.base, idt.limit);
    struct dt gdt = read_gdt();
    printf("GDT at: %lx, limit %d\n", gdt.base, gdt.limit);
    printf("LDT at: %lx\n", read_ldt());
    printf("TR at: %lx\n", read_tr());
    //rdpmc(1);

    printf("started on processor %d\n", get_cpu());

    if (me.quota > 0)
        printf("%0.2f%% CPU configured\n", (float) 100 * me.period / me.quota);
    printf("%0.2f%% CPU used\n", (float) 100 * some.cpu_time / some.wall_time);
    printf("User time\t: %lu usec\n",
            r.ru_utime.tv_sec * 1000000 + r.ru_utime.tv_usec);
    printf("Clock cpu time\t: %lu usec\n", some.cpu_time);
    printf("System time\t: %lu usec\n",
            r.ru_stime.tv_sec * 1000000 + r.ru_stime.tv_usec);
    printf("Wall time\t: %lu usec\n", some.wall_time);
    printf("Involuntary context switches: %lu\n", r.ru_nivcsw);
    printf("Voluntary context switches: %lu\n", r.ru_nvcsw);

    nn_stat(1024);

    exit(0);
}

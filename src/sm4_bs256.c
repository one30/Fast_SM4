#include "sm4_bs256.h"
#include <string.h>
#include <time.h>
 
static const unsigned char SboxTable[16][16] = 
{
    {0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
    {0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
    {0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
    {0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
    {0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
    {0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
    {0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
    {0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
    {0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
    {0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
    {0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
    {0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
    {0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
    {0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
    {0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
    {0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
};

// int main(void)
// {
//     hi();
//     benchmark_sm4_bs_encrypt();
//     hi();
//     return 0;
// }

void hi()
{
    printf("hello world\n");
}

uint64_t start_rdtsc()
{
    uint32_t cycles_high, cycles_low;
    __asm__ volatile(
        "CPUID\n\t"
        "RDTSC\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        : "=r"(cycles_high), "=r"(cycles_low)::"%rax", "%rbx", "%rcx", "%rdx");
    return ((uint64_t)cycles_low) | (((uint64_t)cycles_high) << 32);
}

uint64_t end_rdtsc()
{
    uint32_t cycles_high, cycles_low;
    __asm__ volatile(
        "RDTSCP\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "CPUID\n\t"
        : "=r"(cycles_high), "=r"(cycles_low)::"%rax", "%rbx", "%rcx", "%rdx");
    return ((uint64_t)cycles_low) | (((uint64_t)cycles_high) << 32);
}

void benchmark_sm4_bs_ecb_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m256i (*rk)[32])
{
    int turns = 10000;
    clock_t t = clock();
    for(int i=0; i<turns; i++)
    {
        sm4_bs256_ecb_encrypt(cipher,plain,size,rk);
    }
    double tt = (double)(clock() - t) / (CLOCKS_PER_SEC*turns);
	double speed = (double) size / (1024 * 1024 * tt);
    printf("SM4_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
}

void benchmark_sm4_bs_ctr_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m256i (*rk)[32],uint8_t * iv)
{
    int turns = 10000;
    clock_t t = clock();
    for(int i=0; i<turns; i++)
    {
        sm4_bs256_ctr_encrypt(cipher,plain,size,rk,iv);
    }
    double tt = (double)(clock() - t) / (CLOCKS_PER_SEC*turns);
	double speed = (double) size / (1024 * 1024 * tt);
    printf("SM4_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
}

void sm4_bs256_ecb_encrypt(uint8_t* outputb,uint8_t* inputb,int size,__m256i (*rk)[32])
{
    __m256i output_space[BLOCK_SIZE];
    __m128i input_space[BLOCK_SIZE*2];
    __m128i state[256];
    __m128i t;
    __m256i t2;
    //the masking for shuffle the data
    __m128i vindex_swap = _mm_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);
    __m256i vindex_swap2 = _mm256_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8,
        7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);

    memset(outputb,0,size);
    __m256i* out = (__m256i*)outputb;
    __m128i* in = (__m128i*)inputb;
    
    // sm4_bs256_key_schedule(key,rk);

    while(size > 0)
    {
        if(size < BS_BLOCK_SIZE)
        {
            memset(input_space,0,BS_BLOCK_SIZE);
            for(int i=0; i<size/16; i++)
            {
                t = _mm_shuffle_epi8(in[i],vindex_swap);
                _mm_storeu_si128(input_space+i,t);
            }
            sm4_bs256_enc(input_space,output_space,rk);
            // for(int i=0; i<(size+16)/32; i++)
            // {
            //     t2 = _mm256_shuffle_epi8(output_space[i],vindex_swap2);
            //     _mm256_storeu_si256(out+i,t2);          
            // }
            __m128i* out_t = (__m128i*)out;
            for(int i=0; i<size/16; i++)
            {
                t = _mm_shuffle_epi8(input_space[i],vindex_swap);
                _mm_storeu_si128(out_t,t);
                out_t++;
            }
            size = 0;
            //out += size;
        }
        else
        {
            memmove(state,inputb,BS_BLOCK_SIZE);
            for(int i=0; i<BLOCK_SIZE*2; i++){
                t = _mm_shuffle_epi8(in[i],vindex_swap);
                _mm_storeu_si128(input_space+i,t);
            }
            sm4_bs256_enc(input_space,output_space,rk);
            for(int i=0; i<BLOCK_SIZE; i++)
            {
                t2 = _mm256_shuffle_epi8(output_space[i],vindex_swap2);
                _mm256_storeu_si256(out+i,t2);          
            }
            size -= BS_BLOCK_SIZE;
            out += BLOCK_SIZE;
            in += BLOCK_SIZE*2;
        }
        
    }
}

static void INC_CTR(uint8_t * ctr, uint8_t i)
{
    ctr += BLOCK_SIZE/8 - 1;
    uint8_t n = *(ctr);
    *ctr += i;
    while(*ctr < n)
    {
        ctr--;
        n = *ctr;
        (*ctr)++;
    }
}

// static void INC_CTR(uint8_t * ctr, uint8_t i)
// {
//     ctr += BLOCK_SIZE/8 - 1;
//     uint8_t n = *(ctr);
//     *ctr += i;
//     while(*ctr < n)
//     {
//         ctr--;
//         n = *ctr;
//         (*ctr)++;
//     }
// }

static void ctr128_inc(unsigned char *counter)
{
    uint32_t n = 16, c = 1;

    do {
        --n;
        c += counter[n];
        counter[n] = (uint8_t)c;
        c >>= 8;
    } while (n);
}

/**
 * @brief A constant-time method to zero a block of memory.
 * 
 * @param ptr the pointer of memory location to be zeroed
 * @param size the size of the memory block in bytes
 */
void crypto_memzero(void const* ptr, const size_t size)
{
#if defined(_WIN32)
    SecureZeroMemory((PVOID)ptr, (SIZE_T)size);
#else
    size_t index = 0;
    volatile uint8_t *volatile target_ptr =
        (volatile uint8_t *volatile) ptr;

    for (index=0; index<size; index++)
    {
        target_ptr[index] = 0x00;
    }    
#endif    
}

static void big_endian_store32(uint8_t *x, uint32_t u)
{
    x[3] = u & 0xFF; u >>= 8;
    x[2] = u & 0xFF; u >>= 8;
    x[1] = u & 0xFF; u >>= 8;
    x[0] = u & 0xFF;
}

static void big_endian_store64(uint8_t *x, uint64_t u)
{
    x[7] = u & 0xFF; u >>= 8;
    x[6] = u & 0xFF; u >>= 8;
    x[5] = u & 0xFF; u >>= 8;
    x[4] = u & 0xFF; u >>= 8;
    x[3] = u & 0xFF; u >>= 8;
    x[2] = u & 0xFF; u >>= 8;
    x[1] = u & 0xFF; u >>= 8;
    x[0] = u & 0xFF;
}


/**
 * @brief Computes (a + x)*y.
 * 
 * @param a The input/output vector a, 16 bytes long
 * @param x The input vector x, x_len bytes long
 * @param x_len The length of vector x (in bytes)
 * @param y The input vector y, 16 bytes long
 */
static void add_mul(uint8_t *a,
                    const uint8_t *x, 
                    size_t x_len,
                    const uint8_t *y)
{
    int32_t i, j;
    uint8_t a_bits[128], y_bits[128];
    uint8_t axy_bits[256];
    
    for (i = 0; i < (int)x_len; ++i)
    {
        a[i] ^= x[i];
    }

    /* Performs reflection on (a + x) and y */
    for (i = 0; i < 128; ++i)
    {
        a_bits[i] = (a[i >> 3] >> (7 - (i & 7))) & 1;
        y_bits[i] = (y[i >> 3] >> (7 - (i & 7))) & 1;
    }

    crypto_memzero(axy_bits, sizeof(axy_bits));
    for (i = 0; i < 128; ++i)
    {
        for (j = 0; j < 128; ++j)
        {
            axy_bits[i + j] ^= a_bits[i] & y_bits[j];
        }
    }

    /**
     * Galois field reduction, GF(2^128) is defined 
     * by polynomial x^128 + x^7 + x^2 + 1
     */
    for (i = 127; i >= 0; --i)
    {
        axy_bits[i]       ^= axy_bits[i + 128];
        axy_bits[i +   1] ^= axy_bits[i + 128];
        axy_bits[i +   2] ^= axy_bits[i + 128];
        axy_bits[i +   7] ^= axy_bits[i + 128];
        axy_bits[i + 128] ^= axy_bits[i + 128];
    }

    /* Undo the reflection on the output */
    crypto_memzero(a, 16);
    for (i = 0; i < 128; ++i)
    {
        a[i >> 3] |= (axy_bits[i] << (7 - (i & 7)));
    }
}

// void sm4_bs256_ctr_encrypt(uint8_t * outputb, uint8_t * inputb, int size, __m256i (*rk)[32], uint8_t * iv)
// {
//     __m128i ctr[BLOCK_SIZE*2];
//     __m256i output_space[BLOCK_SIZE];
//     __m128i iv_copy;
//     __m128i t,t2;
//     __m128i count = _mm_setzero_si128();
//     //uint64_t count = 0;
//     uint64_t op[2] = {0,1};
//     __m128i cnt = _mm_loadu_si128((__m128i*)op);
//     __m128i vindex_swap = _mm_setr_epi8(
// 		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
// 	);
//     __m256i vindex_swap2 = _mm256_setr_epi8(
// 		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8,
//         7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
// 	);

//     memset(outputb,0,size);
//     memset(ctr,0,sizeof(ctr));
//     t = _mm_load_si128((__m128i *)iv);
//     iv_copy = _mm_shuffle_epi8(t,vindex_swap);

//     __m256i * state = (__m256i *)outputb;

//     while(size)
//     {
//         int chunk = MIN(size, BS_BLOCK_SIZE);
//         int blocks = chunk / (BLOCK_SIZE/8);

//         int i;
//         for (i = 0; i < blocks; i++)
//         {
//             //memmove(ctr + (i * WORDS_PER_BLOCK), iv_copy, BLOCK_SIZE/8);
//             count = _mm_add_epi64(count,cnt);
//             ctr[i] = iv_copy + count;
//             // count = _mm_add_epi64(count,cnt);
//         }

//         //bs_cipher(ctr, rk);
//         sm4_bs256_enc(ctr,output_space,rk);
//         for(i=0; i<blocks; i++)
//         {
//             ctr[i] = _mm_shuffle_epi8(ctr[i],vindex_swap);     
//         }
//         size -= chunk;

//         uint8_t * ctr_p = (uint8_t *) ctr;
//         for(i=0; i<chunk; i++)
//         {
//             outputb[i] = *ctr_p++ ^ inputb[i];
//         }

//     }
// }

void sm4_bs256_ctr_encrypt(uint8_t * outputb, uint8_t * inputb, int size, __m256i (*rk)[32], uint8_t * iv)
{
    __m128i ctr[BLOCK_SIZE*2];
    __m256i output_space[BLOCK_SIZE];
    __m128i iv_copy;
    __m128i t,t2;
    __m128i count = _mm_setzero_si128();
    //uint64_t count = 0;
    uint64_t op[2] = {0,1};
    __m128i cnt = _mm_loadu_si128((__m128i*)op);
    __m128i vindex_swap = _mm_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);
    __m256i vindex_swap2 = _mm256_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8,
        7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);
    uint8_t Associated_Data[]={
        0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x03,0x7f,0xff,0xff,0xfe,0x89,0x2c,0x38,0x00,
        0x00,0x5c,0x36,0x5c,0x36,0x5c,0x36
    };
    uint8_t accum[16]={
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    uint8_t final_block[16];
    big_endian_store64(final_block, 8 * sizeof(Associated_Data));
    big_endian_store64(final_block + 8, 8 * (sizeof(inputb)-16));

    memset(outputb,0,size);
    memset(ctr,0,sizeof(ctr));
    t = _mm_load_si128((__m128i *)iv);
    iv_copy = _mm_shuffle_epi8(t,vindex_swap);

    __m256i * state = (__m256i *)outputb;

    while(size)
    {
        int chunk = MIN(size, BS_BLOCK_SIZE);
        int blocks = chunk / (BLOCK_SIZE/8);

        int i;
        for (i = 0; i < blocks; i++)
        {
            //memmove(ctr + (i * WORDS_PER_BLOCK), iv_copy, BLOCK_SIZE/8);
            count = _mm_add_epi64(count,cnt);
            ctr[i] = iv_copy + count;
            // count = _mm_add_epi64(count,cnt);
        }

        //bs_cipher(ctr, rk);
        sm4_bs256_enc(ctr,output_space,rk);

        for(i=0; i<blocks; i++)
        {
            //ctr[i] = _mm_shuffle_epi8(ctr[i],vindex_swap);

        }
        size -= chunk;

        uint8_t * ctr_p = (uint8_t *) ctr;
        for(i=0; i<chunk; i++)
        {
            outputb[i] = *ctr_p++ ^ inputb[i];
        }
    }
    // uint8_t *h = (uint8_t *) ctr;
    // // for(int i=0; i<16; i++)
    // // {
    // //     printf("%02x ",inputb[i]);
    // // }
    // // printf("\n");
    // add_mul(accum,Associated_Data,sizeof(Associated_Data),h);
    // uint8_t *c = outputb;
    // c +=16;
    // for(int i=1; i<4; i++)
    // {
    //     add_mul(accum,c,16,h);
    //     c+=16;
    // }
    // add_mul(accum,final_block,16,h);
    // for(int i=0; i<16; i++)
    // {
    //     printf("%02x ",accum[i]);
    // }
}

void sm4_bs256_gcm_encrypt(uint8_t * outputb, uint8_t * inputb, int size, __m256i (*rk)[32], uint8_t * iv)
{
    __m128i ctr[BLOCK_SIZE*2];
    __m256i output_space[BLOCK_SIZE];
    __m128i iv_copy;
    __m128i t,t2;
    __m128i count = _mm_setzero_si128();
    //uint64_t count = 0;
    uint64_t op[2] = {0,1};
    __m128i cnt = _mm_loadu_si128((__m128i*)op);
    __m128i vindex_swap = _mm_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);
    __m256i vindex_swap2 = _mm256_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8,
        7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);

    memset(outputb,0,size);
    memset(ctr,0,sizeof(ctr));
    t = _mm_load_si128((__m128i *)iv);
    iv_copy = _mm_shuffle_epi8(t,vindex_swap);

    __m256i * state = (__m256i *)outputb;

    while(size)
    {
        int chunk = MIN(size, BS_BLOCK_SIZE);
        int blocks = chunk / (BLOCK_SIZE/8);

        count = _mm_add_epi64(count,cnt);
        int i;
        for (i = 0; i < blocks; i++)
        {
            //memmove(ctr + (i * WORDS_PER_BLOCK), iv_copy, BLOCK_SIZE/8);
            count = _mm_add_epi64(count,cnt);
            ctr[i] = iv_copy + count;
            //count = _mm_add_epi64(count,cnt);
        }

        //bs_cipher(ctr, rk);
        sm4_bs256_enc(ctr,output_space,rk);

        //data shuffle
        for(i=0; i<blocks; i++)
        {
            ctr[i] = _mm_shuffle_epi8(ctr[i],vindex_swap); 
        }
        size -= chunk;

        uint8_t * ctr_p = (uint8_t *) ctr;
        for(i=0; i<chunk; i++)
        {
            *outputb++ = *ctr_p++ ^ *inputb++;
        }

    }
}

void BS_init_M(__m128i* M)
{
    uint64_t a[2] = {0x0123456789abcdef,0xfedcba9876543210};
    //uint64_t b[2] = {0xfedcba9876543210,0x0123456789abcdef};
    for(int i=0; i<128; i++)
    {
        M[2*i] = _mm_load_si128((__m128i*)a);
        M[2*i+1] = _mm_load_si128((__m128i*)a);
    }
}

void BS_TRANS_128x256(__m128i* M,__m256i* N){
    __m256i mask[7];
    __m256i mk[7];
    uint64_t m0[4] = {0x5555555555555555,0x5555555555555555,0x5555555555555555,0x5555555555555555};
    uint64_t m1[4] = {0x3333333333333333,0x3333333333333333,0x3333333333333333,0x3333333333333333};
    uint64_t m2[4] = {0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f};
    uint64_t m3[4] = {0x00ff00ff00ff00ff,0x00ff00ff00ff00ff,0x00ff00ff00ff00ff,0x00ff00ff00ff00ff};
    uint64_t m4[4] = {0x0000ffff0000ffff,0x0000ffff0000ffff,0x0000ffff0000ffff,0x0000ffff0000ffff};
    uint64_t m5[4] = {0x00000000ffffffff,0x00000000ffffffff,0x00000000ffffffff,0x00000000ffffffff};
    uint64_t m6[4] = {0x0000000000000000,0xffffffffffffffff,0x0000000000000000,0xffffffffffffffff};
    mask[0] = _mm256_load_si256((__m256i*)m0);
    mask[1] = _mm256_load_si256((__m256i*)m1);
    mask[2] = _mm256_load_si256((__m256i*)m2);
    mask[3] = _mm256_load_si256((__m256i*)m3);
    mask[4] = _mm256_load_si256((__m256i*)m4);
    mask[5] = _mm256_load_si256((__m256i*)m5);
    mask[6] = _mm256_load_si256((__m256i*)m6);
    __m256i test[128];
    for(int i = 0; i < 128; i++)
    {
        //slove the bug
        N[i] = _mm256_setr_m128i(M[i],M[128+i]);  
        //N[i] = _mm256_setr_m128i(M[i],M[2*i+1]);
    }
    //__m256i M_temp[128];
    uint64_t k,k2,kt,l;
    uint64_t t1[4],t2[4];
    uint64_t zero = 0;
    //_mm_setzero_si64();
    __m256i temp,m,n,a,b,o,p;
    //temp = (test[0] & mask[6]) ^ ((test[0]&~mask[6])<<1);
    //temp = (test[0]&~mask[0])<<2；
    for(int j=0; j<7; j++)
    {
        k = 1<<j;
        k2 = k*2;
        kt = 0;
        //r = k-1;
        if(j==6)//when shift bit = 64,128 bit SIMD with shift operation has bug
        {
            for(int i=0; i<64; i++)
            {
                l = kt%127;
                m = N[l];
                n = N[l+k];

                _mm256_store_si256((__m256i*)t1,n);
                o = _mm256_setr_epi64x(zero,t1[0],zero,t1[2]);

                _mm256_store_si256((__m256i*)t2,m);
                p = _mm256_setr_epi64x(t2[1],zero,t2[3],zero);

                temp = (m&~mask[j]) ^ o;
                N[l+k] = (n&(mask[j])) ^ p;
                N[l] = temp;
                // M_temp[l] = temp;
                // M_temp[l+k] = N[l+k];

                kt+=k2;
            }            
        }
        else
        {
            for(int i=0; i<64; i++)
            {
                // l = (k2*i)%63;
                l = kt%127;
                m = N[l];
                n = N[l+k];
                // a = (m&~mask[j]);
                // b = ((n>>k)&mask[j]);
                //temp = (m&~mask[j]) ^ ((n&~mask[j])>>k);
                temp = (m&~mask[j]) ^ ((n>>k)&mask[j]);
                N[l+k] = (n&(mask[j])) ^ ((m<<k)&~mask[j]);
                //N[l+k] = (n&(mask[j])) ^ ((m&(mask[j]))<<k);
                N[l] = temp;

                // M_temp[l] = temp;
                // M_temp[l+k] = N[l+k];

                kt+=k2;           
            }
        }      
    }
}

void BS_TRANS_VER_128x256(__m256i* N,__m128i* M){
    // M[1] = {0xfffffff,0xfffffff,0xfffffff,0xfffffff};
    //uint64_t mask[6];
    __m256i mask[7];
    __m256i mk[7];
    uint64_t m0[4] = {0x5555555555555555,0x5555555555555555,0x5555555555555555,0x5555555555555555};
    uint64_t m1[4] = {0x3333333333333333,0x3333333333333333,0x3333333333333333,0x3333333333333333};
    uint64_t m2[4] = {0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f};
    uint64_t m3[4] = {0x00ff00ff00ff00ff,0x00ff00ff00ff00ff,0x00ff00ff00ff00ff,0x00ff00ff00ff00ff};
    uint64_t m4[4] = {0x0000ffff0000ffff,0x0000ffff0000ffff,0x0000ffff0000ffff,0x0000ffff0000ffff};
    uint64_t m5[4] = {0x00000000ffffffff,0x00000000ffffffff,0x00000000ffffffff,0x00000000ffffffff};
    uint64_t m6[4] = {0x0000000000000000,0xffffffffffffffff,0x0000000000000000,0xffffffffffffffff};
    mask[0] = _mm256_load_si256((__m256i*)m0);
    mask[1] = _mm256_load_si256((__m256i*)m1);
    mask[2] = _mm256_load_si256((__m256i*)m2);
    mask[3] = _mm256_load_si256((__m256i*)m3);
    mask[4] = _mm256_load_si256((__m256i*)m4);
    mask[5] = _mm256_load_si256((__m256i*)m5);
    mask[6] = _mm256_load_si256((__m256i*)m6);
    __m256i M_temp[128];
    uint64_t k,k2,kt,l;
    uint64_t t1[4],t2[4];
    uint64_t zero = 0;
    //_mm_setzero_si64();
    __m256i temp,m,n,a,b,o,p;
    //temp = (test[0] & mask[6]) ^ ((test[0]&~mask[6])<<1);
    //temp = (test[0]&~mask[0])<<2；


    for(int j=0; j<7; j++)
    {
        k = 1<<j;
        k2 = k*2;
        kt = 0;
        //r = k-1;
        //when shift bit = 64,128 bit SIMD with shift operation has bug
        //set j==7
        if(j==6)
        {
            for(int i=0; i<64; i++)
            {
                l = kt%127;
                m = N[l];
                n = N[l+k];

                _mm256_store_si256((__m256i*)t1,n);
                o = _mm256_setr_epi64x(zero,t1[0],zero,t1[2]);

                _mm256_store_si256((__m256i*)t2,m);
                p = _mm256_setr_epi64x(t2[1],zero,t2[3],zero);

                temp = (m&~mask[j]) ^ o;
                N[l+k] = (n&(mask[j])) ^ p;
                N[l] = temp;
                // M_temp[l] = temp;
                // M_temp[l+k] = N[l+k];

                kt+=k2;
            }

            
        }
        else
        {
            for(int i=0; i<64; i++)
            {
                // l = (k2*i)%63;
                l = kt%127;
                m = N[l];
                n = N[l+k];
                // a = (m&~mask[j]);
                // b = ((n>>k)&mask[j]);
                //temp = (m&~mask[j]) ^ ((n&~mask[j])>>k);
                temp = (m&~mask[j]) ^ ((n>>k)&mask[j]);
                N[l+k] = (n&(mask[j])) ^ ((m<<k)&~mask[j]);
                //N[l+k] = (n&(mask[j])) ^ ((m&(mask[j]))<<k);
                N[l] = temp;

                // M_temp[l] = temp;
                // M_temp[l+k] = N[l+k];

                kt+=k2;           
            }
        }      
    }

    __m128i t[2];
    for(int i = 0; i < 128; i++)
    {
        _mm256_store_si256((__m256i*)t,N[i]);
        M[i] = t[0];
        M[128+i] = t[1]; 
        // test[i] = t[0];
        // test[128+i] = t[1];         
    }
}

/*
 * private function:
 * look up in SboxTable and get the related value.
 * args:    [in] inch: 0x00~0xFF (8 bits unsigned value).
 */
static unsigned char sm4Sbox(unsigned char inch)
{
    unsigned char *pTable = (unsigned char *)SboxTable;
    unsigned char retVal = (unsigned char)(pTable[inch]);
    return retVal;
}

/* private function:
 * Calculating round encryption key.
 * args:    [in] a: a is a 32 bits unsigned value;
 * return: sk[i]: i{0,1,2,3,...31}.
 */
static unsigned long sm4CalciRK(unsigned long ka)
{
    unsigned long bb = 0;
    unsigned long rk = 0;
    unsigned char a[4];
    unsigned char b[4];
    PUT_ULONG_BE(ka,a,0)
    b[0] = sm4Sbox(a[0]);
    b[1] = sm4Sbox(a[1]);
    b[2] = sm4Sbox(a[2]);
    b[3] = sm4Sbox(a[3]);
	GET_ULONG_BE(bb,b,0)
    rk = bb^(ROTL(bb, 13))^(ROTL(bb, 23));
    return rk;
}

void sm4_bs256_key_schedule(uint8_t* key, __m256i (*BS_RK_256)[32])
{
    uint32_t rkey[32];
    uint64_t BS_RK[32][32][4];
	// System parameter or family key
	const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

	const uint32_t CK[32] = {
	0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
	0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
	0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
	0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
	0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
	0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
	0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
	0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
	};

	uint32_t K[36];
    uint32_t MK[4];
    GET_ULONG_BE( MK[0], key, 0 );
    GET_ULONG_BE( MK[1], key, 4 );
    GET_ULONG_BE( MK[2], key, 8 );
    GET_ULONG_BE( MK[3], key, 12 );

	K[0] = MK[0] ^ FK[0];
	K[1] = MK[1] ^ FK[1];
	K[2] = MK[2] ^ FK[2];
	K[3] = MK[3] ^ FK[3];

	// for(int i=0; i<32; i++)
	// {
	// 	K[i % 4] ^= SM4_Tp(K[(i+1)%4] ^ K[(i+2)%4] ^ K[(i+3)%4] ^ CK[i]);
	// 	rkey[i] = K[i % 4];
	// }

    for(int i = 0; i<32; i++)
    {
        K[i+4] = K[i] ^ (sm4CalciRK(K[i+1]^K[i+2]^K[i+3]^CK[i]));
        rkey[i] = K[i+4];
        //printf("rkey[%d]=%08x\n",i,rkey[i]);
	}

    //rkey[] 
    for(int i = 0; i<32; i++)
    {
        //printf("rkey[%d]=%08x\n",i,rkey[i]);
        uint64_t t = 0x1;
        for(int j = 0; j < 32; j++)
        {
            for(int k = 0; k < 4; k++)
            {
                if(rkey[i] & t)
                    BS_RK[i][31-j][k] = ~0;
                else
                {
                    BS_RK[i][31-j][k] = 0;
                }
            }
            t = t << 1;
        }
    }

    for(int i = 0; i < 32; i++)//load data
    {
        for(int j = 0; j < 32; j++)
        {
            BS_RK_256[i][j] = _mm256_loadu_si256((__m256i*)BS_RK[i][j]);
        }
    }
    
}

void BS_iteration(__m256i* N,__m256i BS_RK_256[32][32])
{
    int i = 0;
    uint64_t t1 , t2;
    __m256i buf_256[36][32];
    __m256i N_temp[128];
    __m256i temp_256[36][32];

    //printf("test init_buf[][] 4 round:\n");
    for(int j = 0; j < 4; j++)//bingo 256bit
    {
        for(int k = 0; k < 32; k++)
        {
            buf_256[j][k] = N[32*j+k];//load data
        }     
    }
        
    while(i < 32)//32轮迭代计算
    {
        for(int j = 0; j < 32; j++)//4道32bit数据操作:
        {
            buf_256[4+i][j]= buf_256[i+1][j] ^ buf_256[i+2][j] ^ buf_256[i+3][j] ^ BS_RK_256[i][j];
        }

        S_box(i,buf_256);//bingo256 合成置换T的非线性变换
        
        //printf("\tafter shift\n");
        for(int j = 0; j < 32; j++)//bingo256 4道32bit数据操作:合成置换T的线性变换L
        {
            temp_256[4+i][j]= buf_256[4+i][j] ^ buf_256[4+i][(j+2)%32] ^ buf_256[4+i][(j+10)%32] ^ buf_256[4+i][(j+18)%32] ^ buf_256[4+i][(j+24)%32];
        }
        for(int j = 0; j < 32; j++)//4道32bit数据操作
        {
            buf_256[4+i][j]= temp_256[i+4][j] ^ buf_256[i][j];
        }        
        i++;
    }

    for(int j = 0; j < 4; j++)//反序计算
    {
        for(int k = 0; k < 32; k++)
        {

            N[32*j+k] = buf_256[35-j][k];
        }
    }

}

void S_box(int round,__m256i buf_256[36][32])
{
    bits sm4;

    for(int i = 0; i<4; i++)
    {
        sm4.b7 = buf_256[round+4][i*8];
        sm4.b6 = buf_256[round+4][i*8+1];
        sm4.b5 = buf_256[round+4][i*8+2];
        sm4.b4 = buf_256[round+4][i*8+3];
        sm4.b3 = buf_256[round+4][i*8+4];
        sm4.b2 = buf_256[round+4][i*8+5];
        sm4.b1 = buf_256[round+4][i*8+6];
        sm4.b0 = buf_256[round+4][i*8+7];

        Sm4_BoolFun(sm4,&buf_256[round+4][i*8+7],&buf_256[round+4][i*8+6],&buf_256[round+4][i*8+5],&buf_256[round+4][i*8+4],
            &buf_256[round+4][i*8+3],&buf_256[round+4][i*8+2],&buf_256[round+4][i*8+1],&buf_256[round+4][i*8]);

    }
    //for(int )

}


void sm4_bs256_enc(__m128i M[256],__m256i N[128],__m256i rk[32][32])
{
    BS_TRANS_128x256(M,N);
    BS_iteration(N,rk);
    BS_TRANS_VER_128x256(N,M);
}

//899gatesmake
// void Sm4_BoolFun(bits in, bit_t *out0, bit_t *out1, bit_t *out2, bit_t *out3, bit_t *out4, bit_t *out5, bit_t *out6, bit_t *out7) {
//     bit_t x0 = in.b0;
//     bit_t x1 = in.b1;
//     bit_t x2 = in.b2;
//     bit_t x3 = in.b3;
//     bit_t x4 = in.b4;
//     bit_t x5 = in.b5;
//     bit_t x6 = in.b6;
//     bit_t x7 = in.b7;
//     uint64_t t = 0x0;
//     uint64_t n[4] = {~t,~t,~t,~t};
//     bit_t y0 = x0&x2&x3&x4&x5| x0&x1&x2&x3&x5| x1&x2&x3&x5&x7| x1&x2&x4&x5&x7| x0&x1&x2&x3&x4&x5| x0&x1&x3&x4&x5&x7| x0&x2&x3&x4&x6&x7| x0&x1&x4&x5&x6&x7| x0&x1&x4&x5&x6&x7| x0&x1&x2&x3&x4&x7| x0&x1&x2&x3&x5&x7| x0&x1&x3&x4&x5&x7| x0&x2&x4&x5&x6&x7| x0&x1&x2&x4&x6&x7| x0&x2&x3&x4&x6&x7| x0&x1&x2&x3&x4&x5&x6| x0&x1&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x1&x2&x5&x6| x1&x2&x3&x4&x7| x0&x1&x2&x3&x4&x5| x0&x1&x2&x3&x4&x6| x0&x1&x2&x3&x5&x7| x1&x2&x3&x4&x6&x7| x0&x2&x3&x4&x6&x7| x0&x1&x3&x5&x6&x7| x0&x2&x4&x5&x6&x7| x1&x3&x4&x5&x6&x7| x0&x2&x4&x5&x6&x7| x0&x1&x2&x3&x6&x7| x1&x2&x3&x5&x6&x7| x0&x1&x3&x5&x6&x7| x0&x1&x4&x5&x6&x7| x1&x2&x3&x5&x6&x7| x0&x1&x3&x4&x6&x7| x0&x2&x3&x5&x6&x7| x0&x1&x2&x3&x4&x5&x6| x0&x1&x2&x4&x5&x6&x7| x0&x2&x3&x4&x5&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x6&x7| x0&x1&x2&x3&x4&x6&x7| x0&x1&x2&x3&x5&x6&x7| x0&x1&x2&x3&x4&x6&x7| x0&x1&x2&x4&x5&x6&x7| x0&x2&x3&x4&x5&x6&x7| x1&x2&x3&x4&x5&x6&x7;
//     bit_t y1 = x1&x3&x5&x6&x7| x1&x3&x5&x6&x7| x0&x2&x3&x4&x5&x6| x0&x2&x3&x4&x5&x7| x1&x2&x3&x5&x6&x7| x0&x3&x4&x5&x6&x7| x1&x2&x4&x5&x6&x7| x1&x2&x3&x4&x6&x7| x0&x1&x4&x5&x6&x7| x0&x1&x2&x3&x4&x5&x7| x0&x1&x2&x3&x4&x5&x7| x0&x1&x2&x4&x5&x6&x7| x0&x2&x3&x4&x5&x6&x7| x0&x1&x2&x3&x6| x0&x1&x2&x3&x7| x0&x1&x3&x6&x7| x0&x1&x2&x3&x4&x6| x0&x1&x2&x3&x4&x6| x0&x1&x2&x3&x5&x6| x0&x1&x3&x4&x5&x6| x0&x1&x2&x3&x5&x6| x0&x1&x2&x4&x5&x6| x0&x1&x3&x4&x5&x6| x1&x2&x3&x4&x5&x7| x0&x2&x3&x4&x5&x7| x0&x2&x3&x5&x6&x7| x0&x2&x4&x5&x6&x7| x1&x2&x3&x5&x6&x7| x0&x1&x2&x4&x6&x7| x1&x2&x3&x4&x6&x7| x1&x2&x3&x4&x6&x7| x1&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x5&x7| x0&x1&x2&x3&x4&x6&x7| x0&x1&x2&x3&x4&x6&x7| x0&x1&x2&x3&x4&x6&x7| x0&x1&x2&x3&x5&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x6&x7| x0&x1&x2&x3&x4&x5&x7| x0&x1&x2&x3&x4&x5&x7| x0&x1&x2&x3&x4&x6&x7| x1&x2&x3&x4&x5&x6&x7| x1&x2&x3&x4&x5&x6&x7| x0&x1&x2&x4&x5&x6&x7| x0&x1&x2&x4&x5&x6&x7| x1&x2&x3&x4&x5&x6&x7;
//     bit_t y2 = x0&x2&x3&x4&x6| x3&x4&x5&x6&x7| x0&x1&x3&x4&x5&x6| x0&x1&x3&x4&x5&x6| x1&x2&x3&x4&x6&x7| x1&x2&x3&x4&x6&x7| x1&x2&x3&x5&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x2&x3&x4&x5&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x5| x0&x1&x2&x3&x4&x6| x0&x1&x2&x4&x5&x6| x1&x2&x3&x4&x5&x6| x0&x1&x2&x3&x5&x6| x0&x2&x3&x4&x5&x6| x0&x1&x3&x4&x5&x6| x1&x2&x3&x4&x5&x6| x0&x1&x2&x4&x5&x6| x0&x1&x2&x4&x5&x7| x1&x2&x3&x4&x5&x7| x0&x1&x2&x3&x5&x7| x0&x1&x2&x3&x5&x7| x0&x1&x2&x4&x5&x7| x0&x1&x2&x4&x5&x7| x0&x1&x3&x5&x6&x7| x0&x1&x4&x5&x6&x7| x1&x2&x3&x5&x6&x7| x1&x3&x4&x5&x6&x7| x0&x1&x4&x5&x6&x7| x0&x2&x4&x5&x6&x7| x0&x2&x4&x5&x6&x7| x0&x1&x3&x4&x5&x7| x0&x1&x2&x4&x5&x7| x1&x2&x3&x4&x5&x7| x0&x1&x2&x4&x6&x7| x0&x1&x4&x5&x6&x7| x0&x1&x2&x4&x6&x7| x0&x1&x2&x5&x6&x7| x1&x2&x3&x5&x6&x7| x0&x1&x2&x3&x4&x5&x6| x0&x1&x2&x4&x5&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x2&x3&x4&x5&x6&x7| x0&x1&x2&x3&x5&x6&x7| x0&x2&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x6&x7| x0&x2&x3&x4&x5&x6&x7;
//     bit_t y3 = x0&x2&x3&x4&x6| x0&x2&x4&x5&x7| x0&x1&x2&x3&x4&x5| x1&x2&x3&x5&x6&x7| x0&x1&x2&x3&x4&x7| x0&x2&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x6&x7| x1&x2&x3&x4&x5&x6&x7| x0&x2&x3&x4&x5&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x5&x7| x0&x1&x2&x3&x4&x6&x7| x0&x1&x2&x3&x4&x5&x6&x7| x0&x1&x2&x3&x5| x0&x1&x2&x5&x6| x2&x3&x4&x5&x6| x0&x2&x3&x6&x7| x0&x1&x2&x3&x4&x5| x0&x1&x3&x4&x5&x6| x0&x1&x3&x4&x5&x6| x1&x2&x3&x4&x5&x6| x0&x1&x2&x3&x5&x6| x0&x1&x3&x4&x5&x6| x0&x1&x2&x4&x5&x6| x0&x2&x3&x4&x5&x7| x0&x2&x3&x4&x5&x7| x0&x1&x3&x4&x6&x7| x0&x3&x4&x5&x6&x7| x0&x1&x4&x5&x6&x7| x0&x2&x4&x5&x6&x7| x1&x3&x4&x5&x6&x7| x2&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x7| x0&x1&x2&x3&x4&x7| x0&x1&x2&x4&x5&x7| x0&x1&x2&x5&x6&x7| x1&x2&x4&x5&x6&x7| x1&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x5&x6| x0&x1&x2&x3&x4&x5&x6| x0&x1&x2&x3&x5&x6&x7| x0&x1&x2&x4&x5&x6&x7| x0&x1&x2&x3&x5&x6&x7| x0&x1&x2&x4&x5&x6&x7;
//     bit_t y4 = x0&x1&x2&x3&x4&x5| x1&x2&x3&x4&x5&x6| x0&x1&x3&x4&x5&x6| x0&x1&x3&x4&x5&x6| x0&x1&x2&x3&x5&x6| x0&x2&x3&x5&x6&x7| x0&x1&x2&x4&x6&x7| x0&x2&x3&x4&x6&x7| x0&x2&x3&x4&x6&x7| x2&x3&x4&x5&x6&x7| x1&x3&x4&x5&x6&x7| x2&x3&x4&x5&x6&x7| x2&x3&x4&x5&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x2&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x5&x6&x7| x1&x2&x5&x6&x7| x0&x1&x2&x3&x4&x5| x1&x2&x3&x4&x5&x6| x0&x1&x2&x3&x5&x6| x0&x1&x2&x3&x5&x6| x0&x2&x3&x4&x5&x6| x0&x1&x2&x4&x5&x7| x1&x2&x3&x5&x6&x7| x1&x2&x3&x4&x6&x7| x0&x1&x3&x5&x6&x7| x0&x2&x4&x5&x6&x7| x0&x1&x2&x3&x5&x7| x0&x1&x2&x4&x5&x7| x0&x1&x3&x4&x5&x7| x0&x1&x2&x3&x6&x7| x0&x1&x2&x4&x6&x7| x1&x2&x3&x4&x6&x7| x0&x3&x4&x5&x6&x7| x1&x2&x4&x5&x6&x7| x0&x1&x2&x3&x6&x7| x0&x1&x3&x4&x6&x7| x0&x1&x4&x5&x6&x7| x0&x1&x2&x3&x4&x5&x6| x0&x1&x2&x3&x4&x5&x6| x0&x1&x3&x4&x5&x6&x7| x0&x1&x2&x3&x5&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x2&x3&x4&x5&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x1&x2&x4&x5&x6&x7| x0&x2&x3&x4&x5&x6&x7;
//     bit_t y5 = x0&x1&x2&x3&x5| x0&x1&x3&x4&x5| x0&x2&x4&x5&x7| x2&x3&x5&x6&x7| x0&x4&x5&x6&x7| x0&x1&x2&x3&x5&x6| x0&x2&x3&x4&x5&x6| x0&x1&x2&x3&x5&x6| x0&x1&x3&x4&x5&x6| x0&x1&x2&x3&x5&x7| x0&x1&x2&x3&x4&x7| x1&x2&x3&x4&x5&x7| x0&x1&x2&x4&x6&x7| x0&x1&x2&x5&x6&x7| x1&x3&x4&x5&x6&x7| x1&x2&x3&x5&x6&x7| x0&x2&x4&x5&x6&x7| x0&x1&x2&x3&x4&x5&x6| x0&x1&x2&x3&x4&x5&x7| x1&x2&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x5| x0&x1&x3&x4&x5&x7| x1&x2&x3&x5&x6&x7| x0&x3&x4&x5&x6&x7| x1&x2&x3&x4&x6&x7| x0&x1&x2&x4&x6&x7| x0&x1&x4&x5&x6&x7| x0&x1&x2&x4&x5&x7| x0&x1&x2&x3&x5&x7| x0&x1&x2&x4&x6&x7| x1&x2&x3&x4&x6&x7| x1&x2&x4&x5&x6&x7| x0&x1&x2&x3&x4&x5&x6| x0&x1&x2&x3&x4&x5&x6| x0&x1&x2&x3&x4&x5&x7| x0&x1&x2&x3&x5&x6&x7| x0&x1&x2&x4&x5&x6&x7| x0&x1&x2&x3&x5&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x5&x7| x0&x1&x2&x3&x5&x6&x7| x0&x1&x2&x3&x4&x6&x7| x0&x1&x2&x3&x4&x6&x7| x1&x2&x3&x4&x5&x6&x7| x0&x2&x3&x4&x5&x6&x7| x1&x2&x3&x4&x5&x6&x7;
//     bit_t y6 = x0&x1&x2&x6&x7| x0&x1&x2&x3&x4&x5| x0&x1&x2&x3&x4&x5| x0&x1&x2&x4&x5&x7| x1&x3&x4&x5&x6&x7| x0&x1&x3&x4&x6&x7| x1&x2&x3&x5&x6&x7| x0&x1&x2&x3&x4&x5&x6| x0&x1&x2&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x5&x6&x7| x0&x1&x2&x3&x5| x0&x3&x4&x5&x6| x0&x1&x2&x6&x7| x0&x1&x2&x3&x4&x5| x1&x2&x3&x4&x5&x6| x0&x2&x3&x4&x5&x6| x0&x1&x2&x4&x5&x6| x0&x1&x2&x3&x4&x6| x0&x1&x2&x3&x4&x7| x0&x1&x2&x3&x5&x7| x0&x1&x2&x3&x5&x7| x1&x2&x3&x4&x6&x7| x0&x1&x3&x4&x6&x7| x0&x2&x4&x5&x6&x7| x0&x1&x2&x5&x6&x7| x0&x2&x3&x5&x6&x7| x0&x1&x2&x5&x6&x7| x1&x2&x4&x5&x6&x7| x1&x2&x3&x4&x5&x7| x0&x1&x2&x4&x5&x7| x0&x1&x3&x4&x5&x7| x0&x1&x2&x3&x5&x7| x0&x2&x3&x5&x6&x7| x1&x3&x4&x5&x6&x7| x0&x1&x3&x4&x6&x7| x0&x2&x3&x5&x6&x7| x0&x1&x2&x3&x4&x6&x7| x0&x1&x2&x3&x4&x6&x7| x0&x2&x3&x4&x5&x6&x7| x1&x2&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x5&x7| x0&x1&x3&x4&x5&x6&x7| x1&x2&x3&x4&x5&x6&x7| x1&x2&x3&x4&x5&x6&x7| x0&x1&x2&x3&x5&x6&x7;
//     bit_t y7 = x0&x1&x3&x5&x6| x0&x1&x2&x3&x4&x7| x1&x2&x3&x4&x5&x7| x0&x2&x3&x4&x6&x7| x0&x3&x4&x5&x6&x7| x1&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x5&x6| x0&x1&x2&x3&x4&x5&x6| x0&x2&x3&x4&x5&x6&x7| x1&x2&x3&x5&x6| x1&x2&x5&x6&x7| x0&x1&x2&x3&x4&x5| x1&x2&x3&x4&x5&x6| x0&x1&x2&x4&x5&x6| x0&x1&x2&x4&x5&x7| x0&x1&x2&x4&x5&x7| x1&x2&x3&x4&x6&x7| x0&x2&x3&x5&x6&x7| x0&x1&x4&x5&x6&x7| x1&x3&x4&x5&x6&x7| x0&x1&x3&x4&x6&x7| x0&x2&x3&x4&x6&x7| x0&x1&x3&x5&x6&x7| x0&x2&x3&x5&x6&x7| x1&x2&x3&x5&x6&x7| x1&x2&x4&x5&x6&x7| x0&x1&x2&x3&x4&x7| x0&x1&x2&x4&x5&x7| x1&x2&x4&x5&x6&x7| x0&x1&x2&x5&x6&x7| x1&x2&x4&x5&x6&x7| x0&x2&x3&x4&x6&x7| x0&x3&x4&x5&x6&x7| x0&x2&x4&x5&x6&x7| x1&x2&x4&x5&x6&x7| x0&x3&x4&x5&x6&x7| x0&x1&x2&x3&x4&x5&x7| x0&x1&x2&x3&x5&x6&x7| x0&x1&x2&x3&x4&x6&x7| x0&x1&x3&x4&x5&x6&x7| x0&x1&x2&x4&x5&x6&x7| x0&x2&x3&x4&x5&x6&x7| x0&x1&x2&x4&x5&x6&x7;
//     *out0 = y0;
//     *out1 = y1;
//     *out2 = y2;
//     *out3 = y3;
//     *out4 = y4;
//     *out5 = y5;
//     *out6 = y6;
//     *out7 = y7;
// }

// void Sm4_BoolFun(bits in, bit_t *out0, bit_t *out1, bit_t *out2, bit_t *out3, bit_t *out4, bit_t *out5, bit_t *out6, bit_t *out7) {
//     bit_t x0 = in.b0;
//     bit_t x1 = in.b1;
//     bit_t x2 = in.b2;
//     bit_t x3 = in.b3;
//     bit_t x4 = in.b4;
//     bit_t x5 = in.b5;
//     bit_t x6 = in.b6;
//     bit_t x7 = in.b7;
//     uint64_t t = 0x0;
//     uint64_t n[4] = {~t,~t,~t,~t};
//     bit_t N = _mm256_loadu_si256((__m256i*)n);
//     bit_t y0 = x1 | x0&x1 | x0&x2 | x1&x3 | x0&x1&x3 | x4 | x0&x1&x4 | x2&x4 | x0&x2&x4 | x1&x2&x4 | x0&x1&x2&x4 | x3&x4 | x1&x3&x4 | x0&x2&x3&x4 | x1&x2&x3&x4 | x1&x5 | x0&x1&x5 | x2&x5 | x0&x2&x5 | x1&x2&x5 | x3&x5 | x0&x3&x5 | x1&x3&x5 | x2&x3&x5 | x0&x2&x3&x5 | x0&x1&x2&x3&x5 | x4&x5 | x0&x4&x5 | x0&x1&x4&x5 | x2&x4&x5 | x0&x2&x4&x5 | x1&x2&x4&x5 | x0&x1&x2&x4&x5 | x0&x3&x4&x5 | x1&x3&x4&x5 | x2&x3&x4&x5 | x0&x2&x3&x4&x5 | x0&x1&x2&x3&x4&x5 | x6 | x1&x6 | x0&x2&x6 | x0&x1&x3&x6 | x2&x3&x6 | x0&x2&x3&x6 | x0&x1&x2&x3&x6 | x0&x4&x6 | x1&x4&x6 | x0&x2&x4&x6 | x1&x2&x4&x6 | x0&x1&x2&x4&x6 | x3&x4&x6 | x0&x1&x3&x4&x6 | x0&x2&x3&x4&x6 | x1&x2&x3&x4&x6 | x5&x6 | x1&x5&x6 | x1&x2&x5&x6 | x1&x3&x5&x6 | x2&x3&x5&x6 | x0&x1&x2&x3&x5&x6 | x1&x4&x5&x6 | x0&x1&x4&x5&x6 | x1&x2&x4&x5&x6 | x0&x1&x2&x4&x5&x6 | x3&x4&x5&x6 | x1&x3&x4&x5&x6 | x0&x1&x3&x4&x5&x6 | x2&x3&x4&x5&x6 | x0&x2&x3&x4&x5&x6 | x0&x1&x2&x3&x4&x5&x6 | x0&x7 | x1&x7 | x0&x2&x7 | x0&x1&x2&x7 | x3&x7 | x0&x3&x7 | x1&x2&x3&x7 | x0&x1&x2&x3&x7 | x4&x7 | x0&x4&x7 | x1&x4&x7 | x0&x1&x4&x7 | x1&x2&x4&x7 | x0&x1&x2&x4&x7 | x3&x4&x7 | x0&x3&x4&x7 | x2&x3&x4&x7 | x0&x2&x3&x4&x7 | x1&x2&x3&x4&x7 | x0&x1&x2&x3&x4&x7 | x5&x7 | x0&x1&x5&x7 | x3&x5&x7 | x0&x1&x3&x5&x7 | x2&x3&x5&x7 | x0&x2&x3&x5&x7 | x0&x1&x2&x3&x5&x7 | x4&x5&x7 | x0&x4&x5&x7 | x3&x4&x5&x7 | x1&x3&x4&x5&x7 | x2&x3&x4&x5&x7 | x0&x2&x3&x4&x5&x7 | x0&x6&x7 | x1&x6&x7 | x0&x2&x6&x7 | x1&x2&x6&x7 | x0&x1&x2&x6&x7 | x3&x6&x7 | x0&x3&x6&x7 | x2&x3&x6&x7 | x4&x6&x7 | x0&x4&x6&x7 | x1&x4&x6&x7 | x0&x1&x4&x6&x7 | x0&x2&x4&x6&x7 | x1&x2&x4&x6&x7 | x0&x1&x2&x4&x6&x7 | x0&x3&x4&x6&x7 | x2&x3&x4&x6&x7 | x0&x2&x3&x4&x6&x7 | x0&x1&x2&x3&x4&x6&x7 | x0&x2&x5&x6&x7 | x0&x3&x5&x6&x7 | x1&x3&x5&x6&x7 | x1&x2&x3&x5&x6&x7 | x0&x4&x5&x6&x7 | x1&x4&x5&x6&x7 | x0&x1&x4&x5&x6&x7 | x2&x4&x5&x6&x7 | x1&x2&x4&x5&x6&x7 | x1&x3&x4&x5&x6&x7 | x0&x2&x3&x4&x5&x6&x7 | x1&x2&x3&x4&x5&x6&x7;
//     bit_t y1 = N | x0 | x1 | x2 | x0&x2 | x1&x2 | x0&x1&x2 | x0&x3 | x0&x1&x3 | x0&x1&x2&x3 | x0&x4 | x1&x4 | x2&x4 | x0&x2&x4 | x2&x3&x4 | x0&x1&x2&x3&x4 | x5 | x1&x5 | x0&x1&x5 | x2&x5 | x0&x2&x5 | x1&x2&x5 | x3&x5 | x0&x3&x5 | x0&x1&x3&x5 | x2&x3&x5 | x0&x1&x2&x3&x5 | x0&x4&x5 | x1&x4&x5 | x2&x4&x5 | x3&x4&x5 | x0&x1&x3&x4&x5 | x0&x2&x3&x4&x5 | x1&x2&x3&x4&x5 | x0&x1&x2&x3&x4&x5 | x0&x6 | x1&x6 | x0&x1&x6 | x2&x6 | x0&x2&x6 | x1&x2&x6 | x1&x3&x6 | x0&x1&x3&x6 | x1&x2&x3&x6 | x0&x1&x2&x3&x6 | x4&x6 | x1&x4&x6 | x0&x1&x4&x6 | x2&x4&x6 | x1&x2&x4&x6 | x0&x1&x2&x4&x6 | x0&x3&x4&x6 | x0&x1&x3&x4&x6 | x2&x3&x4&x6 | x0&x2&x3&x4&x6 | x1&x2&x3&x4&x6 | x0&x1&x2&x3&x4&x6 | x5&x6 | x0&x5&x6 | x1&x5&x6 | x0&x1&x5&x6 | x2&x5&x6 | x0&x2&x5&x6 | x1&x3&x5&x6 | x2&x3&x5&x6 | x0&x2&x3&x5&x6 | x0&x1&x2&x3&x5&x6 | x0&x4&x5&x6 | x0&x2&x4&x5&x6 | x1&x2&x4&x5&x6 | x2&x3&x4&x5&x6 | x1&x2&x3&x4&x5&x6 | x0&x1&x2&x3&x4&x5&x6 | x0&x7 | x1&x7 | x1&x2&x7 | x0&x3&x7 | x0&x1&x3&x7 | x0&x2&x3&x7 | x4&x7 | x1&x4&x7 | x0&x1&x4&x7 | x2&x4&x7 | x1&x3&x4&x7 | x0&x1&x3&x4&x7 | x1&x2&x3&x4&x7 | x0&x5&x7 | x2&x5&x7 | x0&x2&x5&x7 | x0&x1&x2&x5&x7 | x3&x5&x7 | x0&x2&x3&x5&x7 | x1&x2&x3&x5&x7 | x0&x1&x2&x3&x5&x7 | x4&x5&x7 | x1&x4&x5&x7 | x2&x4&x5&x7 | x0&x1&x2&x4&x5&x7 | x0&x1&x3&x4&x5&x7 | x0&x2&x3&x4&x5&x7 | x1&x2&x3&x4&x5&x7 | x0&x1&x2&x3&x4&x5&x7 | x6&x7 | x2&x6&x7 | x1&x2&x6&x7 | x0&x3&x6&x7 | x1&x2&x3&x6&x7 | x0&x1&x2&x3&x6&x7 | x4&x6&x7 | x0&x4&x6&x7 | x1&x4&x6&x7 | x2&x4&x6&x7 | x1&x2&x4&x6&x7 | x3&x4&x6&x7 | x0&x3&x4&x6&x7 | x1&x3&x4&x6&x7 | x0&x1&x3&x4&x6&x7 | x2&x3&x4&x6&x7 | x0&x2&x3&x4&x6&x7 | x0&x5&x6&x7 | x0&x1&x5&x6&x7 | x1&x2&x5&x6&x7 | x0&x1&x2&x5&x6&x7 | x1&x3&x5&x6&x7 | x0&x2&x3&x5&x6&x7 | x0&x1&x2&x3&x5&x6&x7 | x1&x4&x5&x6&x7 | x2&x4&x5&x6&x7 | x0&x3&x4&x5&x6&x7 | x1&x2&x3&x4&x5&x6&x7;
//     bit_t y2 = N | x0 | x1 | x1&x2 | x0&x1&x2 | x0&x3 | x1&x3 | x0&x1&x3 | x2&x3 | x4 | x1&x4 | x0&x1&x2&x4 | x0&x3&x4 | x1&x3&x4 | x0&x1&x3&x4 | x2&x3&x4 | x2&x5 | x3&x5 | x0&x3&x5 | x2&x3&x5 | x0&x2&x3&x5 | x1&x2&x3&x5 | x0&x1&x2&x3&x5 | x4&x5 | x0&x2&x4&x5 | x1&x2&x4&x5 | x0&x1&x2&x4&x5 | x0&x3&x4&x5 | x1&x3&x4&x5 | x2&x3&x4&x5 | x0&x2&x3&x4&x5 | x0&x6 | x1&x6 | x2&x6 | x3&x6 | x0&x3&x6 | x2&x3&x6 | x0&x1&x2&x3&x6 | x1&x4&x6 | x2&x4&x6 | x0&x2&x4&x6 | x1&x2&x4&x6 | x0&x1&x2&x4&x6 | x3&x4&x6 | x0&x3&x4&x6 | x1&x3&x4&x6 | x0&x1&x3&x4&x6 | x2&x3&x4&x6 | x2&x5&x6 | x1&x2&x5&x6 | x0&x1&x2&x5&x6 | x1&x3&x5&x6 | x0&x1&x3&x5&x6 | x2&x3&x5&x6 | x1&x2&x3&x5&x6 | x0&x1&x2&x3&x5&x6 | x0&x4&x5&x6 | x0&x1&x4&x5&x6 | x3&x4&x5&x6 | x0&x3&x4&x5&x6 | x0&x2&x3&x4&x5&x6 | x1&x2&x3&x4&x5&x6 | x0&x1&x2&x3&x4&x5&x6 | x7 | x1&x7 | x0&x1&x7 | x1&x2&x7 | x0&x3&x7 | x1&x3&x7 | x2&x3&x7 | x0&x2&x3&x7 | x1&x2&x3&x7 | x4&x7 | x1&x2&x4&x7 | x0&x1&x2&x4&x7 | x3&x4&x7 | x0&x3&x4&x7 | x1&x3&x4&x7 | x2&x3&x4&x7 | x5&x7 | x0&x5&x7 | x1&x5&x7 | x0&x2&x5&x7 | x1&x2&x5&x7 | x0&x1&x2&x5&x7 | x0&x3&x5&x7 | x1&x3&x5&x7 | x2&x3&x5&x7 | x1&x2&x3&x5&x7 | x4&x5&x7 | x0&x4&x5&x7 | x2&x4&x5&x7 | x0&x2&x4&x5&x7 | x1&x2&x4&x5&x7 | x3&x4&x5&x7 | x0&x3&x4&x5&x7 | x0&x2&x3&x4&x5&x7 | x0&x1&x2&x3&x4&x5&x7 | x6&x7 | x0&x6&x7 | x1&x6&x7 | x0&x1&x6&x7 | x1&x2&x6&x7 | x1&x3&x6&x7 | x2&x3&x6&x7 | x4&x6&x7 | x0&x4&x6&x7 | x2&x4&x6&x7 | x0&x2&x4&x6&x7 | x0&x1&x2&x4&x6&x7 | x1&x3&x4&x6&x7 | x0&x1&x3&x4&x6&x7 | x2&x3&x4&x6&x7 | x0&x1&x5&x6&x7 | x0&x2&x5&x6&x7 | x3&x5&x6&x7 | x1&x3&x5&x6&x7 | x0&x2&x3&x5&x6&x7 | x0&x1&x2&x3&x5&x6&x7 | x4&x5&x6&x7 | x0&x4&x5&x6&x7 | x0&x2&x4&x5&x6&x7 | x1&x2&x4&x5&x6&x7 | x3&x4&x5&x6&x7 | x1&x3&x4&x5&x6&x7 | x2&x3&x4&x5&x6&x7 | x0&x2&x3&x4&x5&x6&x7 | x1&x2&x3&x4&x5&x6&x7;
//     bit_t y3 = x1 | x2 | x0&x2 | x1&x2 | x1&x3 | x0&x2&x3 | x1&x2&x3 | x0&x1&x2&x3 | x4 | x0&x4 | x1&x4 | x2&x4 | x0&x1&x3&x4 | x5 | x0&x5 | x0&x1&x5 | x0&x2&x5 | x1&x2&x5 | x3&x5 | x0&x3&x5 | x1&x3&x5 | x0&x2&x3&x5 | x0&x1&x2&x3&x5 | x1&x4&x5 | x0&x1&x4&x5 | x2&x4&x5 | x1&x2&x4&x5 | x0&x1&x2&x4&x5 | x3&x4&x5 | x1&x3&x4&x5 | x0&x1&x3&x4&x5 | x2&x3&x4&x5 | x1&x2&x3&x4&x5 | x0&x1&x2&x3&x4&x5 | x1&x6 | x0&x1&x6 | x2&x6 | x0&x2&x6 | x1&x2&x6 | x0&x3&x6 | x1&x2&x3&x6 | x0&x4&x6 | x0&x1&x4&x6 | x0&x3&x4&x6 | x0&x1&x3&x4&x6 | x0&x2&x3&x4&x6 | x1&x2&x3&x4&x6 | x0&x1&x5&x6 | x2&x5&x6 | x0&x2&x5&x6 | x1&x2&x5&x6 | x0&x3&x5&x6 | x1&x3&x5&x6 | x0&x1&x3&x5&x6 | x2&x3&x5&x6 | x0&x1&x2&x3&x5&x6 | x0&x4&x5&x6 | x0&x1&x4&x5&x6 | x0&x2&x4&x5&x6 | x3&x4&x5&x6 | x0&x3&x4&x5&x6 | x1&x3&x4&x5&x6 | x0&x1&x3&x4&x5&x6 | x0&x2&x3&x4&x5&x6 | x1&x2&x3&x4&x5&x6 | x7 | x1&x7 | x0&x1&x7 | x0&x2&x7 | x3&x7 | x1&x3&x7 | x1&x2&x3&x7 | x0&x1&x2&x3&x7 | x0&x1&x4&x7 | x2&x4&x7 | x0&x2&x3&x4&x7 | x5&x7 | x1&x5&x7 | x0&x1&x2&x5&x7 | x3&x5&x7 | x0&x3&x5&x7 | x0&x2&x3&x5&x7 | x0&x1&x2&x3&x5&x7 | x0&x4&x5&x7 | x1&x4&x5&x7 | x0&x1&x4&x5&x7 | x2&x4&x5&x7 | x1&x2&x4&x5&x7 | x0&x1&x2&x4&x5&x7 | x1&x3&x4&x5&x7 | x0&x1&x3&x4&x5&x7 | x2&x3&x4&x5&x7 | x0&x1&x2&x3&x4&x5&x7 | x1&x6&x7 | x0&x1&x6&x7 | x0&x2&x6&x7 | x0&x1&x2&x6&x7 | x1&x3&x6&x7 | x0&x1&x3&x6&x7 | x2&x3&x6&x7 | x0&x2&x3&x6&x7 | x4&x6&x7 | x0&x4&x6&x7 | x0&x1&x4&x6&x7 | x2&x4&x6&x7 | x3&x4&x6&x7 | x1&x3&x4&x6&x7 | x0&x1&x2&x3&x4&x6&x7 | x0&x5&x6&x7 | x2&x5&x6&x7 | x0&x2&x5&x6&x7 | x0&x1&x2&x5&x6&x7 | x0&x3&x5&x6&x7 | x0&x1&x3&x5&x6&x7 | x0&x2&x3&x5&x6&x7 | x1&x2&x3&x5&x6&x7 | x0&x1&x2&x3&x5&x6&x7 | x2&x4&x5&x6&x7 | x0&x2&x4&x5&x6&x7 | x0&x1&x2&x4&x5&x6&x7 | x1&x3&x4&x5&x6&x7 | x0&x1&x3&x4&x5&x6&x7 | x2&x3&x4&x5&x6&x7;
//     bit_t y4 = N | x1 | x0&x1 | x2 | x0&x1&x2 | x1&x3 | x0&x2&x3 | x0&x1&x2&x3 | x4 | x0&x1&x4 | x2&x4 | x0&x2&x4 | x1&x2&x4 | x1&x3&x4 | x0&x1&x3&x4 | x0&x5 | x1&x5 | x2&x5 | x0&x1&x2&x5 | x0&x3&x5 | x0&x1&x3&x5 | x2&x3&x5 | x0&x2&x3&x5 | x1&x2&x3&x5 | x0&x1&x2&x3&x5 | x1&x4&x5 | x2&x4&x5 | x0&x1&x2&x4&x5 | x0&x3&x4&x5 | x0&x1&x3&x4&x5 | x0&x2&x3&x4&x5 | x1&x2&x3&x4&x5 | x6 | x1&x6 | x0&x3&x6 | x2&x3&x6 | x1&x2&x3&x6 | x0&x1&x2&x3&x6 | x4&x6 | x0&x1&x4&x6 | x2&x4&x6 | x1&x2&x4&x6 | x3&x4&x6 | x1&x3&x4&x6 | x0&x1&x3&x4&x6 | x0&x2&x3&x4&x6 | x5&x6 | x0&x1&x5&x6 | x2&x5&x6 | x3&x5&x6 | x0&x3&x5&x6 | x1&x3&x5&x6 | x0&x1&x3&x5&x6 | x2&x3&x5&x6 | x1&x4&x5&x6 | x3&x4&x5&x6 | x1&x3&x4&x5&x6 | x2&x3&x4&x5&x6 | x1&x2&x3&x4&x5&x6 | x7 | x0&x7 | x1&x7 | x0&x1&x7 | x2&x7 | x0&x2&x7 | x1&x2&x7 | x0&x1&x2&x7 | x2&x3&x7 | x0&x1&x2&x3&x7 | x4&x7 | x0&x4&x7 | x1&x4&x7 | x1&x2&x4&x7 | x0&x1&x2&x4&x7 | x0&x3&x4&x7 | x0&x1&x3&x4&x7 | x2&x3&x4&x7 | x0&x2&x3&x4&x7 | x5&x7 | x0&x2&x5&x7 | x0&x1&x2&x5&x7 | x3&x5&x7 | x0&x3&x5&x7 | x0&x1&x3&x5&x7 | x2&x3&x5&x7 | x0&x2&x3&x5&x7 | x0&x4&x5&x7 | x1&x4&x5&x7 | x2&x4&x5&x7 | x0&x2&x4&x5&x7 | x0&x1&x2&x4&x5&x7 | x0&x3&x4&x5&x7 | x6&x7 | x1&x6&x7 | x2&x6&x7 | x1&x2&x6&x7 | x3&x6&x7 | x1&x3&x6&x7 | x0&x1&x3&x6&x7 | x2&x3&x6&x7 | x1&x2&x3&x6&x7 | x4&x6&x7 | x0&x1&x4&x6&x7 | x2&x4&x6&x7 | x1&x2&x4&x6&x7 | x0&x3&x4&x6&x7 | x2&x3&x4&x6&x7 | x0&x2&x3&x4&x6&x7 | x1&x2&x3&x4&x6&x7 | x2&x5&x6&x7 | x0&x2&x5&x6&x7 | x3&x5&x6&x7 | x0&x3&x5&x6&x7 | x1&x3&x5&x6&x7 | x0&x1&x3&x5&x6&x7 | x0&x2&x3&x5&x6&x7 | x4&x5&x6&x7 | x1&x4&x5&x6&x7 | x0&x1&x4&x5&x6&x7 | x2&x4&x5&x6&x7 | x0&x2&x4&x5&x6&x7 | x1&x2&x4&x5&x6&x7 | x1&x3&x4&x5&x6&x7 | x0&x1&x3&x4&x5&x6&x7 | x2&x3&x4&x5&x6&x7 | x1&x2&x3&x4&x5&x6&x7;
//     bit_t y5 = x1 | x0&x2 | x0&x1&x2 | x0&x3 | x1&x3 | x0&x1&x3 | x2&x3 | x0&x1&x2&x3 | x4 | x0&x1&x4 | x0&x2&x4 | x1&x3&x4 | x0&x2&x3&x4 | x1&x2&x3&x4 | x1&x5 | x0&x1&x5 | x3&x5 | x0&x1&x3&x5 | x2&x3&x5 | x0&x2&x3&x5 | x1&x2&x3&x5 | x1&x4&x5 | x0&x1&x4&x5 | x2&x4&x5 | x0&x1&x2&x4&x5 | x0&x3&x4&x5 | x1&x3&x4&x5 | x0&x2&x3&x4&x5 | x0&x1&x2&x3&x4&x5 | x2&x6 | x0&x2&x6 | x0&x3&x6 | x1&x3&x6 | x2&x3&x6 | x0&x2&x3&x6 | x0&x1&x2&x3&x6 | x2&x4&x6 | x0&x2&x4&x6 | x1&x3&x4&x6 | x0&x2&x3&x4&x6 | x1&x2&x3&x4&x6 | x0&x1&x2&x3&x4&x6 | x0&x5&x6 | x1&x2&x5&x6 | x0&x3&x5&x6 | x0&x1&x3&x5&x6 | x2&x3&x5&x6 | x0&x2&x3&x5&x6 | x1&x2&x3&x5&x6 | x0&x1&x2&x3&x5&x6 | x4&x5&x6 | x0&x4&x5&x6 | x1&x4&x5&x6 | x0&x1&x4&x5&x6 | x2&x4&x5&x6 | x0&x1&x2&x4&x5&x6 | x3&x4&x5&x6 | x0&x3&x4&x5&x6 | x1&x3&x4&x5&x6 | x0&x1&x3&x4&x5&x6 | x2&x3&x4&x5&x6 | x0&x1&x2&x3&x4&x5&x6 | x7 | x2&x7 | x0&x2&x7 | x0&x1&x2&x7 | x0&x3&x7 | x1&x2&x3&x7 | x0&x1&x2&x3&x7 | x4&x7 | x1&x2&x4&x7 | x0&x3&x4&x7 | x1&x3&x4&x7 | x0&x1&x3&x4&x7 | x1&x2&x3&x4&x7 | x5&x7 | x0&x5&x7 | x1&x5&x7 | x2&x5&x7 | x1&x2&x5&x7 | x0&x1&x2&x5&x7 | x3&x5&x7 | x1&x3&x5&x7 | x0&x1&x2&x3&x5&x7 | x0&x4&x5&x7 | x1&x4&x5&x7 | x2&x4&x5&x7 | x1&x2&x4&x5&x7 | x0&x1&x2&x4&x5&x7 | x0&x3&x4&x5&x7 | x1&x3&x4&x5&x7 | x0&x1&x3&x4&x5&x7 | x2&x3&x4&x5&x7 | x0&x2&x3&x4&x5&x7 | x1&x2&x3&x4&x5&x7 | x6&x7 | x0&x1&x6&x7 | x2&x6&x7 | x1&x2&x6&x7 | x0&x3&x6&x7 | x1&x3&x6&x7 | x2&x3&x6&x7 | x0&x1&x2&x3&x6&x7 | x0&x1&x4&x6&x7 | x2&x4&x6&x7 | x1&x2&x4&x6&x7 | x3&x4&x6&x7 | x0&x3&x4&x6&x7 | x0&x1&x3&x4&x6&x7 | x0&x1&x2&x3&x4&x6&x7 | x5&x6&x7 | x0&x5&x6&x7 | x1&x5&x6&x7 | x0&x1&x5&x6&x7 | x3&x5&x6&x7 | x0&x1&x3&x5&x6&x7 | x0&x2&x3&x5&x6&x7 | x0&x1&x2&x3&x5&x6&x7 | x4&x5&x6&x7 | x0&x2&x4&x5&x6&x7 | x0&x1&x2&x4&x5&x6&x7 | x0&x3&x4&x5&x6&x7 | x2&x3&x4&x5&x6&x7 | x1&x2&x3&x4&x5&x6&x7;
//     bit_t y6 = N | x0 | x0&x1 | x0&x2 | x1&x2 | x0&x1&x2 | x3 | x0&x3 | x1&x2&x3 | x0&x1&x2&x3 | x4 | x0&x1&x4 | x1&x2&x4 | x3&x4 | x0&x3&x4 | x0&x1&x3&x4 | x2&x3&x4 | x0&x2&x3&x4 | x5 | x1&x5 | x0&x2&x5 | x3&x5 | x0&x3&x5 | x1&x3&x5 | x0&x1&x3&x5 | x2&x3&x5 | x0&x2&x3&x5 | x1&x2&x3&x5 | x0&x1&x2&x3&x5 | x0&x1&x4&x5 | x1&x2&x4&x5 | x0&x3&x4&x5 | x0&x1&x3&x4&x5 | x2&x3&x4&x5 | x1&x6 | x0&x1&x6 | x1&x2&x6 | x0&x1&x2&x6 | x0&x3&x6 | x1&x3&x6 | x0&x1&x3&x6 | x2&x3&x6 | x0&x2&x3&x6 | x1&x2&x3&x6 | x4&x6 | x0&x4&x6 | x0&x1&x4&x6 | x0&x2&x4&x6 | x0&x1&x2&x4&x6 | x0&x3&x4&x6 | x1&x3&x4&x6 | x0&x1&x3&x4&x6 | x1&x2&x3&x4&x6 | x0&x1&x2&x3&x4&x6 | x0&x5&x6 | x0&x1&x5&x6 | x2&x5&x6 | x0&x3&x5&x6 | x1&x3&x5&x6 | x2&x3&x5&x6 | x1&x2&x3&x5&x6 | x4&x5&x6 | x0&x1&x4&x5&x6 | x0&x2&x4&x5&x6 | x3&x4&x5&x6 | x0&x3&x4&x5&x6 | x1&x3&x4&x5&x6 | x2&x3&x4&x5&x6 | x0&x2&x3&x4&x5&x6 | x1&x2&x3&x4&x5&x6 | x1&x7 | x0&x1&x7 | x1&x2&x7 | x0&x1&x2&x7 | x0&x3&x7 | x0&x1&x3&x7 | x2&x3&x7 | x1&x2&x3&x7 | x4&x7 | x1&x4&x7 | x0&x1&x4&x7 | x2&x4&x7 | x1&x2&x4&x7 | x0&x1&x2&x4&x7 | x3&x4&x7 | x0&x2&x3&x4&x7 | x1&x2&x3&x4&x7 | x1&x5&x7 | x0&x1&x2&x5&x7 | x3&x5&x7 | x0&x3&x5&x7 | x1&x3&x5&x7 | x0&x1&x3&x5&x7 | x2&x3&x5&x7 | x0&x2&x3&x5&x7 | x1&x2&x3&x5&x7 | x0&x1&x2&x3&x5&x7 | x4&x5&x7 | x0&x4&x5&x7 | x1&x4&x5&x7 | x2&x4&x5&x7 | x1&x2&x4&x5&x7 | x0&x1&x2&x4&x5&x7 | x0&x3&x4&x5&x7 | x0&x1&x3&x4&x5&x7 | x0&x2&x3&x4&x5&x7 | x0&x1&x2&x3&x4&x5&x7 | x6&x7 | x0&x6&x7 | x0&x1&x6&x7 | x1&x2&x6&x7 | x0&x1&x2&x6&x7 | x3&x6&x7 | x0&x1&x3&x6&x7 | x0&x2&x3&x6&x7 | x1&x2&x3&x6&x7 | x4&x6&x7 | x1&x4&x6&x7 | x2&x4&x6&x7 | x1&x2&x4&x6&x7 | x0&x1&x2&x4&x6&x7 | x0&x3&x4&x6&x7 | x1&x3&x4&x6&x7 | x2&x3&x4&x6&x7 | x5&x6&x7 | x0&x1&x5&x6&x7 | x2&x5&x6&x7 | x0&x2&x5&x6&x7 | x1&x2&x5&x6&x7 | x0&x1&x2&x5&x6&x7 | x3&x5&x6&x7 | x0&x1&x3&x5&x6&x7 | x2&x3&x5&x6&x7 | x2&x4&x5&x6&x7 | x0&x2&x4&x5&x6&x7 | x0&x1&x2&x4&x5&x6&x7 | x3&x4&x5&x6&x7 | x0&x3&x4&x5&x6&x7 | x1&x2&x3&x4&x5&x6&x7;
//     bit_t y7 = N | x1&x2 | x0&x1&x2 | x3 | x0&x3 | x1&x2&x3 | x4 | x1&x4 | x0&x1&x4 | x0&x2&x4 | x2&x3&x4 | x0&x2&x3&x4 | x1&x2&x3&x4 | x0&x5 | x1&x5 | x0&x2&x5 | x1&x3&x5 | x2&x3&x5 | x0&x2&x3&x5 | x4&x5 | x0&x4&x5 | x1&x4&x5 | x0&x2&x4&x5 | x0&x1&x2&x4&x5 | x3&x4&x5 | x0&x3&x4&x5 | x0&x1&x3&x4&x5 | x2&x3&x4&x5 | x1&x2&x3&x4&x5 | x6 | x1&x6 | x2&x6 | x0&x2&x6 | x1&x2&x6 | x0&x1&x2&x6 | x0&x1&x3&x6 | x2&x3&x6 | x1&x2&x3&x6 | x4&x6 | x1&x4&x6 | x0&x1&x4&x6 | x2&x4&x6 | x0&x3&x4&x6 | x0&x1&x3&x4&x6 | x2&x3&x4&x6 | x0&x2&x3&x4&x6 | x1&x2&x3&x4&x6 | x0&x1&x2&x3&x4&x6 | x0&x5&x6 | x2&x5&x6 | x1&x2&x5&x6 | x3&x5&x6 | x0&x3&x5&x6 | x1&x3&x5&x6 | x0&x1&x3&x5&x6 | x0&x2&x3&x5&x6 | x1&x2&x3&x5&x6 | x0&x1&x2&x3&x5&x6 | x0&x1&x4&x5&x6 | x2&x4&x5&x6 | x0&x2&x4&x5&x6 | x1&x2&x4&x5&x6 | x0&x3&x4&x5&x6 | x1&x3&x4&x5&x6 | x0&x2&x3&x4&x5&x6 | x2&x7 | x0&x2&x7 | x1&x2&x7 | x0&x1&x2&x7 | x3&x7 | x0&x3&x7 | x2&x3&x7 | x4&x7 | x2&x4&x7 | x0&x2&x4&x7 | x0&x1&x3&x4&x7 | x1&x2&x3&x4&x7 | x5&x7 | x1&x2&x5&x7 | x3&x5&x7 | x1&x3&x5&x7 | x1&x2&x3&x5&x7 | x0&x1&x4&x5&x7 | x0&x2&x4&x5&x7 | x3&x4&x5&x7 | x1&x3&x4&x5&x7 | x0&x1&x3&x4&x5&x7 | x0&x2&x3&x4&x5&x7 | x6&x7 | x0&x6&x7 | x1&x6&x7 | x0&x1&x6&x7 | x0&x2&x6&x7 | x1&x2&x6&x7 | x0&x1&x2&x6&x7 | x3&x6&x7 | x0&x1&x3&x6&x7 | x0&x1&x4&x6&x7 | x2&x4&x6&x7 | x1&x2&x4&x6&x7 | x0&x1&x2&x4&x6&x7 | x3&x4&x6&x7 | x1&x3&x4&x6&x7 | x0&x1&x3&x4&x6&x7 | x0&x2&x3&x4&x6&x7 | x1&x2&x3&x4&x6&x7 | x0&x1&x2&x3&x4&x6&x7 | x5&x6&x7 | x1&x5&x6&x7 | x0&x1&x5&x6&x7 | x0&x1&x2&x5&x6&x7 | x0&x3&x5&x6&x7 | x0&x1&x3&x5&x6&x7 | x2&x3&x5&x6&x7 | x1&x2&x3&x5&x6&x7 | x0&x1&x2&x3&x5&x6&x7 | x4&x5&x6&x7 | x0&x4&x5&x6&x7 | x1&x4&x5&x6&x7 | x0&x1&x4&x5&x6&x7 | x2&x4&x5&x6&x7 | x0&x2&x4&x5&x6&x7 | x0&x3&x4&x5&x6&x7 | x1&x2&x3&x4&x5&x6&x7;
//     *out0 = y0;
//     *out1 = y1;
//     *out2 = y2;
//     *out3 = y3;
//     *out4 = y4;
//     *out5 = y5;
//     *out6 = y6;
//     *out7 = y7;
// }

//130 gates - lwaes_isa
void Sm4_BoolFun(bits in, bit_t *out0, bit_t *out1, bit_t *out2, bit_t *out3, bit_t *out4, bit_t *out5, bit_t *out6, bit_t *out7){
        bit_t y_t[21], t_t[8], t_m[46], y_m[18], t_b[30];
  	    y_t[18] = in.b2 ^in.b6;
		t_t[ 0] = in.b3 ^in.b4;
		t_t[ 1] = in.b2 ^in.b7;
		t_t[ 2] = in.b7 ^y_t[18];
		t_t[ 3] = in.b1 ^t_t[ 1];
		t_t[ 4] = in.b6 ^in.b7;
		t_t[ 5] = in.b0 ^y_t[18];
		t_t[ 6] = in.b3 ^in.b6;
		y_t[10] = in.b1 ^y_t[18];
		y_t[ 0] = in.b5 ^~ y_t[10];
		y_t[ 1] = t_t[ 0] ^t_t[ 3];
		y_t[ 2] = in.b0 ^t_t[ 0];
		y_t[ 4] = in.b0 ^t_t[ 3];
		y_t[ 3] = in.b3 ^y_t[ 4];
		y_t[ 5] = in.b5 ^t_t[ 5];
		y_t[ 6] = in.b0 ^~ in.b1;
		y_t[ 7] = t_t[ 0] ^~ y_t[10];
		y_t[ 8] = t_t[ 0] ^t_t[ 5];
		y_t[ 9] = in.b3;
		y_t[11] = t_t[ 0] ^t_t[ 4];
		y_t[12] = in.b5 ^t_t[ 4];
		y_t[13] = in.b5 ^~ y_t[ 1];
		y_t[14] = in.b4 ^~ t_t[ 2];
		y_t[15] = in.b1 ^~ t_t[ 6];
		y_t[16] = in.b0 ^~ t_t[ 2];
		y_t[17] = t_t[ 0] ^~ t_t[ 2];
		y_t[19] = in.b5 ^~ y_t[14];
		y_t[20] = in.b0 ^t_t[ 1];

    //The shared non-linear middle part for AES, AES^-1, and SM4
  	t_m[ 0] = y_t[ 3] ^	 y_t[12];
		t_m[ 1] = y_t[ 9] &	 y_t[ 5];
		t_m[ 2] = y_t[17] &	 y_t[ 6];
		t_m[ 3] = y_t[10] ^	 t_m[ 1];
		t_m[ 4] = y_t[14] &	 y_t[ 0];
		t_m[ 5] = t_m[ 4] ^	 t_m[ 1];
		t_m[ 6] = y_t[ 3] &	 y_t[12];
		t_m[ 7] = y_t[16] &	 y_t[ 7];
		t_m[ 8] = t_m[ 0] ^	 t_m[ 6];
		t_m[ 9] = y_t[15] &	 y_t[13];
		t_m[10] = t_m[ 9] ^	 t_m[ 6];
		t_m[11] = y_t[ 1] &	 y_t[11];
		t_m[12] = y_t[ 4] &	 y_t[20];
		t_m[13] = t_m[12] ^	 t_m[11];
		t_m[14] = y_t[ 2] &	 y_t[ 8];
		t_m[15] = t_m[14] ^	 t_m[11];
		t_m[16] = t_m[ 3] ^	 t_m[ 2];
		t_m[17] = t_m[ 5] ^	 y_t[18];
		t_m[18] = t_m[ 8] ^	 t_m[ 7];
		t_m[19] = t_m[10] ^	 t_m[15];
		t_m[20] = t_m[16] ^	 t_m[13];
		t_m[21] = t_m[17] ^	 t_m[15];
		t_m[22] = t_m[18] ^	 t_m[13];
		t_m[23] = t_m[19] ^	 y_t[19];
		t_m[24] = t_m[22] ^	 t_m[23];
		t_m[25] = t_m[22] &	 t_m[20];
		t_m[26] = t_m[21] ^	 t_m[25];
		t_m[27] = t_m[20] ^	 t_m[21];
		t_m[28] = t_m[23] ^	 t_m[25];
		t_m[29] = t_m[28] &	 t_m[27];
		t_m[30] = t_m[26] &	 t_m[24];
		t_m[31] = t_m[20] &	 t_m[23];
		t_m[32] = t_m[27] &	 t_m[31];
		t_m[33] = t_m[27] ^	 t_m[25];
		t_m[34] = t_m[21] &	 t_m[22];
		t_m[35] = t_m[24] &	 t_m[34];
		t_m[36] = t_m[24] ^	 t_m[25];
		t_m[37] = t_m[21] ^	 t_m[29];
		t_m[38] = t_m[32] ^	 t_m[33];
		t_m[39] = t_m[23] ^	 t_m[30];
		t_m[40] = t_m[35] ^	 t_m[36];
		t_m[41] = t_m[38] ^	 t_m[40];
		t_m[42] = t_m[37] ^	 t_m[39];
		t_m[43] = t_m[37] ^	 t_m[38];
		t_m[44] = t_m[39] ^	 t_m[40];
		t_m[45] = t_m[42] ^	 t_m[41];
		y_m[ 0] = t_m[38] &	 y_t[ 7];
		y_m[ 1] = t_m[37] &	 y_t[13];
		y_m[ 2] = t_m[42] &	 y_t[11];
		y_m[ 3] = t_m[45] &	 y_t[20];
		y_m[ 4] = t_m[41] &	 y_t[ 8];
		y_m[ 5] = t_m[44] &	 y_t[ 9];
		y_m[ 6] = t_m[40] &	 y_t[17];
		y_m[ 7] = t_m[39] &	 y_t[14];
		y_m[ 8] = t_m[43] &	 y_t[ 3];
		y_m[ 9] = t_m[38] &	 y_t[16];
		y_m[10] = t_m[37] &	 y_t[15];
		y_m[11] = t_m[42] &	 y_t[ 1];
		y_m[12] = t_m[45] &	 y_t[ 4];
		y_m[13] = t_m[41] &	 y_t[ 2];
		y_m[14] = t_m[44] &	 y_t[ 5];
		y_m[15] = t_m[40] &	 y_t[ 6];
		y_m[16] = t_m[39] &	 y_t[ 0];
		y_m[17] = t_m[43] &	 y_t[12];

  //bottom(outer) linear layer for sm4
  	t_b[ 0] = y_m[ 4] ^	 y_m[ 7];
		t_b[ 1] = y_m[13] ^	 y_m[15];
		t_b[ 2] = y_m[ 2] ^	 y_m[16];
		t_b[ 3] = y_m[ 6] ^	 t_b[ 0];
		t_b[ 4] = y_m[12] ^	 t_b[ 1];
		t_b[ 5] = y_m[ 9] ^	 y_m[10];
		t_b[ 6] = y_m[11] ^	 t_b[ 2];
		t_b[ 7] = y_m[ 1] ^	 t_b[ 4];
		t_b[ 8] = y_m[ 0] ^	 y_m[17];
		t_b[ 9] = y_m[ 3] ^	 y_m[17];
		t_b[10] = y_m[ 8] ^	 t_b[ 3];
		t_b[11] = t_b[ 2] ^	 t_b[ 5];
		t_b[12] = y_m[14] ^	 t_b[ 6];
		t_b[13] = t_b[ 7] ^	 t_b[ 9];
		t_b[14] = y_m[ 0] ^	 y_m[ 6];
		t_b[15] = y_m[ 7] ^	 y_m[16];
		t_b[16] = y_m[ 5] ^	 y_m[13];
		t_b[17] = y_m[ 3] ^	 y_m[15];
		t_b[18] = y_m[10] ^	 y_m[12];
		t_b[19] = y_m[ 9] ^	 t_b[ 1];
		t_b[20] = y_m[ 4] ^	 t_b[ 4];
		t_b[21] = y_m[14] ^	 t_b[ 3];
		t_b[22] = y_m[16] ^	 t_b[ 5];
		t_b[23] = t_b[ 7] ^	 t_b[14];
		t_b[24] = t_b[ 8] ^	 t_b[11];
		t_b[25] = t_b[ 0] ^	 t_b[12];
		t_b[26] = t_b[17] ^	 t_b[ 3];
		t_b[27] = t_b[18] ^	 t_b[10];
		t_b[28] = t_b[19] ^	 t_b[ 6];
		t_b[29] = t_b[ 8] ^	 t_b[10];
		*out0 = t_b[11] ^~ t_b[13];
		*out1 = t_b[15] ^~ t_b[23];
		*out2 = t_b[20] ^	 t_b[24];
		*out3 = t_b[16] ^	 t_b[25];
		*out4 = t_b[26] ^~ t_b[22];
		*out5 = t_b[21] ^	 t_b[13];
		*out6 = t_b[27] ^~ t_b[12];
		*out7 = t_b[28] ^~ t_b[29];
}

//360 gates - selection function
// void Sm4_BoolFun(bits in, bit_t *out0, bit_t *out1, bit_t *out2, bit_t *out3, bit_t *out4, bit_t *out5, bit_t *out6, bit_t *out7) {
//   bit_t var8 = ~in.b7;
//   bit_t var9 = var8 | in.b6;
//   bit_t var10 = var9 & in.b5;
//   bit_t var11 = in.b2 ^ var10;
//   bit_t var12 = var11 | in.b0;
//   bit_t var13 = in.b6 ^ var12;
//   bit_t var14 = in.b7 & var11;
//   bit_t var15 = var14 | in.b0;
//   bit_t var16 = var10 ^ var15;
//   bit_t var17 = var16 & in.b4;
//   bit_t var18 = var13 ^ var17;
//   bit_t var19 = var18 ^ var8;
//   bit_t var20 = var19 | in.b5;
//   bit_t var21 = in.b7 ^ var20;
//   bit_t var22 = var18 | in.b7;
//   bit_t var23 = var22 ^ var15;
//   bit_t var24 = var23 | in.b4;
//   bit_t var25 = var21 ^ var24;
//   bit_t var26 = var25 | in.b2;
//   bit_t var27 = var18 ^ var26;
//   bit_t var28 = in.b7 ^ in.b2;
//   bit_t var29 = var28 & in.b4;
//   bit_t var30 = var27 ^ var29;
//   bit_t var31 = var18 | var28;
//   bit_t var32 = var31 ^ var25;
//   bit_t var33 = var32 & in.b5;
//   bit_t var34 = var30 ^ var33;
//   bit_t var35 = var8 & var32;
//   bit_t var36 = in.b6 ^ var9;
//   bit_t var37 = var36 | in.b2;
//   bit_t var38 = var35 ^ var37;
//   bit_t var39 = var38 | in.b0;
//   bit_t var40 = var34 ^ var39;
//   bit_t var41 = var40 & in.b1;
//   bit_t var42 = var27 ^ var41;
//   bit_t var43 = var10 & in.b6;
//   bit_t var44 = var43 ^ var40;
//   bit_t var45 = var26 & var19;
//   bit_t var46 = var45 | in.b4;
//   bit_t var47 = var44 ^ var46;
//   bit_t var48 = in.b0 ^ var24;
//   bit_t var49 = var48 ^ var44;
//   bit_t var50 = var48 & var47;
//   bit_t var51 = var50 & in.b7;
//   bit_t var52 = var49 ^ var51;
//   bit_t var53 = var52 & in.b1;
//   bit_t var54 = var47 ^ var53;
//   bit_t var55 = var42 & var9;
//   bit_t var56 = var55 ^ var39;
//   bit_t var57 = var53 ^ var43;
//   bit_t var58 = var57 & in.b4;
//   bit_t var59 = var56 ^ var58;
//   bit_t var60 = var59 & var25;
//   bit_t var61 = var60 ^ var13;
//   bit_t var62 = var8 | var59;
//   bit_t var63 = var62 ^ var30;
//   bit_t var64 = var63 & in.b1;
//   bit_t var65 = var61 ^ var64;
//   bit_t var66 = var65 & in.b0;
//   bit_t var67 = var59 ^ var66;
//   bit_t var68 = var67 & in.b2;
//   bit_t var69 = var54 ^ var68;
//   bit_t var70 = var69 & in.b3;
//   *out4 = var42 ^ var70;
//   bit_t var72 = in.b4 ^ var27;
//   bit_t var73 = in.b0 ^ var30;
//   bit_t var74 = var73 & in.b6;
//   bit_t var75 = var72 ^ var74;
//   bit_t var76 = var49 & *out4;
//   bit_t var77 = in.b7 ^ var69;
//   bit_t var78 = var77 ^ var36;
//   bit_t var79 = var78 | in.b4;
//   bit_t var80 = var76 ^ var79;
//   bit_t var81 = var80 | in.b5;
//   bit_t var82 = var75 ^ var81;
//   bit_t var83 = var69 & var53;
//   bit_t var84 = var83 ^ var13;
//   bit_t var85 = var75 & in.b2;
//   bit_t var86 = var84 ^ var85;
//   bit_t var87 = in.b6 ^ var8;
//   bit_t var88 = var39 ^ var53;
//   bit_t var89 = var88 | var65;
//   bit_t var90 = var89 & in.b5;
//   bit_t var91 = var87 ^ var90;
//   bit_t var92 = var91 & in.b4;
//   bit_t var93 = var86 ^ var92;
//   bit_t var94 = var93 | in.b3;
//   bit_t var95 = var82 ^ var94;
//   bit_t var96 = var75 & var63;
//   bit_t var97 = var96 | var92;
//   bit_t var98 = var97 | in.b2;
//   bit_t var99 = var69 ^ var98;
//   bit_t var100 = var12 & var19;
//   bit_t var101 = var100 ^ var84;
//   bit_t var102 = var101 | in.b2;
//   bit_t var103 = var66 ^ var102;
//   bit_t var104 = var103 & in.b3;
//   bit_t var105 = var99 ^ var104;
//   bit_t var106 = var67 & var104;
//   bit_t var107 = var106 ^ var19;
//   bit_t var108 = var107 | in.b6;
//   bit_t var109 = var35 ^ var108;
//   bit_t var110 = var31 & *out4;
//   bit_t var111 = var110 ^ in.b3;
//   bit_t var112 = var42 ^ var101;
//   bit_t var113 = var112 & in.b6;
//   bit_t var114 = var111 ^ var113;
//   bit_t var115 = var114 & in.b4;
//   bit_t var116 = var109 ^ var115;
//   bit_t var117 = var116 & in.b5;
//   bit_t var118 = var105 ^ var117;
//   bit_t var119 = var118 | in.b1;
//   *out6 = var95 ^ var119;
//   bit_t var121 = var117 ^ var63;
//   bit_t var122 = var121 & var108;
//   bit_t var123 = var49 | in.b4;
//   bit_t var124 = var122 ^ var123;
//   bit_t var125 = var93 ^ var98;
//   bit_t var126 = var97 ^ var34;
//   bit_t var127 = var126 | var60;
//   bit_t var128 = var127 | in.b4;
//   bit_t var129 = var125 ^ var128;
//   bit_t var130 = var129 & in.b3;
//   bit_t var131 = var124 ^ var130;
//   bit_t var132 = var81 ^ var78;
//   bit_t var133 = var36 ^ var35;
//   bit_t var134 = var133 | in.b4;
//   bit_t var135 = var132 ^ var134;
//   bit_t var136 = var119 | *out6;
//   bit_t var137 = var60 | var132;
//   bit_t var138 = var137 | in.b7;
//   bit_t var139 = var136 ^ var138;
//   bit_t var140 = var139 | in.b3;
//   bit_t var141 = var135 ^ var140;
//   bit_t var142 = var141 & in.b2;
//   bit_t var143 = var131 ^ var142;
//   bit_t var144 = var49 & var121;
//   bit_t var145 = ~var144;
//   bit_t var146 = var106 | var113;
//   bit_t var147 = var146 | in.b2;
//   bit_t var148 = var145 ^ var147;
//   bit_t var149 = var40 ^ var113;
//   bit_t var150 = var149 | in.b3;
//   bit_t var151 = var148 ^ var150;
//   bit_t var152 = var109 & var105;
//   bit_t var153 = var152 ^ var97;
//   bit_t var154 = var153 & in.b0;
//   bit_t var155 = var95 ^ var154;
//   bit_t var156 = var118 | var135;
//   bit_t var157 = var156 ^ var128;
//   bit_t var158 = var157 | in.b3;
//   bit_t var159 = var147 ^ var158;
//   bit_t var160 = var159 & in.b5;
//   bit_t var161 = var155 ^ var160;
//   bit_t var162 = var161 | in.b7;
//   bit_t var163 = var151 ^ var162;
//   bit_t var164 = var163 & in.b1;
//   *out7 = var143 ^ var164;
//   bit_t var166 = var115 & var82;
//   bit_t var167 = var166 ^ var77;
//   bit_t var168 = var156 ^ var60;
//   bit_t var169 = var168 | in.b2;
//   bit_t var170 = var167 ^ var169;
//   bit_t var171 = var152 & var115;
//   bit_t var172 = var171 ^ var65;
//   bit_t var173 = var172 & in.b1;
//   bit_t var174 = var170 ^ var173;
//   bit_t var175 = var87 ^ in.b4;
//   bit_t var176 = var175 ^ var139;
//   bit_t var177 = var61 & in.b1;
//   bit_t var178 = var176 ^ var177;
//   bit_t var179 = var49 & var37;
//   bit_t var180 = var179 ^ *out7;
//   bit_t var181 = var180 | in.b7;
//   bit_t var182 = var178 ^ var181;
//   bit_t var183 = var182 | in.b3;
//   bit_t var184 = var174 ^ var183;
//   bit_t var185 = var137 & var83;
//   bit_t var186 = ~var162;
//   bit_t var187 = var186 | var95;
//   bit_t var188 = var187 | in.b1;
//   bit_t var189 = var185 ^ var188;
//   bit_t var190 = var166 | var10;
//   bit_t var191 = var160 | var100;
//   bit_t var192 = var191 | in.b1;
//   bit_t var193 = var190 ^ var192;
//   bit_t var194 = var193 & in.b3;
//   bit_t var195 = var189 ^ var194;
//   bit_t var196 = var192 ^ var149;
//   bit_t var197 = var196 & var138;
//   bit_t var198 = ~var43;
//   bit_t var199 = var128 ^ var140;
//   bit_t var200 = var199 & in.b2;
//   bit_t var201 = var198 ^ var200;
//   bit_t var202 = var201 & in.b1;
//   bit_t var203 = var197 ^ var202;
//   bit_t var204 = var203 | in.b4;
//   bit_t var205 = var195 ^ var204;
//   bit_t var206 = var205 & in.b0;
//   *out2 = var184 ^ var206;
//   bit_t var208 = var200 ^ var29;
//   bit_t var209 = var61 | var30;
//   bit_t var210 = var209 | in.b5;
//   bit_t var211 = var208 ^ var210;
//   bit_t var212 = var168 & var132;
//   bit_t var213 = var212 ^ var205;
//   bit_t var214 = var213 | in.b1;
//   bit_t var215 = var211 ^ var214;
//   bit_t var216 = var136 ^ var32;
//   bit_t var217 = var164 | var196;
//   bit_t var218 = var217 & in.b0;
//   bit_t var219 = var216 ^ var218;
//   bit_t var220 = var96 & var214;
//   bit_t var221 = var220 | var54;
//   bit_t var222 = var158 ^ var176;
//   bit_t var223 = var222 & in.b0;
//   bit_t var224 = var221 ^ var223;
//   bit_t var225 = var224 & in.b4;
//   bit_t var226 = var219 ^ var225;
//   bit_t var227 = var226 | in.b6;
//   bit_t var228 = var215 ^ var227;
//   bit_t var229 = var146 | var172;
//   bit_t var230 = var229 & var215;
//   bit_t var231 = var164 | var80;
//   bit_t var232 = var231 ^ var228;
//   bit_t var233 = var93 & in.b4;
//   bit_t var234 = var232 ^ var233;
//   bit_t var235 = var234 & in.b5;
//   bit_t var236 = var230 ^ var235;
//   bit_t var237 = var234 | var124;
//   bit_t var238 = var237 ^ var131;
//   bit_t var239 = var223 ^ var127;
//   bit_t var240 = var191 ^ var197;
//   bit_t var241 = var240 & in.b1;
//   bit_t var242 = var239 ^ var241;
//   bit_t var243 = var242 & in.b4;
//   bit_t var244 = var238 ^ var243;
//   bit_t var245 = var244 & in.b6;
//   bit_t var246 = var236 ^ var245;
//   bit_t var247 = var246 & in.b3;
//   *out1 = var228 ^ var247;
//   bit_t var249 = var200 ^ var47;
//   bit_t var250 = var184 ^ var75;
//   bit_t var251 = var250 | in.b5;
//   bit_t var252 = var249 ^ var251;
//   bit_t var253 = var92 | var53;
//   bit_t var254 = var56 ^ var153;
//   bit_t var255 = var254 | in.b3;
//   bit_t var256 = var253 ^ var255;
//   bit_t var257 = var256 | in.b0;
//   bit_t var258 = var252 ^ var257;
//   bit_t var259 = var142 ^ var158;
//   bit_t var260 = var259 | var97;
//   bit_t var261 = var73 ^ var253;
//   bit_t var262 = var169 ^ var21;
//   bit_t var263 = var262 & in.b3;
//   bit_t var264 = var261 ^ var263;
//   bit_t var265 = var264 | in.b0;
//   bit_t var266 = var260 ^ var265;
//   bit_t var267 = var266 | in.b7;
//   bit_t var268 = var258 ^ var267;
//   bit_t var269 = var245 ^ var167;
//   bit_t var270 = var269 & in.b4;
//   bit_t var271 = in.b2 ^ var270;
//   bit_t var272 = var249 & var145;
//   bit_t var273 = var84 ^ var235;
//   bit_t var274 = var273 | in.b2;
//   bit_t var275 = var272 ^ var274;
//   bit_t var276 = var275 | in.b6;
//   bit_t var277 = var271 ^ var276;
//   bit_t var278 = var193 | var67;
//   bit_t var279 = var278 & var94;
//   bit_t var280 = *out4 | var278;
//   bit_t var281 = var280 ^ var237;
//   bit_t var282 = var70 | var48;
//   bit_t var283 = var282 | in.b2;
//   bit_t var284 = var281 ^ var283;
//   bit_t var285 = var284 & in.b6;
//   bit_t var286 = var279 ^ var285;
//   bit_t var287 = var286 & in.b0;
//   bit_t var288 = var277 ^ var287;
//   bit_t var289 = var288 | in.b1;
//   *out3 = var268 ^ var289;
//   bit_t var291 = in.b7 & var216;
//   bit_t var292 = var80 ^ var259;
//   bit_t var293 = var292 | in.b4;
//   bit_t var294 = var291 ^ var293;
//   bit_t var295 = var231 ^ var140;
//   bit_t var296 = var295 | var113;
//   bit_t var297 = var296 & in.b5;
//   bit_t var298 = var294 ^ var297;
//   bit_t var299 = var31 ^ var79;
//   bit_t var300 = var78 ^ var126;
//   bit_t var301 = var300 | in.b2;
//   bit_t var302 = var299 ^ var301;
//   bit_t var303 = var50 ^ var271;
//   bit_t var304 = var303 | in.b7;
//   bit_t var305 = var216 ^ var304;
//   bit_t var306 = var305 & in.b0;
//   bit_t var307 = var302 ^ var306;
//   bit_t var308 = var307 & in.b1;
//   bit_t var309 = var298 ^ var308;
//   bit_t var310 = var168 ^ var102;
//   bit_t var311 = var181 ^ var276;
//   bit_t var312 = var311 | in.b7;
//   bit_t var313 = var310 ^ var312;
//   bit_t var314 = var305 | var243;
//   bit_t var315 = var314 ^ var134;
//   bit_t var316 = var315 & in.b5;
//   bit_t var317 = var313 ^ var316;
//   bit_t var318 = var32 ^ var154;
//   bit_t var319 = var318 ^ var186;
//   bit_t var320 = var289 ^ var194;
//   bit_t var321 = var125 & in.b0;
//   bit_t var322 = var320 ^ var321;
//   bit_t var323 = var322 | in.b2;
//   bit_t var324 = var319 ^ var323;
//   bit_t var325 = var324 | in.b1;
//   bit_t var326 = var317 ^ var325;
//   bit_t var327 = var326 & in.b3;
//   *out5 = var309 ^ var327;
//   bit_t var329 = var122 ^ var115;
//   bit_t var330 = var140 | var299;
//   bit_t var331 = var330 & in.b7;
//   bit_t var332 = var329 ^ var331;
//   bit_t var333 = var115 ^ var250;
//   bit_t var334 = var236 & in.b0;
//   bit_t var335 = var333 ^ var334;
//   bit_t var336 = var335 & in.b3;
//   bit_t var337 = var332 ^ var336;
//   bit_t var338 = var266 ^ var164;
//   bit_t var339 = var70 ^ var239;
//   bit_t var340 = var339 | in.b5;
//   bit_t var341 = var338 ^ var340;
//   bit_t var342 = var88 ^ var242;
//   bit_t var343 = var342 | var98;
//   bit_t var344 = var343 | in.b7;
//   bit_t var345 = var341 ^ var344;
//   bit_t var346 = var345 & in.b1;
//   bit_t var347 = var337 ^ var346;
//   bit_t var348 = var295 ^ var74;
//   bit_t var349 = var348 ^ var268;
//   bit_t var350 = var59 ^ var157;
//   bit_t var351 = var347 ^ var262;
//   bit_t var352 = var351 | in.b7;
//   bit_t var353 = var350 ^ var352;
//   bit_t var354 = var353 & in.b1;
//   bit_t var355 = var349 ^ var354;
//   bit_t var356 = var115 ^ var15;
//   bit_t var357 = var356 | var126;
//   bit_t var358 = var193 ^ var286;
//   bit_t var359 = var25 ^ var260;
//   bit_t var360 = var359 & in.b0;
//   bit_t var361 = var358 ^ var360;
//   bit_t var362 = var361 | in.b1;
//   bit_t var363 = var357 ^ var362;
//   bit_t var364 = var363 & in.b3;
//   bit_t var365 = var355 ^ var364;
//   bit_t var366 = var365 & in.b2;
//   *out0 = var347 ^ var366;
// }
#ifndef _SSL_H_
#define _SSL_H_

#define u8    unsigned char
#define s8    char
#define s32   int
#define u32   unsigned int
#define s64   long
#define u64   unsigned long

#define RSANUMBYTES         256           /* 2048 bit key length */
#define RSANUMWORDS         (RSANUMBYTES / sizeof(u32))
#define SHA_DIGEST_SIZE     20

#endif

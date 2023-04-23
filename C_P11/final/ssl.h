#ifndef _SSL_H_
#define _SSL_H_

#include <openssl/sha.h>

#define u8    unsigned char
#define s8    char
#define s32   int
#define u32   unsigned int
#define s64   long
#define u64   unsigned long

#define RSANUMBYTES         256           /* 2048 bit key length */
#define RSANUMWORDS         (RSANUMBYTES / sizeof(u32))
#define SHA_DIGEST_SIZE     20
#define SIGN_KEY_ID_SIZE    4

typedef struct MC_RSAPublicKey {
    int len; /* Length of n[] in number of u32 */
    unsigned int n0inv; /* -1 / n[0] mod 2^32 */
    unsigned int n[RSANUMWORDS]; /* modulus as little endian array */
    unsigned int rr[RSANUMWORDS]; /* R^2 as little endian array */
} MC_RSAPublicKey;


int MC_RSA_verify(const MC_RSAPublicKey *key, const u8 *signature, const int len, const u8 *sha); 
void n_to_MC_RSAPublicKey(unsigned char* n_arr, int len, MC_RSAPublicKey *pkey); 
unsigned char *__base64_encode(const unsigned char *str, int length);
unsigned char *__base64_decode(const unsigned char *str, int length);

#endif

#ifndef _CRYPT_H_
#define _CRYPT_H_

#include <cryptoki.h>

//#define FALSE 0
//#define TRUE 1

#define NUM(a) (sizeof(a) / sizeof((a)[0]))

typedef unsigned char uchar;
typedef unsigned int uint;

extern CK_FUNCTION_LIST *gFunctionList;

void SAFE_FREE(void* ptr);

int nCipher_SEC_raw_rsa_sign(CK_SESSION_HANDLE hSession, uchar *hashVal, CK_ULONG hash_len, CK_OBJECT_HANDLE hPrK, uchar **sig, CK_ULONG *sig_len);
int nCipher_SEC_raw_rsa_verify(CK_SESSION_HANDLE hSession, uchar *hashVal, CK_ULONG hash_len, uchar *sig, CK_ULONG sig_len, CK_OBJECT_HANDLE hPuK);
#endif



#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "crypt.h"
#include "keyTemplate.h"

void SAFE_FREE(void* ptr)
{
	if(ptr != NULL)
		free(ptr);
	else
		fprintf(stderr, "[-] free is failed : mem indicates null pointer.!\n");
}

int nCipher_SEC_raw_rsa_sign(CK_SESSION_HANDLE hSession, uchar *hashVal, CK_ULONG hash_len, CK_OBJECT_HANDLE hPrK, uchar **sig, CK_ULONG *sig_len) {

  CK_ULONG rv;
  CK_MECHANISM rsa_sign_mech = {CKM_RSA_X_509, NULL_PTR, 0};

  rv = gFunctionList->C_SignInit(hSession, &rsa_sign_mech, hPrK);
  if (rv == CKR_OK) {
    rv = gFunctionList->C_Sign(hSession, hashVal, hash_len, NULL_PTR, sig_len);
    if (rv == CKR_OK) {

      *sig = (CK_BYTE*) malloc(sizeof(uchar)*(*sig_len));
      rv = gFunctionList->C_Sign(hSession, hashVal, hash_len, *sig, sig_len);
    }
  }

  if (rv == CKR_OK)
    return 1;

  return 0;
}


int nCipher_SEC_raw_rsa_verify(CK_SESSION_HANDLE hSession, uchar *hashVal, CK_ULONG hash_len, uchar *sig, CK_ULONG sig_len, CK_OBJECT_HANDLE hPuK) {

  CK_ULONG rv;
  CK_MECHANISM rsa_sign_mech = {CKM_RSA_X_509, NULL_PTR, 0};
  //CK_MECHANISM rsa_sign_mech = {CKM_RSA_PKCS, NULL_PTR, 0};

  rv = gFunctionList->C_VerifyInit(hSession, &rsa_sign_mech, hPuK);
  if (rv == CKR_OK) 
    rv = gFunctionList->C_Verify(hSession, hashVal, hash_len, sig, sig_len);

  if (rv == CKR_OK)
    return 1;

  return 0;
}

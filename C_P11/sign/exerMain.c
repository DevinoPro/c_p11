
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "crypt.h"
#include "ssl.h"


#define IMEI_KEY_NAME      "testkey2"
#define SW_CARD_LABEL      "TESTSWCARD"
#define SW_CARD_PROTECTION "TESTCARD"


#define SECURE_IMEI_ROOT_KEY        "secure_imei_root_key"
#define SECURE_IMEI_SIGNER_KEY      "secure_imei_signer_key"
#define SECURE_MSL_ROOT_KEY         "secure_msl_root_key"
#define SECURE_MSL_SIGNER_KEY       "secure_msl_signer_key"


CK_RV get_slot(int private_objects, int print_used, CK_SLOT_ID *hSlot);
CK_RV ocs_login(CK_SESSION_HANDLE hSession);
void binToHex(unsigned char* src, unsigned int	srcsz, char** dst);


const u8 padding[RSANUMBYTES - SHA_DIGEST_SIZE] = { 0x00, 0x01,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0x00, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
                               0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
                             };


CK_FUNCTION_LIST *gFunctionList;


void check_return_value(CK_RV rv, const char *msg) {

	if (rv != CKR_OK) {
		fprintf(stderr, "Error at %s: %u\n", msg, (unsigned int) rv);
		exit(EXIT_FAILURE);
	}
}

CK_SESSION_HANDLE start_session() {

  CK_SLOT_ID hSlot = 0;
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

  C_GetFunctionList(&gFunctionList);

  rv = gFunctionList->C_Initialize(NULL_PTR);
  check_return_value(rv, "initialize");

  int private_objects = 1;
  int print_used = 1;
  rv = get_slot(private_objects, print_used, &hSlot);
  check_return_value(rv, "get_slot");

  rv = gFunctionList->C_OpenSession(hSlot,
                                    CKF_RW_SESSION | CKF_SERIAL_SESSION,
                                    NULL, NULL,
                                    &hSession);
  
	check_return_value(rv, "open session");
    
        
     //login
    rv = ocs_login(hSession);
    if (rv != CKR_OK){
        fprintf(stderr, "Failed to login\n");
        return NULL ;
    }


    
	return hSession;
}

CK_OBJECT_HANDLE get_private_key_by_label(CK_SESSION_HANDLE hSession, char *sigKeyName){

  if (!sigKeyName)
    return NULL_PTR;

  CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
  CK_ULONG sigKeyLen = strlen(sigKeyName);
  CK_ATTRIBUTE sigKeyTemplate[] = {
      {CKA_CLASS, &keyClass, sizeof(keyClass)},
      {CKA_LABEL, sigKeyName, sigKeyLen}
  };

  CK_ULONG cnt = 0;
  CK_OBJECT_HANDLE pGetHandles[2];
  gFunctionList->C_FindObjectsInit(hSession, sigKeyTemplate, NUM(sigKeyTemplate));
  gFunctionList->C_FindObjects(hSession, pGetHandles, 2, &cnt);
  gFunctionList->C_FindObjectsFinal(hSession);

  if (cnt == 0) {
    fprintf(stderr, "cannot find the %s key object!\n", sigKeyName);
    return NULL_PTR;
  }
  else if (cnt > 1) {
    fprintf(stderr, "%s Label collision detected\n", sigKeyName);
    return NULL_PTR;
  }

  return pGetHandles[0];
}

CK_OBJECT_HANDLE get_public_key_by_label(CK_SESSION_HANDLE hSession, char *sigKeyName){

  if (!sigKeyName)
    return NULL_PTR;

  CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
  CK_ULONG sigKeyLen = strlen(sigKeyName);
  CK_ATTRIBUTE sigKeyTemplate[] = {
      {CKA_CLASS, &keyClass, sizeof(keyClass)},
      {CKA_LABEL, sigKeyName, sigKeyLen}
  };

  CK_ULONG cnt = 0;
  CK_OBJECT_HANDLE pGetHandles[2];
  gFunctionList->C_FindObjectsInit(hSession, sigKeyTemplate, NUM(sigKeyTemplate));
  gFunctionList->C_FindObjects(hSession, pGetHandles, 2, &cnt);
  gFunctionList->C_FindObjectsFinal(hSession);

  if (cnt == 0) {
    fprintf(stderr, "cannot find the %s key object!\n", sigKeyName);
    return NULL_PTR;
  }
  else if (cnt > 1) {
    fprintf(stderr, "%s Label collision detected\n", sigKeyName);
    return NULL_PTR;
  }

  return pGetHandles[0];
}

void sign_imei_data(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE key, uchar* data, CK_ULONG datalen, uchar** sig, CK_ULONG* siglen) {

  if (!hSession || !key || !data) {

    fprintf(stderr, "parameter cannot be NULL\n");
    exit(1);
  }

  uchar real_data[RSANUMBYTES];
  memcpy(real_data, padding, RSANUMBYTES - SHA_DIGEST_SIZE);
  memcpy(real_data + RSANUMBYTES - SHA_DIGEST_SIZE, data, SHA_DIGEST_SIZE);

  int ret = nCipher_SEC_raw_rsa_sign(hSession, real_data, RSANUMBYTES, key, sig, siglen);
  if (ret != 1) { 
    fprintf(stderr, "Failed to Signing\n");
    exit(1);
  }
}

int verify_imei_data(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE key, uchar* data, int datalen, uchar* sig, int siglen) {

  if (!hSession || !key || !data || !sig) {

    fprintf(stderr, "parameter cannot be NULL\n");
    exit(1);
  }

  uchar real_data[RSANUMBYTES];
  memcpy(real_data, padding, RSANUMBYTES - SHA_DIGEST_SIZE);
  memcpy(real_data + RSANUMBYTES - SHA_DIGEST_SIZE, data, SHA_DIGEST_SIZE);

    
  return nCipher_SEC_raw_rsa_verify(hSession, real_data, RSANUMBYTES, sig, siglen, key);
}

void print_hex_value(const char *label, uchar* data, int datalen) {

  printf("%s = ", label);
  for (int i=0; i<datalen; i++) {
    
    fprintf(stdout, "%02X", data[i]);
  }
  fprintf(stdout, "\n");
}

int main(int argc, char** argv) {

  // 싸인되는 데이터 값 (서버에 올라오는 sha1 digest)
  unsigned char hex_data[SHA_DIGEST_SIZE] = {0xb1, 0xcc, 0x31, 0x1c, 0x38, 0xd2, 0x5d, 0x7c, 0xd3, 0x86, 
                                             0x7a, 0x3b, 0x83, 0x5d, 0xe4, 0x09, 0x07, 0x52, 0x17, 0x0b};

  CK_SESSION_HANDLE hSession;
  hSession = start_session();

  if (!hSession) {

    fprintf(stderr, "session has null value");
    exit(1);
  }
  
  uchar *sig;
  CK_ULONG siglen;

  // print signed data to hex value  
  print_hex_value("target data to be signed", hex_data, SHA_DIGEST_SIZE);
  

  // sign hex data with IMEI_KEY
  CK_OBJECT_HANDLE skey = get_private_key_by_label(hSession, IMEI_KEY_NAME);
  if (!skey) {

    fprintf(stderr, "cannot get private key value");
    exit(1);
  }
  sign_imei_data(hSession, skey, hex_data, SHA_DIGEST_SIZE, &sig, &siglen);

  // verify signed data with IMEI_KEY
  CK_OBJECT_HANDLE pkey = get_public_key_by_label(hSession, IMEI_KEY_NAME);
  if (!pkey) {

    fprintf(stderr, "cannot get public key value");
    exit(1);
  }
  
  if (verify_imei_data(hSession, pkey, hex_data, SHA_DIGEST_SIZE, sig, siglen) == 1) {

    fprintf(stdout, "verify success !!\n");
  }
  else {
    fprintf(stderr, "failed to verify !!\n");
  }

  // print signed data to hex value  
  print_hex_value("signed imei hex data", sig, siglen);

  return 0;
}

CK_RV get_slot(int private_objects, int print_used, CK_SLOT_ID *hSlot) {
	CK_ULONG i, islot, nslots = 0;
	CK_SLOT_ID_PTR pslots = NULL;
	CK_RV rv;
	CK_TOKEN_INFO tinfo;
	char label_padded[32]; /* same size as tinfo.label */

	// Get OCS Name
    char *label = strdup(SW_CARD_LABEL);
	// char *label = (char*)calloc(sizeof(tinfo.label), sizeof(char));
	// if (private_objects) {
		// printf("Input OCS NAME: ");
		// if(fgets(label, sizeof(tinfo.label), stdin) == NULL_PTR)
			// return CK_FALSE;
		// fputc('\n', stdin);
		// short lasti = strlen(label);
		// label[lasti-1] = '\0';
	// }

	assert(sizeof(tinfo.label) == sizeof(label_padded));
	if (label) {
		if (strlen(label) > sizeof(tinfo.label)) {
			fprintf(stderr, "Label can only be %ld chars long",
					(long)sizeof(label_padded));
			return CKR_ARGUMENTS_BAD;
		}
		memset(label_padded, ' ', sizeof(label_padded));
		memcpy(label_padded, label, strlen(label));
	}

	rv = gFunctionList->C_GetSlotList(0, NULL_PTR, &nslots);
	if (rv != CKR_OK) goto err;
	if (nslots == 0) {
		rv = CKR_TOKEN_NOT_PRESENT;
		goto err;
	}

	pslots = malloc(sizeof(CK_SLOT_ID) * nslots);
	if (!pslots) {
		fprintf(stderr, "failed to malloc %ld slotIDs", nslots);
		rv = CKR_HOST_MEMORY; goto err;
	}
	rv = gFunctionList->C_GetSlotList(1, pslots, &nslots);
	if (rv != CKR_OK) goto err;

	if(private_objects == 0){
		*hSlot = pslots[0];
		goto err;
	}


	for (islot = 0; islot < nslots; islot++) {
		rv = gFunctionList->C_GetTokenInfo(pslots[islot], &tinfo);

		if (rv == CKR_TOKEN_NOT_PRESENT) {
			/* Could have been removed since the C_GetSlotList call. */
			continue;
		}

		if (rv != CKR_OK) goto err;

		if (private_objects &&
				!(tinfo.flags & CKF_USER_PIN_INITIALIZED))
			continue;

		if (label &&
				strncmp(label_padded,
						(char *)tinfo.label,
						sizeof(tinfo.label)))
			continue;

		if (print_used) {
			/* islot not very meaningful with tokenPresent used */
			printf("Using token with label \"");
			for (i = 0; i < sizeof(tinfo.label); i++)
				printf("%c", tinfo.label[i]);
			printf("\"\n");
		}

		break;
	}
	if (islot < nslots) {
		rv = CKR_OK;
		*hSlot = pslots[islot];
	} else
		rv = CKR_TOKEN_NOT_PRESENT;

err:
	SAFE_FREE(label);
	SAFE_FREE(pslots);
	return rv;
}

CK_RV ocs_login(CK_SESSION_HANDLE hSession) {
	CK_RV rv = CK_TRUE;
    char *passphrase = strdup(SW_CARD_PROTECTION);//(char*)calloc(20, sizeof(char));

    
	// char *passphrase = (char*)calloc(20, sizeof(char));

	// printf("Input Password: ");
	// if(fgets(passphrase, 20, stdin) == NULL_PTR)
		// return CK_FALSE;

	// fputc('\n', stdin);

	// short lasti = strlen(passphrase);
	// passphrase[lasti-1] = '\0';

	if (passphrase != NULL_PTR)
		rv = C_Login(hSession, CKU_USER,
				(CK_UTF8CHAR*)passphrase, (CK_ULONG)strlen((char *)passphrase));

	SAFE_FREE(passphrase);

	return rv;
}


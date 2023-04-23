
#include "ssl.h"

#include <string.h>

#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>


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



/* a[] -= mod */
static void subM(const MC_RSAPublicKey *key, u32 *a)
{
  s64 A = (s64)0;
  s32 i;
  for (i = 0; i < key->len; ++i)
  {
    A += (u64)a[i] - (u64)key->n[i];
    a[i] = (u32) A;
    A = (A >> 32);
  }
}

/* return a[] >= mod */
static s32 geM(const MC_RSAPublicKey *key, const u32 *a)
{
  s32 i;
  for (i = key->len; i;)
  {
    --i;
    if (a[i] < key->n[i])
    {
      return 0;
    }
    if (a[i] > key->n[i])
    {
      return 1;
    }
  }
  return 1; /* equal */
}

/* montgomery c[] += a * b[] / R % mod */
static void montMulAdd(const MC_RSAPublicKey *key, u32* c, const u32 a,
             const u32* b)
{
  u64 A = (u64)a * (u64)b[0] + (u64)c[0];
  u32 d0 = (u32)( A * (u64)key->n0inv);
  u64 B = (u64)(d0) * (u64)(key->n[0]) + (u64)((u32)A);
  s32 i;

  for (i = 1; i < key->len; ++i)
  {
    A = (u64)(A >> 32) + (u64)(a) * (u64) b[i] + (u64)c[i];
    B = (u64)(B >> 32) + (u64)(d0) * (u64)(key->n[i]) + (u64)((u32) A);
    c[i - 1] = (u32) B;
  }

  A = (u64)(A >> 32) + (u64)(B >> 32);

  c[i - 1] = (u32) A;

  if ((u32)(A >> 32))
  {
    subM(key, c);
  }
}

/* montgomery c[] = a[] * b[] / R % mod */
static void montMul(const MC_RSAPublicKey *key, u32* c, const u32* a,
          const u32* b)
{
  s32 i;
  for (i = 0; i < key->len; ++i)
  {
    c[i] = 0;
  } 
  for (i = 0; i < key->len; ++i)
  {
    montMulAdd(key, c, a[i], b);
  }
}

/* In-place public exponentiation.
 ** Input and output big-endian byte array in inout.
 */
static void modpow3(const MC_RSAPublicKey *key, u8* inout)
{
  u32 a[RSANUMWORDS];
  u32 aR[RSANUMWORDS];
  u32 aaR[RSANUMWORDS];
  u32 *aaa = aR; /* Re-use location. */
  s32 i;

  /* Convert from big endian byte array to little endian word array. */
  for (i = 0; i < key->len; ++i)
  {
    u32 tmp = (inout[((key->len - 1 - i) * 4) + 0] << 24)
          | (inout[((key->len - 1 - i) * 4) + 1] << 16)
          | (inout[((key->len - 1 - i) * 4) + 2] << 8)
          | (inout[((key->len - 1 - i) * 4) + 3] << 0);
    a[i] = tmp;
  }

  montMul(key, aR, a, key->rr); /* aR = a * RR / R mod M   */
  montMul(key, aaR, aR, aR); /* aaR = aR * aR / R mod M */
  montMul(key, aaa, aaR, a); /* aaa = aaR * a / R mod M */

  /* Make sure aaa < mod; aaa is at most 1x mod too large. */
  if (geM(key, aaa))
  {
    subM(key, aaa);
  }

  /* Convert to bigendian byte array */
  for (i = key->len - 1; i >= 0; --i)
  {
    u32 tmp = aaa[i];
    *inout++ = tmp >> 24;
    *inout++ = tmp >> 16;
    *inout++ = tmp >> 8;
    *inout++ = tmp >> 0;
  }
}

int MC_RSA_verify(const MC_RSAPublicKey *key, const u8 *signature,
          const int len, const u8 *sha) {
  u8 buf[RSANUMBYTES];
  int i;

  if (key->len != RSANUMWORDS)
    return 0; /* Wrong key passed in. */

  if (len != sizeof(buf))
    return 0; /* Wrong input length. */


  for (i = 0; i < len; ++i)
    buf[i] = signature[i];

  modpow3(key, buf);

  printf("[+] DECRYPTED SIG DATA :: ");
  for (int j=0; j<len; j++) {
    printf("%02x", buf[j]);
  }
  printf("\n");

  /* Check pkcs1.5 padding bytes. */
  for (i = 0; i < (int) sizeof(padding); ++i)
  {
    if (buf[i] != padding[i])
    {
      printf("[-] MC_RSA_verify :: padding check failed\n");
      return 0;
    }
  }

  printf("[+] DECRYPTED HASH :: ");
  for (int j = (int) sizeof(padding); j < len; j++) {
    printf("%02x", buf[j]);
  }
  printf("\n");

  printf("[+] PARAMETER HASH :: ");
  for (int j = 0; j < SHA_DIGEST_SIZE; j++) {
    printf("%02x", sha[j]);
  }
  printf("\n");

  /* Check sha digest matches. */
  for (; i < len; ++i)
  {
    if (buf[i] != *sha++)
    {
      printf("[-] MC_RSA_verify :: wrong hash value\n");
      return 0;
    }
  }

  return 1;
}

void n_to_MC_RSAPublicKey(unsigned char* n_arr, int len, MC_RSAPublicKey *pkey){

  unsigned int i;

  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* r32 = BN_new();
  BIGNUM* rr = BN_new();
  BIGNUM* r = BN_new();
  BIGNUM* rem = BN_new();
  BIGNUM* n = BN_new();
  BIGNUM* n0inv = BN_new();

  BN_set_bit(r32, 32);

  n = BN_bin2bn(n_arr, len, n);

  BN_set_bit(r, RSANUMWORDS * 32);
  BN_mod_sqr(rr, r, n, ctx);
  BN_div(NULL, rem, n, r32, ctx);
  BN_mod_inverse(n0inv, rem, r32, ctx);

  pkey->len = RSANUMWORDS;
  pkey->n0inv = 0 - BN_get_word(n0inv);
  for (i = 0; i < RSANUMWORDS; i++) {

    BN_div(rr, rem, rr, r32, ctx);
    pkey->rr[i] = BN_get_word(rem);
    BN_div(n, rem, n, r32, ctx);
    pkey->n[i] = BN_get_word(rem);
  }

  BN_free(n0inv);
  BN_free(n);
  BN_free(rem);
  BN_free(r);
  BN_free(rr);
  BN_free(r32);
  BN_CTX_free(ctx);
}

// BASE64
static char __base64_table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '\0'
};

static char __base64_pad = '=';

unsigned char *__base64_encode(const unsigned char *str, int length) {
	const unsigned char *current = str;
	int i = 0;
	unsigned char *result = (unsigned char *)malloc(((length + 3 - length % 3) * 4 / 3 + 1) * sizeof(char));

	while (length > 2) { /* keep going until we have less than 24 bits */
		result[i++] = __base64_table[current[0] >> 2];
		result[i++] = __base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
		result[i++] = __base64_table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
		result[i++] = __base64_table[current[2] & 0x3f];

		current += 3;
		length -= 3; /* we just handle 3 octets of data */
	}

	/* now deal with the tail end of things */
	if (length != 0) {
		result[i++] = __base64_table[current[0] >> 2];
		if (length > 1) {
			result[i++] = __base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
			result[i++] = __base64_table[(current[1] & 0x0f) << 2];
			result[i++] = __base64_pad;
		}
		else {
			result[i++] = __base64_table[(current[0] & 0x03) << 4];
			result[i++] = __base64_pad;
			result[i++] = __base64_pad;
		}
	}

	result[i] = '\0';
	return result;
}

/* as above, but backwards. :) */
unsigned char *__base64_decode(const unsigned char *str, int length) {
	const unsigned char *current = str;
	int ch, i = 0, j = 0, k;
	/* this sucks for threaded environments */
	static short reverse_table[256];
	static int table_built;
	unsigned char *result;

	if (++table_built == 1) {
		char *chp;
		for (ch = 0; ch < 256; ch++) {
			chp = strchr(__base64_table, ch);
			if (chp) {
				reverse_table[ch] = chp - __base64_table;
			}
			else {
				reverse_table[ch] = -1;
			}
		}
	}

	result = (unsigned char *)malloc(length + 1);
	if (result == NULL) {
		return NULL;
	}

	/* run through the whole string, converting as we go */
	while ((ch = *current++) != '\0') {
		if (ch == __base64_pad) break;

		/* When Base64 gets POSTed, all pluses are interpreted as spaces.
		This line changes them back.  It's not exactly the Base64 spec,
		but it is completely compatible with it (the spec says that
		spaces are invalid).  This will also save many people considerable
		headache.  - Turadg Aleahmad <turadg@wise.berkeley.edu>
		*/

		if (ch == ' ') ch = '+';

		ch = reverse_table[ch];
		if (ch < 0) continue;

		switch (i % 4) {
		case 0:
			result[j] = ch << 2;
			break;
		case 1:
			result[j++] |= ch >> 4;
			result[j] = (ch & 0x0f) << 4;
			break;
		case 2:
			result[j++] |= ch >> 2;
			result[j] = (ch & 0x03) << 6;
			break;
		case 3:
			result[j++] |= ch;
			break;
		}
		i++;
	}

	k = j;
	/* mop things up if we ended on a boundary */
	if (ch == __base64_pad) {
		switch (i % 4) {
		case 0:
		case 1:
			free(result);
			return NULL;
		case 2:
			k++;
		case 3:
			result[k++] = 0;
		}
	}

	result[k] = '\0';
	return result;
}

/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <malloc.h>
#include <time.h>

#include "xtest_test.h"
#include "xtest_helpers.h"

#include <tee_api_types.h>
#include <tee_api_defines_extensions.h>
#include <ta_crypt.h>
#include <utee_defines.h>
#include <util.h>

#include <nist/186-2ecdsatestvectors.h>

#include <assert.h>

#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/nid.h>
#include <openssl/objects.h>
#include <openssl/crypto.h>

static TEEC_Result ta_crypt_cmd_digest_do_final(ADBG_Case_t *c, TEEC_Session *s,
						TEE_OperationHandle oph,
						const void *chunk,
						size_t chunk_len, void *hash,
						size_t *hash_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)chunk;
	op.params[1].tmpref.size = chunk_len;

	op.params[2].tmpref.buffer = (void *)hash;
	op.params[2].tmpref.size = *hash_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_DIGEST_DO_FINAL, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*hash_len = op.params[2].tmpref.size;

	return res;
}

static TEEC_Result ta_crypt_cmd_asymmetric_operate(ADBG_Case_t *c,
						   TEEC_Session *s,
						   TEE_OperationHandle oph,
						   uint32_t cmd,
						   const TEE_Attribute *params,
						   uint32_t paramCount,
						   const void *src,
						   size_t src_len,
						   void *dst,
						   size_t *dst_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	uint8_t *buf = NULL;
	size_t blen = 0;

	res = pack_attrs(params, paramCount, &buf, &blen);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return res;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = blen;

	op.params[2].tmpref.buffer = (void *)src;
	op.params[2].tmpref.size = src_len;

	op.params[3].tmpref.buffer = dst;
	op.params[3].tmpref.size = *dst_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT);

	res = TEEC_InvokeCommand(s, cmd, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*dst_len = op.params[3].tmpref.size;

	free(buf);
	return res;
}

static TEEC_Result ta_crypt_cmd_asymmetric_sign(ADBG_Case_t *c,
						TEEC_Session *s,
						TEE_OperationHandle oph,
						const TEE_Attribute *params,
						uint32_t paramCount,
						const void *digest,
						size_t digest_len,
						void *signature,
						size_t *signature_len)
{
	return ta_crypt_cmd_asymmetric_operate(c, s, oph,
			TA_CRYPT_CMD_ASYMMETRIC_SIGN_DIGEST, params, paramCount,
			digest, digest_len, signature, signature_len);
}

static TEEC_Result ta_crypt_cmd_asymmetric_verify(ADBG_Case_t *c,
						  TEEC_Session *s,
						  TEE_OperationHandle oph,
						  const TEE_Attribute *params,
						  uint32_t paramCount,
						  const void *digest,
						  size_t digest_len,
						  const void *signature,
						  size_t signature_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	uint8_t *buf = NULL;
	size_t blen = 0;

	res = pack_attrs(params, paramCount, &buf, &blen);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return res;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = blen;

	op.params[2].tmpref.buffer = (void *)digest;
	op.params[2].tmpref.size = digest_len;

	op.params[3].tmpref.buffer = (void *)signature;
	op.params[3].tmpref.size = signature_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_ASYMMETRIC_VERIFY_DIGEST,
				 &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	free(buf);
	return res;
}

struct xtest_ac_case {
	unsigned int level;
	uint32_t algo;
	TEE_OperationMode mode;
	uint32_t hash_algo;

	union {
		struct {
			const uint8_t *private;
			size_t private_len;
			const uint8_t *public_x;
			size_t public_x_len;
			const uint8_t *public_y;
			size_t public_y_len;
		} ecdsa;
	} params;

	const uint8_t *ptx;
	size_t ptx_len;
	size_t line;
};

#define WITHOUT_SALT(x) -1
#define WITH_SALT(x)    x

#define ARRAY(a)            a, ARRAY_SIZE(a)
#define NULL_ARRAY(a)       NULL, 0

#define XTEST_AC_CASE(level, algo, mode, hash_algo, vect, union_params) \
	{ level, (algo), (mode), (hash_algo), .params = union_params, \
	  ARRAY(vect ## _ptx), \
	  __LINE__ }

#define XTEST_AC_ECDSA_UNION(vect) \
	{ .ecdsa = { \
		  ARRAY(vect ## _private), \
		  ARRAY(vect ## _public_x), \
		  ARRAY(vect ## _public_y), \
	  } }

#define XTEST_AC_ECDSA_CASE(level, algo, mode, hash_algo, vect) \
	XTEST_AC_CASE(level, algo, mode, hash_algo, vect, XTEST_AC_ECDSA_UNION(vect))

static const uint8_t vts_ecdsa_521_testvector_ptx[] = {
/* Msg */
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
};
static const uint8_t vts_ecdsa_521_testvector_private[] = {
/* d */
	0x00, 0x11, 0x45, 0x8c, 0x58, 0x6d, 0xb5, 0xda, 0xa9, 0x2a, 0xfa, 0xb0, 0x3f, 0x4f, 0xe4, 0x6a, 0xa9,
	0xd9, 0xc3, 0xce, 0x9a, 0x9b, 0x7a, 0x00, 0x6a, 0x83, 0x84, 0xbe, 0xc4, 0xc7, 0x8e, 0x8e, 0x9d, 
	0x18, 0xd7, 0xd0, 0x8b, 0x5b, 0xcf, 0xa0, 0xe5, 0x3c, 0x75, 0xb0, 0x64, 0xad, 0x51, 0xc4, 0x49, 
	0xba, 0xe0, 0x25, 0x8d, 0x54, 0xb9, 0x4b, 0x1e, 0x88, 0x5d, 0xed, 0x08, 0xed, 0x4f, 0xb2, 0x5c, 
	0xe9
};
static const uint8_t vts_ecdsa_521_testvector_public_x[] = {
/* Qx */
	0x01, 0x49, 0xec, 0x11, 0xc6, 0xdf, 0x0f, 0xa1, 0x22, 0xc6, 0xa9, 0xaf, 0xd9, 0x75, 0x4a, 0x4f, 
	0xa9, 0x51, 0x3a, 0x62, 0x7c, 0xa3, 0x29, 0xe3, 0x49, 0x53, 0x5a, 0x56, 0x29, 0x87, 0x5a, 0x8a, 
	0xdf, 0xbe, 0x27, 0xdc, 0xb9, 0x32, 0xc0, 0x51, 0x98, 0x63, 0x77, 0x10, 0x8d, 0x05, 0x4c, 0x28, 
	0xc6, 0xf3, 0x9b, 0x6f, 0x2c, 0x9a, 0xf8, 0x18, 0x02, 0xf9, 0xf3, 0x26, 0xb8, 0x42, 0xff, 0x2e, 
	0x5f, 0x3c, 
};
static const uint8_t vts_ecdsa_521_testvector_public_y[] = {
/* Qy */
	0x00, 0xab, 0x76, 0x35, 0xcf, 0xb3, 0x61, 0x57, 0xfc, 0x08, 0x82, 0xd5, 0x74, 0xa1, 0x0d, 0x83, 0x9c, 
	0x1a, 0x0c, 0x04, 0x9d, 0xc5, 0xe0, 0xd7, 0x75, 0xe2, 0xee, 0x50, 0x67, 0x1a, 0x20, 0x84, 0x31, 
	0xbb, 0x45, 0xe7, 0x8e, 0x70, 0xbe, 0xfe, 0x93, 0x0d, 0xb3, 0x48, 0x18, 0xee, 0x4d, 0x5c, 0x26, 
	0x25, 0x9f, 0x5c, 0x6b, 0x8e, 0x28, 0xa6, 0x52, 0x95, 0x0f, 0x9f, 0x88, 0xd7, 0xb4, 0xb2, 0xc9, 
	0xd9, 
};

static const uint8_t vts_ecdsa_256_testvector_ptx[] = {
/* Msg */
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
};
static const uint8_t vts_ecdsa_256_testvector_private[] = {
/* d */
	0x73, 0x7c, 0x2e, 0xcd, 0x7b, 0x8d, 0x19, 0x40, 0xbf, 0x29, 0x30, 0xaa, 0x9b, 0x4e, 0xd3, 0xff, 
	0x94, 0x1e, 0xed, 0x09, 0x36, 0x6b, 0xc0, 0x32, 0x99, 0x98, 0x64, 0x81, 0xf3, 0xa4, 0xd8, 0x59, 
};
static const uint8_t vts_ecdsa_256_testvector_public_x[] = {
/* Qx */
	0xbf, 0x85, 0xd7, 0x72, 0x0d, 0x07, 0xc2, 0x54, 0x61, 0x68, 0x3b, 0xc6, 0x48, 0xb4, 0x77, 0x8a, 
	0x9a, 0x14, 0xdd, 0x8a, 0x02, 0x4e, 0x3b, 0xdd, 0x8c, 0x7d, 0xdd, 0x9a, 0xb2, 0xb5, 0x28, 0xbb, 
};
static const uint8_t vts_ecdsa_256_testvector_public_y[] = {
/* Qy */
	0xc7, 0xaa, 0x1b, 0x51, 0xf1, 0x4e, 0xbb, 0xbb, 0x0b, 0xd0, 0xce, 0x21, 0xbc, 0xc4, 0x1c, 0x6e, 
	0xb0, 0x00, 0x83, 0xcf, 0x33, 0x76, 0xd1, 0x1f, 0xd4, 0x49, 0x49, 0xe0, 0xb2, 0x18, 0x3b, 0xfe, 
};

static const struct xtest_ac_case xtest_ac_cases[] = {
	/* ECDSA tests */
	/* From VTS test case */
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    vts_ecdsa_256_testvector),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    vts_ecdsa_256_testvector),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    vts_ecdsa_256_testvector),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    vts_ecdsa_256_testvector),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    vts_ecdsa_256_testvector),

	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    vts_ecdsa_521_testvector),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    vts_ecdsa_521_testvector),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    vts_ecdsa_521_testvector),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    vts_ecdsa_521_testvector),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    vts_ecdsa_521_testvector),

	/* [P-224] */
	/* SHA1 hash */
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_16),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_17),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_18),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_19),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_20),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_21),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_22),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_23),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_24),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_25),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_26),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_27),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_28),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_29),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_30),


	/* [P-224] */
	/* SHA224 hash */
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_16),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_17),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_18),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_19),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_20),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_21),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_22),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_23),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_24),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_25),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_26),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_27),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_28),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_29),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_30),

	/* [P-224] */
	/* SHA256 hash */
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_16),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_17),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_18),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_19),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_20),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_21),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_22),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_23),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_24),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_25),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_26),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_27),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_28),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_29),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_30),

	/* [P-224] */
	/* SHA384 hash */
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_16),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_17),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_18),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_19),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_20),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_21),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_22),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_23),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_24),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_25),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_26),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_27),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_28),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_29),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_30),

	/* [P-224] */
	/* SHA512 hash */
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_16),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_17),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_18),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_19),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_20),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_21),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_22),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_23),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_24),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_25),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_26),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_27),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_28),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_29),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_30),

	/* [P-256] */
	/* SHA1 hash */
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_31),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_32),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_33),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_34),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_35),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_36),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_37),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_38),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_39),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_40),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_41),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_42),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_43),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_44),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_45),

	/* [P-256] */
	/* SHA224 hash */
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_31),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_32),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_33),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_34),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_35),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_36),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_37),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_38),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_39),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_40),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_41),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_42),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_43),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_44),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_45),

	/* [P-256] */
	/* SHA256 hash */
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_31),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_32),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_33),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_34),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_35),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_36),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_37),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_38),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_39),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_40),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_41),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_42),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_43),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_44),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_45),

	/* [P-256] */
	/* SHA384 hash */
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_31),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_32),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_33),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_34),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_35),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_36),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_37),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_38),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_39),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_40),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_41),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_42),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_43),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_44),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_45),

	/* [P-256] */
	/* SHA512 hash */
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_31),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_32),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_33),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_34),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_35),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_36),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_37),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_38),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_39),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_40),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_41),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_42),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_43),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_44),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_45),

	/* [P-384] */
	/* SHA1 hash */
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_46),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_47),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_48),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_49),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_50),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_51),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_52),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_53),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_54),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_55),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_56),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_57),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_58),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_59),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_60),

	/* [P-384] */
	/* SHA224 hash */
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_46),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_47),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_48),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_49),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_50),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_51),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_52),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_53),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_54),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_55),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_56),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_57),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_58),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_59),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_60),

	/* [P-384] */
	/* SHA256 hash */
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_46),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_47),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_48),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_49),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_50),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_51),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_52),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_53),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_54),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_55),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_56),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_57),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_58),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_59),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_60),

	/* [P-384] */
	/* SHA384 hash */
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_46),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_47),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_48),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_49),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_50),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_51),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_52),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_53),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_54),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_55),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_56),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_57),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_58),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_59),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_60),

	/* [P-384] */
	/* SHA512 hash */
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_46),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_47),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_48),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_49),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_50),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_51),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_52),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_53),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_54),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_55),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_56),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_57),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_58),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_59),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_60),

	/* [P-521] */
	/* SHA1 hash */
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_61),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_62),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_63),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_64),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_65),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_66),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_67),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_68),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_69),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_70),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_71),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_72),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_73),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_74),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_75),

	/* [P-521] */
	/* SHA224 hash */
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_61),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_62),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_63),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_64),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_65),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_66),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_67),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_68),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_69),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_70),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_71),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_72),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_73),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_74),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_75),

	/* [P-521] */
	/* SHA256 hash */
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_61),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_62),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_63),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_64),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_65),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_66),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_67),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_68),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_69),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_70),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_71),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_72),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_73),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_74),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_75),

	/* [P-521] */
	/* SHA384 hash */
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_61),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_62),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_63),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_64),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_65),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_66),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_67),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_68),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_69),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_70),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_71),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_72),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_73),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_74),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_75),

	/* [P-521] */
	/* SHA512 hash */
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_61),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_62),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_63),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_64),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_65),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_66),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_67),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_68),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_69),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_70),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_71),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_72),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_73),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_74),
	XTEST_AC_ECDSA_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_75),

};

static bool create_key(ADBG_Case_t *c, TEEC_Session *s,
		       uint32_t max_key_size, uint32_t key_type,
		       TEE_Attribute *attrs, size_t num_attrs,
		       TEE_ObjectHandle *handle)
{
	size_t n = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_transient_object(c, s, key_type,
			max_key_size, handle)))
		return false;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_populate_transient_object(c, s, *handle, attrs,
			num_attrs)))
		return false;

	for (n = 0; n < num_attrs; n++) {
		uint8_t out[512] = { };
		size_t out_size = sizeof(out);

		if (attrs[n].attributeID == TEE_ATTR_ECC_CURVE)
			continue;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_get_object_buffer_attribute(c, s, *handle,
				attrs[n].attributeID, out, &out_size)))
			return false;

		if (out_size < attrs[n].content.ref.length) {
			memmove(out + (attrs[n].content.ref.length - out_size),
				out,
				attrs[n].content.ref.length);
			memset(out, 0, attrs[n].content.ref.length - out_size);
			out_size = attrs[n].content.ref.length;
		}

		if (!ADBG_EXPECT_BUFFER(c, attrs[n].content.ref.buffer,
			attrs[n].content.ref.length, out, out_size))
			return false;
	}

	return true;
}

static void xtest_tee_test_9000(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle priv_key_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle pub_key_handle = TEE_HANDLE_NULL;
	TEE_Attribute key_attrs[8] = { };
	TEE_Attribute algo_params[1] = { };
	size_t num_algo_params = 0;
	uint8_t out[512] = { };
	size_t out_size = 0;
	uint8_t ptx_hash[TEE_MAX_HASH_SIZE] = { };
	size_t ptx_hash_size = 0;
	size_t max_key_size = 0;
	size_t num_key_attrs = 0;
	uint32_t ret_orig = 0;
	size_t n = 0;
	uint32_t curve = 0;
	uint32_t hash_algo = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
			&ret_orig)))
		return;

	for (n = 0; n < ARRAY_SIZE(xtest_ac_cases); n++) {
		const struct xtest_ac_case *tv = xtest_ac_cases + n;

		if (tv->level > level)
			continue;

		Do_ADBG_BeginSubCase(c, "Asym Crypto case %d algo 0x%x line %d",
				     (int)n, (unsigned int)tv->algo,
				     (int)tv->line);

		/*
		 * When signing or verifying we're working with the hash of
		 * the payload.
		 */
		hash_algo = tv->hash_algo;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session,
				&op, hash_algo, TEE_MODE_DIGEST, 0)))
			goto out;

		ptx_hash_size = sizeof(ptx_hash);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_digest_do_final(c, & session, op,
				tv->ptx, tv->ptx_len, ptx_hash,
				&ptx_hash_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op)))
			goto out;

		num_algo_params = 0;
		num_key_attrs = 0;
		switch (TEE_ALG_GET_MAIN_ALG(tv->algo)) {
		case TEE_MAIN_ALGO_ECDSA:
			switch (tv->algo) {
			case TEE_ALG_ECDSA_P192:
				curve = TEE_ECC_CURVE_NIST_P192;
				break;
			case TEE_ALG_ECDSA_P224:
				curve = TEE_ECC_CURVE_NIST_P224;
				break;
			case TEE_ALG_ECDSA_P256:
				curve = TEE_ECC_CURVE_NIST_P256;
				break;
			case TEE_ALG_ECDSA_P384:
				curve = TEE_ECC_CURVE_NIST_P384;
				break;
			case TEE_ALG_ECDSA_P521:
				curve = TEE_ECC_CURVE_NIST_P521;
				break;
			default:
				curve = 0xFF;
				break;
			}

			if (tv->algo == TEE_ALG_ECDSA_P521)
				max_key_size = 521;
			else
				max_key_size = tv->params.ecdsa.private_len * 8;

			xtest_add_attr_value(&num_key_attrs, key_attrs,
					     TEE_ATTR_ECC_CURVE, curve, 0);
			xtest_add_attr(&num_key_attrs, key_attrs,
				       TEE_ATTR_ECC_PUBLIC_VALUE_X,
				       tv->params.ecdsa.public_x,
				       tv->params.ecdsa.public_x_len);
			xtest_add_attr(&num_key_attrs, key_attrs,
				       TEE_ATTR_ECC_PUBLIC_VALUE_Y,
				       tv->params.ecdsa.public_y,
				       tv->params.ecdsa.public_y_len);

			if (!ADBG_EXPECT_TRUE(c,
				create_key(c, &session, max_key_size,
					   TEE_TYPE_ECDSA_PUBLIC_KEY, key_attrs,
					   num_key_attrs, &pub_key_handle)))
				goto out;

			xtest_add_attr(&num_key_attrs, key_attrs,
				       TEE_ATTR_ECC_PRIVATE_VALUE,
				       tv->params.ecdsa.private,
				       tv->params.ecdsa.private_len);

			if (!ADBG_EXPECT_TRUE(c,
				create_key(c, &session, max_key_size,
					   TEE_TYPE_ECDSA_KEYPAIR, key_attrs,
					   num_key_attrs, &priv_key_handle)))
				goto out;
			break;

		default:
			ADBG_EXPECT_TRUE(c, false);
			goto out;
		}

		out_size = sizeof(out);
		memset(out, 0, sizeof(out));
		switch (tv->mode) {
		case TEE_MODE_SIGN:
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_allocate_operation(c, &session,
					&op, tv->algo, TEE_MODE_SIGN,
					max_key_size)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_set_operation_key(c, &session, op,
					priv_key_handle)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_free_transient_object(c, &session,
					priv_key_handle)))
				goto out;

			priv_key_handle = TEE_HANDLE_NULL;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_asymmetric_sign(c, &session, op,
					algo_params, num_algo_params, ptx_hash,
					ptx_hash_size, out, &out_size)))
				goto out;

			if (TEE_ALG_GET_MAIN_ALG(tv->algo) == TEE_MAIN_ALGO_ECDSA) {
				EC_KEY         *ec_key = NULL;
				int curve = 0;

				// Select NIST curve according to key size
				// More details here https://www.secg.org/sec2-v2.pdf
				switch (tv->algo) {
				case TEE_ALG_ECDSA_P192:
					curve = OBJ_txt2nid("prime192v1");
					break;
				case TEE_ALG_ECDSA_P224:
					curve = OBJ_txt2nid("secp224r1");
					break;
				case TEE_ALG_ECDSA_P256:
					curve = OBJ_txt2nid("prime256v1");
					break;
				case TEE_ALG_ECDSA_P384:
					curve = OBJ_txt2nid("secp384r1");
					break;
				case TEE_ALG_ECDSA_P521:
					curve = OBJ_txt2nid("secp521r1");
					break;
				default:
					Do_ADBG_Log("Invalid key size %zu",tv->params.ecdsa.private_len);
					break;
				}

				if (curve)
					ec_key = EC_KEY_new_by_curve_name(curve);

				if (ec_key) {
					ECDSA_SIG *sig = NULL;
					BIGNUM *private = BN_bin2bn(tv->params.ecdsa.private,tv->params.ecdsa.private_len, NULL);
					BIGNUM *point_x = BN_bin2bn(tv->params.ecdsa.public_x,tv->params.ecdsa.public_x_len, NULL);
					BIGNUM *point_y = BN_bin2bn(tv->params.ecdsa.public_y,tv->params.ecdsa.public_y_len, NULL);

					BIGNUM *r = BN_bin2bn(out,tv->params.ecdsa.private_len, NULL);
					BIGNUM *s = BN_bin2bn(out + tv->params.ecdsa.private_len, tv->params.ecdsa.private_len, NULL);;

					ADBG_EXPECT(c,1,EC_KEY_set_private_key(ec_key, private));
					ADBG_EXPECT(c,1,EC_KEY_set_public_key_affine_coordinates(ec_key, point_x, point_y));

					BN_free(point_x);
					BN_free(point_y);
					BN_free(private);

					Do_ADBG_Log("Check with OpenSSL case %d algo 0x%x line %d key size %d",
							     (int)n, (unsigned int)tv->algo,
							     (int)tv->line,
							     (int)tv->params.ecdsa.public_x_len);

					ADBG_EXPECT(c,1,EC_KEY_check_key(ec_key));

					sig = ECDSA_SIG_new();
					ADBG_EXPECT(c,1,ECDSA_SIG_set0(sig,r,s));

					ADBG_EXPECT(c,1,ECDSA_do_verify(ptx_hash,ptx_hash_size,sig,ec_key));

					ECDSA_SIG_free(sig);
					BN_free(r);
					BN_free(s);

					sig = ECDSA_do_sign(ptx_hash,ptx_hash_size,ec_key);
					if (sig)
					{
						ECDSA_SIG_get0(sig,(const BIGNUM**)&r,(const BIGNUM**)&s);

						ADBG_EXPECT(c,1,BN_bn2bin_padded(out, tv->params.ecdsa.private_len, r));
						out_size = tv->params.ecdsa.private_len;
						ADBG_EXPECT(c,1,BN_bn2bin_padded(out + out_size, tv->params.ecdsa.private_len, s));
						out_size += tv->params.ecdsa.private_len;

						Do_ADBG_Log("OpenSSL signature size %zu", out_size);
						Do_ADBG_HexLog(out, out_size, 16);

						ECDSA_SIG_free(sig);
						BN_free(r);
						BN_free(s);

						if (!ADBG_EXPECT_TEEC_SUCCESS(c,
							ta_crypt_cmd_allocate_operation(c,
								&session, &op, tv->algo,
								TEE_MODE_VERIFY, max_key_size)))
							goto out;

						if (!ADBG_EXPECT_TEEC_SUCCESS(c,
							ta_crypt_cmd_set_operation_key(c,
								&session, op, pub_key_handle)))
							goto out;

						if (!ADBG_EXPECT_TEEC_SUCCESS(c,
							ta_crypt_cmd_free_transient_object(c,
								&session, pub_key_handle)))
							goto out;

						pub_key_handle = TEE_HANDLE_NULL;

						ADBG_EXPECT_TEEC_SUCCESS(c,
							ta_crypt_cmd_asymmetric_verify(c,
								&session, op, algo_params,
								num_algo_params, ptx_hash,
								ptx_hash_size, out, out_size));

					}

					EC_KEY_free(ec_key);
				} else {
					Do_ADBG_Log("Failed to create key");
				}

			}
			break;

		default:
			break;
		}

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
				pub_key_handle)))
			goto out;
		pub_key_handle = TEE_HANDLE_NULL;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
				priv_key_handle)))
			goto out;

		priv_key_handle = TEE_HANDLE_NULL;

		Do_ADBG_EndSubCase(c, NULL);
	}
out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 9000, xtest_tee_test_9000,
		"Test TEE Internal API Asymmetric ECDSA operations");


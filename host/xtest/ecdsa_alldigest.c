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
	const uint8_t *ctx;
	size_t ctx_len;
	size_t line;
};

#define WITHOUT_SALT(x) -1
#define WITH_SALT(x)    x

#define ARRAY(a)            a, ARRAY_SIZE(a)
#define NULL_ARRAY(a)       NULL, 0

#define XTEST_AC_CASE(level, algo, mode, hash_algo, vect, union_params) \
	{ level, (algo), (mode), (hash_algo), .params = union_params, \
	  ARRAY(vect ## _ptx), \
	  ARRAY(vect ## _out), \
	  __LINE__ }

#define XTEST_AC_ECDSA_UNION(vect) \
	{ .ecdsa = { \
		  ARRAY(vect ## _private), \
		  ARRAY(vect ## _public_x), \
		  ARRAY(vect ## _public_y), \
	  } }

#define XTEST_AC_ECDSA_CASE(level, algo, mode, hash_algo, vect) \
	XTEST_AC_CASE(level, algo, mode, hash_algo, vect, XTEST_AC_ECDSA_UNION(vect))

static const struct xtest_ac_case xtest_ac_cases[] = {
	/* ECDSA tests */
	/* [P-224] */
	/* SHA1 hash */
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA1,
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
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA224,
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
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA256,
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
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA384,
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
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN, TEE_ALG_SHA512,
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
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA384,
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
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, TEE_ALG_SHA512,
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
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA1,
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
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA224,
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
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA256,
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
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA384,
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
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN, TEE_ALG_SHA512,
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
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_62),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_63),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_64),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_65),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_66),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_67),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_68),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_69),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_70),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_71),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_72),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_73),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_74),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA1,
			    nist_186_2_ecdsa_testvector_75),

	/* [P-521] */
	/* SHA224 hash */
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_61),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_62),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_63),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_64),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_65),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_66),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_67),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_68),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_69),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_70),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_71),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_72),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_73),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_74),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA224,
			    nist_186_2_ecdsa_testvector_75),

	/* [P-521] */
	/* SHA256 hash */
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_61),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_62),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_63),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_64),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_65),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_66),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_67),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_68),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_69),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_70),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_71),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_72),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_73),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_74),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA256,
			    nist_186_2_ecdsa_testvector_75),

	/* [P-521] */
	/* SHA384 hash */
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_61),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_62),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_63),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_64),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_65),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_66),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_67),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_68),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_69),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_70),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_71),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_72),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_73),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_74),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA384,
			    nist_186_2_ecdsa_testvector_75),

	/* [P-521] */
	/* SHA512 hash */
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_61),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_62),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_63),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_64),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_65),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_66),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_67),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_68),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_69),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_70),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_71),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_72),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_73),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
			    nist_186_2_ecdsa_testvector_74),
	XTEST_AC_ECDSA_CASE(0, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN, TEE_ALG_SHA512,
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
		case TEE_MODE_VERIFY:
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_allocate_operation(c, &session,
					&op, tv->algo, TEE_MODE_VERIFY,
					max_key_size)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_set_operation_key(c, &session, op,
					pub_key_handle)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_free_transient_object(c, &session,
					pub_key_handle)))
				goto out;

			pub_key_handle = TEE_HANDLE_NULL;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_asymmetric_verify(c, &session, op,
					algo_params, num_algo_params, ptx_hash,
					ptx_hash_size, tv->ctx, tv->ctx_len)))
				goto out;
			break;

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
					uint8_t *der_sig;
					size_t der_sig_len;
					BIGNUM *private = BN_bin2bn(tv->params.ecdsa.private,tv->params.ecdsa.private_len, NULL);
					BIGNUM *point_x = BN_bin2bn(tv->params.ecdsa.public_x,tv->params.ecdsa.public_x_len, NULL);
					BIGNUM *point_y = BN_bin2bn(tv->params.ecdsa.public_y,tv->params.ecdsa.public_y_len, NULL);

					BIGNUM *r = BN_bin2bn(out,tv->params.ecdsa.private_len, NULL);
					BIGNUM *s = BN_bin2bn(out + tv->params.ecdsa.private_len, tv->params.ecdsa.private_len, NULL);;

					ADBG_EXPECT(c,1,EC_KEY_set_private_key(ec_key, private));
					ADBG_EXPECT(c,1,EC_KEY_set_public_key_affine_coordinates(ec_key, point_x, point_y));

					Do_ADBG_Log("Check with OpenSSL case %d algo 0x%x line %d key size %d",
							     (int)n, (unsigned int)tv->algo,
							     (int)tv->line,
							     (int)tv->params.ecdsa.public_x_len);

					ADBG_EXPECT(c,1,EC_KEY_check_key(ec_key));

					sig = ECDSA_SIG_new();
					ADBG_EXPECT(c,1,ECDSA_SIG_set0(sig,r,s));
					ADBG_EXPECT(c,1,ECDSA_SIG_to_bytes(&der_sig,&der_sig_len,sig));

					ADBG_EXPECT(c,1,ECDSA_verify(0,ptx_hash,ptx_hash_size,der_sig,der_sig_len,ec_key));

					OPENSSL_free(der_sig);
					ECDSA_SIG_free(sig);
					EC_KEY_free(ec_key);
					BN_free(point_x);
					BN_free(point_y);
					BN_free(private);
					BN_free(r);
					BN_free(s);
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


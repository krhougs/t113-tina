#include <tee_api.h>
#include <stdio.h>
#include <secp256k1.h>
#include "user_ta_header_defines.h"

int sign(unsigned char privateKey[32], unsigned char msgHash[32], unsigned char signature[64])
{
	int retVal;
	secp256k1_ecdsa_signature sig;
	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	// todo: use randomness to protect ctx against side channel
	retVal = secp256k1_ecdsa_sign(ctx, &sig, msgHash, privateKey, NULL, NULL);
	if (retVal == 0)
	{
		return -1;
	}
	retVal = secp256k1_ecdsa_signature_serialize_compact(ctx, signature, &sig);
	if (retVal == 0)
	{
		return -2;
	}
	return 0;
}

int getPublicKey(unsigned char privateKey[32], unsigned char publicKeyReceiver[33])
{
	secp256k1_pubkey pubkey;
	int retVal;
	size_t len;
	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	retVal = secp256k1_ec_pubkey_create(ctx, &pubkey, privateKey);
	if (retVal == 0)
	{
		return -1;
	}
	len = sizeof(*publicKeyReceiver);
	retVal = secp256k1_ec_pubkey_serialize(ctx, publicKeyReceiver, &len, &pubkey, SECP256K1_EC_COMPRESSED);
	if (retVal == 0)
	{
		return -2;
	}
	return 0;
}

static TEE_Result createKey(uint32_t param_types, TEE_Param params[4]) {
    char private_key_id[] = "tee_private_key";
    char *obj_id = private_key_id;
    size_t obj_id_sz = sizeof(private_key_id);
    TEE_ObjectHandle object;
    TEE_Result res;
    uint32_t obj_data_flag;

    const uint32_t exp_param_types =
            TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                            TEE_PARAM_TYPE_NONE,
                            TEE_PARAM_TYPE_NONE,
                            TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    // Assert key size
    if (params[0].memref.size != sizeof(unsigned char[32])) {
        return TEE_ERROR_SHORT_BUFFER;
    }

    // Allocate Key memory
    void *private_key_content = TEE_Malloc(sizeof(unsigned char[32]), 0);
    TEE_MemMove(private_key_content, params[0].memref.buffer, params[0].memref.size);

    obj_data_flag = TEE_DATA_FLAG_ACCESS_READ |        /* we can later read the oject */
                    TEE_DATA_FLAG_ACCESS_WRITE |        /* we can later write into the object */
                    TEE_DATA_FLAG_ACCESS_WRITE_META;    /* we can later destroy or rename the object */
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                     obj_id, obj_id_sz,
                                     obj_data_flag,
                                     TEE_HANDLE_NULL,
                                     private_key_content,
                                     sizeof(unsigned char[32]),        /* we may not fill it right now */
                                     &object);
    TEE_Free(private_key_content);
    return res;
}

int loadKey(unsigned char buffer[32]) {
    char private_key_id[] = "tee_private_key";
    TEE_ObjectHandle object;
    TEE_ObjectInfo object_info;
    TEE_Result res;
    uint32_t read_bytes;
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                   private_key_id, sizeof(private_key_id),
                                   TEE_DATA_FLAG_ACCESS_READ |
                                   TEE_DATA_FLAG_SHARE_READ,
                                   &object);
    if (res != TEE_SUCCESS) {
        return -1;
    }

    res = TEE_GetObjectInfo1(object, &object_info);
    if (res != TEE_SUCCESS) {
        TEE_CloseObject(object);
        return -2;
    }
    if (object_info.dataSize != sizeof(unsigned char[32])) {
        TEE_CloseObject(object);
        return -3;
    }
    // Copy data into buffer
    res = TEE_ReadObjectData(object, buffer, sizeof(unsigned char[32]), &read_bytes);
    TEE_CloseObject(object);
    if (res != TEE_SUCCESS) {
        TEE_CloseObject(object);
        return -4;
    }
    return 0;
}


/*
 * Trusted Application Entry Points
 */

/* Called each time a new instance is created */
TEE_Result TA_CreateEntryPoint(void)
{
	printf("TA:creatyentry!\n");
	return TEE_SUCCESS;
}

/* Called each time an instance is destroyed */
void TA_DestroyEntryPoint(void)
{
}

/* Called each time a session is opened */
TEE_Result TA_OpenSessionEntryPoint(uint32_t nParamTypes,
									TEE_Param pParams[4],
									void **ppSessionContext)
{
	(void)nParamTypes;
	(void)pParams;
	(void)ppSessionContext;
	printf("TA:open session!\n");
	return TEE_SUCCESS;
}

/* Called each time a session is closed */
void TA_CloseSessionEntryPoint(void *pSessionContext)
{
	(void)pSessionContext;
}

static TEE_Result signHash(uint32_t param_types, TEE_Param params[4]) {
    int retVal;
    uint32_t exp_param_types = TEE_PARAM_TYPES(
            TEE_PARAM_TYPE_MEMREF_INPUT, // Input Hash
            TEE_PARAM_TYPE_MEMREF_OUTPUT, // Output Signature
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE
    );
    if (param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    // Check param size
    if (params[0].memref.size < sizeof(unsigned char[32])) {
        return TEE_ERROR_SHORT_BUFFER;
    }
    if (params[0].memref.size < sizeof(unsigned char[64])) {
        return TEE_ERROR_SHORT_BUFFER;
    }
    void *msgHashIn = TEE_Malloc(sizeof(unsigned char[32]), 0);
    // Copy sig hash in
    TEE_MemMove(msgHashIn, params[0].memref.buffer, sizeof(unsigned char[32]));
    void *sigOut = TEE_Malloc(sizeof(unsigned char[64]), 0);
    // Invoke Cryptography Ops.
    /// Allocate private key buffer;
    void *privateKeyBuffer = TEE_Malloc(sizeof(unsigned char[32]), 0);
    retVal = loadKey(privateKeyBuffer);
    if (retVal != 0) {
        TEE_Free(privateKeyBuffer);
        return TEE_ERROR_BAD_STATE;
    }
    retVal = sign(privateKeyBuffer, msgHashIn, sigOut);
    TEE_Free(msgHashIn);
    TEE_Free(privateKeyBuffer);
    if (retVal == 0) {
        TEE_MemMove(params[1].memref.buffer, sigOut, sizeof(unsigned char[64]));
        TEE_Free(sigOut);
        return TEE_SUCCESS;
    }
    TEE_Free(sigOut);
    return TEE_ERROR_SECURITY;
}

static TEE_Result getPublicKeyTee(uint32_t param_types, TEE_Param params[4]) {
    int retVal;
    uint32_t exp_param_types = TEE_PARAM_TYPES(
            TEE_PARAM_TYPE_MEMREF_OUTPUT,
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE
    );
    if (param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[0].memref.size < sizeof(unsigned char[33])) {
        return TEE_ERROR_SHORT_BUFFER;
    }
    // Allocate public key receiver
    void *outMem = TEE_Malloc(sizeof(unsigned char[33]), 0);
    /// Allocate private key buffer;
    void *privateKeyBuffer = TEE_Malloc(sizeof(unsigned char[32]), 0);
    retVal = loadKey(privateKeyBuffer);
    if (retVal != 0) {
        TEE_Free(privateKeyBuffer);
        return TEE_ERROR_BAD_STATE;
    }
    retVal = getPublicKey(privateKeyBuffer, outMem);
    TEE_Free(privateKeyBuffer);
    if (retVal == 0) {
        TEE_MemMove(params[0].memref.buffer, outMem, sizeof(unsigned char[33]));
        TEE_Free(outMem);
        return TEE_SUCCESS;
    }
    TEE_Free(outMem);
    return TEE_ERROR_SECURITY;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void
										  *sess_ctx,
									  uint32_t cmd_id,
									  uint32_t
										  param_types,
									  TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id)
	{
		case TA_COMMAND_PUB:
            return
                    getPublicKeyTee(param_types, params
                    );
        case TA_COMMAND_SIGN:
            return
                    signHash(param_types, params
                    );
        case TA_COMMAND_INIT:
            return createKey(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

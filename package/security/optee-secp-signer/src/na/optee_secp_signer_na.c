#include <tee_client_api.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <stdlib.h>

#include "optee_secp_signer_na.h"

#define TA_UUID { 0xc6fbfdbf, 0x7034, 0x4bda, \
	{0x85,0xb5,0x67,0xeb,0x3b,0x17,0x58,0xa7} }

void prepare_tee_session(struct tee_ctx *ctx) {
    TEEC_UUID uuid = TA_UUID;
    uint32_t origin;
    TEEC_Result res;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx->ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    /* Open a session with the TA */
    res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
             res, origin);
}

void terminate_tee_session(struct tee_ctx *ctx) {
    TEEC_CloseSession(&ctx->sess);
    TEEC_FinalizeContext(&ctx->ctx);
}

TEEC_Result initKey(struct tee_ctx *ctx, unsigned char *buf) {
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = buf;
    op.params[0].tmpref.size = sizeof(unsigned char[32]);

    res = TEEC_InvokeCommand(&ctx->sess, 3, &op, &origin); // todo add commandID define
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
             res, origin);
    return res;
}

TEEC_Result getPubKey(struct tee_ctx *ctx) {
    unsigned char pubkey[33];
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = pubkey;
    op.params[0].tmpref.size = sizeof(pubkey);
    res = TEEC_InvokeCommand(&ctx->sess, 1, &op, &origin); // todo add commandID define
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
             res, origin);
    // print hex pubkey
    for (unsigned int i = 0; i < sizeof(pubkey); i++) {
        printf("%02x", pubkey[i]);
    }
    printf("\n");
    return res;
}

TEEC_Result signPayload(struct tee_ctx *ctx, unsigned char msgHash[32]) {
    unsigned char signature[64];
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = msgHash;
    op.params[0].tmpref.size = sizeof(unsigned char[32]);
    op.params[1].tmpref.buffer = signature;
    op.params[1].tmpref.size = sizeof(unsigned char[64]);
    res = TEEC_InvokeCommand(&ctx->sess, 2, &op, &origin); // todo add commandID define
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
             res, origin);
    // print hex pubkey
    for (unsigned int i = 0; i < sizeof(signature); i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");
    return res;
}

unsigned char *hexToBytes(char *input) {
    size_t len = strlen(input);
    unsigned char *output = malloc(len / 2);
    for (unsigned int i = 0; i < len; i += 2) {
        sscanf(input + i, "%02hhx", output + (i / 2));
    }
    return output;
}

int main(int argc, char **argv) {
    if (argc <= 1) {
        printf("no args given\n"
               "init key in tee: sclient init <hexbytes>\n"
               "sign: sclient sign <hexbytes>\n"
               "get public key: sclient pub\n");
        return 0;
    }
    // init tee ctx
    struct tee_ctx ctx;
    prepare_tee_session(&ctx);
    if (strcmp("pub", argv[1]) == 0) {
        getPubKey(&ctx);
    }
    if (strcmp("sign", argv[1]) == 0) {
        if (argc <= 2) {
            printf("no args given\n"
                   "sign: sclient sign <hexbytes>\n");
            return 0;
        }
        unsigned char *msgHash = hexToBytes(argv[2]);
        signPayload(&ctx, msgHash);
    }
    if (strcmp("init", argv[1]) == 0) {
        if (argc <= 2) {
            printf("no args given\n"
                   "init key in tee: sclient init <hexbytes>\n");
            return 0;
        }
        unsigned char *buf = hexToBytes(argv[2]);
        initKey(&ctx, buf);
    }
    // close tee ctx
    terminate_tee_session(&ctx);
}

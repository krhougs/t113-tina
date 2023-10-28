#ifndef OPTEE_SECP_SIGNER_NA
#define OPTEE_SECP_SIGNER_NA

struct tee_ctx {
    TEEC_Context ctx;
    TEEC_Session sess;
};

void prepare_tee_session(struct tee_ctx *ctx);
void terminate_tee_session(struct tee_ctx *ctx);
TEEC_Result initKey(struct tee_ctx *ctx, unsigned char *buf);
TEEC_Result getPubKey(struct tee_ctx *ctx);
TEEC_Result signPayload(struct tee_ctx *ctx, unsigned char msgHash[32]);
unsigned char *hexToBytes(char *input);

#endif
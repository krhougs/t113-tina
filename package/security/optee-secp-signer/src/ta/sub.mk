global-incdirs-y += include
srcs-y += optee_secp_signer_ta.c

libnames += secp256k1

libdeps += library/libsecp256k1.a
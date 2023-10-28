#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#define TA_UUID { 0xc6fbfdbf, 0x7034, 0x4bda, \
	{0x85,0xb5,0x67,0xeb,0x3b,0x17,0x58,0xa7} }

/*
 * This is important to have TA_FLAG_SINGLE_INSTANCE && !TA_FLAG_MULTI_SESSION
 * as it is used by the ytest
 */
#define TA_FLAGS		(TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR | \
				TA_FLAG_MULTI_SESSION)
#define TA_STACK_SIZE		(2 * 1024)
#define TA_DATA_SIZE		(32 * 1024)

#define TA_COMMAND_INIT 3
#define TA_COMMAND_SIGN 2
#define TA_COMMAND_PUB 1

#endif

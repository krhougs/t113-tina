# Normally this makefile shouldn't be called directly and we expect the output
# path to be on a certain location to fit together with the other OP-TEE
# gits and helper scripts.

include ../scripts/common.mk
out-dir := $(call strip-trailing-slashes-and-dots,$(O))
ifeq ($(out-dir),)
$(error invalid output directory (O=$(O)))
endif

#include $(TA_DEV_KIT_DIR)/host_include/conf.mk

# By default we expect optee_client exported folder to be on a certain relative
# path, but if the client specifies the OPTEE_CLIENT_EXPORT then that path will
# be used instead.
OPTEE_CLIENT_EXPORT ?= $(CA_DEV_KIT_DIR)

CC		?= $(CROSS_COMPILE)gcc
CPP		?= $(CROSS_COMPILE)cpp
LD		?= $(CROSS_COMPILE)ld
AR		?= $(CROSS_COMPILE)ar
NM		?= $(CROSS_COMPILE)nm
OBJCOPY		?= $(CROSS_COMPILE)objcopy
OBJDUMP		?= $(CROSS_COMPILE)objdump
READELF		?= $(CROSS_COMPILE)readelf


srcs +=	optee_secp_signer_na.c

objs 	:= $(patsubst %.c,$(out-dir)/%.o, $(srcs))

CFLAGS += -I./

CFLAGS += -I$(OPTEE_CLIENT_EXPORT)/include

ifndef CFG_GP_PACKAGE_PATH
CFLAGS += -Wall -Wcast-align -Werror \
	  -Werror-implicit-function-declaration -Wextra -Wfloat-equal \
	  -Wformat-nonliteral -Wformat-security -Wformat=2 -Winit-self \
	  -Wmissing-declarations -Wmissing-format-attribute \
	  -Wmissing-include-dirs -Wmissing-noreturn \
	  -Wmissing-prototypes -Wnested-externs -Wpointer-arith \
	  -Wshadow -Wstrict-prototypes -Wswitch-default \
	  -Wwrite-strings \
	  -Wno-missing-field-initializers -Wno-format-zero-length
endif

CFLAGS += -g3 -fPIC
LDFLAGS += -L$(OPTEE_CLIENT_EXPORT)/exportlib -lteec
LDFLAGS += -lpthread -lm

.PHONY: all
all: secp_signer_na

secp_signer_na: $(objs)
	@echo "  LD      $(out-dir)/$@"
	$(q)@$(CC) -o $(out-dir)/$@ $+ $(LDFLAGS)

$(out-dir)/%.o: $(CURDIR)/%.c
	$(q)mkdir -p $(out-dir)/
	@echo '  CC      $<'
	$(q)$(CC) $(CFLAGS) -c $< -o $@

RMDIR := rmdir --ignore-fail-on-non-empty
define rm-build-dirs
	$(q)$(RMDIR) $(out-dir) 2> /dev/null; true
	$(q)$(RMDIR) $(out-dir) 2> /dev/null; true
endef

.PHONY: clean
clean:
	@echo '  CLEAN $(out-dir)'
	$(q)rm -f $(out-dir)/secp_signer_na
	$(q)$(foreach obj,$(objs), rm -f $(obj))
	$(call rm-build-dirs)

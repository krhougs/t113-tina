#
# Copyright (C) 2014-2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=optee-os-dev-kit
PKG_VERSION:=2.5.0
PKG_RELEASE:=1

PKG_BUILD_DIR := $(COMPILE_DIR)/$(PKG_NAME)

# PKG_BUILD_DEPENDS += python-crypto/host

PKG_CONFIG_DEPENDS += CONFIG_OPTEE_ENCRYPT_TA CONFIG_OPTEE_ENCRYPT_TA_SSK_KEY CONFIG_OPTEE_ENCRYPT_TA_ROTPK_DERIVE_KEY

PKG_LICENSE:=BSD 2-Clause
PKG_LICENSE_FILES:=LICENSE

include $(BUILD_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=utils
  CATEGORY:=Security
  SUBMENU:=OPTEE
  DEPENDS:=
  TITLE:=optee-os-dev-kit
endef

define Package/$(PKG_NAME)/description
This component provides the TA development environment.
endef

define Package/$(PKG_NAME)/config
source "$(SOURCE)/Config.in"
endef

define Build/Prepare
#	mkdir -p $(PKG_BUILD_DIR)
#	$(CP) -rf ./dev_kit/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/
	$(INSTALL_DIR) $(1)/usr/dev_kit/

	rm -rf $(STAGING_DIR)/usr/dev_kit/*
	$(CP) ./dev_kit/arm-plat-$(TARGET_CHIP) $(1)/usr/dev_kit/

ifeq ($(CONFIG_OPTEE_ENCRYPT_TA),y)
	sed -i "/^SUNXI_TA_ENCRYPT=/d" $(1)/usr/dev_kit/arm-plat-$(TARGET_CHIP)/export-ta_arm32/mk/conf.mk && \
		echo "SUNXI_TA_ENCRYPT=y" >> $(1)/usr/dev_kit/arm-plat-$(TARGET_CHIP)/export-ta_arm32/mk/conf.mk
ifeq ($(CONFIG_OPTEE_ENCRYPT_TA_SSK_KEY),y)
	sed -i "/^USING_DERIVE_KEY=/d" $(1)/usr/dev_kit/arm-plat-$(TARGET_CHIP)/export-ta_arm32/mk/conf.mk && \
		echo "USING_DERIVE_KEY=n" >> $(1)/usr/dev_kit/arm-plat-$(TARGET_CHIP)/export-ta_arm32/mk/conf.mk
else
	sed -i "/^USING_DERIVE_KEY=/d" $(1)/usr/dev_kit/arm-plat-$(TARGET_CHIP)/export-ta_arm32/mk/conf.mk && \
		echo "USING_DERIVE_KEY=y" >> $(1)/usr/dev_kit/arm-plat-$(TARGET_CHIP)/export-ta_arm32/mk/conf.mk
endif
else
	sed -i "/^SUNXI_TA_ENCRYPT=/d" $(1)/usr/dev_kit/arm-plat-$(TARGET_CHIP)/export-ta_arm32/mk/conf.mk && \
		echo "SUNXI_TA_ENCRYPT=n" >> $(1)/usr/dev_kit/arm-plat-$(TARGET_CHIP)/export-ta_arm32/mk/conf.mk
	sed -i "/^USING_DERIVE_KEY=/d" $(1)/usr/dev_kit/arm-plat-$(TARGET_CHIP)/export-ta_arm32/mk/conf.mk && \
		echo "USING_DERIVE_KEY=n" >> $(1)/usr/dev_kit/arm-plat-$(TARGET_CHIP)/export-ta_arm32/mk/conf.mk
endif
endef

define Package/$(PKG_NAME)/install
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

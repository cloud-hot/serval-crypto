#
# Copyright (C) 2010-2012 Jo-Philipp Wich <xm@subsignal.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=serval-crypto
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/serval-crypto/default
  SECTION:=commotion
  CATEGORY:=Commotion
  TITLE:=Serval signing and verification
  MAINTAINER:=Open Technology Institute
  DEPENDS:=+serval-dna
endef

define Package/serval-crypto
  $(Package/serval-crypto/default)
  MENU:=1
endef

define Package/serval-crypto/description
  This package provides functions for signing 
  arbitrary strings using Serval keypairs, 
  and verifying these signatures.
endef

TARGET_CFLAGS += $(TLS_CFLAGS) -I$(BUILD_DIR)/serval-dna-2012-10-29 -I$(BUILD_DIR)/serval-dna-2012-10-29/nacl/include
TARGET_LDFLAGS += -L$(BUILD_DIR)/serval-dna-2012-10-29/ -lservald

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/serval-crypto/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/serval-* $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,serval-crypto))

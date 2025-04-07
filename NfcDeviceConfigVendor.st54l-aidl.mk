# Device configuration file to be included from device.mk for the vendor image, e.g.
#
#   -include vendor/st/nfc/st21nfc/NfcDeviceConfigVendor.mk
#
# Please make sure to include st in allowed list in build/make/core/tasks/vendor_module_check.mk

######################################################################
##########################  VENDOR image  ############################
######################################################################

# Copy the correct parameters of the NFC controller depending on the hardware layout and CLF version.
#PRODUCT_COPY_FILES += \
#      $(NFC_RF_CONFIG_PATH)/st54l_conf.txt:$(TARGET_COPY_OUT_VENDOR)/etc/st54l_conf.txt:st

################################################
## Configuration for ST NFC packages
PRODUCT_PACKAGES += \
    android.hardware.nfc-service-st \
    nfc_nci.st21nfc.st \
    st54l_firmware \

PRODUCT_COPY_FILES += \
   frameworks/native/data/etc/android.hardware.nfc.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.xml:st \
   frameworks/native/data/etc/android.hardware.nfc.hce.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.hce.xml:st \
   frameworks/native/data/etc/android.hardware.nfc.hcef.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.hcef.xml:st \
   frameworks/native/data/etc/android.hardware.nfc.uicc.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.uicc.xml:st \

PRODUCT_COPY_FILES += frameworks/native/data/etc/android.hardware.nfc.ese.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.ese.xml:st
PRODUCT_COPY_FILES += frameworks/native/data/etc/android.hardware.se.omapi.ese.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.se.omapi.ese.xml:st

# # Stack configuration files (common for ST stack and AOSP stack)
# Note: we install libnfc-nci.conf in vendor/etc
# If OEM install their file in /product/etc or /odm/etc it will have priority
# but the default one in /system/etc has lower priority than vendor/etc
ifneq ($(strip $(TARGET_BUILD_VARIANT)),user)
   PRODUCT_COPY_FILES += \
   vendor/st/opensource/commonsys/packages/modules/Nfc/libnfc-nci/conf/libnfc-nci.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-nci.conf:st \
   vendor/st/opensource/halimpl/conf/libnfc-hal-st.conf.st54l:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-hal-st.conf:st

else
  # Configuration files for user build, remove some logs for GSMA certif
   PRODUCT_COPY_FILES += \
   vendor/st/opensource/commonsys/packages/modules/Nfc/libnfc-nci/conf/libnfc-nci.conf.user:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-nci.conf:st \
   vendor/st/opensource/halimpl/conf/libnfc-hal-st.conf.st54l.user:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-hal-st.conf:st

endif

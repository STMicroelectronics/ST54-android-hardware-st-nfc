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
#      $(NFC_RF_CONFIG_PATH)/st21nfc_conf.txt:$(TARGET_COPY_OUT_VENDOR)/etc/st21nfc_conf.txt:st

################################################
## Configuration for ST NFC packages
PRODUCT_PACKAGES += \
    android.hardware.nfc-service-st \
    nfc_nci.st21nfc.st \
    st21nfcd_firmware st21nfcd7_firmware \

PRODUCT_COPY_FILES += \
   frameworks/native/data/etc/android.hardware.nfc.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.xml:st \
   frameworks/native/data/etc/android.hardware.nfc.hce.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.hce.xml:st \
   frameworks/native/data/etc/android.hardware.nfc.hcef.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.hcef.xml:st \
   frameworks/native/data/etc/android.hardware.nfc.uicc.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.uicc.xml:st \

# if eSE:    frameworks/native/data/etc/android.hardware.nfc.ese.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.ese.xml:st
# if eSE in OMAPI:    frameworks/native/data/etc/android.hardware.se.omapi.ese.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.se.omapi.ese.xml:st

# # Stack configuration files (common for ST stack and AOSP stack)
# Note: we previously installed libnfc-nci.conf in vendor/etc
# The rationale was if OEM install their file in /product/etc or /odm/etc it will have priority
# but the default one in /system/etc has lower priority than vendor/etc
# We now target product/etc by default for better separation of system and vendor files.
# It is therefore now managed by NfcDeviceConfig.mk
ifneq ($(strip $(TARGET_BUILD_VARIANT)),user)
   PRODUCT_COPY_FILES += \
      vendor/st/opensource/halimpl/conf/libnfc-hal-st.conf.st21nfc:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-hal-st.conf:st \

else
   PRODUCT_COPY_FILES += \
      vendor/st/opensource/halimpl/conf/libnfc-hal-st.conf.st21nfc.user:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-hal-st.conf:st \

endif

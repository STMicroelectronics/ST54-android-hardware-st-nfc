# Enable build support for NFC open source vendor modules
ifeq ($(call is-board-platform-in-list, canoe),true)
TARGET_USES_STM_NFC := true
endif

STM_VENDOR_NFC := android.hardware.nfc-service-st
STM_VENDOR_NFC += nfc_nci.st21nfc.st

ifeq ($(strip $(TARGET_USES_STM_NFC)),true)
PRODUCT_COPY_FILES += \
    frameworks/native/data/etc/com.nxp.mifare.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/com.nxp.mifare.xml \
    frameworks/native/data/etc/com.android.nfc_extras.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/com.android.nfc_extras.xml \
    frameworks/native/data/etc/android.hardware.nfc.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.xml \
    frameworks/native/data/etc/android.hardware.nfc.hce.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.hce.xml \
    frameworks/native/data/etc/android.hardware.nfc.hcef.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.hcef.xml \
    frameworks/native/data/etc/android.hardware.nfc.ese.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.ese.xml \
    frameworks/native/data/etc/android.hardware.nfc.uicc.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.uicc.xml \
    vendor/st/opensource/halimpl/conf/libnfc-hal-st.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-hal-st.conf \
    vendor/st/opensource/halimpl/conf/libnfc-hal-st-660_mtp.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-hal-st-660_mtp.conf \
    vendor/st/opensource/halimpl/conf/libnfc-hal-st-660_qrd.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-hal-st-660_qrd.conf \
    vendor/st/opensource/halimpl/conf/libnfc-hal-st-685_mtp.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-hal-st-685_mtp.conf \
    vendor/st/opensource/halimpl/conf/libnfc-hal-st-685_qrd.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-hal-st-685_qrd.conf \
    vendor/st/opensource/halimpl/conf/libnfc-hal-st-727_mtp.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-hal-st-727_mtp.conf \
    vendor/st/opensource/halimpl/conf/libnfc-hal-st-727_qrd.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-hal-st-727_qrd.conf

PRODUCT_PACKAGES += $(STM_VENDOR_NFC)
endif

ifeq ($(call is-board-platform-in-list, canoe),true)
TARGET_ENABLE_PERIPHERAL_CONTROL := true
ifeq ($(TARGET_ENABLE_PERIPHERAL_CONTROL), true)
    $(call soong_config_set,nfc,board_secure_peripheral_framework,sun canoe)
endif
endif

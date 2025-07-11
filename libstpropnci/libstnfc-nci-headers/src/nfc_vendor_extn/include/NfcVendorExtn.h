/*
 * Copyright 2024, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <aidl/android/hardware/nfc/INfc.h>
#include <android/hardware/nfc/1.1/INfc.h>
#include <android/hardware/nfc/1.2/INfc.h>

#include "config.h"
#include "nfc_api.h"
#include "nfc_hal_api.h"

using android::sp;
using android::hardware::nfc::V1_0::INfc;
using INfcAidl = ::aidl::android::hardware::nfc::INfc;

#define NFCSTATUS_EXTN_FEATURE_SUCCESS (0x0050)

// This is only intended for a limited time to handle non-AOSP vendor interface
// implementations on existing upgrading devices and not as a new extension
// point. This will be removed once all devices are upgraded to the latest NFC
// HAL.
/**
 * @brief Vendor extension control block holds below data's
 *        hidlHal - reference to HIDL Hal instance
 *        aidlHal - reference to AIDL Hal instance
 *        pHalCback - reference to HAL events callback
 *        pDataCallback - reference to NCI response and notification packets
 *        configMap - holds the configs as keys and values
 *
 */
struct VendorExtnCb {
  sp<INfc> hidlHal;
  std::shared_ptr<INfcAidl> aidlHal;
  tHAL_NFC_CBACK* pHalCback;
  tHAL_NFC_DATA_CBACK* pDataCback;
  std::map<std::string, ConfigValue> configMap;
};

/**
 * @brief Holds NCI packet data length and data buffer
 *
 */
typedef struct {
  uint16_t data_len;
  uint8_t* p_data;
} NciData_t;

/**
 * @brief Holds functional event datas to support
 *        extension features
 */
typedef struct {
  NciData_t nci_msg;
  NciData_t nci_rsp_ntf;
  uint8_t write_status;
  uint8_t hal_state;
  uint8_t rf_state;
  uint8_t hal_event;
  uint8_t hal_event_status;
} NfcExtEventData_t;

/**
 * @brief Holds functional event codes to support
 *        extension features.
 * Begin with 0x0B to avoid conflicts with standard and vendor specific HAL
 * events
 */
typedef enum {
  HANDLE_VENDOR_NCI_MSG = 0x0B,
  HANDLE_VENDOR_NCI_RSP_NTF,
  HANDLE_WRITE_COMPLETE_STATUS,
  HANDLE_HAL_CONTROL_GRANTED,
  HANDLE_NFC_HAL_STATE_UPDATE,
  HANDLE_RF_HAL_STATE_UPDATE,
  HANDLE_HAL_EVENT,
  HANDLE_FW_DNLD_STATUS_UPDATE,
  HANDLE_DOWNLOAD_FIRMWARE_REQUEST,
  HANDLE_NFC_ADAPTATION_INIT,
  HANDLE_NFC_PRE_DISCOVER,
  HANDLE_NFC_HAL_CORE_INITIALIZE,
  HANDLE_NFC_HAL_POWER_CYCLE,
  HANDLE_NFC_GET_MAX_NFCEE,
  HANDLE_NFC_HAL_CLOSE,
#ifdef ST21NFC
  HANDLE_NFC_DEVICE_SHUTDOWN,
#endif  // ST21NFC
} NfcExtEvent_t;

typedef enum {
  NFCC_HAL_TRANS_ERR_CODE = 6u,
  NFCC_HAL_FATAL_ERR_CODE = 8u,
} NfcExtHal_NFCC_ERROR_CODE_t;

class NfcVendorExtn {
 public:
  /**
   * @brief Get the singleton of this object.
   * @return Reference to this object.
   *
   */
  static NfcVendorExtn* getInstance();

  /**
   * @brief This function sets up and initialize the extension feature
   * @param hidlHal reference to HIDL Hal instance
   * @param aidlHal reference to AIDL Hal instance
   * @return true if init is success else false
   *
   */
  bool Initialize(sp<INfc> hidlHal, std::shared_ptr<INfcAidl> aidlHal);

  /**
   * @brief This function sets ups the NCI event and data callback pointers.
   * @param pHalCback reference to HAL events callback
   * @param pDataCback reference to NCI response and notification packets
   * @return None
   * \Note: This function pointers will be used to notify the
   * NCI event and data to upper layer.
   *
   */
  void setNciCallback(tHAL_NFC_CBACK* pHalCback,
                      tHAL_NFC_DATA_CBACK* pDataCback);

  /**
   * @brief sends the NCI packet to handle extension feature
   * @param  dataLen length of the NCI packet
   * @param  pData data buffer pointer
   * @return returns true if it is vendor specific feature,
   * and handled only by extension library otherwise returns
   * false and it have to be handled by libnfc.
   *
   */
  bool processCmd(uint16_t dataLen, uint8_t* pData);

  /**
   * @brief sends the NCI packet to handle extension feature
   * @param  dataLen length of the NCI packet
   * @param  pData data buffer pointer
   * @return returns true if it is vendor specific feature,
   * and handled only by extension library otherwise returns
   * false and it have to be handled by libnfc.
   *
   */
  bool processRspNtf(uint16_t dataLen, uint8_t* pData);

  /**
   * @brief sends the NCI packet to handle extension feature
   * @param  event
   * @param  status
   * @return returns true if it is vendor specific feature,
   * and handled only by extension library otherwise returns
   * false and it have to be handled by libnfc.
   *
   */
  bool processEvent(uint8_t event, tHAL_NFC_STATUS status);

  /**
   * @brief Loads the Nfc Vendor Config
   * @param pConfigMap pointer to the config map
   * @return None
   * \Note @param pConfigMap is needed for future use
   * to add the vendor specific properties.
   *
   */
  void getVendorConfigs(std::map<std::string, ConfigValue>* pConfigMap);

  /**
   * @brief return the pointer of vendor extension control block.
   * @return A pointer to the VendorExtnCb structure or nullptr,
   * if the structure is not available or invalid.
   *
   */
  VendorExtnCb* getVendorExtnCb();

  /**
   * @brief This function de-initializes the extension feature
   * @return void
   *
   */
  bool finalize();

 private:
  VendorExtnCb mVendorExtnCb;

  NfcVendorExtn();

  ~NfcVendorExtn();
};

/******************************************************************************
 *
 *  Copyright (C) 2017 ST Microelectronics S.A.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 ******************************************************************************/
#define LOG_TAG "NfcNciHalWrapper"
#include <assert.h>
#include <cutils/properties.h>
#include <errno.h>
#include <hardware/nfc.h>
#include <string.h>
#include <unistd.h>
#include "android_logmsg.h"
#include "hal_fd.h"
#include "hal_auth.h"
#include "halcore.h"
#include "st21nfc_dev.h"

extern void HalCoreCallback(void* context, uint32_t event, const void* d,
                            size_t length);
extern bool I2cOpenLayer(void* dev, HAL_CALLBACK callb, HALHANDLE* pHandle);
extern void I2cCloseLayer();
extern void I2cRecovery();
extern int i2cNfccMayUseEse(int use);

static void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data);
static void halWrapperCallback(uint8_t event, uint8_t event_status);

nfc_stack_callback_t* mHalWrapperCallback = NULL;
nfc_stack_data_callback_t* mHalWrapperDataCallback = NULL;
hal_wrapper_state_e mHalWrapperState = HAL_WRAPPER_STATE_CLOSED;
int mHalWrapperStateConfigSubstate = HAL_WRAPPER_CONFSUBSTATE_DONE;
int mHalWrapperStateConfigInDtaMode = 0;
bool mHalWrapperStateConfigChanged = false;
HALHANDLE mHalHandle = NULL;

uint8_t mClfMode;
int mFwUpdateTask;
int mRetryFwDwl;
uint8_t* ConfigBuffer = NULL;
uint8_t mError_count = 0;
bool mIsActiveRW = false;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ready_cond = PTHREAD_COND_INITIALIZER;

static const uint8_t ApduGetAtr[] = {0x2F, 0x04, 0x05, 0x80,
                                     0x8A, 0x00, 0x00, 0x04};

static const uint8_t nciHeaderPropSetConfig[9] = {0x2F, 0x02, 0x98, 0x04, 0x00,
                                                  0x14, 0x01, 0x00, 0x92};
static uint8_t nciPropEnableFwDbgTraces[256];
static uint8_t nciPropEnableFwDbgTracesLen = 0;
static uint8_t nciPropGetFwDbgTracesConfig[] = {0x2F, 0x02, 0x05, 0x03,
                                                0x00, 0x14, 0x01, 0x00};

static uint8_t nciCoreResetNtfAbnormal[] = {0x60, 0x00, 0x05, 0x00,
                                            0x01, 0x20, 0x02, 0x00};

bool mReadFwConfigDone = false;

bool mHciCreditLent = false;
bool mfactoryReset = false;
bool ready_flag = 0;
bool mFieldNtfConfigured = false;
bool mTimerStarted = false;
bool forceRecover = false;
bool mFwLogsUnblocked = false;
bool isTimeout = false;
int recoveryCount = 0;
int const recoveryMax = 3;

void wait_ready() {
  pthread_mutex_lock(&mutex);
  while (!ready_flag) {
    pthread_cond_wait(&ready_cond, &mutex);
  }
  pthread_mutex_unlock(&mutex);
}

void set_ready(bool ready) {
  pthread_mutex_lock(&mutex);
  ready_flag = ready;
  pthread_cond_signal(&ready_cond);
  pthread_mutex_unlock(&mutex);
}

uint8_t mNfceeModeSetPendingId = 0x00;
uint8_t mNfceeModeSetPendingMode = 0x00;

void hal_wrapper_nfceeModeSetSent(uint8_t id, uint8_t mode) {
  mNfceeModeSetPendingId = id;
  mNfceeModeSetPendingMode = mode;
  if (mode == 0x01) {
    if (i2cNfccMayUseEse(1) != 0) {
      STLOG_HAL_W("NFC-NCI HAL: %s  i2cNfccMayUseEse(1) failed", __func__);
    }
  }
}

/* allow firmware log notifications to be sent to upper layers */
void hal_wrapper_unblockFwLogs() {
  STLOG_HAL_D("NFC-NCI HAL: %s", __func__);
  mFwLogsUnblocked = true;
}

bool hal_wrapper_open(st21nfc_dev_t* dev, nfc_stack_callback_t* p_cback,
                      nfc_stack_data_callback_t* p_data_cback,
                      HALHANDLE* pHandle) {
  bool result;

  STLOG_HAL_D("%s", __func__);

  if (hal_fd_init() < 0) {
    return -1;
  }
  mRetryFwDwl = 8;

  mHalWrapperState = HAL_WRAPPER_STATE_OPEN;
  mHalWrapperStateConfigInDtaMode = 0;
  mHciCreditLent = false;
  mReadFwConfigDone = false;
  mNfceeModeSetPendingId = 0x00;
  mError_count = 0;
  mFwLogsUnblocked = false;

  mHalWrapperCallback = p_cback;
  mHalWrapperDataCallback = p_data_cback;

  dev->p_data_cback = halWrapperDataCallback;
  dev->p_cback = halWrapperCallback;

  result = I2cOpenLayer(dev, HalCoreCallback, pHandle);

  if (!result || !(*pHandle)) {
    return -1;  // We are doomed, stop it here, NOW !
  }

  mHalHandle = *pHandle;

  STLOG_HAL_V("%s Start Timer", __func__);
  HalSendDownstreamTimer(mHalHandle, 10000);

  return 1;
}

int hal_wrapper_close(int call_cb, int nfc_mode) {
  STLOG_HAL_V("%s - Sending PROP_NFC_MODE_SET_CMD(%d)", __func__, nfc_mode);
  unsigned long num = 0;
  uint8_t propNfcModeSetCmdQb[] = {0x2f, 0x02, 0x02, 0x02, (uint8_t)nfc_mode};
  uint8_t propNfcFetchLogs[] = {0x2f, 0x02, 0x01, 0x21};

  if (mHalWrapperState == HAL_WRAPPER_STATE_OPEN) {
    // for the case of two calls to StNfc_hal_open very fast
    // there is a possible collision between the sending of these
    // commands and the reception of the CORE_RESET_NTF
    STLOG_HAL_V("%s was HAL_WRAPPER_STATE_OPEN, wait a bit", __func__);
    usleep(50000);
  }

  if ((nfc_mode == 0x02) &&
      GetNumValue(NAME_STNFC_FW_DEBUG_ENABLED, &num, sizeof(num)) &&
      (num & 0x02)) {
    mHalWrapperState = HAL_WRAPPER_STATE_CLOSING_FETCH_LOGS;

    if (!HalSendDownstream(mHalHandle, propNfcFetchLogs,
                           sizeof(propNfcFetchLogs))) {
      STLOG_HAL_E("NFC-NCI HAL: %s  HalSendDownstreamTimer failed", __func__);
      return -1;
    }
    // Let the CLF fetch if needed
    usleep(50000);
  }

  mHalWrapperState = HAL_WRAPPER_STATE_CLOSING;
  mFwLogsUnblocked = false;

  // If NFC is being disabled, no need for the eSE anymore from NFCC
  if (nfc_mode == 0x00) {
    if (i2cNfccMayUseEse(0) != 0) {
      STLOG_HAL_W("NFC-NCI HAL: %s  i2cNfccMayUseEse(0) failed", __func__);
    }
  }

  // Send PROP_NFC_MODE_SET_CMD
  if (nfc_mode != 0x01) {
    if (!HalSendDownstreamTimer(mHalHandle, propNfcModeSetCmdQb,
                                sizeof(propNfcModeSetCmdQb), 40)) {
      STLOG_HAL_E("NFC-NCI HAL: %s  HalSendDownstreamTimer failed", __func__);
      return -1;
    }
    // Let the CLF receive and process this
    usleep(50000);
  }

  I2cCloseLayer();
  if (call_cb) mHalWrapperCallback(HAL_NFC_CLOSE_CPLT_EVT, HAL_NFC_STATUS_OK);

  return 1;
}

void hal_wrapper_send_core_config_prop(int skip) {
  long retlen = 0;
  int isfound = 0;

  // allocate buffer for setting parameters
  if (!skip) {
    ConfigBuffer = (uint8_t*)malloc(256 * sizeof(uint8_t));
  } else {
    STLOG_HAL_D("NFC-NCI HAL: %s  core config skipped (NCI1.0 detected)",
                __func__);
  }
  if (ConfigBuffer != NULL) {
    isfound = GetByteArrayValue(NAME_CORE_CONF_PROP, (char*)ConfigBuffer, 256,
                                &retlen);

    if (isfound > 0) {
      STLOG_HAL_V("%s - Enter", __func__);
      // Are we requesting field ntf?
      {
        int p = 4;  // 1st param
        while (p + 1 < retlen && (p + 2 + ConfigBuffer[p + 1]) <= retlen) {
          if (ConfigBuffer[p] == 0x80 && ConfigBuffer[p + 1] == 0x01 &&
              ConfigBuffer[p + 2] == 0x01) {
            mFieldNtfConfigured = true;
            break;
          }
          p += 2 + ConfigBuffer[p + 1];
        }
      }
      set_ready(0);

      mHalWrapperState = HAL_WRAPPER_STATE_CORE_CONFIG;
      if (!HalSendDownstreamTimer(mHalHandle, ConfigBuffer, retlen, 500)) {
        STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
      }
      wait_ready();
    } else {
      mHalWrapperState = HAL_WRAPPER_STATE_READY;
      mHalWrapperCallback(HAL_NFC_POST_INIT_CPLT_EVT, HAL_NFC_STATUS_OK);
    }
    free(ConfigBuffer);
    ConfigBuffer = NULL;
  } else {
    mHalWrapperState = HAL_WRAPPER_STATE_READY;
    mHalWrapperCallback(HAL_NFC_POST_INIT_CPLT_EVT, HAL_NFC_STATUS_OK);
  }
}

int hal_wrapper_send_config(int skip) {
  if (mHalWrapperState == HAL_WRAPPER_STATE_READY) {
    hal_wrapper_send_core_config_prop(skip);
    return 0;
  }
  if (mHalWrapperState == HAL_WRAPPER_STATE_OPEN_CPLT) {
    hal_wrapper_send_core_config_prop(1);
    return 0;
  }
  // In other states, reject.
  return -1;
}

void hal_wrapper_factoryReset() {
  // mfactoryReset = true;
  STLOG_HAL_V("%s - mfactoryReset = %d", __func__, mfactoryReset);
}

void hal_wrapper_update_complete() {
  STLOG_HAL_V("%s ", __func__);
  mHalWrapperState = HAL_WRAPPER_STATE_OPEN_CPLT;
  mHalWrapperCallback(HAL_NFC_OPEN_CPLT_EVT, HAL_NFC_STATUS_OK);
}

uint8_t* setcmd = NULL;
uint8_t setcmdLen = 0;
uint8_t propNfcReadTestConfig[] = {0x2F, 0x02, 0x05, 0x03,
                                   0x00, 0x11, 0x01, 0x00};
uint8_t propNfcReadNfccConfig[] = {0x2F, 0x02, 0x05, 0x03,
                                   0x00, 0x01, 0x01, 0x00};
uint8_t propNfcReadHwConfig[] = {0x2F, 0x02, 0x05, 0x03,
                                 0x00, 0x02, 0x01, 0x00};
uint8_t propNfcReadInteropConfig[] = {0x2F, 0x02, 0x05, 0x03,
                                      0x00, 0x08, 0x01, 0x00};
extern FWInfo* mFWInfo;
#define IS_ST21NFCD() (mFWInfo != NULL && mFWInfo->chipHwVersion == HW_NFCD)
#define IS_ST54J() (mFWInfo != NULL && mFWInfo->chipHwVersion == HW_ST54J)
void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
  uint8_t propNfcModeSetCmdOn[] = {0x2f, 0x02, 0x02, 0x02, 0x01};
  uint8_t propNfcFetchLogs[] = {0x2f, 0x02, 0x01, 0x21};
  uint8_t propNfcWriteTestConfigHdr[] = {0x2F, 0x02, 0x00 /* len + 6 */,
                                         0x04, 0x00, 0x11,
                                         0x01, 0x00 /* + len + payload */};
  uint8_t propNfcWriteNfccConfigHdr[] = {0x2F, 0x02, 0x00 /* len + 6 */,
                                         0x04, 0x00, 0x01,
                                         0x01, 0x00 /* + len + payload */};
  uint8_t propNfcWriteInteropConfigHdr[] = {0x2F, 0x02, 0x00 /* len + 6 */,
                                            0x04, 0x00, 0x08,
                                            0x01, 0x00 /* + len + payload */};

  uint8_t coreInitCmd[] = {0x20, 0x01, 0x02, 0x00, 0x00};
  uint8_t coreResetCmd[] = {0x20, 0x00, 0x01, 0x01};
  unsigned long num = 0;
  int modifyNdefNfcee = 0;

  if ((mFwLogsUnblocked == false) && (p_data[0] == 0x6f) &&
      (p_data[1] == 0x02)) {
    // Firmware logs must not be sent to upper layer.
    return;
  }

  switch (mHalWrapperState) {
    case HAL_WRAPPER_STATE_CLOSED:  // 0
      STLOG_HAL_V("%s - mHalWrapperState = HAL_WRAPPER_STATE_CLOSED", __func__);
      break;
    case HAL_WRAPPER_STATE_OPEN:  // 1
      // CORE_RESET_NTF
      STLOG_HAL_V("%s - mHalWrapperState = HAL_WRAPPER_STATE_OPEN", __func__);

      if ((p_data[0] == 0x60) && (p_data[1] == 0x00)) {
        mFwUpdateTask = ft_cmd_HwReset(p_data, &mClfMode, mfactoryReset);
        mfactoryReset = (mFwUpdateTask == FU_UPDATE_LOADER);
        STLOG_HAL_V(
            "%s - mFwUpdateTask = %d,  mClfMode = %d,  mRetryFwDwl = %d",
            __func__, mFwUpdateTask, mClfMode, mRetryFwDwl);
        // CLF in MODE LOADER & Update needed.
        if (mClfMode == FT_CLF_MODE_LOADER) {
          // HalSendDownstreamStopTimer(mHalHandle);
          STLOG_HAL_V("%s --- CLF mode is LOADER ---", __func__);
        } else if (mClfMode == FT_CLF_MODE_ROUTER) {
          STLOG_HAL_V("%s - CLF in ROUTER mode", __func__);
        }
        mRetryFwDwl--;
        resetHandlerState();
        if ((mRetryFwDwl == 0) && (mFwUpdateTask != FU_NOTHING_TO_DO)) {
          STLOG_HAL_V(
              "%s - Reached maximum nb of retries, FW update failed, exiting",
              __func__);
          mFwUpdateTask = FU_ERROR;
        }

        if (mClfMode == FT_CLF_MODE_ROUTER &&
            ((mFwUpdateTask == FU_UPDATE_LOADER) ||
             (mFwUpdateTask == FU_UPDATE_FW))) {
          // First, exit hibernate
          if (!HalSendDownstream(mHalHandle, coreResetCmd,
                                 sizeof(coreResetCmd))) {
            STLOG_HAL_E("%s - SendDownstream failed", __func__);
          }
          mHalWrapperState = HAL_WRAPPER_STATE_EXIT_HIBERNATE_INTERNAL;
        } else {
          switch (mFwUpdateTask) {
            case FU_ERROR:
              STLOG_HAL_E("%s - FW update error, exiting", __func__);
              mHalWrapperCallback(HAL_NFC_OPEN_CPLT_EVT, HAL_NFC_STATUS_FAILED);
              break;

            case FU_UPDATE_LOADER:
              STLOG_HAL_V("%s - Send APDU_GET_ATR_CMD", __func__);
              if (!HalSendDownstreamTimer(mHalHandle, ApduGetAtr,
                                          sizeof(ApduGetAtr),
                                          FW_TIMER_DURATION)) {
                STLOG_HAL_E("%s - SendDownstream failed", __func__);
              }
              mHalWrapperState = HAL_WRAPPER_STATE_LD_UPDATE;
              break;

            case FU_UPDATE_FW:
              if (((p_data[3] == 0x01) && (p_data[8] == HW_ST54L)) ||
                  ((p_data[2] == 0x41) && (p_data[3] == 0xA2))) {  // ST54L
                FwUpdateHandler(mHalHandle, data_len, p_data);
              } else {
                STLOG_HAL_V("%s - Send APDU_GET_ATR_CMD", __func__);
                if (!HalSendDownstreamTimer(mHalHandle, ApduGetAtr,
                                            sizeof(ApduGetAtr),
                                            FW_TIMER_DURATION)) {
                  STLOG_HAL_E("%s - SendDownstream failed", __func__);
                }
              }
              mHalWrapperState = HAL_WRAPPER_STATE_UPDATE;
              break;

            case FU_AUTH:
              if ((mClfMode == FT_CLF_MODE_ROUTER) && (p_data[31] == 0xEF) &&
                  (p_data[32] == 0xAC)) {
                mHalWrapperStateConfigInDtaMode = 1;
              }
              STLOG_HAL_V("%s - Send CORE_INIT_CMD", __func__);
              if (!HalSendDownstreamTimer(mHalHandle, coreInitCmd,
                                          sizeof(coreInitCmd),
                                          FW_TIMER_DURATION)) {
                STLOG_HAL_E("%s - SendDownstream failed", __func__);
              }
              mHalWrapperState = HAL_WRAPPER_STATE_AUTH;
              break;

            case FU_UPDATE_PARAMS:
              if (!HalSendDownstream(mHalHandle, coreResetCmd,
                                     sizeof(coreResetCmd))) {
                STLOG_HAL_E("%s - SendDownstream failed", __func__);
              }
              mHalWrapperState = HAL_WRAPPER_STATE_APPLY_CUSTOM_PARAM;
              break;

            case FU_NOTHING_TO_DO:
              if (mClfMode == FT_CLF_MODE_ROUTER) {
                // Check if we find the DTA CRC
                if ((p_data[31] == 0xEF) && (p_data[32] == 0xAC)) {
                  mHalWrapperStateConfigInDtaMode = 1;
                }
                STLOG_HAL_V("%s - Proceeding with startup", __func__);
                mHalWrapperState = HAL_WRAPPER_STATE_OPEN_CPLT;
                mHalWrapperCallback(HAL_NFC_OPEN_CPLT_EVT, HAL_NFC_STATUS_OK);
              } else {
                STLOG_HAL_E("%s - CLF is not in router mode, error", __func__);
                mHalWrapperCallback(HAL_NFC_OPEN_CPLT_EVT,
                                    HAL_NFC_STATUS_FAILED);
              }
              break;
          }
        }
      } else {
        mHalWrapperDataCallback(data_len, p_data);
      }
      break;
    case HAL_WRAPPER_STATE_OPEN_CPLT:  // 2
      STLOG_HAL_V("%s - mHalWrapperState = HAL_WRAPPER_STATE_OPEN_CPLT",
                  __func__);
      // CORE_INIT_RSP
      if ((p_data[0] == 0x40) && (p_data[1] == 0x01)) {
      } else if ((p_data[0] == 0x60) && (p_data[1] == 0x06)) {
        if (GetNumValue(NAME_STNFC_FW_DEBUG_ENABLED, &num, sizeof(num)) &&
            (num & 0x02)) {
          STLOG_HAL_V("%s - Sending FETCH_LOGS", __func__);
          if (!HalSendDownstreamTimer(mHalHandle, propNfcFetchLogs,
                                      sizeof(propNfcFetchLogs), 100)) {
            STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
          }
          mHalWrapperState = HAL_WRAPPER_STATE_FETCH_LOGS;
        } else {
          STLOG_HAL_V("%s - Sending PROP_GET_CONFIG(TEST_CONFIG)", __func__);
          if (!HalSendDownstreamTimer(mHalHandle, propNfcReadTestConfig,
                                      sizeof(propNfcReadTestConfig), 100)) {
            STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
          }
          mHalWrapperState = HAL_WRAPPER_STATE_CONFIG;
          mHalWrapperStateConfigSubstate =
              HAL_WRAPPER_CONFSUBSTATE_TEST_CONFIG_READING;
        }
      } else {
        mHalWrapperDataCallback(data_len, p_data);
      }
      break;
    case HAL_WRAPPER_STATE_FETCH_LOGS:  // 3
      STLOG_HAL_V("%s - mHalWrapperState = HAL_WRAPPER_STATE_FETCH_LOGS",
                  __func__);
      if (p_data[0] == 0x4f) {
        // Wait 100ms before continue to have time to retrieve all the ntfs
        HalSendDownstreamTimer(mHalHandle, 100);
      } else {
        mHalWrapperDataCallback(data_len, p_data);
      }
      break;
    case HAL_WRAPPER_STATE_CONFIG:  // 4
      STLOG_HAL_V("%s - mHalWrapperState = HAL_WRAPPER_STATE_CONFIG", __func__);
      if ((p_data[0] == 0x4f) && (p_data[1] == 0x02)) {
        // Response received
        if (p_data[3] != 0x00) {
          // Status is not OK ==> abandon configuration.
          STLOG_HAL_E("NFC-NCI HAL: %s  unexpected status", __func__);
          mHalWrapperStateConfigSubstate =
              HAL_WRAPPER_CONFSUBSTATE_DONE;  // Done.

        } else if (mHalWrapperStateConfigInDtaMode == 1) {
          STLOG_HAL_D("%s - Skip configuration in DTA mode", __func__);
          mHalWrapperStateConfigSubstate =
              HAL_WRAPPER_CONFSUBSTATE_DONE;  // Done.

        } else {
          int loop;
          do {
            loop = 0;
            switch (mHalWrapperStateConfigSubstate) {
              case HAL_WRAPPER_CONFSUBSTATE_TEST_CONFIG_READING:  // TEST_CONFIG
                                                                  // was read
              {
                // check TEST_CONFIG value is normal.
                if ((p_data[7 + 9] == 0x00) && (p_data[7 + 10] == 0x00)) {
                  // This is abnormal! If we have this value we will kill I2C
                  // comms.
                  STLOG_HAL_E("NFC-NCI HAL: %s  got invalid value !", __func__);
                  assert(0);
                  mHalWrapperStateConfigSubstate =
                      HAL_WRAPPER_CONFSUBSTATE_TEST_CONFIG_WRITING;  // avance
                  loop = 1;
                  break;
                }

// reponse format: 4F022D00010029 + TEST_CONFIG ==> byte 0 of TEST_CONFIG is
// p_data[7]
#define CHECK_CONFIG_BIT_val(bytenr, bitnr) (p_data[7 + bytenr] & (1 << bitnr))
                // These 2 bits in TEST_CONFIG are same in ST21NFCD and ST54J.
                if ((!(CHECK_CONFIG_BIT_val(11, 4) ==
                       0x10))  // SWP activation on
                               // field in switch
                               // off (need to be
                               // set)
                    || (!(CHECK_CONFIG_BIT_val(11, 1) ==
                          0x00))  // CR8  (need to be clear)
                ) {
                  // We need to update it.
                  setcmdLen = sizeof(propNfcWriteTestConfigHdr) + 1 + p_data[6];
                  setcmd = (uint8_t*)malloc(setcmdLen);

                  if (!setcmd) {
                    STLOG_HAL_E("NFC-NCI HAL: %s  malloc error", __func__);
                    mHalWrapperStateConfigSubstate =
                        HAL_WRAPPER_CONFSUBSTATE_DONE;  // Done.
                  } else {
                    // prepare a set command for TEST_CONFIG
                    memcpy(setcmd, propNfcWriteTestConfigHdr,
                           sizeof(propNfcWriteTestConfigHdr));
                    setcmd[2] = p_data[6] + 6;
                    setcmd[sizeof(propNfcWriteTestConfigHdr)] = p_data[6];
                    memcpy(setcmd + sizeof(propNfcWriteTestConfigHdr) + 1,
                           p_data + 7, p_data[6]);

                    // flip the bits we need.
                    setcmd[sizeof(propNfcWriteTestConfigHdr) + 1 + 11] |= 0x10;
                    setcmd[sizeof(propNfcWriteTestConfigHdr) + 1 + 11] &= ~0x02;

                    mHalWrapperStateConfigChanged = true;

                    STLOG_HAL_D("%s - Sending PROP_SET_CONFIG(TEST_CONFIG)",
                                __func__);
                    if (!HalSendDownstreamTimer(mHalHandle, setcmd, setcmdLen,
                                                50)) {
                      STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed",
                                  __func__);
                    }
                    mHalWrapperStateConfigSubstate =
                        HAL_WRAPPER_CONFSUBSTATE_TEST_CONFIG_WRITING;
                  }
                } else {
                  mHalWrapperStateConfigSubstate =
                      HAL_WRAPPER_CONFSUBSTATE_TEST_CONFIG_WRITING;  // avance
                  loop = 1;
                }
              } break;

              case HAL_WRAPPER_CONFSUBSTATE_TEST_CONFIG_WRITING:  // TEST_CONFIG
                                                                  // was set
              {
                STLOG_HAL_D("%s - Sending PROP_GET_CONFIG(HW_CONFIG)",
                            __func__);
                if (!HalSendDownstreamTimer(mHalHandle, propNfcReadHwConfig,
                                            sizeof(propNfcReadHwConfig), 50)) {
                  STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed",
                              __func__);
                }
                mHalWrapperStateConfigSubstate =
                    HAL_WRAPPER_CONFSUBSTATE_HW_CONFIG_READING;
              } break;

              case HAL_WRAPPER_CONFSUBSTATE_HW_CONFIG_READING:  // HW_CONFIG
                                                                // was set
              {
                if (IS_ST54J()) {
                  if (CHECK_CONFIG_BIT_val(20, 0) == 0x01) {
                    STLOG_HAL_D("%s - CLF version : ST54K", __func__);
                  } else {
                    STLOG_HAL_D("%s - CLF version : ST54J", __func__);
                  }
                }
                STLOG_HAL_D("%s - Sending PROP_GET_CONFIG(NFCC_CONFIG)",
                            __func__);
                if (!HalSendDownstreamTimer(mHalHandle, propNfcReadNfccConfig,
                                            sizeof(propNfcReadNfccConfig),
                                            50)) {
                  STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed",
                              __func__);
                }
                mHalWrapperStateConfigSubstate =
                    HAL_WRAPPER_CONFSUBSTATE_NFCC_CONFIG_READING;
              } break;

              case HAL_WRAPPER_CONFSUBSTATE_NFCC_CONFIG_READING:  // NFCC_CONFIG
                                                                  // was read
              {
                // reponse format: 4F022D00010005 + NFCC_CONFIG ==> byte 0 of
                // NFCC_CONFIG is p_data[7]
                // below bit is same between ST21NFCD and ST54J
                num = 0;  // default: NDEF-NFCEE disabled.
                (void)GetNumValue(NAME_NDEF_NFCEE_ENABLE, &num, sizeof(num));
                if ((num == 0) && (CHECK_CONFIG_BIT_val(1, 4) == 0x10)) {
                  // If bit enabled and config disable
                  // disable
                  modifyNdefNfcee = 2;
                } else if ((num == 1) && (CHECK_CONFIG_BIT_val(1, 4) == 0x00)) {
                  // If bit disabled and config enable
                  // enable
                  modifyNdefNfcee = 1;
                }

                if (modifyNdefNfcee != 0)  // Change needed
                {
                  // We need to update it.
                  setcmdLen = sizeof(propNfcWriteNfccConfigHdr) + 1 + p_data[6];
                  setcmd = (uint8_t*)realloc(setcmd, setcmdLen);
                  if (!setcmd) {
                    STLOG_HAL_E("NFC-NCI HAL: %s  malloc error", __func__);
                    mHalWrapperStateConfigSubstate =
                        HAL_WRAPPER_CONFSUBSTATE_DONE;  // Done.
                  } else {
                    // prepare a set command for NFCC_CONFIG
                    memcpy(setcmd, propNfcWriteNfccConfigHdr,
                           sizeof(propNfcWriteNfccConfigHdr));
                    setcmd[2] = p_data[6] + 6;
                    setcmd[sizeof(propNfcWriteNfccConfigHdr)] = p_data[6];
                    memcpy(setcmd + sizeof(propNfcWriteNfccConfigHdr) + 1,
                           p_data + 7, p_data[6]);

                    // flip the bits we need.
                    if (modifyNdefNfcee == 1) {
                      // enable
                      setcmd[sizeof(propNfcWriteNfccConfigHdr) + 1 + 1] |= 0x10;
                    } else {
                      // disable
                      setcmd[sizeof(propNfcWriteNfccConfigHdr) + 1 + 1] &=
                          ~0x10;
                    }

                    mHalWrapperStateConfigChanged = true;

                    STLOG_HAL_D("%s - Sending PROP_SET_CONFIG(NFCC_CONFIG)",
                                __func__);
                    if (!HalSendDownstreamTimer(mHalHandle, setcmd, setcmdLen,
                                                50)) {
                      STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed",
                                  __func__);
                    }
                    mHalWrapperStateConfigSubstate =
                        HAL_WRAPPER_CONFSUBSTATE_NFCC_CONFIG_WRITING;
                  }
                } else {
                  mHalWrapperStateConfigSubstate =
                      HAL_WRAPPER_CONFSUBSTATE_NFCC_CONFIG_WRITING;  // avance
                  loop = 1;
                }
              } break;

              case HAL_WRAPPER_CONFSUBSTATE_NFCC_CONFIG_WRITING:  // NFCC_CONFIG
                                                                  // was set
              {
                STLOG_HAL_D("%s - Sending PROP_GET_CONFIG(LOGGING_CONFIG)",
                            __func__);
                if (!HalSendDownstreamTimer(
                        mHalHandle, nciPropGetFwDbgTracesConfig,
                        sizeof(nciPropGetFwDbgTracesConfig), 50)) {
                  STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed",
                              __func__);
                }
                mHalWrapperStateConfigSubstate =
                    HAL_WRAPPER_CONFSUBSTATE_LOGGING_CONFIG_READING;
              } break;

              case HAL_WRAPPER_CONFSUBSTATE_LOGGING_CONFIG_READING:  // LOGGING
                                                                     // was read
              {
                if (GetNumValue(NAME_STNFC_FW_DEBUG_ENABLED, &num,
                                sizeof(num))) {
                  if (((num != 0) && (p_data[7] == 0)) ||
                      ((num == 0) && (p_data[7] != 0)) ||
                      ((num & 0x02) && (p_data[13] == 0)) ||
                      (((num & 0x02) == 0) && (p_data[13] == 0x01)) ||
                      ((num & 0x04) && (p_data[28] == 0)) ||
                      (((num & 0x04) == 0) && (p_data[28] == 0x01))) {
                    // we need to change the config.
                    // logging_config length: p_data[6]
                    memcpy(nciPropEnableFwDbgTraces, nciHeaderPropSetConfig,
                           sizeof(nciHeaderPropSetConfig));
                    nciPropEnableFwDbgTraces[2] = p_data[6] + 6;
                    nciPropEnableFwDbgTraces[8] = p_data[6];
                    memcpy(&nciPropEnableFwDbgTraces[9], &p_data[7], p_data[6]);
                    // change the enable / disable byte
                    nciPropEnableFwDbgTraces[9] = ((num == 0) ? 0x00 : 0x01);
                    // bit 2 in NAME_STNFC_FW_DEBUG_ENABLED: controls byte 6
                    nciPropEnableFwDbgTraces[15] =
                        (((num & 0x2) == 0) ? 0x00 : 0x01);
                    // bit 3 in NAME_STNFC_FW_DEBUG_ENABLED: controls bytes 21
                    // and 58
                    nciPropEnableFwDbgTraces[30] =
                        nciPropEnableFwDbgTraces[67] =
                            (((num & 0x4) == 0) ? 0x00 : 0x01);

                    nciPropEnableFwDbgTracesLen = p_data[6] + 9;
                    mHalWrapperStateConfigChanged = true;
                    STLOG_HAL_D("%s - Sending PROP_SET_CONFIG(LOGGING_CONFIG)",
                                __func__);
                    if (!HalSendDownstreamTimer(
                            mHalHandle, nciPropEnableFwDbgTraces,
                            nciPropEnableFwDbgTracesLen, 50)) {
                      STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed",
                                  __func__);
                    }
                    mHalWrapperStateConfigSubstate =
                        HAL_WRAPPER_CONFSUBSTATE_LOGGING_CONFIG_WRITING;
                  } else {
                    STLOG_HAL_D("%s - FW logs are already %s", __func__,
                                (p_data[7] == 0) ? "disabled" : "enabled");
                    mHalWrapperStateConfigSubstate =
                        HAL_WRAPPER_CONFSUBSTATE_LOGGING_CONFIG_WRITING;
                    loop = 1;
                  }
                } else {
                  // Failed to read the config, don t change the value.
                  STLOG_HAL_D(
                      "%s - STNFC_FW_DEBUG_ENABLED not configured, keep %s",
                      __func__, (p_data[7] == 0) ? "disabled" : "enabled");
                  mHalWrapperStateConfigSubstate =
                      HAL_WRAPPER_CONFSUBSTATE_LOGGING_CONFIG_WRITING;
                  loop = 1;
                }
              } break;

              case HAL_WRAPPER_CONFSUBSTATE_LOGGING_CONFIG_WRITING:  // LOGGING
                                                                     // was set
              {
                STLOG_HAL_D("%s - Sending PROP_GET_CONFIG(IOT_CONFIG)",
                            __func__);
                if (!HalSendDownstreamTimer(
                        mHalHandle, propNfcReadInteropConfig,
                        sizeof(propNfcReadInteropConfig), 50)) {
                  STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed",
                              __func__);
                }
                mHalWrapperStateConfigSubstate =
                    HAL_WRAPPER_CONFSUBSTATE_IOT_CONFIG_READING;
              } break;

              case HAL_WRAPPER_CONFSUBSTATE_IOT_CONFIG_READING:  // IOT_CONFIG
                                                                 // was read
              {
                // We check this only for ST21NFCD for compatibility with legacy
                // scripts.
                if (IS_ST21NFCD() &&
                    ((CHECK_CONFIG_BIT_val(2, 3) ==
                      0x00)  // AID Forward mode not activated
                     || (CHECK_CONFIG_BIT_val(6, 7) ==
                         0x00)))  // FW 1.7 RNAK dyn params not activated
                {
                  // We need to update it.
                  setcmdLen =
                      sizeof(propNfcWriteInteropConfigHdr) + 1 + p_data[6];
                  setcmd = (uint8_t*)realloc(setcmd, setcmdLen);

                  if (!setcmd) {
                    STLOG_HAL_E("NFC-NCI HAL: %s  malloc error", __func__);
                    mHalWrapperStateConfigSubstate =
                        HAL_WRAPPER_CONFSUBSTATE_DONE;  // Done.
                  } else {
                    // prepare a set command for IOT_CONFIG
                    memcpy(setcmd, propNfcWriteInteropConfigHdr,
                           sizeof(propNfcWriteInteropConfigHdr));
                    setcmd[2] = p_data[6] + 6;
                    setcmd[sizeof(propNfcWriteInteropConfigHdr)] = p_data[6];
                    memcpy(setcmd + sizeof(propNfcWriteInteropConfigHdr) + 1,
                           p_data + 7, p_data[6]);

                    // flip the bits we need.
                    setcmd[sizeof(propNfcWriteInteropConfigHdr) + 1 + 2] |=
                        0x08;

                    // if ISO-DEP RNAK dyn params is disabled, assume legacy
                    // config file and apply FW 1.7 default settings. This is
                    // NOOP for older FW.
                    if (p_data[13] == 0x00 && p_data[14] == 0x00 &&
                        p_data[15] == 0x00) {
                      setcmd[sizeof(propNfcWriteInteropConfigHdr) + 1 + 6] =
                          0xC1;
                      setcmd[sizeof(propNfcWriteInteropConfigHdr) + 1 + 7] =
                          0xC2;
                      setcmd[sizeof(propNfcWriteInteropConfigHdr) + 1 + 8] =
                          0xC2;
                    }

                    mHalWrapperStateConfigChanged = true;
                    STLOG_HAL_D("%s - Sending PROP_SET_CONFIG(IOT_CONFIG)",
                                __func__);
                    if (!HalSendDownstreamTimer(mHalHandle, setcmd, setcmdLen,
                                                50)) {
                      STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed",
                                  __func__);
                    }
                    mHalWrapperStateConfigSubstate =
                        HAL_WRAPPER_CONFSUBSTATE_IOT_CONFIG_WRITING;
                  }
                } else {
                  mHalWrapperStateConfigSubstate =
                      HAL_WRAPPER_CONFSUBSTATE_IOT_CONFIG_WRITING;  // avance
                  loop = 1;
                }
              } break;

              case HAL_WRAPPER_CONFSUBSTATE_IOT_CONFIG_WRITING:  // IOT
                                                                 // was set
              {
                free(setcmd);
                setcmd = NULL;
                setcmdLen = 0;
                mHalWrapperStateConfigSubstate = HAL_WRAPPER_CONFSUBSTATE_DONE;
              } break;

              default:
                STLOG_HAL_E("NFC-NCI HAL: %s  unexpected substate %d", __func__,
                            mHalWrapperStateConfigSubstate);
                mHalWrapperStateConfigSubstate =
                    HAL_WRAPPER_CONFSUBSTATE_DONE;  // Done.
            }
          } while (loop);
        }

        // check if CONFIG phase is complete
        if (mHalWrapperStateConfigSubstate == HAL_WRAPPER_CONFSUBSTATE_DONE) {
          STLOG_HAL_D("%s - Sending PROP_NFC_MODE_SET_CMD", __func__);
          // Send PROP_NFC_MODE_SET_CMD(ON)
          if (!HalSendDownstreamTimer(mHalHandle, propNfcModeSetCmdOn,
                                      sizeof(propNfcModeSetCmdOn), 100)) {
            STLOG_HAL_E("NFC-NCI HAL: %s  HalSendDownstreamTimer failed",
                        __func__);
          }
          mHalWrapperState = HAL_WRAPPER_STATE_NFC_ENABLE_ON;
        }
      } else {
        mHalWrapperDataCallback(data_len, p_data);
      }
      break;

    case HAL_WRAPPER_STATE_NFC_ENABLE_ON:  // 4
      STLOG_HAL_V("%s - mHalWrapperState = HAL_WRAPPER_STATE_NFC_ENABLE_ON",
                  __func__);
      // PROP_NFC_MODE_SET_RSP
      if ((p_data[0] == 0x4f) && (p_data[1] == 0x02)) {
        // DO nothing: wait for core_reset_ntf or timer timeout
      }
      // CORE_RESET_NTF
      else if ((p_data[0] == 0x60) && (p_data[1] == 0x00) && (!isTimeout)) {
        // Stop timer
        HalSendDownstreamStopTimer(mHalHandle);
        if (forceRecover == true) {
          forceRecover = false;
          mHalWrapperDataCallback(data_len, p_data);
          break;
        }

        if (mHalWrapperStateConfigChanged) {
          mHalWrapperStateConfigChanged = false;
          STLOG_HAL_D("%s - Config was updated, reset the chip", __func__);
          I2cResetPulse();
          break;
        }

        // Send CORE_INIT_CMD
        STLOG_HAL_V("%s - Sending CORE_INIT_CMD", __func__);
        if (!HalSendDownstream(mHalHandle, coreInitCmd, sizeof(coreInitCmd))) {
          STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
        }
      }
      // CORE_INIT_RSP
      else if ((p_data[0] == 0x40) && (p_data[1] == 0x01)) {
        STLOG_HAL_D("%s - NFC mode enabled", __func__);
        // Do we need to lend a credit ?
        if (p_data[13] == 0x00) {
          STLOG_HAL_D("%s - 1 credit lent", __func__);
          p_data[13] = 0x01;
          mHciCreditLent = true;
        }
        if (isTimeout) {
          isTimeout = false;
        }

        mHalWrapperState = HAL_WRAPPER_STATE_READY;
        mHalWrapperDataCallback(data_len, p_data);
      }
      break;

    case HAL_WRAPPER_STATE_CORE_CONFIG:
      STLOG_HAL_V("%s - mHalWrapperState = HAL_WRAPPER_STATE_CORE_CONFIG",
                  __func__);
      // CORE_SET_CONFIG_RSP
      if ((p_data[0] == 0x40) && (p_data[1] == 0x02)) {
        HalSendDownstreamStopTimer(mHalHandle);
        if (!mFieldNtfConfigured) {
          STLOG_HAL_V(
              "%s - Received config RSP, deliver CORE_INIT_RSP to upper layer",
              __func__);
          set_ready(1);

          mHalWrapperCallback(HAL_NFC_POST_INIT_CPLT_EVT, HAL_NFC_STATUS_OK);
          mHalWrapperState = HAL_WRAPPER_STATE_READY;
        }
      } else if (mFieldNtfConfigured && (p_data[0] == 0x61) &&
                 (p_data[1] == 0x07)) {
        STLOG_HAL_V(
            "%s - Received field NTF, deliver CORE_INIT_RSP to upper layer",
            __func__);
        set_ready(1);

        mHalWrapperCallback(HAL_NFC_POST_INIT_CPLT_EVT, HAL_NFC_STATUS_OK);
        mHalWrapperState = HAL_WRAPPER_STATE_READY;
      } else if (mHciCreditLent && (p_data[0] == 0x60) && (p_data[1] == 0x06)) {
        if (p_data[4] == 0x01) {  // HCI connection
          mHciCreditLent = false;
          STLOG_HAL_D("%s - credit returned", __func__);
          if (p_data[5] == 0x01) {
            // no need to send this.
            break;
          } else {
            if (p_data[5] != 0x00 && p_data[5] != 0xFF) {
              // send with 1 less
              p_data[5]--;
            }
          }
        }
        mHalWrapperDataCallback(data_len, p_data);
      } else {
        STLOG_HAL_D(
            "%s - HAL_WRAPPER_STATE_CORE_CONFIG, received unexpected data "
            "%02hhx %02hhx ...",
            __func__, p_data[0], p_data[1]);
        mHalWrapperDataCallback(data_len, p_data);
      }
      break;
    case HAL_WRAPPER_STATE_READY:
      STLOG_HAL_V("%s - mHalWrapperState = HAL_WRAPPER_STATE_READY", __func__);
      if (!((p_data[0] == 0x60) && (p_data[3] == 0xa0))) {
        if (mHciCreditLent && (p_data[0] == 0x60) && (p_data[1] == 0x06)) {
          if (p_data[4] == 0x01) {  // HCI connection
            mHciCreditLent = false;
            STLOG_HAL_D("%s - credit returned", __func__);
            if (p_data[5] == 0x01) {
              // no need to send this.
              break;
            } else {
              if (p_data[5] != 0x00 && p_data[5] != 0xFF) {
                // send with 1 less
                p_data[5]--;
              }
            }
          }
        } else if ((p_data[0] == 0x6f) && (p_data[1] == 0x05)) {
          // start timer
          mTimerStarted = true;
          HalSendDownstreamTimer(mHalHandle, 5000);
          mIsActiveRW = true;
        } else if ((p_data[0] == 0x6f) && (p_data[1] == 0x06)) {
          // stop timer
          if (mTimerStarted) {
            HalSendDownstreamStopTimer(mHalHandle);
            mTimerStarted = false;
          }
          if (mIsActiveRW == true) {
            mIsActiveRW = false;
          } else {
            mError_count++;
            STLOG_HAL_E("Error Act -> Act count=%d", mError_count);
            if (mError_count > 20) {
              mError_count = 0;
              STLOG_HAL_E("NFC Recovery Start");
              mTimerStarted = true;
              HalSendDownstreamTimer(mHalHandle, 1);
            }
          }
        } else if (((p_data[0] == 0x61) && (p_data[1] == 0x05)) ||
                   ((p_data[0] == 0x61) && (p_data[1] == 0x03))) {
          mError_count = 0;
          // stop timer
          if (mTimerStarted) {
            HalSendDownstreamStopTimer(mHalHandle);
            mTimerStarted = false;
          }
        } else if ((p_data[0] != 0x40) && (p_data[0] != 0x60) &&
                   (p_data[0] != 0x41) && (p_data[0] != 0x61) &&
                   (p_data[0] != 0x42) && (p_data[0] != 0x62) &&
                   (p_data[0] != 0x4f) && (p_data[0] != 0x6f) &&
                   (p_data[0] != 0x00) && (p_data[0] != 0x10) &&
                   (p_data[0] != 0x01) && (p_data[0] != 0x11) &&
                   (p_data[0] != 0x02) && (p_data[0] != 0x12)) {
          // Check if incorrect frame
          // If so, send back fabricated CORE_RESET_NTF(abnormal) to force stack
          // restart
          STLOG_HAL_E("Received erroneous data, sending back CORE_RESET_NTF");
          p_data = nciCoreResetNtfAbnormal;
          data_len = sizeof(nciCoreResetNtfAbnormal);
          mNfceeModeSetPendingId = false;
        }
        if (mNfceeModeSetPendingId) {
          if ((p_data[0] == 0x42) && (p_data[1] == 0x01) &&
              (p_data[2] == 0x01) && (p_data[3] != 0x00)) {
            // NFCEE_MODE_SET_RSP received with error
            mNfceeModeSetPendingId = 0x00;
            if (mNfceeModeSetPendingMode == 0x01) {
              // activation failed
              if (i2cNfccMayUseEse(0) != 0) {
                STLOG_HAL_W("NFC-NCI HAL: %s  i2cNfccMayUseEse(0) failed",
                            __func__);
              }
            }
          } else if ((p_data[0] == 0x62) && (p_data[1] == 0x01) &&
                     (p_data[2] == 0x01)) {
            // NFCEE_MODE_SET_NTF received
            mNfceeModeSetPendingId = 0x00;
            if ((mNfceeModeSetPendingMode == 0x01) && (p_data[3] != 0x00)) {
              // activation failed
              if (i2cNfccMayUseEse(0) != 0) {
                STLOG_HAL_W("NFC-NCI HAL: %s  i2cNfccMayUseEse(0) failed",
                            __func__);
              }
            } else if ((mNfceeModeSetPendingMode == 0x00) &&
                       (p_data[3] == 0x00)) {
              // deactivation successful
              if (i2cNfccMayUseEse(0) != 0) {
                STLOG_HAL_W("NFC-NCI HAL: %s  i2cNfccMayUseEse(0) failed",
                            __func__);
              }
            }
          }
        }
        mHalWrapperDataCallback(data_len, p_data);
      } else if (forceRecover == true) {
        forceRecover = false;
        mHalWrapperDataCallback(data_len, p_data);
      } else {
        STLOG_HAL_V("%s - Core reset notification - Nfc mode ", __func__);
      }
      break;

    case HAL_WRAPPER_STATE_CLOSING_FETCH_LOGS:
      STLOG_HAL_V(
          "%s - mHalWrapperState = HAL_WRAPPER_STATE_CLOSING_FETCH_LOGS",
          __func__);
      if (p_data[0] == 0x4f) {
        HalSendDownstreamStopTimer(mHalHandle);
      }
      break;

    case HAL_WRAPPER_STATE_CLOSING:
      STLOG_HAL_V("%s - mHalWrapperState = HAL_WRAPPER_STATE_CLOSING",
                  __func__);
      if ((p_data[0] == 0x4f) && (p_data[1] == 0x02)) {
        HalSendDownstreamStopTimer(mHalHandle);
        hal_fd_close();
        // intercept this expected message, don t forward.
        mHalWrapperState = HAL_WRAPPER_STATE_CLOSED;
      } else {
        mHalWrapperDataCallback(data_len, p_data);
      }
      break;

    case HAL_WRAPPER_STATE_EXIT_HIBERNATE_INTERNAL:  // 6
      STLOG_HAL_V(
          "%s - mHalWrapperState = HAL_WRAPPER_STATE_EXIT_HIBERNATE_INTERNAL",
          __func__);
      ExitHibernateHandler(mHalHandle, data_len, p_data);
      break;
    case HAL_WRAPPER_STATE_LD_UPDATE:  // 7
      STLOG_HAL_V("%s - mHalWrapperState = HAL_WRAPPER_STATE_LD_UPDATE",
                  __func__);
      LdUpdateHandler(mHalHandle, data_len, p_data);
      break;
    case HAL_WRAPPER_STATE_UPDATE:  // 7
      STLOG_HAL_V("%s - mHalWrapperState = HAL_WRAPPER_STATE_UPDATE", __func__);
      FwUpdateHandler(mHalHandle, data_len, p_data);
      break;
    case HAL_WRAPPER_STATE_AUTH:  // 8
      STLOG_HAL_V("%s - mHalWrapperState = HAL_WRAPPER_STATE_AUTH", __func__);
      HalSendDownstreamStopTimer(mHalHandle);
      AuthHandler(mHalHandle, data_len, p_data, &mHalWrapperState);
      if (mHalWrapperState == HAL_WRAPPER_STATE_OPEN_CPLT) {
        AuthCheckUnload();
        mHalWrapperCallback(HAL_NFC_OPEN_CPLT_EVT, HAL_NFC_STATUS_OK);
      }
      break;
    case HAL_WRAPPER_STATE_APPLY_CUSTOM_PARAM:  // 9
      STLOG_HAL_V(
          "%s - mHalWrapperState = HAL_WRAPPER_STATE_APPLY_CUSTOM_PARAM",
          __func__);
      ApplyCustomParamHandler(mHalHandle, data_len, p_data);
      break;
  }
}

static void halWrapperCallback(uint8_t event,
                               __attribute__((unused)) uint8_t event_status) {
  uint8_t coreInitCmd[] = {0x20, 0x01, 0x02, 0x00, 0x00};

  switch (mHalWrapperState) {
    case HAL_WRAPPER_STATE_FETCH_LOGS:  // 3
      if (event == HAL_WRAPPER_TIMEOUT_EVT) {
        HalSendDownstreamStopTimer(mHalHandle);
        STLOG_HAL_V("%s - Sending PROP_GET_CONFIG(TEST_CONFIG)", __func__);
        if (!HalSendDownstreamTimer(mHalHandle, propNfcReadTestConfig,
                                    sizeof(propNfcReadTestConfig), 100)) {
          STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
        }
        mHalWrapperState = HAL_WRAPPER_STATE_CONFIG;
        mHalWrapperStateConfigSubstate =
            HAL_WRAPPER_CONFSUBSTATE_TEST_CONFIG_READING;
        return;
      }
      break;

    case HAL_WRAPPER_STATE_CONFIG:
      if (event == HAL_WRAPPER_TIMEOUT_EVT) {
        HalSendDownstreamStopTimer(mHalHandle);

        switch (mHalWrapperStateConfigSubstate) {
          case HAL_WRAPPER_CONFSUBSTATE_TEST_CONFIG_READING:
            STLOG_HAL_V("%s - Sending PROP_GET_CONFIG(TEST_CONFIG)", __func__);
            if (!HalSendDownstreamTimer(mHalHandle, propNfcReadTestConfig,
                                        sizeof(propNfcReadTestConfig), 100)) {
              STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
            }
            break;
          case HAL_WRAPPER_CONFSUBSTATE_TEST_CONFIG_WRITING:
            STLOG_HAL_D("%s - Sending PROP_SET_CONFIG(TEST_CONFIG)", __func__);
            if (!HalSendDownstreamTimer(mHalHandle, setcmd, setcmdLen, 100)) {
              STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
            }
            break;
          case HAL_WRAPPER_CONFSUBSTATE_HW_CONFIG_READING:
            STLOG_HAL_D("%s - Sending PROP_GET_CONFIG(HW_CONFIG)", __func__);
            if (!HalSendDownstreamTimer(mHalHandle, propNfcReadHwConfig,
                                        sizeof(propNfcReadHwConfig), 100)) {
              STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
            }
            break;
          case HAL_WRAPPER_CONFSUBSTATE_NFCC_CONFIG_READING:
            STLOG_HAL_D("%s - Sending PROP_GET_CONFIG(NFCC_CONFIG)", __func__);
            if (!HalSendDownstreamTimer(mHalHandle, propNfcReadNfccConfig,
                                        sizeof(propNfcReadNfccConfig), 100)) {
              STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
            }
            break;
          case HAL_WRAPPER_CONFSUBSTATE_NFCC_CONFIG_WRITING:
            STLOG_HAL_D("%s - Sending PROP_SET_CONFIG(NFCC_CONFIG)", __func__);
            if (!HalSendDownstreamTimer(mHalHandle, setcmd, setcmdLen, 100)) {
              STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
            }
            break;
          case HAL_WRAPPER_CONFSUBSTATE_LOGGING_CONFIG_READING:
            if (!HalSendDownstreamTimer(mHalHandle, nciPropGetFwDbgTracesConfig,
                                        sizeof(nciPropGetFwDbgTracesConfig),
                                        100)) {
              STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
            }
            break;
          case HAL_WRAPPER_CONFSUBSTATE_LOGGING_CONFIG_WRITING:
            STLOG_HAL_D("%s - Sending PROP_SET_CONFIG(LOGGING_CONFIG)",
                        __func__);
            if (!HalSendDownstreamTimer(mHalHandle, nciPropEnableFwDbgTraces,
                                        nciPropEnableFwDbgTracesLen, 100)) {
              STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
            }
            break;
          case HAL_WRAPPER_CONFSUBSTATE_IOT_CONFIG_READING:
            STLOG_HAL_D("%s - Sending PROP_GET_CONFIG(IOT_CONFIG)", __func__);
            if (!HalSendDownstreamTimer(mHalHandle, propNfcReadInteropConfig,
                                        sizeof(propNfcReadInteropConfig),
                                        100)) {
              STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
            }
            break;
          case HAL_WRAPPER_CONFSUBSTATE_IOT_CONFIG_WRITING:
            STLOG_HAL_D("%s - Sending PROP_SET_CONFIG(IOT_CONFIG)", __func__);
            if (!HalSendDownstreamTimer(mHalHandle, setcmd, setcmdLen, 100)) {
              STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
            }
            break;
        }

        return;
      }
      break;

    case HAL_WRAPPER_STATE_CLOSING:
      if (event == HAL_WRAPPER_TIMEOUT_EVT) {
        STLOG_HAL_D("NFC-NCI HAL: %s  Timeout. Close anyway", __func__);
        HalSendDownstreamStopTimer(mHalHandle);
        hal_fd_close();
        mHalWrapperState = HAL_WRAPPER_STATE_CLOSED;
        return;
      }
      break;

    case HAL_WRAPPER_STATE_OPEN:
      if (event == HAL_WRAPPER_TIMEOUT_EVT) {
        STLOG_HAL_D(
            "NFC-NCI HAL: %s  Timeout accessing the CLF. Recoveries %d/%d",
            __func__, recoveryCount, recoveryMax);
        HalSendDownstreamStopTimer(mHalHandle);
        if (recoveryCount < recoveryMax) {
          I2cRecovery();
          recoveryCount++;
          HalSendDownstreamTimer(mHalHandle, 5000);
        } else {
          // Failed to open.
          mHalWrapperCallback(HAL_NFC_OPEN_CPLT_EVT, HAL_NFC_STATUS_FAILED);
        }
        return;
      }
      break;

    case HAL_WRAPPER_STATE_CLOSED:
      if (event == HAL_WRAPPER_TIMEOUT_EVT) {
        STLOG_HAL_D("NFC-NCI HAL: %s  Timeout. Close anyway", __func__);
        HalSendDownstreamStopTimer(mHalHandle);
        return;
      }
      break;

    case HAL_WRAPPER_STATE_LD_UPDATE:
    case HAL_WRAPPER_STATE_UPDATE:
    case HAL_WRAPPER_STATE_AUTH:
      if (event == HAL_WRAPPER_TIMEOUT_EVT) {
        STLOG_HAL_E("%s - Timer for FW update procedure timeout, retry",
                    __func__);
        HalSendDownstreamStopTimer(mHalHandle);
        mHalWrapperState = HAL_WRAPPER_STATE_OPEN;
        resetHandlerState();
        I2cResetPulse();
      }
      break;

    case HAL_WRAPPER_STATE_NFC_ENABLE_ON:
      if (event == HAL_WRAPPER_TIMEOUT_EVT) {
        HalSendDownstreamStopTimer(mHalHandle);
        // timeout
        isTimeout = true;
        // Send CORE_INIT_CMD
        STLOG_HAL_V("%s - Sending CORE_INIT_CMD", __func__);
        if (!HalSendDownstream(mHalHandle, coreInitCmd, sizeof(coreInitCmd))) {
          STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
        }
        return;
      }
      break;

    case HAL_WRAPPER_STATE_CORE_CONFIG:
      if (event == HAL_WRAPPER_TIMEOUT_EVT) {
        STLOG_HAL_E("%s - Timer when sending conf parameters, retry", __func__);
        HalSendDownstreamStopTimer(mHalHandle);
        mHalWrapperState = HAL_WRAPPER_STATE_OPEN;
        resetHandlerState();
        I2cResetPulse();
      }
      break;

    case HAL_WRAPPER_STATE_READY:
      if (event == HAL_WRAPPER_TIMEOUT_EVT) {
        if (mTimerStarted) {
          STLOG_HAL_D("NFC-NCI HAL: %s  Timeout.. Recover", __func__);
          HalSendDownstreamStopTimer(mHalHandle);
          mTimerStarted = false;
          forceRecover = true;
          resetHandlerState();
          I2cResetPulse();
          mHalWrapperState = HAL_WRAPPER_STATE_OPEN;
        }
        return;
      }
      break;

    default:
      break;
  }

  mHalWrapperCallback(event, event_status);
}

/*******************************************************************************
 **
 ** Function         nfc_set_state
 **
 ** Description      Set the state of NFC stack
 **
 ** Returns          void
 **
 *******************************************************************************/
void hal_wrapper_set_state(hal_wrapper_state_e new_wrapper_state) {
  ALOGD("nfc_set_state %d->%d", mHalWrapperState, new_wrapper_state);

  mHalWrapperState = new_wrapper_state;
}

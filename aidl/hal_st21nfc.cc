/******************************************************************************
 *
 *  Copyright (C) 1999-2012 Broadcom Corporation
 *  Copyright (C) 2013 ST Microelectronics S.A.
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
 *  Modified by ST Microelectronics S.A. (adaptation of nfc_nci.c for ST21NFC
 *NCI version)
 *
 ******************************************************************************/

#include <android-base/properties.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>

#include "StNfc_hal_api.h"
#include "android_logmsg.h"
#include "hal_config.h"
#include "halcore.h"
#include "st21nfc_dev.h"

#define VENDOR_LIB_PATH "/vendor/lib64/"
#define VENDOR_LIB_EXT ".so"

bool dbg_logging = false;

extern void HalCoreCallback(void* context, uint32_t event, const void* d,
                            size_t length);
extern bool I2cOpenLayer(void* dev, HAL_CALLBACK callb, HALHANDLE* pHandle);
extern void i2cSetTimeBetweenCmds(int ms);

typedef int (*STEseReset)(void);

const char* halVersion = "ST21NFC AIDL HAL Version 140-20230525-23W21p0";

uint8_t cmd_set_nfc_mode_enable[] = {0x2f, 0x02, 0x02, 0x02, 0x01};
uint8_t hal_is_closed = 1;
pthread_mutex_t hal_mtx = PTHREAD_MUTEX_INITIALIZER;
st21nfc_dev_t dev;
int nfc_mode = 0;
int delay_in_raw_mode = 20;

/*
 * NCI HAL method implementations. These must be overridden
 */

extern bool hal_wrapper_open(st21nfc_dev_t* dev, nfc_stack_callback_t* p_cback,
                             nfc_stack_data_callback_t* p_data_cback,
                             HALHANDLE* pHandle);

extern int hal_wrapper_close(int call_cb, int nfc_mode);

static bool client_is_nci_10 = false;

extern void hal_wrapper_nfceeModeSetSent(uint8_t id, uint8_t mode);
extern void hal_wrapper_unblockFwLogs();
extern int hal_wrapper_send_config(int skip);
extern void hal_wrapper_factoryReset();

/* Make sure to always post nfc_stack_callback_t in a separate thread.
This prevents a possible deadlock in upper layer on some sequences.
We need to synchronize finely for the callback called for hal close,
otherwise the upper layer either does not receive the event, or deadlocks,
because the HAL is closing while the callback may be blocked.
 */
static struct async_callback_struct {
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  pthread_t thr;
  int event_pending;
  int stop_thread;
  int thread_running;
  nfc_event_t event;
  nfc_status_t event_status;
} async_callback_data;

static void* async_callback_thread_fct(void* arg) {
  int ret;
  struct async_callback_struct* pcb_data = (struct async_callback_struct*)arg;

  ret = pthread_mutex_lock(&pcb_data->mutex);
  if (ret != 0) {
    STLOG_HAL_E("HAL: %s pthread_mutex_lock failed", __func__);
    goto error;
  }

  do {
    if (pcb_data->event_pending == 0) {
      ret = pthread_cond_wait(&pcb_data->cond, &pcb_data->mutex);
      if (ret != 0) {
        STLOG_HAL_E("HAL: %s pthread_cond_wait failed", __func__);
        break;
      }
    }

    if (pcb_data->event_pending) {
      nfc_event_t event = pcb_data->event;
      nfc_status_t event_status = pcb_data->event_status;
      int ending = pcb_data->stop_thread;
      pcb_data->event_pending = 0;
      ret = pthread_cond_signal(&pcb_data->cond);
      if (ret != 0) {
        STLOG_HAL_E("HAL: %s pthread_cond_signal failed", __func__);
        break;
      }
      if (ending) {
        pcb_data->thread_running = 0;
      }
      ret = pthread_mutex_unlock(&pcb_data->mutex);
      if (ret != 0) {
        STLOG_HAL_E("HAL: %s pthread_mutex_unlock failed", __func__);
      }
      STLOG_HAL_D("HAL st21nfc: %s event %hhx status %hhx", __func__, event,
                  event_status);
      dev.p_cback_unwrap(event, event_status);
      if (ending) {
        return NULL;
      }
      ret = pthread_mutex_lock(&pcb_data->mutex);
      if (ret != 0) {
        STLOG_HAL_E("HAL: %s pthread_mutex_lock failed", __func__);
        goto error;
      }
    }
  } while (pcb_data->stop_thread == 0 || pcb_data->event_pending);

  ret = pthread_mutex_unlock(&pcb_data->mutex);
  if (ret != 0) {
    STLOG_HAL_E("HAL: %s pthread_mutex_unlock failed", __func__);
  }

error:
  pcb_data->thread_running = 0;
  return NULL;
}

static int async_callback_thread_start() {
  int ret;

  memset(&async_callback_data, 0, sizeof(async_callback_data));

  ret = pthread_mutex_init(&async_callback_data.mutex, NULL);
  if (ret != 0) {
    STLOG_HAL_E("HAL: %s pthread_mutex_init failed", __func__);
    return ret;
  }

  ret = pthread_cond_init(&async_callback_data.cond, NULL);
  if (ret != 0) {
    STLOG_HAL_E("HAL: %s pthread_cond_init failed", __func__);
    return ret;
  }

  async_callback_data.thread_running = 1;

  ret = pthread_create(&async_callback_data.thr, NULL,
                       async_callback_thread_fct, &async_callback_data);
  if (ret != 0) {
    STLOG_HAL_E("HAL: %s pthread_create failed", __func__);
    async_callback_data.thread_running = 0;
    return ret;
  }

  return 0;
}

static int async_callback_thread_end() {
  if (async_callback_data.thread_running != 0) {
    int ret;

    ret = pthread_mutex_lock(&async_callback_data.mutex);
    if (ret != 0) {
      STLOG_HAL_E("HAL: %s pthread_mutex_lock failed", __func__);
      return ret;
    }

    async_callback_data.stop_thread = 1;

    // Wait for the thread to have no event pending
    while (async_callback_data.thread_running &&
           async_callback_data.event_pending) {
      ret = pthread_cond_signal(&async_callback_data.cond);
      if (ret != 0) {
        STLOG_HAL_E("HAL: %s pthread_cond_signal failed", __func__);
        return ret;
      }
      ret = pthread_cond_wait(&async_callback_data.cond,
                              &async_callback_data.mutex);
      if (ret != 0) {
        STLOG_HAL_E("HAL: %s pthread_cond_wait failed", __func__);
        break;
      }
    }

    ret = pthread_mutex_unlock(&async_callback_data.mutex);
    if (ret != 0) {
      STLOG_HAL_E("HAL: %s pthread_mutex_unlock failed", __func__);
      return ret;
    }

    ret = pthread_cond_signal(&async_callback_data.cond);
    if (ret != 0) {
      STLOG_HAL_E("HAL: %s pthread_cond_signal failed", __func__);
      return ret;
    }

    ret = pthread_join(async_callback_data.thr, (void**)NULL);
    if (ret != 0) {
      STLOG_HAL_E("HAL: %s pthread_join failed", __func__);
      return ret;
    }
  }
  return 0;
}

static void async_callback_post(nfc_event_t event, nfc_status_t event_status) {
  int ret;

  if (pthread_equal(pthread_self(), async_callback_data.thr)) {
    dev.p_cback_unwrap(event, event_status);
  }

  ret = pthread_mutex_lock(&async_callback_data.mutex);
  if (ret != 0) {
    STLOG_HAL_E("HAL: %s pthread_mutex_lock failed", __func__);
    return;
  }

  if (async_callback_data.thread_running == 0) {
    (void)pthread_mutex_unlock(&async_callback_data.mutex);
    STLOG_HAL_E("HAL: %s thread is not running", __func__);
    dev.p_cback_unwrap(event, event_status);
    return;
  }

  while (async_callback_data.event_pending) {
    ret = pthread_cond_wait(&async_callback_data.cond,
                            &async_callback_data.mutex);
    if (ret != 0) {
      STLOG_HAL_E("HAL: %s pthread_cond_wait failed", __func__);
      return;
    }
  }

  async_callback_data.event_pending = 1;
  async_callback_data.event = event;
  async_callback_data.event_status = event_status;

  ret = pthread_mutex_unlock(&async_callback_data.mutex);
  if (ret != 0) {
    STLOG_HAL_E("HAL: %s pthread_mutex_unlock failed", __func__);
    return;
  }

  ret = pthread_cond_signal(&async_callback_data.cond);
  if (ret != 0) {
    STLOG_HAL_E("HAL: %s pthread_cond_signal failed", __func__);
    return;
  }
}
/* ------ */

int StNfc_hal_open(nfc_stack_callback_t* p_cback,
                   nfc_stack_data_callback_t* p_data_cback) {
  bool result = false;

  STLOG_HAL_D("HAL st21nfc: %s %s", __func__, halVersion);

  client_is_nci_10 = false;

  (void)pthread_mutex_lock(&hal_mtx);

  if (!hal_is_closed) {
    hal_wrapper_close(0, nfc_mode);
  }

  dev.p_cback = p_cback;  // will be replaced by wrapper version
  dev.p_cback_unwrap = p_cback;
  dev.p_data_cback = p_data_cback;
  // Initialize and get global logging level
  InitializeSTLogLevel();

  if ((hal_is_closed || !async_callback_data.thread_running) &&
      (async_callback_thread_start() != 0)) {
    dev.p_cback(HAL_NFC_OPEN_CPLT_EVT, HAL_NFC_STATUS_FAILED);
    (void)pthread_mutex_unlock(&hal_mtx);
    return -1;  // We are doomed, stop it here, NOW !
  }
  result =
      hal_wrapper_open(&dev, async_callback_post, p_data_cback, &(dev.hHAL));

  if (!result || !(dev.hHAL)) {
    async_callback_post(HAL_NFC_OPEN_CPLT_EVT, HAL_NFC_STATUS_FAILED);
    (void)pthread_mutex_unlock(&hal_mtx);
    return -1;  // We are doomed, stop it here, NOW !
  }
  hal_is_closed = 0;
  (void)pthread_mutex_unlock(&hal_mtx);
  return 0;
}

int StNfc_hal_write(uint16_t data_len, const uint8_t* p_data) {
  STLOG_HAL_D("HAL st21nfc: %s", __func__);

  /* check if HAL is closed */
  int ret = (int)data_len;
  (void)pthread_mutex_lock(&hal_mtx);
  if (hal_is_closed) {
    ret = 0;
  }

  if (!ret) {
    (void)pthread_mutex_unlock(&hal_mtx);
    return ret;
  }
  // Identify and block NCI 1.0 invalid clients such as
  // replay_test_android.hardware.nfc_1.0_17261139999.vts.trace_default
  {
    uint8_t CORE_INIT_CMD_NCI1[] = {0x20, 0x01, 0x00};
    if (data_len == sizeof(CORE_INIT_CMD_NCI1) &&
        !memcmp(p_data, CORE_INIT_CMD_NCI1, data_len)) {
      STLOG_HAL_W(
          "NFC-NCI HAL: %s  Detected NCI 1.0 command, stop forwarding to CLF",
          __func__);
      client_is_nci_10 = true;
    }
  }
  if (client_is_nci_10 == true) {
    STLOG_HAL_D("NFC-NCI HAL: %s  frame ignored (NCI1.0 detected)", __func__);
    (void)pthread_mutex_unlock(&hal_mtx);
    return 0;
  }

  // Identify an NFCEE_MODE_SET command for eSE (id 82 or 86)
  {
    uint8_t NFCEE_MODE_SET_PREFIX[] = {0x22, 0x01, 0x02};
    if (data_len == 5 &&
        !memcmp(p_data, NFCEE_MODE_SET_PREFIX, sizeof(NFCEE_MODE_SET_PREFIX))) {
      if (p_data[3] == 0x82 || p_data[3] == 0x86) {
        hal_wrapper_nfceeModeSetSent(p_data[3], p_data[4]);
      }
    }
  }

  // entering RAW mode ?
  {
#define PROP_CTRL_RF_RAW_MODE_CMD 0x13
    uint8_t ENTER_RAW_MODE_PREFIX[] = {0x2f, 0x02, 0x02,
                                       PROP_CTRL_RF_RAW_MODE_CMD};
    if (data_len == 5 &&
        !memcmp(p_data, ENTER_RAW_MODE_PREFIX, sizeof(ENTER_RAW_MODE_PREFIX))) {
      if (p_data[4] == 0x01) {
        // Limit the rate
        unsigned long num;
        if (GetNumValue(NAME_STNFC_CMD_DELAY_IN_RAWMODE_MS, &num,
                        sizeof(num))) {
          delay_in_raw_mode = (int)num;
        }
        i2cSetTimeBetweenCmds(delay_in_raw_mode);

      } else {
        // remove the limit
        i2cSetTimeBetweenCmds(0);
      }
    }
  }

  // Identify if ST stack is the client by matching the RF_FIELD_INFO param
  // set during the initialization.
  {
    uint8_t RF_FIELD_INFO_SET_PREFIX[] = {0x20, 0x02, 0x04, 0x01,
                                          0x80, 0x01, 0x01};
    if (data_len == sizeof(RF_FIELD_INFO_SET_PREFIX) &&
        !memcmp(p_data, RF_FIELD_INFO_SET_PREFIX,
                sizeof(RF_FIELD_INFO_SET_PREFIX))) {
      hal_wrapper_unblockFwLogs();
    }
  }

  if (!HalSendDownstream(dev.hHAL, p_data, data_len)) {
    STLOG_HAL_E("HAL st21nfc %s  SendDownstream failed", __func__);
    (void)pthread_mutex_unlock(&hal_mtx);
    return 0;
  }
  (void)pthread_mutex_unlock(&hal_mtx);

  return ret;
}

int StNfc_hal_core_initialized() {
  int ret;
  STLOG_HAL_D("HAL st21nfc: %s", __func__);

  (void)pthread_mutex_lock(&hal_mtx);
  ret = hal_wrapper_send_config((client_is_nci_10 == true) ? 1 : 0);
  (void)pthread_mutex_unlock(&hal_mtx);

  return ret;  // return != 0 to signal ready immediate
}

int StNfc_hal_pre_discover() {
  STLOG_HAL_D("HAL st21nfc: %s", __func__);
  async_callback_post(HAL_NFC_PRE_DISCOVER_CPLT_EVT, HAL_NFC_STATUS_OK);
  // callback directly if no vendor-specific pre-discovery actions are needed
  return 0;
}

int StNfc_hal_close(int nfc_mode_value) {
  STLOG_HAL_D("HAL st21nfc: %s nfc_mode = %d", __func__, nfc_mode_value);

  /* check if HAL is closed */
  (void)pthread_mutex_lock(&hal_mtx);
  if (hal_is_closed) {
    (void)pthread_mutex_unlock(&hal_mtx);
    return 1;
  }
  if (hal_wrapper_close(1, nfc_mode_value) == -1) {
    hal_is_closed = 1;
    (void)pthread_mutex_unlock(&hal_mtx);
    return 1;
  }
  hal_is_closed = 1;
  (void)pthread_mutex_unlock(&hal_mtx);

  deInitializeHalLog();

  if (async_callback_thread_end() != 0) {
    STLOG_HAL_E("HAL st21nfc: %s async_callback_thread_end failed", __func__);
    return -1;  // We are doomed, stop it here, NOW !
  }

  std::string valueStr =
      android::base::GetProperty("persist.vendor.nfc.streset", "");
  if (valueStr.length() > 0) {
    valueStr = VENDOR_LIB_PATH + valueStr + VENDOR_LIB_EXT;
    void* stdll = dlopen(valueStr.c_str(), RTLD_NOW);
    if (stdll) {
      STLOG_HAL_D("STReset Cold reset");
      STEseReset fn = (STEseReset)dlsym(stdll, "cold_reset");
      if (fn) {
        int ret = fn();
        STLOG_HAL_D("STReset Result=%d", ret);
      }
    } else {
      STLOG_HAL_D("%s not found, do nothing.", valueStr.c_str());
    }
  }

  STLOG_HAL_D("HAL st21nfc: %s close", __func__);
  return 0;
}

int StNfc_hal_power_cycle() {
  STLOG_HAL_D("HAL st21nfc: %s", __func__);

  /* check if HAL is closed */
  int ret = HAL_NFC_STATUS_OK;
  (void)pthread_mutex_lock(&hal_mtx);
  if (hal_is_closed) {
    ret = HAL_NFC_STATUS_FAILED;
  }

  if (ret != HAL_NFC_STATUS_OK) {
    (void)pthread_mutex_unlock(&hal_mtx);
    return ret;
  }
  async_callback_post(HAL_NFC_OPEN_CPLT_EVT, HAL_NFC_STATUS_OK);

  (void)pthread_mutex_unlock(&hal_mtx);
  return HAL_NFC_STATUS_OK;
}

void StNfc_hal_factoryReset() {
  STLOG_HAL_D("HAL st21nfc: %s", __func__);
  hal_wrapper_factoryReset();
}

int StNfc_hal_closeForPowerOffCase() {
  STLOG_HAL_D("HAL st21nfc: %s (%d)", __func__, nfc_mode);
  return StNfc_hal_close(nfc_mode);
}

void StNfc_hal_getConfig(NfcConfig& config) {
  STLOG_HAL_D("HAL st21nfc: %s", __func__);
  unsigned long num = 0;
  std::array<uint8_t, 10> buffer;

  buffer.fill(0);
  long retlen = 0;

  memset(&config, 0x00, sizeof(NfcConfig));

  if (GetNumValue(NAME_CE_ON_SWITCH_OFF_STATE, &num, sizeof(num))) {
    if (num == 0x1) {
      nfc_mode = 0x1;
    }
  }

  if (GetNumValue(NAME_POLL_BAIL_OUT_MODE, &num, sizeof(num))) {
    config.nfaPollBailOutMode = num;
  }

  if (GetNumValue(NAME_ISO_DEP_MAX_TRANSCEIVE, &num, sizeof(num))) {
    config.maxIsoDepTransceiveLength = num;
  }
  if (GetNumValue(NAME_DEFAULT_OFFHOST_ROUTE, &num, sizeof(num))) {
    config.defaultOffHostRoute = num;
  }
  if (GetNumValue(NAME_DEFAULT_NFCF_ROUTE, &num, sizeof(num))) {
    config.defaultOffHostRouteFelica = num;
  }
  if (GetNumValue(NAME_DEFAULT_SYS_CODE_ROUTE, &num, sizeof(num))) {
    config.defaultSystemCodeRoute = num;
  }
  if (GetNumValue(NAME_DEFAULT_SYS_CODE_PWR_STATE, &num, sizeof(num))) {
    config.defaultSystemCodePowerState = num;
  }
  if (GetNumValue(NAME_DEFAULT_ROUTE, &num, sizeof(num))) {
    config.defaultRoute = num;
  }
  if (GetByteArrayValue(NAME_DEVICE_HOST_ALLOW_LIST, (char*)buffer.data(),
                        buffer.size(), &retlen)) {
    config.hostAllowlist.resize(retlen);
    for (int i = 0; i < retlen; i++) {
      config.hostAllowlist[i] = buffer[i];
    }
  }

  if (GetNumValue(NAME_OFF_HOST_ESE_PIPE_ID, &num, sizeof(num))) {
    config.offHostESEPipeId = num;
  }
  if (GetNumValue(NAME_OFF_HOST_SIM_PIPE_ID, &num, sizeof(num))) {
    config.offHostSIMPipeId = num;
  }
  if ((GetByteArrayValue(NAME_NFA_PROPRIETARY_CFG, (char*)buffer.data(),
                         buffer.size(), &retlen)) &&
      (retlen == 9)) {
    config.nfaProprietaryCfg.protocol18092Active = (uint8_t)buffer[0];
    config.nfaProprietaryCfg.protocolBPrime = (uint8_t)buffer[1];
    config.nfaProprietaryCfg.protocolDual = (uint8_t)buffer[2];
    config.nfaProprietaryCfg.protocol15693 = (uint8_t)buffer[3];
    config.nfaProprietaryCfg.protocolKovio = (uint8_t)buffer[4];
    config.nfaProprietaryCfg.protocolMifare = (uint8_t)buffer[5];
    config.nfaProprietaryCfg.discoveryPollKovio = (uint8_t)buffer[6];
    config.nfaProprietaryCfg.discoveryPollBPrime = (uint8_t)buffer[7];
    config.nfaProprietaryCfg.discoveryListenBPrime = (uint8_t)buffer[8];
  } else {
    memset(&config.nfaProprietaryCfg, 0xFF, sizeof(ProtocolDiscoveryConfig));
  }
  if (GetNumValue(NAME_PRESENCE_CHECK_ALGORITHM, &num, sizeof(num))) {
    config.presenceCheckAlgorithm = (PresenceCheckAlgorithm)num;
  }

  if (GetNumValue(NAME_STNFC_USB_CHARGING_MODE, &num, sizeof(num))) {
    if ((num == 1) && (nfc_mode == 0x1)) {
      nfc_mode = 0x2;
    }
  }

  if (GetByteArrayValue(NAME_OFFHOST_ROUTE_UICC, (char*)buffer.data(),
                        buffer.size(), &retlen)) {
    config.offHostRouteUicc.resize(retlen);
    for (int i = 0; i < retlen; i++) {
      config.offHostRouteUicc[i] = buffer[i];
    }
  }

  if (GetByteArrayValue(NAME_OFFHOST_ROUTE_ESE, (char*)buffer.data(),
                        buffer.size(), &retlen)) {
    config.offHostRouteEse.resize(retlen);
    for (int i = 0; i < retlen; i++) {
      config.offHostRouteEse[i] = buffer[i];
    }
  }

  if (GetNumValue(NAME_DEFAULT_ISODEP_ROUTE, &num, sizeof(num))) {
    config.defaultIsoDepRoute = num;
  }
}

void StNfc_hal_setLogging(bool enable) {
  dbg_logging = enable;
  if (dbg_logging) {
    hal_trace_level = STNFC_TRACE_LEVEL_VERBOSE;
  } else {
    hal_trace_level = STNFC_TRACE_LEVEL_ERROR;
  }
}

bool StNfc_hal_isLoggingEnabled() { return dbg_logging; }

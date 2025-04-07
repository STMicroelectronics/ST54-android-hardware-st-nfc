/******************************************************************************
 *
 *  Copyright (C) 2025 STMicroelectronics
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
 ******************************************************************************/

#ifndef STPROPNCI_INTERNAL_H
#define STPROPNCI_INTERNAL_H

#include <pthread.h>
#include <nci_defs.h>
#include <nfc_types.h>
#include <stpropnci.h>

#include <stpropnci_prop_st.h>

/* Logging facility */
#define LOG_TAG "StNfcPropNci"
extern int stpropnci_loglvl;
#ifndef STPROPNCI_VENDOR
#include <log/log.h>
#define LOG_D(fmt, ...)                                                      \
  {                                                                          \
    if (stpropnci_loglvl > 1)                                                \
      LOG_PRI(ANDROID_LOG_DEBUG, LOG_TAG, "%s:%d: " fmt, __func__, __LINE__, \
              ##__VA_ARGS__);                                                \
  }
#define LOG_I(fmt, ...)                                                      \
  {                                                                          \
    if (stpropnci_loglvl > 0)                                                \
      LOG_PRI(ANDROID_LOG_DEBUG, LOG_TAG, "%s:%d: " fmt, __func__, __LINE__, \
              ##__VA_ARGS__);                                                \
  }
#define LOG_E(fmt, ...)                                                      \
  {                                                                          \
    if (stpropnci_loglvl > 0)                                                \
      LOG_PRI(ANDROID_LOG_ERROR, LOG_TAG, "%s:%d: " fmt, __func__, __LINE__, \
              ##__VA_ARGS__);                                                \
  }
#else  // STPROPNCI_VENDOR
#include <android/log.h>
#define LOG_D(fmt, ...)                                                        \
  {                                                                            \
    if (stpropnci_loglvl > 1)                                                  \
      __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "%s:%d: " fmt, __func__, \
                          __LINE__, ##__VA_ARGS__);                            \
  }
#define LOG_I(fmt, ...)                                                        \
  {                                                                            \
    if (stpropnci_loglvl > 0)                                                  \
      __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "%s:%d: " fmt, __func__, \
                          __LINE__, ##__VA_ARGS__);                            \
  }
#define LOG_E(fmt, ...)                                                        \
  {                                                                            \
    if (stpropnci_loglvl > 0)                                                  \
      __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "%s:%d: " fmt, __func__, \
                          __LINE__, ##__VA_ARGS__);                            \
  }
#endif  // STPROPNCI_VENDOR

// Submodules (different NCI proprietary processors) can register to intercept
// messages before the normal handling.
typedef bool (*module_cb_t)(bool dir_from_upper, const uint8_t* payload,
                            const uint16_t payloadlen, uint8_t mt, uint8_t gid,
                            uint8_t oid);

typedef struct modcblist {
  module_cb_t cb;
  bool must_match_mt;
  uint8_t mt;
  bool must_match_gid;
  uint8_t gid;
  bool must_match_oid;
  uint8_t oid;
  bool must_match_suboid;
  uint8_t suboid;
  struct modcblist* next;
} modcblist_t;

// Structure to queue messages
#define MAX_NCI_MESSAGE_LEN (NCI_MSG_HDR_SIZE + NCI_MAX_VSC_SIZE)
#define MAX_HCI_RECEIVE_LEN 1024
typedef struct msg {
  struct timespec ts;
  uint8_t payload[MAX_NCI_MESSAGE_LEN];
  uint16_t payloadlen;
  bool dir_to_nfcc;
  bool retried;
  module_cb_t rspcb;
  struct msg* next;
} msg_t;

// Structure to queue watchdog events to monitor
typedef enum {
  WD_FIELD_ON_TOO_LONG = 1,  // no NCI_MSG_RF_FIELD(off) received after
                             // (duration) of NCI_MSG_RF_FIELD(on)
  WD_ACTIVE_RW_TOO_LONG,     // no ST_NCI_MSG_PROP_PWR_MON_RW_OFF_NTF received
                             // within 5s after ON
} watchdog_event_t;
typedef struct watchdog {
  struct timespec ts_expire;
  watchdog_event_t event;
  struct watchdog* next;
} watchdog_t;

/* State machine */
extern struct stpropnci_state {
  /*****************************
      NCI prop state machine
  *****************************/
  /* If a proprietary sequence is ongoing */
  enum {
    ST_INIT = 0,

  } cmd_state;

  // Data from the last CORE_RESET_NTF (len=0 if not received)
  uint8_t manu_specific_info_len;
  uint8_t manu_specific_info[40];
  enum {
    CLF_MODE_UNKNOWN = 0,
    CLF_MODE_LOADER,
    CLF_MODE_ROUTER_DISABLED,
    CLF_MODE_ROUTER_ENABLED,
    CLF_MODE_ROUTER_USBCHARGING,
  } clf_mode;

  // Flag indicating if we use observe mode per tech or not.
  bool observe_per_tech;
  // Flag indicating observe mode is temporarily suspended.
  bool observe_mode_suspended;

  // flag for sending polling frame notif data
  bool pollingframe_inCE;

  // PROP_PWR_MON_RW stability related
  bool pwr_mon_isActiveRW;
  int pwr_mon_errorCount;

  // Storage for nfcee Ids of active NFCEE
  uint8_t active_nfcee_ids[5];
  uint8_t nb_active_nfcees;
  bool wait_nfcee_ntf;
  uint8_t waiting_nfcee_id;

  // APDU gate data
  bool apdu_gate_ready;
  uint8_t apdu_pipe_id;
  uint32_t tx_waiting_time;

  // HCI data handling
  bool (*hci_rsp_cb)(const uint8_t* payload, const uint16_t payloadlen);
  uint8_t hci_reassembly_buff[MAX_HCI_RECEIVE_LEN];
  uint8_t* hci_reassembly_p;
  uint8_t hci_cr_cnt;

  // To ensure enough time after sending RF data, before deactivation
  struct timespec ts_last_rf_tx;

  /*****************************
       Internal lib configs
  *****************************/
  // A storage for building messages for sending out.
  uint8_t* tmpbuff;
  uint16_t* tmpbufflen;

  // Management of the thread sending messages out.
  struct {
    pthread_t pump_thr;
    pthread_mutex_t pump_mtx;
    pthread_cond_t pump_cnd;
    pthread_mutex_t pump_pool_mtx;
    msg_t msgPool;
    int msgPool_ctr;
    msg_t toSend;
    int toSend_ctr;
    msg_t toAck;
    int toAck_ctr;
    watchdog_t toWatch;
    watchdog_t wdPool;
    bool mustExit;
  } pumpstate;

  // Management of the submodules callbacks.
  struct {
    modcblist_t modcblist;
    modcblist_t modcbpool;
    pthread_mutex_t modcb_mtx;
  } modcbstate;

  // callback when sending messages out of the library
  outgoing_cb_t outCb;

} stpropnci_state;

// Get the HW version from the structure
#define HW_VERSION (stpropnci_state.manu_specific_info[0])
#define HW_VERSION_ST21NFCL 0x07
#define HW_VERSION_ST54L 0x06
#define HW_VERSION_ST54J 0x05
#define HW_VERSION_ST21NFCD 0x04

// Get the FW version from the structure
#define FW_VERSION_MAJOR (stpropnci_state.manu_specific_info[2])
#define FW_VERSION_MINOR (stpropnci_state.manu_specific_info[3] & 0x7F)
#define FW_VERSION_MINOR_BIS (stpropnci_state.manu_specific_info[3] & 0x80)
#define FW_VERSION_REV                            \
  ((stpropnci_state.manu_specific_info[4] << 8) | \
   stpropnci_state.manu_specific_info[5])

#define FW_VERSION                                       \
  ((FW_VERSION_MAJOR << 24) | (FW_VERSION_MINOR << 16) | \
   (FW_VERSION_MINOR_BIS << 16) | FW_VERSION_REV)

// Helper that we use often
#define IS_HW_54L_FAMILY() \
  ((HW_VERSION == HW_VERSION_ST21NFCL) || (HW_VERSION == HW_VERSION_ST54L))

// Generation 1 firmwares (old & no more updated): 1.x on ST21NFCD, 1.x or 2.x
// on ST54J, 1.x on 54L/21L.
#define IS_FW_GEN_1()                                                     \
  (((HW_VERSION == HW_VERSION_ST21NFCD) && (FW_VERSION_MAJOR == 0x01)) || \
   ((HW_VERSION == HW_VERSION_ST54J) &&                                   \
    ((FW_VERSION_MAJOR == 0x01) || (FW_VERSION_MAJOR == 0x02))) ||        \
   (IS_HW_54L_FAMILY() && (FW_VERSION_MAJOR == 0x01)))

// Generation 2 firmwares: 13.x on ST21NFCJ or 3.x on ST54J
#define IS_FW_GEN_2()                                                     \
  (((HW_VERSION == HW_VERSION_ST21NFCD) && (FW_VERSION_MAJOR == 0x13)) || \
   ((HW_VERSION == HW_VERSION_ST54J) && (FW_VERSION_MAJOR == 0x03)))

// Generation 3 firmwares: 2.x on ST21NFCL/ST54L
#define IS_FW_GEN_3() (IS_HW_54L_FAMILY() && (FW_VERSION_MAJOR == 0x02))

// Returns the generation of the FW or 0 if unknown.
#define GET_FW_GEN() \
  (IS_FW_GEN_3() ? 3 : (IS_FW_GEN_2() ? 2 : (IS_FW_GEN_1() ? 1 : (0))))

/* Process standard NCI frames (GID 0-2 and data) */
bool stpropnci_process_std(bool inform_only, bool dir_from_upper,
                           const uint8_t* payload, const uint16_t payloadlen,
                           uint8_t mt, uint8_t gid, uint8_t oid);

/* Process proprietary NCI frames (GID F) */
bool stpropnci_process_prop(bool inform_only, bool dir_from_upper,
                            const uint8_t* payload, const uint16_t payloadlen,
                            uint8_t mt, uint8_t oid);

/* Manage the message pump related information */
bool stpropnci_pump_post(bool dir_to_nfcc, const uint8_t* payload,
                         uint16_t payloadlen, module_cb_t rspcb);
void stpropnci_pump_got(const uint8_t* payload, uint16_t payloadlen,
                        bool* handled);
bool stpropnci_pump_watchdog_add(watchdog_event_t t, int ms);
void stpropnci_pump_watchdog_remove(watchdog_event_t t);
bool stpropnci_pump_init();
void stpropnci_pump_fini();

void stpropnci_tmpbuff_reset();

void stpropnci_build_prop_status_rsp(uint8_t* buf, uint16_t* buflen,
                                     uint8_t oid, uint8_t suboid,
                                     uint8_t status);

bool stpropnci_send_core_reset_ntf_recovery(uint8_t hint);

bool stpropnci_cb_passthrough_rsp(bool dir_from_upper, const uint8_t* payload,
                                  const uint16_t payloadlen, uint8_t mt,
                                  uint8_t gid, uint8_t oid);

bool stpropnci_cb_block_rsp(bool dir_from_upper, const uint8_t* payload,
                            const uint16_t payloadlen, uint8_t mt, uint8_t gid,
                            uint8_t oid);

/* Sub modules callbacks management */
bool stpropnci_modcb_init();
void stpropnci_modcb_fini();
bool stpropnci_modcb_register(module_cb_t cb, bool match_mt, uint8_t mt,
                              bool match_gid, uint8_t gid, bool match_oid,
                              uint8_t oid, bool match_suboid, uint8_t suboid);
bool stpropnci_modcb_process(bool dir_from_upper, const uint8_t* payload,
                             const uint16_t payloadlen, uint8_t mt, uint8_t gid,
                             uint8_t oid);
void stpropnci_modcb_unregister(module_cb_t cb);

/**************************
    Android NCI management
  **************************/
bool stpropnci_process_prop_android(bool inform_only, bool dir_from_upper,
                                    const uint8_t* payload,
                                    const uint16_t payloadlen, uint8_t mt,
                                    uint8_t oid);

#endif  // STPROPNCI_INTERNAL_H

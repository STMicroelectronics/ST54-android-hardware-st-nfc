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
#include <pthread.h>
#include <string.h>
#include <stpropnci-internal.h>

/* Declarations */
static void stpropnci_build_get_caps_rsp(uint8_t *buf, uint16_t *buflen);

static void stpropnci_build_get_observer_cmd(uint8_t *buf, uint16_t *buflen);
static bool stpropnci_cb_get_observer_rsp(bool dir_from_upper,
                                          const uint8_t *payload,
                                          const uint16_t payloadlen, uint8_t mt,
                                          uint8_t gid, uint8_t oid);

static void stpropnci_build_set_config_observer_cmd(uint8_t *buf,
                                                    uint16_t *buflen,
                                                    uint8_t enable);
static bool stpropnci_cb_set_config_observer_rsp(bool dir_from_upper,
                                                 const uint8_t *payload,
                                                 const uint16_t payloadlen,
                                                 uint8_t mt, uint8_t gid,
                                                 uint8_t oid);

static bool stpropnci_cb_generate_polling_loop_frame(bool dir_from_upper,
                                                     const uint8_t *payload,
                                                     const uint16_t payloadlen,
                                                     uint8_t mt, uint8_t gid,
                                                     uint8_t oid);

#define OBSERVE_ALL 0x7
#define OBSERVE_NONE 0x0
static void stpropnci_build_rf_set_listen_passive_observer_cmd(uint8_t *buf,
                                                               uint16_t *buflen,
                                                               uint8_t mode);
static bool stpropnci_cb_rf_set_listen_passive_observer_rsp(
    bool dir_from_upper, const uint8_t *payload, const uint16_t payloadlen,
    uint8_t mt, uint8_t gid, uint8_t oid);

static bool stpropnci_build_set_exit_frame_cmd(uint8_t *buf, uint16_t *buflen,
                                               const uint8_t *incoming,
                                               const uint16_t incominglen);
static bool stpropnci_cb_set_exit_frame_rsp(bool dir_from_upper,
                                            const uint8_t *payload,
                                            const uint16_t payloadlen,
                                            uint8_t mt, uint8_t gid,
                                            uint8_t oid);
static bool stpropnci_build_set_custom_polling_cmd(uint8_t *buf,
                                                   uint16_t *buflen,
                                                   const uint8_t *incoming,
                                                   const uint16_t incominglen);
static bool stpropnci_cb_set_custom_polling_rsp(bool dir_from_upper,
                                                const uint8_t *payload,
                                                const uint16_t payloadlen,
                                                uint8_t mt, uint8_t gid,
                                                uint8_t oid);
static bool stpropnci_cb_observe_mode_suspend(bool dir_from_upper,
                                              const uint8_t *payload,
                                              const uint16_t payloadlen,
                                              uint8_t mt, uint8_t gid,
                                              uint8_t oid);

static uint16_t iso14443_crc(const uint8_t *data, size_t szLen, int type);
#define CRC_PRESET_A 0x6363
#define CRC_PRESET_B 0xFFFF
#define Type_A 0
#define Type_B 1

/*******************************************************************************
**
** Function         stpropnci_process_prop_android
**
** Description      This function is default handler for Android NCI
**
** Returns          true if message was handled and does not need to be
*forwarded
**
*******************************************************************************/
bool stpropnci_process_prop_android(bool inform_only, bool dir_from_upper,
                                    const uint8_t *payload,
                                    const uint16_t payloadlen, uint8_t mt,
                                    uint8_t oid) {
  bool handled = false;
  stpropnci_tmpbuff_reset();

  switch (mt) {
    case NCI_MT_CMD:
      switch (payload[3]) {
        case NCI_ANDROID_GET_CAPS:

          // parse the FW information & generate a response
          stpropnci_build_get_caps_rsp(stpropnci_state.tmpbuff,
                                       stpropnci_state.tmpbufflen);

          // send this answer and don't forward the cmd to NFCC
          handled =
              stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                  *stpropnci_state.tmpbufflen, nullptr);

          break;

        case NCI_QUERY_ANDROID_PASSIVE_OBSERVE:

          // Prepare the native message based on
          // stpropnci_state.observe_per_tech
          stpropnci_build_get_observer_cmd(stpropnci_state.tmpbuff,
                                           stpropnci_state.tmpbufflen);

          // send it to NFCC
          handled = stpropnci_pump_post(
              MSG_DIR_TO_NFCC, stpropnci_state.tmpbuff,
              *stpropnci_state.tmpbufflen, stpropnci_cb_get_observer_rsp);
          break;

        case NCI_ANDROID_PASSIVE_OBSERVE:
          if (stpropnci_state.observe_per_tech) {
            // It can happen that the stack sends this command when
            // !useNewObserveModeCmd; In this situation, it does not disable the
            // discovery. If this happens we use the new command otherwise the
            // FW rejects. We default to mute A&B only in this scenario, as it
            // covers more real use-cases.
            stpropnci_build_rf_set_listen_passive_observer_cmd(
                stpropnci_state.tmpbuff, stpropnci_state.tmpbufflen,
                (payload[4] == NCI_ANDROID_PASSIVE_OBSERVE_PARAM_ENABLE)
                    ? (NCI_ANDROID_PASSIVE_OBSERVE_PARAM_ENABLE_A |
                       NCI_ANDROID_PASSIVE_OBSERVE_PARAM_ENABLE_B)
                    : NCI_ANDROID_PASSIVE_OBSERVE_PARAM_DISABLE);
          } else {
            // Prepare the native message: CORE_SET_CONFIG
            stpropnci_build_set_config_observer_cmd(stpropnci_state.tmpbuff,
                                                    stpropnci_state.tmpbufflen,
                                                    payload[4]);
          }

          // send it to NFCC
          handled =
              stpropnci_pump_post(MSG_DIR_TO_NFCC, stpropnci_state.tmpbuff,
                                  *stpropnci_state.tmpbufflen,
                                  stpropnci_cb_set_config_observer_rsp);
          break;

        case NCI_ANDROID_SET_PASSIVE_OBSERVER_TECH:

          // Prepare the native message: RF_SET_LISTEN_OBSERVE_MODE_CMD
          stpropnci_build_rf_set_listen_passive_observer_cmd(
              stpropnci_state.tmpbuff, stpropnci_state.tmpbufflen, payload[4]);

          // send it to NFCC
          handled = stpropnci_pump_post(
              MSG_DIR_TO_NFCC, stpropnci_state.tmpbuff,
              *stpropnci_state.tmpbufflen,
              stpropnci_cb_rf_set_listen_passive_observer_rsp);
          break;

        case NCI_ANDROID_SET_PASSIVE_OBSERVER_EXIT_FRAME:
          // Prepare the native message:
          // ST_NCI_MSG_PROP_RF_SET_OBSERVE_MODE_EXIT_FRAME
          if (!stpropnci_build_set_exit_frame_cmd(stpropnci_state.tmpbuff,
                                                  stpropnci_state.tmpbufflen,
                                                  payload, payloadlen)) {
            // the frame was not valid.
            stpropnci_tmpbuff_reset();
            stpropnci_build_prop_status_rsp(
                stpropnci_state.tmpbuff, stpropnci_state.tmpbufflen,
                NCI_MSG_PROP_ANDROID,
                NCI_ANDROID_SET_PASSIVE_OBSERVER_EXIT_FRAME,
                NCI_STATUS_MESSAGE_CORRUPTED);

            // send it back
            handled =
                stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                    *stpropnci_state.tmpbufflen, nullptr);
          } else {
            // send it to NFCC
            handled = stpropnci_pump_post(
                MSG_DIR_TO_NFCC, stpropnci_state.tmpbuff,
                *stpropnci_state.tmpbufflen, stpropnci_cb_set_exit_frame_rsp);
          }
          break;

        case NCI_ANDROID_SET_TECH_A_POLLING_LOOP_ANNOTATION:
          // Prepare the native message
          // ST_NCI_MSG_PROP_RF_SET_CUST_PASSIVE_POLL_FRAME (add CRC)
          if (!stpropnci_build_set_custom_polling_cmd(
                  stpropnci_state.tmpbuff, stpropnci_state.tmpbufflen, payload,
                  payloadlen)) {
            // the frame was not valid.
            stpropnci_tmpbuff_reset();
            stpropnci_build_prop_status_rsp(
                stpropnci_state.tmpbuff, stpropnci_state.tmpbufflen,
                NCI_MSG_PROP_ANDROID,
                NCI_ANDROID_SET_TECH_A_POLLING_LOOP_ANNOTATION,
                NCI_STATUS_MESSAGE_CORRUPTED);

            // send it back
            handled =
                stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                    *stpropnci_state.tmpbufflen, nullptr);
          } else {
            // send it to NFCC
            handled =
                stpropnci_pump_post(MSG_DIR_TO_NFCC, stpropnci_state.tmpbuff,
                                    *stpropnci_state.tmpbufflen,
                                    stpropnci_cb_set_custom_polling_rsp);
          }
          break;

        case NCI_ANDROID_GET_PASSIVE_OBSERVER_EXIT_FRAME:
          // TODO ST_NCI_MSG_PROP_RF_GET_OBSERVE_MODE_EXIT_FRAME
          // don't support yet since not used by AOSP, wait for integration.
        case NCI_ANDROID_POWER_SAVING:  // not used for ST
        case NCI_ANDROID_BLANK_NCI:     // not supposed to reach HAL
        default:
          // ?
          LOG_E("Unsupported Android NCI subOID %02hhx", payload[3]);

          stpropnci_build_prop_status_rsp(
              stpropnci_state.tmpbuff, stpropnci_state.tmpbufflen,
              NCI_MSG_PROP_ANDROID, payload[3], NCI_STATUS_NOT_SUPPORTED);

          // send this answer and don't forward the cmd to NFCC
          handled =
              stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                  *stpropnci_state.tmpbufflen, nullptr);
          break;
      }
      break;
    case NCI_MT_RSP:
    case NCI_MT_NTF:
      // This is unexpected !
      LOG_E("Unexpected RSP or NTF in NCI_ANDROID wrapper");
      break;
  }

  return handled;
}

/*******************************************************************************
**
** Function         stpropnci_build_get_caps_rsp
**
** Description      Prepare the response to GET_CAPS based on FW capabilities
**
** Returns          none
**
*******************************************************************************/
static void stpropnci_build_get_caps_rsp(uint8_t *buf, uint16_t *buflen) {
  uint8_t *pp = buf, *paylen, *nbtlv;
  uint16_t version = 0x0000;
  int fw_gen = GET_FW_GEN();
  uint8_t obsmode = 0;
  uint8_t exitframe = 0;
  uint8_t annotations = 0;

  if (stpropnci_state.manu_specific_info_len == 0) {
    LOG_E(
        "Android GET_CAPS received but no firmware information available yet");
    stpropnci_build_prop_status_rsp(buf, buflen, NCI_MSG_PROP_ANDROID,
                                    NCI_ANDROID_GET_CAPS,
                                    NCI_STATUS_NOT_INITIALIZED);
    return;
  }

  if (fw_gen < 2) {
    LOG_D("No support for Android NCI feats in this FW (gen %d)", fw_gen);
    stpropnci_build_prop_status_rsp(buf, buflen, NCI_MSG_PROP_ANDROID,
                                    NCI_ANDROID_GET_CAPS,
                                    NCI_STATUS_NOT_SUPPORTED);
    return;
  }

  NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_PROP);
  NCI_MSG_BLD_HDR1(pp, NCI_MSG_PROP_ANDROID);
  paylen = pp++;
  UINT8_TO_STREAM(pp, NCI_ANDROID_GET_CAPS);
  UINT8_TO_STREAM(pp, NCI_STATUS_OK);
  UINT16_TO_STREAM(pp, version);
  nbtlv = pp++;

// Passive Observe mode
#define PASSIVE_OBSERVE_MODE 0x00
#define PASSIVE_OBSERVE_MODE__NOT_SUPPORTED 0x00
#define PASSIVE_OBSERVE_MODE__SUPPORT_WITH_RF_DEACTIVATION 0x01
#define PASSIVE_OBSERVE_MODE__SUPPORT_WITHOUT_RF_DEACTIVATION 0x02

  UINT8_TO_STREAM(pp, PASSIVE_OBSERVE_MODE);
  UINT8_TO_STREAM(pp, 1);
  if (fw_gen == 2) {
    // Only with deactivation for gen2 firmwares
    obsmode = PASSIVE_OBSERVE_MODE__SUPPORT_WITH_RF_DEACTIVATION;
  } else if (fw_gen > 3) {
    // Next generations will support without RF deact directly
    obsmode = PASSIVE_OBSERVE_MODE__SUPPORT_WITHOUT_RF_DEACTIVATION;
  } else if (IS_HW_54L_FAMILY() && (FW_VERSION_MAJOR == 0x02)) {
    if (FW_VERSION_MINOR == 0x01) {
      // This version had a bug
      obsmode = PASSIVE_OBSERVE_MODE__NOT_SUPPORTED;
    } else if (FW_VERSION_MINOR <= 0x04) {
      // from 54L FW 2.5, observe mode per tech is supported.
      // AOSP uses per-tech if "support without rf deact" caps &&
      // "useNewObserveModeCmd" flag
      obsmode = PASSIVE_OBSERVE_MODE__SUPPORT_WITH_RF_DEACTIVATION;
    } else {
      // since 2.5, can support without deactivation
      obsmode = PASSIVE_OBSERVE_MODE__SUPPORT_WITHOUT_RF_DEACTIVATION;
    }
  } else {
    // gen 3 that is not 54L 2.x FW, assume full support.
    obsmode = PASSIVE_OBSERVE_MODE__SUPPORT_WITHOUT_RF_DEACTIVATION;
  }
  UINT8_TO_STREAM(pp, obsmode);
  *nbtlv += 1;  // 1 TLV was stored.

  if (obsmode == PASSIVE_OBSERVE_MODE__SUPPORT_WITHOUT_RF_DEACTIVATION) {
    // Default on using new command in that case until stack sends the old one
    stpropnci_state.observe_per_tech = true;
  }

// Polling frame ntf
#define POLLING_FRAME_NTF 0x01
#define POLLING_FRAME_NTF__NOT_SUPPORTED 0x00
#define POLLING_FRAME_NTF__SUPPORTED 0x01
  // Register the callback to generate the polling frame ntf
  if (obsmode != PASSIVE_OBSERVE_MODE__NOT_SUPPORTED) {
    if (!stpropnci_modcb_register(stpropnci_cb_generate_polling_loop_frame,
                                  true, NCI_MT_NTF, true, NCI_GID_PROP, true,
                                  ST_NCI_MSG_PROP, true, ST_NCI_PROP_LOG)) {
      // update obsmode so we report PF not supported if we failed to register
      // cb
      obsmode = PASSIVE_OBSERVE_MODE__NOT_SUPPORTED;
    }
  }
  // Report PF support based on our observe mode support (seems not really
  // used).
  UINT8_TO_STREAM(pp, POLLING_FRAME_NTF);
  UINT8_TO_STREAM(pp, 1);
  UINT8_TO_STREAM(pp, obsmode == PASSIVE_OBSERVE_MODE__NOT_SUPPORTED
                          ? POLLING_FRAME_NTF__NOT_SUPPORTED
                          : POLLING_FRAME_NTF__SUPPORTED);
  *nbtlv += 1;  // 1 TLV was stored.

// Power saving mode
#define POWER_SAVING_MODE 0x02
#define POWER_SAVING_MODE__NOT_SUPPORTED 0x00
#define POWER_SAVING_MODE__SUPPORTED 0x01

  // ST does not use this.
  UINT8_TO_STREAM(pp, POWER_SAVING_MODE);
  UINT8_TO_STREAM(pp, 1);
  UINT8_TO_STREAM(pp, POWER_SAVING_MODE__NOT_SUPPORTED);
  *nbtlv += 1;  // 1 TLV was stored.

// Autotransact polling loop filter
#define AUTOTRANSACT_POLLING_LOOP_FILTER 0x03
#define AUTOTRANSACT_POLLING_LOOP_FILTER__NOT_SUPPORTED 0x00
#define AUTOTRANSACT_POLLING_LOOP_FILTER__SUPPORTED 0x01

  // supported from 54L 2.6 only at the moment
  if (fw_gen == 2) {
    exitframe = AUTOTRANSACT_POLLING_LOOP_FILTER__NOT_SUPPORTED;
  } else if (fw_gen > 3) {
    // Next generations will support it
    exitframe = AUTOTRANSACT_POLLING_LOOP_FILTER__SUPPORTED;
  } else if (IS_HW_54L_FAMILY() && (FW_VERSION_MAJOR == 0x02)) {
    if (FW_VERSION_MINOR <= 0x05) {
      // not yet
      exitframe = AUTOTRANSACT_POLLING_LOOP_FILTER__NOT_SUPPORTED;
    } else {
      // since 2.6, exit frame is supported
      exitframe = AUTOTRANSACT_POLLING_LOOP_FILTER__SUPPORTED;
    }
  } else {
    // gen 3 that is not 54L 2.x FW, assume full support.
    exitframe = AUTOTRANSACT_POLLING_LOOP_FILTER__SUPPORTED;
  }

  // Register the callbacks related to exit frame
  if (exitframe != AUTOTRANSACT_POLLING_LOOP_FILTER__NOT_SUPPORTED) {
    if (!stpropnci_modcb_register(stpropnci_cb_observe_mode_suspend, true,
                                  NCI_MT_NTF, true, NCI_GID_PROP, true,
                                  ST_NCI_MSG_PROP_RF_OBSERVE_MODE_SUSPENDED,
                                  false, 0)) {
      LOG_E(
          "Failed to register cb for observe mode suspend, change exit frame "
          "support to not supported.");
      exitframe = AUTOTRANSACT_POLLING_LOOP_FILTER__NOT_SUPPORTED;
    } else if (!stpropnci_modcb_register(
                   stpropnci_cb_observe_mode_suspend, true, NCI_MT_NTF, true,
                   NCI_GID_PROP, true, ST_NCI_MSG_PROP_RF_OBSERVE_MODE_RESUMED,
                   false, 0)) {
      LOG_E(
          "Failed to register cb for observe mode resumed, change exit frame "
          "support to not supported.");
      stpropnci_modcb_unregister(stpropnci_cb_observe_mode_suspend);
      exitframe = AUTOTRANSACT_POLLING_LOOP_FILTER__NOT_SUPPORTED;
    }
  }

  UINT8_TO_STREAM(pp, AUTOTRANSACT_POLLING_LOOP_FILTER);
  UINT8_TO_STREAM(pp, 1);
  UINT8_TO_STREAM(pp, exitframe);
  *nbtlv += 1;  // 1 TLV was stored.

// Number of exit frames supported
#define NUMBER_OF_EXIT_FRAMES_SUPPORTED 0x04

  UINT8_TO_STREAM(pp, NUMBER_OF_EXIT_FRAMES_SUPPORTED);
  UINT8_TO_STREAM(pp, 1);
  // stack seems don t use this yet, just align with observe mode.
  UINT8_TO_STREAM(pp,
                  exitframe == AUTOTRANSACT_POLLING_LOOP_FILTER__NOT_SUPPORTED
                      ? 0
                      : 10);  // Currently the table is limited to 10 entries
  *nbtlv += 1;                // 1 TLV was stored.

// Number of exit frames supported
#define READER_MODE_ANNOTATIONS_SUPPORTED 0x05

  UINT8_TO_STREAM(pp, READER_MODE_ANNOTATIONS_SUPPORTED);
  UINT8_TO_STREAM(pp, 1);
  if (fw_gen == 2) {
    // Not supported
    annotations = 0x00;
  } else if (fw_gen > 3) {
    // Next generations will support
    annotations = 0x01;
  } else if (IS_HW_54L_FAMILY() && (FW_VERSION_MAJOR == 0x02)) {
    if (FW_VERSION_MINOR <= 0x05) {
      // Supported from version 2.6
      annotations = 0x00;
    } else {
      // since 2.6, can support without deactivation
      annotations = 0x01;
    }
  } else {
    // gen 3 that is not 54L 2.x FW, no support.
    annotations = 0x00;
  }
  UINT8_TO_STREAM(pp, annotations);
  *nbtlv += 1;  // 1 TLV was stored.

  // Update the pending fields
  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;
}

/*******************************************************************************
**
** Function         stpropnci_build_get_observer_cmd
**
** Description      Prepare command to read observe mode current state
**                  It uses either CORE_GET_CONFIG (old) or
*RF_GET_LISTEN_OBSERVE_MODE (new)
**                  depending on the observe_per_tech flag in stpropnci_state
**
** Returns          none
**
*******************************************************************************/
static void stpropnci_build_get_observer_cmd(uint8_t *buf, uint16_t *buflen) {
  uint8_t *pp = buf, *paylen;

  if (stpropnci_state.observe_per_tech) {
    NCI_MSG_BLD_HDR0(pp, NCI_MT_CMD, NCI_GID_RF_MANAGE);
    NCI_MSG_BLD_HDR1(pp, NCI_MSG_RF_GET_LISTEN_OBSERVE_MODE_STATE);
    paylen = pp++;
  } else {
    NCI_MSG_BLD_HDR0(pp, NCI_MT_CMD, NCI_GID_CORE);
    NCI_MSG_BLD_HDR1(pp, NCI_MSG_CORE_GET_CONFIG);
    paylen = pp++;

    UINT8_TO_STREAM(pp, 1 /* we set only 1 param */);
    UINT8_TO_STREAM(pp, ST_NCI_PARAM_ID_RF_DONT_ANSWER_PASSIVE_LISTEN);
  }

  // Update the pending fields
  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;
}

/*******************************************************************************
**
** Function         stpropnci_cb_get_observer_rsp
**
** Description      Process the response of stpropnci_build_get_observer_cmd
**
** Returns          true if the response was handled and shall not be fwded.
**
*******************************************************************************/
static bool stpropnci_cb_get_observer_rsp(bool dir_from_upper,
                                          const uint8_t *payload,
                                          const uint16_t payloadlen, uint8_t mt,
                                          uint8_t gid, uint8_t oid) {
  uint8_t *buf = stpropnci_state.tmpbuff;
  uint16_t *buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;

  stpropnci_tmpbuff_reset();

  // build the response to stack
  NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_PROP);
  NCI_MSG_BLD_HDR1(pp, NCI_MSG_PROP_ANDROID);
  paylen = pp++;
  UINT8_TO_STREAM(pp, NCI_QUERY_ANDROID_PASSIVE_OBSERVE);
  UINT8_TO_STREAM(pp, payload[3]);
  if (payload[3] == NCI_STATUS_OK) {
    UINT8_TO_STREAM(pp, stpropnci_state.observe_per_tech
                            ? (((payload[4] == OBSERVE_NONE) ||
                                (stpropnci_state.observe_mode_suspended))
                                   ? NCI_ANDROID_PASSIVE_OBSERVE_PARAM_DISABLE
                                   : payload[4])
                            : payload[7]);
  }

  // Update the pending fields
  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;

  return stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                             *stpropnci_state.tmpbufflen, nullptr);
}

/*******************************************************************************
**
** Function         stpropnci_build_set_config_observer_cmd
**
** Description      Prepare the CORE_SET_CONFIG for observe mode (old method)
**
** Returns          none
**
*******************************************************************************/
static void stpropnci_build_set_config_observer_cmd(uint8_t *buf,
                                                    uint16_t *buflen,
                                                    uint8_t enable) {
  uint8_t *pp = buf, *paylen;
  NCI_MSG_BLD_HDR0(pp, NCI_MT_CMD, NCI_GID_CORE);
  NCI_MSG_BLD_HDR1(pp, NCI_MSG_CORE_SET_CONFIG);
  paylen = pp++;

  UINT8_TO_STREAM(pp, 1 /* we set only 1 param */);
  UINT8_TO_STREAM(pp, ST_NCI_PARAM_ID_RF_DONT_ANSWER_PASSIVE_LISTEN);
  UINT8_TO_STREAM(pp, 1 /* this param is 1 byte */);
  UINT8_TO_STREAM(pp, enable);

  // Update the pending fields
  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;
}

/*******************************************************************************
**
** Function         stpropnci_cb_set_config_observer_rsp
**
** Description      Process the response from CORE_SET_CONFIG (old method)
**
** Returns          true if the response was handled and shall not be fwded.
**
*******************************************************************************/
static bool stpropnci_cb_set_config_observer_rsp(bool dir_from_upper,
                                                 const uint8_t *payload,
                                                 const uint16_t payloadlen,
                                                 uint8_t mt, uint8_t gid,
                                                 uint8_t oid) {
  uint8_t *buf = stpropnci_state.tmpbuff;
  uint16_t *buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;

  stpropnci_tmpbuff_reset();

  // build the response to stack
  NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_PROP);
  NCI_MSG_BLD_HDR1(pp, NCI_MSG_PROP_ANDROID);
  paylen = pp++;
  UINT8_TO_STREAM(pp, NCI_ANDROID_PASSIVE_OBSERVE);
  UINT8_TO_STREAM(pp, payload[3]);

  // Update the pending fields
  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;

  return stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                             *stpropnci_state.tmpbufflen, nullptr);
}

/*******************************************************************************
**
** Function         stpropnci_cb_generate_polling_loop_frame
**
** Description      Generate PLF notifications when receiving FW logs.
**
** Returns          false so the FW logs can reach additional modules as needed.
**
*******************************************************************************/
#define TAG_FIELD_CHANGE 0
#define TAG_NFC_A 1
#define TAG_NFC_B 2
#define TAG_NFC_F 3
#define TAG_NFC_V 4
#define TAG_NFC_UNKNOWN 7

#define FORMAT_IS_ST21NFCD(f) (((f) & 0xF0) == 0x10)
#define FORMAT_IS_ST54J(f) (((f) & 0xF0) == 0x20)
#define FORMAT_IS_ST54L(f) (((f) & 0xF0) == 0x30)

static bool stpropnci_cb_generate_polling_loop_frame(bool dir_from_upper,
                                                     const uint8_t *payload,
                                                     const uint16_t payloadlen,
                                                     uint8_t mt, uint8_t gid,
                                                     uint8_t oid) {
  uint8_t *buf = stpropnci_state.tmpbuff;
  uint16_t *buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;

  uint8_t format = payload[3];
  int current_tlv_pos = 6;  // position of first byte of the first TLV
  int current_tlv_length;
  int idx;
  int conv_tlv = 0;
  uint32_t ts = 0;

  stpropnci_tmpbuff_reset();

  // build the ntf to stack
  NCI_MSG_BLD_HDR0(pp, NCI_MT_NTF, NCI_GID_PROP);
  NCI_MSG_BLD_HDR1(pp, NCI_MSG_PROP_ANDROID);
  paylen = pp++;
  UINT8_TO_STREAM(pp, NCI_ANDROID_POLLING_FRAME_NTF);

  // Parse TLVs from the FW log notification.
  for (idx = 0;; ++idx) {
    uint8_t T;
    bool process = false;

    // Check there is a full TLV
    if (current_tlv_pos + 1 > payloadlen) break;
    current_tlv_length = payload[current_tlv_pos + 1] + 2;
    if (current_tlv_pos + current_tlv_length > payloadlen) break;

    // check the type
    T = payload[current_tlv_pos];
    switch (T) {
      case FWLOG_T_fieldOn:
      case FWLOG_T_fieldOff:
        stpropnci_state.pollingframe_inCE = false;
        process = true;
        break;
      case FWLOG_T_CERx:
      case FWLOG_T_CERxError:
        if (!stpropnci_state.pollingframe_inCE) {
          process = true;
        }
        break;
      case FWLOG_T_CETx:
      case FWLOG_T_Active_A:
      case FWLOG_T_Sleep_A:
        stpropnci_state.pollingframe_inCE = true;
        break;
      case FWLOG_T_fieldLevel:
      case FWLOG_T_Idle:
        stpropnci_state.pollingframe_inCE = false;
        break;
      default:
        // we are not interested in other TLVs
        break;
    }

    if (process) {
      uint8_t flag = 0, type = 0, gain = 0xFF, error = 0;
      int reallenidx = 0;
      uint16_t reallen = 0;
      int availlen = current_tlv_length;

      // Prepare the timestamp
      if ((format & 0x1) == 0 || current_tlv_length < 6) {
        ts = 0;
      } else {
        availlen -= 4;
        ts = (payload[current_tlv_pos + current_tlv_length - 4] << 24) |
             (payload[current_tlv_pos + current_tlv_length - 3] << 16) |
             (payload[current_tlv_pos + current_tlv_length - 2] << 8) |
             payload[current_tlv_pos + current_tlv_length - 1];
        if ((format & 0x30) == 0x30) {
          // ST54L: 3.95us unit
          ts = (uint32_t)((((long long)ts * 1024) / 259) + 0.5);
        } else {
          // ST54J/K: 4.57us unit
          ts = (uint32_t)((((long long)ts * 128) / 28) + 0.5);
        }
      }

      // Fill the TLV in PF based on FW log data
      switch (T) {
        case FWLOG_T_fieldOn:
        case FWLOG_T_fieldOff:
          // fill this TLV
          UINT8_TO_STREAM(pp, TAG_FIELD_CHANGE);
          UINT8_TO_STREAM(pp, flag);
          UINT8_TO_STREAM(pp, 6 /* fixed length */);
          UINT8_TO_STREAM(pp, (ts >> 24) & 0xFF);
          UINT8_TO_STREAM(pp, (ts >> 16) & 0xFF);
          UINT8_TO_STREAM(pp, (ts >> 8) & 0xFF);
          UINT8_TO_STREAM(pp, ts & 0xFF);
          UINT8_TO_STREAM(pp, gain);
          UINT8_TO_STREAM(pp, (T == FWLOG_T_fieldOn) ? 0x01 : 0x00);
          break;

        case FWLOG_T_CERxError:
        case FWLOG_T_CERx:
          // first byte is frame bitrate and type
          switch (payload[current_tlv_pos + 2] & 0x0F) {
            case 0x0:  // unknown
              type = TAG_NFC_UNKNOWN;
              break;
            case 0x1:        // A, short frame
              flag |= 0x01;  // short frame
              type = TAG_NFC_A;
              break;
            case 0x2:  // A, bit-oriented
            case 0x3:  // A, standard
            case 0x4:  // A, transparent
            case 0x5:  // A, T1T
            case 0x6:  // A, thinfilm
              type = TAG_NFC_A;
              break;
            case 0x7:  // B, standard frame
              type = TAG_NFC_B;
              break;
            case 0x8:  // F, standard frame
            case 0x9:  // F, slot-aligned
              type = TAG_NFC_F;
              break;
            case 0xA:  // V, standard.
              type = TAG_NFC_V;
              break;
            case 0xB:  // A, enhanced frame
              type = TAG_NFC_A;
              break;
            case 0xC:  // B, enhanced frame
              type = TAG_NFC_B;
              break;
            case 0xD:  // A, unknown frame type
              type = TAG_NFC_A;
              break;
            default:  // others are not defined
              type = TAG_NFC_UNKNOWN;
              break;
          }

          // 2nd byte is gain except for T=T_CERx for ST54L
          // following bytes depend on the chip and the type of TLV.
          // it always end with 2 bytes reallen then the payload
          if (FORMAT_IS_ST21NFCD(format)) {
            gain = payload[current_tlv_pos + 3];
            if (T == FWLOG_T_CERx) {
              error = 0;
              reallenidx = current_tlv_pos + 4;
              availlen -= 6;
            } else {
              error = payload[current_tlv_pos + 4];
              reallenidx = current_tlv_pos + 5;
              availlen -= 7;
            }
          } else {  // 54J, 54L
            gain = (payload[current_tlv_pos + 3] & 0xF0) >> 4;
            if (T == FWLOG_T_CERx) {
              error = 0;
              if (FORMAT_IS_ST54L(format)) {
                gain = 0xFF;
                reallenidx = current_tlv_pos + 3;
                availlen -= 5;
              } else {
                reallenidx = current_tlv_pos + 5;
                availlen -= 7;
              }
            } else {
              error = payload[current_tlv_pos + 5];
              reallenidx = current_tlv_pos + 6;
              availlen -= 8;
            }
          }
          reallen = (payload[reallenidx] << 8) | payload[reallenidx + 1];

          if ((availlen > 2) && (reallen > availlen)) {
            // data is truncated, so our buffer 2 last bytes are the end of the
            // frame, remove them
            availlen -= 2;
          }

          // In case of error, consider the type is unknown.
          if (error != 0) {
            type = TAG_NFC_UNKNOWN;
          }

          // 54J bug on short frames
          if (FORMAT_IS_ST54J(format) && (flag & 1) && error == 0) {
            reallen = 1;
          }

          // Type A but not WUPA / REQA, change to unknown
          if ((type == TAG_NFC_A) && (reallen >= 1) &&
              ((payload[reallenidx + 2] != 0x26) &&
               (payload[reallenidx + 2] != 0x52))) {
            // received a type A frame that is not WUPA / REQA, change to
            // unknown.
            type = TAG_NFC_UNKNOWN;
          }

          // Type B but not REQB, change to unknown
          if ((type == TAG_NFC_B) && (reallen == 3) &&
              (payload[reallenidx + 2] != 0x05)) {
            type = TAG_NFC_UNKNOWN;
          }

          // Now prepare the TLV
          UINT8_TO_STREAM(pp, type);
          UINT8_TO_STREAM(pp, flag);
          UINT8_TO_STREAM(pp, 5 + availlen);
          UINT8_TO_STREAM(pp, (ts >> 24) & 0xFF);
          UINT8_TO_STREAM(pp, (ts >> 16) & 0xFF);
          UINT8_TO_STREAM(pp, (ts >> 8) & 0xFF);
          UINT8_TO_STREAM(pp, ts & 0xFF);
          UINT8_TO_STREAM(pp, gain);
          if (availlen > 0) {
            ARRAY_TO_STREAM(pp, payload + (reallenidx + 2), availlen);
          }
          break;
      }

      // Mark the TLV added in PF
      conv_tlv++;
    }

    // go to next TLV
    current_tlv_pos = current_tlv_pos + current_tlv_length;
  }  // idx is now the number of TLVs

  if (conv_tlv) {
    // We have at least one PF TLV, send the message
    *paylen = pp - (paylen + 1);
    *buflen = pp - buf;

    if (!stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                             *stpropnci_state.tmpbufflen, nullptr))
      LOG_E("Failed to send one Polling Frame ntf");
  }

  // Always return false to let other modules process FW logs as well.
  return false;
}

/*******************************************************************************
**
** Function         stpropnci_build_rf_set_listen_passive_observer_cmd
**
** Description      Prepare the RF_SET_LISTEN_OBSERVE_MODE_CMD for observe mode
*(new method)
**
** Returns          none
**
*******************************************************************************/
static void stpropnci_build_rf_set_listen_passive_observer_cmd(uint8_t *buf,
                                                               uint16_t *buflen,
                                                               uint8_t mode) {
  uint8_t *pp = buf, *paylen;
  NCI_MSG_BLD_HDR0(pp, NCI_MT_CMD, NCI_GID_RF_MANAGE);
  NCI_MSG_BLD_HDR1(pp, NCI_MSG_RF_SET_LISTEN_OBSERVE_MODE);
  paylen = pp++;

  // Mask with types we support only (e.g. remove type V)
  UINT8_TO_STREAM(pp, mode & OBSERVE_ALL);

  // Update the pending fields
  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;
}

/*******************************************************************************
**
** Function         stpropnci_cb_rf_set_listen_passive_observer_rsp
**
** Description      Process the response from RF_SET_LISTEN_OBSERVE_MODE_CMD
**
** Returns          true if the response was handled and shall not be fwded.
**
*******************************************************************************/
static bool stpropnci_cb_rf_set_listen_passive_observer_rsp(
    bool dir_from_upper, const uint8_t *payload, const uint16_t payloadlen,
    uint8_t mt, uint8_t gid, uint8_t oid) {
  uint8_t *buf = stpropnci_state.tmpbuff;
  uint16_t *buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;

  stpropnci_tmpbuff_reset();

  // build the response to stack
  NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_PROP);
  NCI_MSG_BLD_HDR1(pp, NCI_MSG_PROP_ANDROID);
  paylen = pp++;
  UINT8_TO_STREAM(pp, NCI_ANDROID_SET_PASSIVE_OBSERVER_TECH);
  UINT8_TO_STREAM(pp, payload[3]);

  // Update the pending fields
  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;

  return stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                             *stpropnci_state.tmpbufflen, nullptr);
}

/*******************************************************************************
**
** Function         stpropnci_build_set_exit_frame_cmd
**
** Description      Prepare the PROP_RF_SET_OBSERVE_MODE_EXIT_FRAME_CMD
**                  based on Android NCI command, but some params need to be
*remaped a bit.
**
** Returns          none
**
*******************************************************************************/
static bool stpropnci_build_set_exit_frame_cmd(uint8_t *buf, uint16_t *buflen,
                                               const uint8_t *incoming,
                                               const uint16_t incominglen) {
  const uint8_t *in;
  uint16_t crc;
  uint8_t remaining_frames;
  uint16_t remaining = incominglen;
  uint8_t *pp = buf, *paylen;
  NCI_MSG_BLD_HDR0(pp, NCI_MT_CMD, NCI_GID_PROP);
  NCI_MSG_BLD_HDR1(pp, ST_NCI_MSG_PROP_RF_SET_OBSERVE_MODE_EXIT_FRAME);
  paylen = pp++;

  // NCI_ANDROID_SET_PASSIVE_OBSERVER_EXIT_FRAME
  //   subOID
  //   more
  //   timeout[2] //  LSB, unit ms.
  //   num frames
  //   {
  //     qualifier
  //     value_len
  //     power state
  //     data[1~16]
  //     mask[1~16]
  //   }
  // ST_NCI_MSG_PROP_RF_SET_OBSERVE_MODE_EXIT_FRAME
  //   more
  //   timeout[2] // LSB, unit ms; values 0x64~0xFFFF
  //   num frames
  //   {
  //     qualifier
  //     value_len
  //     power state
  //     data[1~16] // including CRC...
  //     mask[1~16]
  //   }

  if (remaining < (3 + 4)) {
    LOG_E("NCI_ANDROID_SET_PASSIVE_OBSERVER_EXIT_FRAME too short");
    return false;
  } else if (remaining > MAX_NCI_MESSAGE_LEN) {
    // 1 entry in exit table is up to 35 bytes max in NFC FW.
    // we can support up to 10 entries ==> we may need to send in 2 messages.
    // As the length is exactly the same as Android NCI, at the moment we
    // don't support longer frames.
    LOG_E(
        "NCI_ANDROID_SET_PASSIVE_OBSERVER_EXIT_FRAME too long, not supported "
        "yet");
    return false;
  }

  in = incoming + 4;
  UINT8_TO_STREAM(pp, *in++);  // "more"
  if (in[0] < 0x64 && in[1] == 0x00) {
    // NFC FW min timeout is 100ms
    UINT8_TO_STREAM(pp, 0x64);  // "timeout[LSB]"
    UINT8_TO_STREAM(pp, 0x00);  // "timeout[MSB]"
    in += 2;
  } else {
    UINT8_TO_STREAM(pp, *in++);  // "timeout[LSB]"
    UINT8_TO_STREAM(pp, *in++);  // "timeout[MSB]"
  }
  UINT8_TO_STREAM(pp, (remaining_frames = *in++));  // "num frames"
  remaining -= 7;

  while (remaining_frames) {
    uint8_t qual;
    uint8_t vallen, motiflen;

    if (remaining < 2) {
      LOG_E("NCI_ANDROID_SET_PASSIVE_OBSERVER_EXIT_FRAME too short");
      return false;
    }

    qual = *in++;
    vallen = *in++;
    motiflen = (vallen - 1) / 2;
    remaining -= 2;
    if (remaining < vallen) {
      LOG_E("NCI_ANDROID_SET_PASSIVE_OBSERVER_EXIT_FRAME too short");
      return false;
    }

    // Maybe add the CRC. To be discussed how to handle if there is not enough
    // space ? We will just fail at the moment. ref AOSP commit
    // ade96b0468011e6c08ce35e12dc4f6060544f84f
    crc = 0;
    if (motiflen > 15) {
      // no choice, we add "longer than" as there is not enough space to add
      // CRC.
      qual |= 0x10;
    }

    if ((qual & 0x10) == 0) {
      // There is no "longer than", we need to match the CRC, compute it
      switch (qual & 0x7) {
        case 0x00:
          crc = iso14443_crc(in + 1, motiflen, Type_A);
          break;
        case 0x01:
          crc = iso14443_crc(in + 1, motiflen, Type_B);
          break;
        default:  // no CRC for other modes at the moment.
          break;
      }
    }

    // sanity check, do we have enough space to store this entry in target
    // message ?
    if ((MAX_NCI_MESSAGE_LEN - (pp - buf)) < (2 + vallen + (crc ? 4 : 0))) {
      LOG_E(
          "Failing to generate ST_NCI_MSG_PROP_RF_SET_OBSERVE_MODE_EXIT_FRAME "
          "due to CRC overheads, need to adapt the logic to split message");
      return false;
    }

    // if needed to remap the technologies, we could do it here
    UINT8_TO_STREAM(pp, qual);    // qualifier
    UINT8_TO_STREAM(pp, vallen);  // len
    if (crc == 0) {
      // we just copy the power state, data and mask as is.
      ARRAY_TO_STREAM(pp, in, vallen);
      in += vallen;
    } else {
      bool exact = true;
      UINT8_TO_STREAM(pp, *in++);         // power state
      ARRAY_TO_STREAM(pp, in, motiflen);  // data
      in += motiflen;
      UINT8_TO_STREAM(pp, (uint8_t)(crc & 0xFF));
      UINT8_TO_STREAM(pp, (uint8_t)(crc >> 8));
      while (motiflen--) {
        if (*in != 0xFF) {
          // At least one byte in the motif has a wildcard, so the CRC will not
          // match.
          exact = false;
        }
        UINT8_TO_STREAM(pp, *in++);  // mask byte
      }
      // Add mask for the CRC bytes; it will be a match only if all bytes were
      // exact match
      UINT8_TO_STREAM(pp, exact ? 0xFF : 0x00);
      UINT8_TO_STREAM(pp, exact ? 0xFF : 0x00);
    }

    remaining_frames--;
  }

  // Update the pending fields
  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;

  return true;
}

/*******************************************************************************
**
** Function         stpropnci_cb_set_exit_frame_rsp
**
** Description      Process the response from
*PROP_RF_SET_OBSERVE_MODE_EXIT_FRAME_CMD
**
** Returns          true if the response was handled and shall not be fwded.
**
*******************************************************************************/
static bool stpropnci_cb_set_exit_frame_rsp(bool dir_from_upper,
                                            const uint8_t *payload,
                                            const uint16_t payloadlen,
                                            uint8_t mt, uint8_t gid,
                                            uint8_t oid) {
  uint8_t *buf = stpropnci_state.tmpbuff;
  uint16_t *buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;

  stpropnci_tmpbuff_reset();

  // build the response to stack
  NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_PROP);
  NCI_MSG_BLD_HDR1(pp, NCI_MSG_PROP_ANDROID);
  paylen = pp++;
  UINT8_TO_STREAM(pp, NCI_ANDROID_SET_PASSIVE_OBSERVER_EXIT_FRAME);
  UINT8_TO_STREAM(pp, payload[3]);

  // Update the pending fields
  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;

  return stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                             *stpropnci_state.tmpbufflen, nullptr);
}

/*******************************************************************************
**
** Function         stpropnci_build_set_custom_polling_cmd
**
** Description      Prepare the ST_NCI_MSG_PROP_RF_SET_CUST_PASSIVE_POLL_FRAME
**                  based on Android NCI command, but some params need to be
*remaped a bit.
**
** Returns          none
**
*******************************************************************************/
static bool stpropnci_build_set_custom_polling_cmd(uint8_t *buf,
                                                   uint16_t *buflen,
                                                   const uint8_t *incoming,
                                                   const uint16_t incominglen) {
  const uint8_t *in;
  uint16_t remaining = incominglen;
  uint8_t *pp = buf, *paylen;
  uint8_t nb_frames = 0, motiflen = 0;
  NCI_MSG_BLD_HDR0(pp, NCI_MT_CMD, NCI_GID_PROP);
  NCI_MSG_BLD_HDR1(pp, ST_NCI_MSG_PROP_RF_SET_CUST_PASSIVE_POLL_FRAME);
  paylen = pp++;

  // Android NCI NCI_ANDROID_SET_TECH_A_POLLING_LOOP_ANNOTATION payload:
  //  number of frames (0 or 1)
  //   position and type, 0x21
  //   len [N+3]
  //   waiting time 0x0A
  //   annotation_data[N bytes]
  //   0x00, 0x00  (?)

  // ST FW ST_NCI_MSG_PROP_RF_SET_CUST_PASSIVE_POLL_FRAME
  //  number of frames (0 or 1)
  //   qual-type (position, response expected, tech)
  //   len [N+1]
  //    RFU [1B]
  //    RF frame [N=1~16B]

  if (remaining < (3 + 2)) {
    LOG_E("NCI_ANDROID_SET_TECH_A_POLLING_LOOP_ANNOTATION too short");
    return false;
  }

  in = incoming + 4;  // beginning of the payload
  nb_frames = *in;
  if (nb_frames > 1) {
    LOG_E(
        "NCI_ANDROID_SET_TECH_A_POLLING_LOOP_ANNOTATION unsupported number of "
        "frames");
    return false;
  }

  UINT8_TO_STREAM(pp, *in++);  // nb_frames
  remaining -= 5;

  if (nb_frames) {
    uint16_t crc;

    if (remaining < 7) {
      LOG_E("NCI_ANDROID_SET_TECH_A_POLLING_LOOP_ANNOTATION too short");
      return false;
    }

    // Convert the frame content -- may need to revisit, JNI code seems not
    // aligned with definition.

    if (*in++ != 0x21) {
      LOG_E(
          "NCI_ANDROID_SET_TECH_A_POLLING_LOOP_ANNOTATION unsupported "
          "position/type value");
      return false;
    }
    UINT8_TO_STREAM(pp, 0x20);  // position 1, no response, type A std

    motiflen = *in - 3;
    UINT8_TO_STREAM(
        pp,
        *in++);  // length. JNI already added 3 to the payload. Spec to check...
    UINT8_TO_STREAM(pp, *in++);  // RFU, (waiting time according to JNI)

    crc = iso14443_crc(in, motiflen, Type_A);

    ARRAY_TO_STREAM(pp, in, motiflen);
    in += motiflen;

    UINT8_TO_STREAM(pp, (uint8_t)(crc & 0xFF));
    UINT8_TO_STREAM(pp, (uint8_t)(crc >> 8));
  }

  // Update the pending fields
  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;

  return true;
}

/*******************************************************************************
**
** Function         stpropnci_cb_set_custom_polling_rsp
**
** Description      Process the response from
*ST_NCI_MSG_PROP_RF_SET_CUST_PASSIVE_POLL_FRAME
**
** Returns          true if the response was handled and shall not be fwded.
**
*******************************************************************************/
static bool stpropnci_cb_set_custom_polling_rsp(bool dir_from_upper,
                                                const uint8_t *payload,
                                                const uint16_t payloadlen,
                                                uint8_t mt, uint8_t gid,
                                                uint8_t oid) {
  uint8_t *buf = stpropnci_state.tmpbuff;
  uint16_t *buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;

  stpropnci_tmpbuff_reset();

  // build the response to stack
  NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_PROP);
  NCI_MSG_BLD_HDR1(pp, NCI_MSG_PROP_ANDROID);
  paylen = pp++;
  UINT8_TO_STREAM(pp, NCI_ANDROID_SET_TECH_A_POLLING_LOOP_ANNOTATION);
  UINT8_TO_STREAM(pp, payload[3]);

  // Update the pending fields
  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;

  return stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                             *stpropnci_state.tmpbufflen, nullptr);
}

/*******************************************************************************
**
** Function         stpropnci_cb_observe_mode_suspend
**
** Description      Process the ntfs related to observe mode when exit frame is
*set
**
** Returns          true if the response was handled and shall not be fwded.
**
*******************************************************************************/
static bool stpropnci_cb_observe_mode_suspend(bool dir_from_upper,
                                              const uint8_t *payload,
                                              const uint16_t payloadlen,
                                              uint8_t mt, uint8_t gid,
                                              uint8_t oid) {
  // Shall we report this to stack ?
  LOG_D("Exit frame: observe mode is %s",
        oid == ST_NCI_MSG_PROP_RF_OBSERVE_MODE_SUSPENDED ? "suspended"
                                                         : "resumed");

  // This prop ntf never needs to be forwarded.
  return true;
}

/*******************************************************************************
**
** Function         iso14443_crc
**
** Description      Computes a CRC value needed for ST FW for exit frames
**
** Returns          the CRC
**
*******************************************************************************/
static uint16_t iso14443_crc(const uint8_t *data, size_t szLen, int type) {
  uint16_t tempCrc;
  if (type == Type_A) {
    tempCrc = (unsigned short)CRC_PRESET_A;
  } else {
    tempCrc = (unsigned short)CRC_PRESET_B;
  }
  do {
    uint8_t bt;
    bt = *data++;
    bt = (bt ^ (uint8_t)(tempCrc & 0x00FF));
    bt = (bt ^ (bt << 4));
    tempCrc = (tempCrc >> 8) ^ ((uint32_t)bt << 8) ^ ((uint32_t)bt << 3) ^
              ((uint32_t)bt >> 4);
  } while (--szLen);

  return tempCrc;
}

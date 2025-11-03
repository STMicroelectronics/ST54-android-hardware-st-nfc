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
#include <stdlib.h>
#include <string.h>
#include <stpropnci-internal.h>
#include <nfa_hci_defs.h>
#include <nfc_api.h>

static bool stpropnci_prop_st_cb_apdu_gate_atr(const uint8_t* payload,
                                               const uint16_t payloadlen);
static bool stpropnci_cb_get_apdu_info(bool dir_from_upper,
                                       const uint8_t* payload,
                                       const uint16_t payloadlen, uint8_t mt,
                                       uint8_t gid, uint8_t oid);
bool stpropnci_prop_st_send_hci(uint8_t pipe_id, uint8_t type,
                                uint8_t instruction, uint16_t msg_len,
                                const uint8_t* p_msg,
                                bool (*hci_cb)(const uint8_t* payload,
                                               const uint16_t payloadlen));
bool stpropnci_prop_st_hci_reassembly_cb(bool dir_from_upper,
                                         const uint8_t* payload,
                                         const uint16_t payloadlen, uint8_t mt,
                                         uint8_t gid, uint8_t oid);
static bool stpropnci_prop_st_cb_apdu_gate_transceive(
    const uint8_t* payload, const uint16_t payloadlen);
void parse_fw_ntf(const uint8_t* payload, const uint16_t payloadlen);
void eseMonitor(uint8_t format, uint16_t data_len, const uint8_t* p_data,
                bool last);
static bool stpropnci_prop_st_cb_set_custom_polling_rsp(
    bool dir_from_upper, const uint8_t* payload, const uint16_t payloadlen,
    uint8_t mt, uint8_t gid, uint8_t oid);
static bool stpropnci_prop_st_build_set_custom_polling_cmd(
    uint8_t* buf, uint16_t* buflen, const uint8_t* incoming,
    const uint16_t incominglen);
extern uint16_t iso14443_crc(const uint8_t* data, size_t szLen, int type);

static bool stpropnci_cb_disable_ese_rsp(bool dir_from_upper,
                                         const uint8_t* payload,
                                         const uint16_t payloadlen, uint8_t mt,
                                         uint8_t gid, uint8_t oid);
static bool stpropnci_cb_reset_ese_rsp(bool dir_from_upper,
                                       const uint8_t* payload,
                                       const uint16_t payloadlen, uint8_t mt,
                                       uint8_t gid, uint8_t oid);

static const uint8_t ESE_ATR_REG_IDX = 0x01;
static const uint8_t EVT_SE_SOFT_RESET = 0x11;
static const uint8_t EVT_WTX_REQUEST = 0x11;
static const uint8_t EVT_TRANSMIT_DATA = 0x10;

/*******************************************************************************
**
** Function         stpropnci_process_prop_st
**
** Description      This function is default handler for ST NCI
**
** Returns          true if message was handled and does not need to be
*forwarded
**
*******************************************************************************/
bool stpropnci_process_prop_st(bool inform_only, bool dir_from_upper,
                               const uint8_t* payload,
                               const uint16_t payloadlen, uint8_t mt,
                               uint8_t oid) {
  bool handled = false;
  uint8_t* buf = stpropnci_state.tmpbuff;
  uint16_t* buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;

  stpropnci_tmpbuff_reset();

  if (inform_only) {
    // Process the updates as needed

    return false;
  }

  switch (mt) {
    case NCI_MT_CMD:
      /*********************************************************************/
      /***                CMD                     ***/
      /*********************************************************************/
      if (dir_from_upper != MSG_DIR_FROM_STACK) {
        LOG_E(" Unexpected CMD coming from NFCC");
        return false;
      }
      switch (oid) {
        case ST_PROP_NCI_OID:  // command from extensions
          /******************* NFC OEM ext CMD ***********************/
          switch (payload[3]) {
            case ST_PROP_NCI_SET_LIB_PASSTHOUGH: {
              LOG_I("Set passthrough mode: %02hhx", payload[4]);
              stpropnci_state.passthrough_mode = (payload[4] == 0x01);
              // and respond
              NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_PROP);
              NCI_MSG_BLD_HDR1(pp, ST_PROP_NCI_OID);
              paylen = pp++;
              UINT8_TO_STREAM(pp, ST_PROP_NCI_SET_LIB_PASSTHOUGH);
              UINT8_TO_STREAM(pp, NCI_STATUS_OK);
              *paylen = pp - (paylen + 1);
              *buflen = pp - buf;
              // send it
              handled =
                  stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                      *stpropnci_state.tmpbufflen, nullptr);
            } break;

            case ST_PROP_NCI_GET_STPROPNCI_VERSION_SUBOID: {
              uint16_t version = STPROPNCI_LIB_VERSION;

              NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_PROP);
              NCI_MSG_BLD_HDR1(pp, ST_PROP_NCI_OID);
              paylen = pp++;
              UINT8_TO_STREAM(pp, ST_PROP_NCI_GET_STPROPNCI_VERSION_SUBOID);
              UINT8_TO_STREAM(pp, NCI_STATUS_OK);
              UINT8_TO_STREAM(pp, (version >> 8) & 0xFF);
              UINT8_TO_STREAM(pp, version & 0xFF);
              *paylen = pp - (paylen + 1);
              *buflen = pp - buf;
              // send it back
              handled =
                  stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                      *stpropnci_state.tmpbufflen, nullptr);
            } break;

            case ST_PROP_NCI_GET_MANUF_DATA_SUBOID: {
              NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_PROP);
              NCI_MSG_BLD_HDR1(pp, ST_PROP_NCI_OID);
              paylen = pp++;
              UINT8_TO_STREAM(pp, ST_PROP_NCI_GET_MANUF_DATA_SUBOID);
              if (stpropnci_state.manu_specific_info_len > 0) {
                UINT8_TO_STREAM(pp, NCI_STATUS_OK);
                ARRAY_TO_STREAM(pp, stpropnci_state.manu_specific_info,
                                stpropnci_state.manu_specific_info_len);
              } else {
                UINT8_TO_STREAM(pp, NCI_STATUS_NOT_INITIALIZED);
              }

              *paylen = pp - (paylen + 1);
              *buflen = pp - buf;
              // send it back
              handled =
                  stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                      *stpropnci_state.tmpbufflen, nullptr);
            } break;

            case ST_PROP_NCI_GET_NFCEE_ID_LIST: {
              NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_PROP);
              NCI_MSG_BLD_HDR1(pp, ST_PROP_NCI_OID);
              paylen = pp++;
              UINT8_TO_STREAM(pp, ST_PROP_NCI_GET_NFCEE_ID_LIST);

              if (stpropnci_state.nb_active_nfcees > 0) {
                UINT8_TO_STREAM(pp, NCI_STATUS_OK);
                UINT8_TO_STREAM(pp, stpropnci_state.nb_active_nfcees);
                ARRAY_TO_STREAM(pp, stpropnci_state.active_nfcee_ids,
                                stpropnci_state.nb_active_nfcees);
              } else {
                UINT8_TO_STREAM(pp, NCI_STATUS_FAILED);
              }

              *paylen = pp - (paylen + 1);
              *buflen = pp - buf;
              // send it back
              handled =
                  stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                      *stpropnci_state.tmpbufflen, nullptr);
            } break;

            case ST_PROP_NCI_SETUP_ADPU_GATE: {
              if (stpropnci_state.apdu_gate_ready) {
                // Send SOFT RESET
                if (!stpropnci_prop_st_send_hci(
                        stpropnci_state.apdu_pipe_id & 0x7F, NFA_HCI_EVENT_TYPE,
                        EVT_SE_SOFT_RESET, 0, nullptr, nullptr)) {
                  LOG_E("Send HCI message failed");
                  stpropnci_build_prop_status_rsp(
                      stpropnci_state.tmpbuff, stpropnci_state.tmpbufflen,
                      ST_PROP_NCI_OID, payload[3], NCI_STATUS_FAILED);
                  // send it back
                  handled = stpropnci_pump_post(
                      MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                      *stpropnci_state.tmpbufflen, nullptr);
                  break;
                }

                // Send GET ATR
                uint8_t get_atr[] = {ESE_ATR_REG_IDX};
                if (!stpropnci_prop_st_send_hci(
                        stpropnci_state.apdu_pipe_id & 0x7F,
                        NFA_HCI_COMMAND_TYPE, NFA_HCI_ANY_GET_PARAMETER,
                        sizeof(get_atr), get_atr,
                        stpropnci_prop_st_cb_apdu_gate_atr)) {
                  LOG_E(" Send HCI message failed");
                  stpropnci_build_prop_status_rsp(
                      stpropnci_state.tmpbuff, stpropnci_state.tmpbufflen,
                      ST_PROP_NCI_OID, payload[3], NCI_STATUS_FAILED);
                  // send it back
                  handled = stpropnci_pump_post(
                      MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                      *stpropnci_state.tmpbufflen, nullptr);
                  break;
                }
                handled = true;
              } else {
                LOG_E(" APDU gate not functional");
                stpropnci_build_prop_status_rsp(
                    stpropnci_state.tmpbuff, stpropnci_state.tmpbufflen,
                    ST_PROP_NCI_OID, payload[3], NCI_STATUS_FAILED);
                // send it back
                handled = stpropnci_pump_post(
                    MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                    *stpropnci_state.tmpbufflen, nullptr);
              }
            } break;

            case ST_PROP_NCI_TRANSCEIVE_ADPU_GATE: {
              if (stpropnci_state.apdu_gate_ready) {
                if (!stpropnci_prop_st_send_hci(
                        stpropnci_state.apdu_pipe_id & 0x7F, NFA_HCI_EVENT_TYPE,
                        EVT_TRANSMIT_DATA, payloadlen - 4, (payload + 4),
                        stpropnci_prop_st_cb_apdu_gate_transceive)) {
                  LOG_E("Send HCI message failed");
                  stpropnci_build_prop_status_rsp(
                      stpropnci_state.tmpbuff, stpropnci_state.tmpbufflen,
                      ST_PROP_NCI_OID, payload[3], NCI_STATUS_FAILED);
                  // send it back
                  handled = stpropnci_pump_post(
                      MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                      *stpropnci_state.tmpbufflen, nullptr);
                  break;
                } else {
                  stpropnci_build_prop_status_rsp(
                      stpropnci_state.tmpbuff, stpropnci_state.tmpbufflen,
                      ST_PROP_NCI_OID, payload[3], NCI_STATUS_OK);
                  // send it back
                  handled = stpropnci_pump_post(
                      MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                      *stpropnci_state.tmpbufflen, nullptr);
                }
              } else {
                LOG_E(" APDU gate not functional");
                stpropnci_build_prop_status_rsp(
                    stpropnci_state.tmpbuff, stpropnci_state.tmpbufflen,
                    ST_PROP_NCI_OID, payload[3], NCI_STATUS_FAILED);
                // send it back
                handled = stpropnci_pump_post(
                    MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                    *stpropnci_state.tmpbufflen, nullptr);
              }
            } break;

            case ST_PROP_EMULATE_NFC_A_CARD_2: {
              stpropnci_state.is_card_a_on =
                  ((payload[4] & 0xFF) == 0x01 ? true : false);

              NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_PROP);
              NCI_MSG_BLD_HDR1(pp, ST_PROP_NCI_OID);
              paylen = pp++;
              UINT8_TO_STREAM(pp, ST_PROP_EMULATE_NFC_A_CARD_2);
              UINT8_TO_STREAM(pp, NCI_STATUS_OK);
              *paylen = pp - (paylen + 1);
              *buflen = pp - buf;
              // send it back
              handled =
                  stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                      *stpropnci_state.tmpbufflen, nullptr);
            } break;

            case ST_PROP_SET_FELICA_CARD_ENABLED:
              stpropnci_state.is_ese_felica_enabled =
                  ((payload[4] & 0xFF) == 0x01 ? true : false);

              // Save to configuration file
              stpropnci_cfg_write_value(STPROPNCI_CFG_FELICA_ESE_SUPPORT,
                                        stpropnci_state.is_ese_felica_enabled
                                            ? STPROPNCI_CFG__true
                                            : STPROPNCI_CFG__false);

              NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_PROP);
              NCI_MSG_BLD_HDR1(pp, ST_PROP_NCI_OID);
              paylen = pp++;
              UINT8_TO_STREAM(pp, ST_PROP_SET_FELICA_CARD_ENABLED);
              UINT8_TO_STREAM(pp, NCI_STATUS_OK);
              *paylen = pp - (paylen + 1);
              *buflen = pp - buf;
              // send it back
              handled =
                  stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                      *stpropnci_state.tmpbufflen, nullptr);

              // Resend last EE discovery req, so stack triggers an LMRT update.
              if (stpropnci_state.last_ee_discovery_req_length) {
                (void)stpropnci_pump_post(
                    MSG_DIR_TO_STACK, stpropnci_state.last_ee_discovery_req,
                    stpropnci_state.last_ee_discovery_req_length, nullptr);
              }
              break;

            case ST_PROP_SET_RF_CUSTOM_POLL_FRAME:
              stpropnci_state.is_cust_poll_frame_set =
                  ((payload[4] & 0xFF) >= 0x01 ? true : false);
              stpropnci_state.is_rf_intf_cust_tx = false;
              // Prepare the native message
              // ST_NCI_MSG_PROP_RF_SET_CUST_PASSIVE_POLL_FRAME (add CRC)
              if (!stpropnci_prop_st_build_set_custom_polling_cmd(
                      stpropnci_state.tmpbuff, stpropnci_state.tmpbufflen,
                      payload, payloadlen)) {
                // the frame was not valid.
                stpropnci_tmpbuff_reset();
                stpropnci_build_prop_status_rsp(
                    stpropnci_state.tmpbuff, stpropnci_state.tmpbufflen,
                    ST_PROP_NCI_OID, ST_PROP_SET_RF_CUSTOM_POLL_FRAME,
                    NCI_STATUS_MESSAGE_CORRUPTED);

                // send it back
                handled = stpropnci_pump_post(
                    MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                    *stpropnci_state.tmpbufflen, nullptr);
              } else {
                // send it to NFCC
                handled = stpropnci_pump_post(
                    MSG_DIR_TO_NFCC, stpropnci_state.tmpbuff,
                    *stpropnci_state.tmpbufflen,
                    stpropnci_prop_st_cb_set_custom_polling_rsp);
              }
              break;

            default:
              LOG_I("ST OID(1) suboid %02hhx not supported", payload[3]);
              stpropnci_build_prop_status_rsp(
                  stpropnci_state.tmpbuff, stpropnci_state.tmpbufflen,
                  ST_PROP_NCI_OID, payload[3], NCI_STATUS_NOT_SUPPORTED);

              // send it back
              handled =
                  stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                      *stpropnci_state.tmpbufflen, nullptr);
          }
          break;

        case ST_NCI_MSG_PROP:
          /******************* NFC ST NCI PROP ***********************/
          switch (payload[3]) {
            case ST_NCI_PROP_GET_CONFIG:
              if (payload[4] == ST_NCI_PROP_GET_CONFIG__ESE_ATTR_ID) {
                handled =
                    stpropnci_pump_post(MSG_DIR_TO_NFCC, payload, payloadlen,
                                        stpropnci_cb_get_apdu_info);
              } else if (payload[4] & 0x08) {
                // Retrieve pipe list for another SE, expected, just
                // passthrough.
                handled =
                    stpropnci_pump_post(MSG_DIR_TO_NFCC, payload, payloadlen,
                                        stpropnci_cb_passthrough_rsp);
              } else {
                // Another config, not used so far
                LOG_I(
                    "Received ST FW prop command from stack, unexpected but "
                    "let it passthrough");
                handled =
                    stpropnci_pump_post(MSG_DIR_TO_NFCC, payload, payloadlen,
                                        stpropnci_cb_passthrough_rsp);
              }
              break;
            default:
              LOG_I(
                  "Received ST FW prop command from stack, unexpected but let "
                  "it "
                  "passthrough");
              handled =
                  stpropnci_pump_post(MSG_DIR_TO_NFCC, payload, payloadlen,
                                      stpropnci_cb_passthrough_rsp);
              break;
          }
          break;

        default:
          /******************* default ***********************/
          LOG_I(
              "Received ST prop command from stack, unexpected but let it "
              "passthrough");
          handled = stpropnci_pump_post(MSG_DIR_TO_NFCC, payload, payloadlen,
                                        stpropnci_cb_passthrough_rsp);

          break;
      }
      break;

    case NCI_MT_RSP:
      /*********************************************************************/
      /***                RSP                     ***/
      /*********************************************************************/
      LOG_E(" Unexpected RSP to process, should be always via cb. let through");
      return false;

    case NCI_MT_NTF:
      /*********************************************************************/
      /***                NTF                     ***/
      /*********************************************************************/
      if (dir_from_upper != MSG_DIR_FROM_NFCC) {
        LOG_E(" Unexpected NTF coming from stack, let it go");
        return false;
      }

      switch (oid) {
        case ST_NCI_MSG_PROP_PWR_MON_RW_ON_NTF:
          stpropnci_state.pwr_mon_isActiveRW = true;
          stpropnci_state.pwr_mon_errorCount = 0;
          handled = true;
          break;

        case ST_NCI_MSG_PROP_PWR_MON_RW_OFF_NTF:
          stpropnci_pump_watchdog_remove(WD_ACTIVE_RW_TOO_LONG);
          if (stpropnci_state.pwr_mon_isActiveRW) {
            stpropnci_state.pwr_mon_isActiveRW = false;
          } else {
            if (stpropnci_state.pwr_mon_errorCount++ > 20) {
              LOG_E("Too many PWR_MON_RW_OFF without ON, recovery");
              if (!stpropnci_send_core_reset_ntf_recovery(0)) {
                LOG_E("Failed to send CORE_RESET_NTF, critical failure");
                abort();
              }
            }
          }
          handled = true;
          break;

        case ST_NCI_MSG_PROP_RF_OBSERVE_MODE_SUSPENDED:
          stpropnci_state.observe_mode_suspended = true;
          // send NCI_ANDROID_PASSIVE_OBSERVER_SUSPENDED_NTF
          NCI_MSG_BLD_HDR0(pp, NCI_MT_NTF, NCI_GID_PROP);
          NCI_MSG_BLD_HDR1(pp, NCI_MSG_PROP_ANDROID);
          paylen = pp++;
          UINT8_TO_STREAM(pp, NCI_ANDROID_PASSIVE_OBSERVER_SUSPENDED_NTF);

          // Add the content of the notif but remove 2 bytes of the CRC
          {
            const uint8_t* in = payload + 3;
            uint8_t motiflen;
            UINT8_TO_STREAM(pp, *in++);  // type byte
            motiflen = *in++ - 2;
            UINT8_TO_STREAM(pp, motiflen);      // length byte
            ARRAY_TO_STREAM(pp, in, motiflen);  // matching motif except the CRC
          }

          *paylen = pp - (paylen + 1);
          *buflen = pp - buf;
          // send it
          handled =
              stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                  *stpropnci_state.tmpbufflen, nullptr);
          break;

        case ST_NCI_MSG_PROP_RF_OBSERVE_MODE_RESUMED:
          stpropnci_state.observe_mode_suspended = false;
          // send NCI_ANDROID_PASSIVE_OBSERVER_RESUMED_NTF
          NCI_MSG_BLD_HDR0(pp, NCI_MT_NTF, NCI_GID_PROP);
          NCI_MSG_BLD_HDR1(pp, NCI_MSG_PROP_ANDROID);
          paylen = pp++;
          UINT8_TO_STREAM(pp, NCI_ANDROID_PASSIVE_OBSERVER_RESUMED_NTF);
          // no payload in this one
          *paylen = pp - (paylen + 1);
          *buflen = pp - buf;
          // send it
          handled =
              stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                  *stpropnci_state.tmpbufflen, nullptr);
          break;

        case ST_NCI_MSG_PROP:
          /******************* NFC ST NCI PROP ***********************/
          switch (payload[4]) {
            case ST_NCI_PROP_LOG:
              // Parse FW NTF
              parse_fw_ntf(payload, payloadlen);

              // We have no further processing at the moment.
              // we may add more workarounds here later.
              handled = true;
              break;

            default:
              LOG_I("ST Prop NTF not processed, but block it");
              handled = true;
              break;
          }
          break;

        default:
          /******************* default ***********************/
          LOG_I("ST Prop NTF not processed, but block it");
          handled = true;
          break;
      }
      break;
  }

  return handled;
}

/*******************************************************************************
**
** Function         stpropnci_st_set_hal_passthrough
**
** Description      Instruct lower lib to stop processing.
**
** Returns          true
**
*******************************************************************************/
void stpropnci_st_set_hal_passthrough() {
#ifdef STPROPNCI_VENDOR
  LOG_E("This method shall not be called in VENDOR version");
#else   // STPROPNCI_VENDOR
  uint8_t* buf = stpropnci_state.tmpbuff;
  uint16_t* buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;

  stpropnci_tmpbuff_reset();

  // send NCI_ANDROID_PASSIVE_OBSERVER_SUSPENDED_NTF
  NCI_MSG_BLD_HDR0(pp, NCI_MT_CMD, NCI_GID_PROP);
  NCI_MSG_BLD_HDR1(pp, ST_PROP_NCI_OID);
  paylen = pp++;
  UINT8_TO_STREAM(pp, ST_PROP_NCI_SET_LIB_PASSTHOUGH);
  UINT8_TO_STREAM(pp, 0x01);  // enable passthrough
  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;

  (void)stpropnci_pump_post(MSG_DIR_TO_NFCC, stpropnci_state.tmpbuff,
                            *stpropnci_state.tmpbufflen,
                            stpropnci_cb_block_rsp);
#endif  // STPROPNCI_VENDOR
}

/*******************************************************************************
**
** Function         stpropnci_cb_get_apdu_info
**
** Description      Save pipes information.
**
** Returns          true if success
**
*******************************************************************************/
static bool stpropnci_cb_get_apdu_info(
    __attribute__((unused)) bool dir_from_upper, const uint8_t* payload,
    const uint16_t payloadlen, __attribute__((unused)) uint8_t mt,
    __attribute__((unused)) uint8_t gid, __attribute__((unused)) uint8_t oid) {
  // Check status
  if (payload[3] != 0x00) {
    LOG_E(" status NOK");
  } else {
    // Check if APDU gate if ready for use
    int i = 0;
    int nb_entry = payload[6] / 12;
    stpropnci_state.apdu_gate_ready = false;

    while (i < nb_entry) {
      if (payload[12 * i + 12] != 0) {
        if ((payload[12 * i + 8] == 0xf0) && (payload[12 * i + 12] == 0x06)) {
          stpropnci_state.apdu_gate_ready = true;
          stpropnci_state.apdu_pipe_id = payload[12 * i + 11];
          LOG_I(" Found functional APDU gate, pipeId=0x%x",
                stpropnci_state.apdu_pipe_id);
          break;
        }
      }
      i++;
    }
  }

  return stpropnci_pump_post(MSG_DIR_TO_STACK, payload, payloadlen, nullptr);
}

/*******************************************************************************
**
** Function         stpropnci_prop_st_cb_apdu_gate_atr
**
** Description      If we let a command passthrough, let the rsp as well.
**
** Returns          true
**
*******************************************************************************/
static bool stpropnci_prop_st_cb_apdu_gate_atr(const uint8_t* payload,
                                               __attribute__((unused))
                                               const uint16_t payloadlen) {
  // Try and get the BWI value in ATR response
  uint8_t bwi_idx = 3 /*1*/, level = 1, nb_bit_set, bwi;
  stpropnci_state.tx_waiting_time = 0xFF;
  int status = NCI_STATUS_OK;
  uint8_t* buf = stpropnci_state.tmpbuff;
  uint16_t* buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;

  stpropnci_tmpbuff_reset();

  if (payload[1] == 0x80) {
    while (level != 3)  // BWI is 4MSB of TB3
    {
      nb_bit_set = 0;
      for (int i = 0; i < 4; i++)  // Check bitmap (T0 or TDi)
      {
        if (payload[bwi_idx] & (0x10 << i)) {
          nb_bit_set++;
        }
      }

      // Check that there is a bitmap for next level until level 3, i.e
      // there is a TDi
      if (payload[bwi_idx] & 0x80) {
        level++;
      } else
        // No next level(TDi, i={1, 2}), exit
        break;

      bwi_idx += nb_bit_set;
    }

    if (level == 3)  // Level 3 reached
    {
      nb_bit_set = 0;
      // Check if TA3 is here, is so, go next byte
      if (payload[bwi_idx] & 0x10) {
        nb_bit_set++;
      }
      // TB3 here? BWI is in there. Update mBwi value.
      if (payload[bwi_idx] & 0x20) {
        nb_bit_set++;
        bwi_idx += nb_bit_set;
        bwi = (payload[bwi_idx] & 0xF0) >> 4;
        stpropnci_state.tx_waiting_time = (0x1 << bwi) * 100;  // in ms
        stpropnci_state.tx_waiting_time =
            (stpropnci_state.tx_waiting_time * 10) /
            3;  // eSE clock may run at 30%
        LOG_I(" APDU gate waiting time=%d", stpropnci_state.tx_waiting_time);
      }
    }
  } else {
    status = NCI_STATUS_FAILED;
  }

  // Prepare RSP for ST OEM Ext
  NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_PROP);
  NCI_MSG_BLD_HDR1(pp, ST_PROP_NCI_OID);
  paylen = pp++;
  UINT8_TO_STREAM(pp, ST_PROP_NCI_SETUP_ADPU_GATE);
  UINT8_TO_STREAM(pp, status);
  UINT8_TO_STREAM(pp, stpropnci_state.tx_waiting_time >> 8);
  UINT8_TO_STREAM(pp, stpropnci_state.tx_waiting_time & 0xFF);

  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;
  // send it back
  return stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                             *stpropnci_state.tmpbufflen, nullptr);
}

/*******************************************************************************
**
** Function         stpropnci_prop_st_cb_apdu_gate_transceive
**
** Description      If we let a command passthrough, let the rsp as well.
**
** Returns          true
**
*******************************************************************************/
static bool stpropnci_prop_st_cb_apdu_gate_transceive(
    const uint8_t* payload, const uint16_t payloadlen) {
  int status = NCI_STATUS_OK;
  uint8_t* buf = stpropnci_state.tmpbuff;
  uint16_t* buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;
  uint8_t type, instruction;

  stpropnci_tmpbuff_reset();
  LOG_D("0x%x 0x%x 0x%x", payload[0], payload[1], payload[2]);

  if ((payload[0] & 0x7F) != stpropnci_state.apdu_pipe_id) {
    LOG_E("HCI data not from APDU pipe");
    return false;
  }
  type = payload[1] >> 6;
  instruction = (payload[1] & 0x3F);
  if (type != NFA_HCI_EVENT_TYPE) {
    LOG_E("Not NFA_HCI_EVENT_TYPE");
    return false;
  }

  // Prepare NTF for ST OEM Ext
  NCI_MSG_BLD_HDR0(pp, NCI_MT_NTF, NCI_GID_PROP);
  NCI_MSG_BLD_HDR1(pp, ST_PROP_NCI_OID);
  paylen = pp++;
  UINT8_TO_STREAM(pp, ST_PROP_NCI_TRANSCEIVE_ADPU_GATE);
  UINT8_TO_STREAM(pp, NFC_STATUS_OK);
  if (instruction == EVT_TRANSMIT_DATA) {
    ARRAY_TO_STREAM(pp, (payload + 2), payloadlen - 2);
  }

  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;
  // send it back
  return stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                             *stpropnci_state.tmpbufflen, nullptr);
}

/*******************************************************************************
**
** Function         stpropnci_prop_st_hciu_send_msg
**
** Description      This function will fragment the given packet, if necessary
**                  and send it on the given pipe.
**
** Returns          status
**
*******************************************************************************/
bool stpropnci_prop_st_send_hci(uint8_t pipe_id, uint8_t type,
                                uint8_t instruction, uint16_t msg_len,
                                const uint8_t* p_msg,
                                bool (*hci_cb)(const uint8_t* payload,
                                               const uint16_t payloadlen)) {
  NFC_HDR* p_buf;
  uint8_t* p_data;
  bool first_pkt = true;
  uint16_t data_len;
  int cb = 0;

  // As described in DS: The maximum payload length of an NCI Data Packet
  // Size of NCI header is not included
  uint16_t max_seg_hcp_pkt_size = 255;

  if ((msg_len != 0) && (p_msg == nullptr)) {
    LOG_E(" msg_len is 0 and p_msg is null");
    return false;
  }

  if (hci_cb != nullptr) {
    if (stpropnci_state.hci_rsp_cb != nullptr) {
      LOG_E(" HCI CB function already registered");
      return false;
    }
    if (!stpropnci_modcb_register(stpropnci_prop_st_hci_reassembly_cb, true,
                                  NCI_MT_DATA, true, NFC_HCI_CONN_ID, false,
                                  0x00, false, 0)) {
      LOG_E(" Error registering HCI cb function");
      return false;
    }
    // Reset pointer for reassembly to beginning of reassembly buff
    stpropnci_state.hci_reassembly_p = stpropnci_state.hci_reassembly_buff;
    stpropnci_state.hci_rsp_cb = hci_cb;
  }

  while ((first_pkt == true) || (msg_len != 0)) {
    /* First packet has a 2-byte header, subsequent fragments have a 1-byte
     * header */
    data_len =
        first_pkt ? (max_seg_hcp_pkt_size - 2) : (max_seg_hcp_pkt_size - 1);

    // Initialize pointer
    p_data = stpropnci_state.tmpbuff;
    stpropnci_tmpbuff_reset();

    /* Last or only segment has "no fragmentation" bit set */
    if (msg_len > data_len) {
      cb = 0;
    } else {
      data_len = msg_len;
      cb = 1;
    }

    /* build NCI Data packet header */
    NCI_DATA_PBLD_HDR(p_data, 0, NFC_HCI_CONN_ID,
                      data_len + (first_pkt ? 2 : 1));

    *p_data++ = (cb << 7) | (pipe_id & 0x7F);

    /* Message header only goes in the first segment */
    if (first_pkt) {
      first_pkt = false;
      *p_data++ = (type << 6) | instruction;
    }

    if (data_len > 0) {
      memcpy(p_data, p_msg, data_len);
      p_data += data_len;
    }
    msg_len -= data_len;
    p_msg += data_len;

    *stpropnci_state.tmpbufflen = p_data - stpropnci_state.tmpbuff;

    stpropnci_state.hci_cr_cnt++;

    if (!stpropnci_pump_post(MSG_DIR_TO_NFCC, stpropnci_state.tmpbuff,
                             *stpropnci_state.tmpbufflen, nullptr)) {
      LOG_E(" Failed to send fragment");
      return false;
    }
  }

  return true;
}

/*******************************************************************************
**
** Function         stpropnci_hci_reassembly_cb
**
** Description      This function will fragment the given packet, if necessary
**                  and send it on the given pipe.
**
** Returns          status
**
*******************************************************************************/
bool stpropnci_prop_st_hci_reassembly_cb(
    __attribute__((unused)) bool dir_from_upper, const uint8_t* payload,
    __attribute__((unused)) const uint16_t payloadlen,
    __attribute__((unused)) uint8_t mt, __attribute__((unused)) uint8_t gid,
    __attribute__((unused)) uint8_t oid) {
  const uint8_t* pp;
  uint8_t cb, pbf, cid, instruction;
  uint8_t *ps, *pd;
  uint16_t size;
  uint16_t len;
  bool handled = false, first = (stpropnci_state.hci_reassembly_p ==
                                 stpropnci_state.hci_reassembly_buff);
  pp = payload;

  NCI_DATA_PRS_HDR(pp, pbf, cid, len);

  if (cid != NFC_HCI_CONN_ID) {
    LOG_D("not HCI data, dropping");
    return false;
  }

  cb = (pp[0] & 0x80) ? 1 : 0;
  if (!first) {
    // Skip first byte
    pp++;
    len--;
  }
  if (stpropnci_state.hci_reassembly_p - stpropnci_state.hci_reassembly_buff >
      MAX_HCI_RECEIVE_LEN - len) {
    LOG_E("too much HCI data, truncate");
    cb = 1;
  } else {
    memcpy(stpropnci_state.hci_reassembly_p, pp, len);
    stpropnci_state.hci_reassembly_p += len;
  }
  handled = true;

  // last fragment
  if (cb == 1) {
    handled = (*stpropnci_state.hci_rsp_cb)(
        stpropnci_state.hci_reassembly_buff,
        stpropnci_state.hci_reassembly_p - stpropnci_state.hci_reassembly_buff);

    // DO not unregister if EVT_WTX
    instruction = stpropnci_state.hci_reassembly_buff[1] & 0x3F;
    if (instruction != EVT_WTX_REQUEST) {
      stpropnci_state.hci_rsp_cb = nullptr;
      stpropnci_modcb_unregister(stpropnci_prop_st_hci_reassembly_cb);
    }

    stpropnci_state.hci_reassembly_p = stpropnci_state.hci_reassembly_buff;
  }

  return handled;
}

/*******************************************************************************
**
** Function         parse_fw_ntf
**
** Description      This function will fragment the given packet, if necessary
**                  and send it on the given pipe.
**
** Returns          status
**
*******************************************************************************/
void parse_fw_ntf(const uint8_t* payload, const uint16_t payloadlen) {
  int current_tlv_pos = 6;
  int current_tlv_length;

  while (1) {
    if (current_tlv_pos + 1 > payloadlen) break;
    current_tlv_length = payload[current_tlv_pos + 1] + 2;
    if (current_tlv_pos + current_tlv_length > payloadlen) break;

    // check that eSE behavior is OK ( no repeat frames)
    eseMonitor(payload[3], current_tlv_length, payload + current_tlv_pos,
               current_tlv_pos + current_tlv_length >= payloadlen);

    // go to next TLV
    current_tlv_pos = current_tlv_pos + current_tlv_length;
  }
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
static bool stpropnci_prop_st_build_set_custom_polling_cmd(
    uint8_t* buf, uint16_t* buflen, const uint8_t* incoming,
    const uint16_t incominglen) {
  const uint8_t* in;
  uint16_t remaining = incominglen;
  uint8_t *pp = buf, *paylen;
  uint8_t nb_frames = 0, motiflen = 0, frame_type = 0, is_crc = 0;
  NCI_MSG_BLD_HDR0(pp, NCI_MT_CMD, NCI_GID_PROP);  // idx 0
  NCI_MSG_BLD_HDR1(pp, ST_NCI_MSG_PROP_RF_SET_CUST_PASSIVE_POLL_FRAME);  // idx
                                                                         // 1
  paylen = pp++;  // idx 2

  if (remaining < (3 + 2)) {
    LOG_E("ST_NCI_MSG_PROP_RF_SET_CUST_PASSIVE_POLL_FRAME too short");
    return false;
  }

  in = incoming + 4;  // beginning of the payload
  nb_frames = *in;
  if (nb_frames > 4) {
    LOG_E(
        "ST_NCI_MSG_PROP_RF_SET_CUST_PASSIVE_POLL_FRAME unsupported number of "
        "frames");
    return false;
  }

  UINT8_TO_STREAM(pp, *in++);  // nb_frames - idx 3
  remaining -= 5;
  if ((nb_frames > 0) && (remaining < 4)) {
    LOG_E("ST_NCI_MSG_PROP_RF_SET_CUST_PASSIVE_POLL_FRAME too short");
    return false;
  }

  if (nb_frames) {
    uint16_t crc = 0;

    while (nb_frames--) {
      frame_type = (*in & 0x07);

      UINT8_TO_STREAM(pp, *in++);  // qual-type - idx 4

      // pointing to lengh: length RF frame = length - waiting time byte
      motiflen = *in - 1;

      is_crc = (*(in + 1) & 0x80) >> 7;
      UINT8_TO_STREAM(pp, *in++ + ((is_crc != 0) ? 2 : 0));  // length - idx 5
      UINT8_TO_STREAM(pp, *in++);  // waiting time - idx 6

      if ((is_crc != 0) && (frame_type <= NFC_B_FRAME)) {
        crc = iso14443_crc(in, motiflen, frame_type);
      }

      ARRAY_TO_STREAM(pp, in, motiflen);
      in += motiflen;

      if (is_crc != 0) {
        UINT8_TO_STREAM(pp, (uint8_t)(crc & 0xFF));
        UINT8_TO_STREAM(pp, (uint8_t)(crc >> 8));
      }
    }
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
static bool stpropnci_prop_st_cb_set_custom_polling_rsp(
    bool dir_from_upper, const uint8_t* payload, const uint16_t payloadlen,
    uint8_t mt, uint8_t gid, uint8_t oid) {
  uint8_t* buf = stpropnci_state.tmpbuff;
  uint16_t* buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;

  stpropnci_tmpbuff_reset();

  // build the response to stack
  NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_PROP);
  NCI_MSG_BLD_HDR1(pp, ST_PROP_NCI_OID);
  paylen = pp++;
  UINT8_TO_STREAM(pp, ST_PROP_SET_RF_CUSTOM_POLL_FRAME);
  UINT8_TO_STREAM(pp, payload[3]);

  // Update the pending fields
  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;

  return stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                             *stpropnci_state.tmpbufflen, nullptr);
}

/*******************************************************************************
**
** Function         eseMonitor
**
** Description      Checks FW logs to detect any abnormal SWP flow
**
** Returns          -
**
*******************************************************************************/
void eseMonitor(uint8_t format, uint16_t data_len, const uint8_t* p_data,
                bool last) {
  uint8_t* buf = stpropnci_state.tmpbuff;
  uint16_t* buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;

  if ((format & 0x1) == 1) {
    data_len -= 4;  // ignore the timestamp
  }

  if (p_data[0] == FWLOG_T_SwpDeact) {
    // SWP deactivated, we clear our state
    stpropnci_state.last_tx_cnt = 0;
    stpropnci_state.last_tx_len = 0;
    if (stpropnci_state.last_rx_param_len) {
      LOG_D("clear saved param on deact");
    }
    stpropnci_state.last_rx_param_len = 0;
    stpropnci_state.last_rx_is_frag[0] = false;
    stpropnci_state.last_rx_is_frag[1] = false;
    stpropnci_state.last_rx_is_frag[2] = false;
    stpropnci_state.last_rx_is_frag[3] = false;
    return;
  }

  if (data_len <= 2) return;

  if (p_data[2] != 0x01) {
    // if it is an SWP log, it s not for eSE, we can return
    return;
  }

  if (p_data[0] >= FWLOG_T_RxAct && p_data[0] <= FWLOG_T_RxErr) {
    // We received something, we can reset Tx counter
    stpropnci_state.last_tx_cnt = 0;
    stpropnci_state.last_tx_len = 0;

    // check if it is a ANY_SET_PARAM e.g. TT LL SS RL 86 A3 01 07 00
    if ((data_len >= 8) && ((p_data[4] & 0xC0) == 0x80)) {
      bool has_cb = (p_data[5] & 0x80) == 0x80;
      bool is_first_frag = true;
      uint8_t pid = p_data[5] & 0x7F;

      // manage fragmented frames on pipes 21~24.
      if (pid >= 0x21 && pid <= 0x24) {
        if (stpropnci_state.last_rx_is_frag[pid - 0x21]) {
          // we got a fragment before
          is_first_frag = false;
        }
        stpropnci_state.last_rx_is_frag[pid - 0x21] = !has_cb;
      }

      // I frame
      if (is_first_frag && (pid >= 0x21)           // one of the card gates
          && (pid <= 0x24) && (p_data[6] == 0x01)  // ANY-SET_PARAM
      ) {
        // This is an ANY_SET-PARAM
        int newParamLen =
            data_len -
            4;  // this is at least 4 for II + pID + cmd + the param ID
        // same as last one ?
        if ((stpropnci_state.last_rx_param_len == newParamLen) &&
            ((p_data[4] & 0x38) != (stpropnci_state.last_rx_param[0] &
                                    0x38))  // N(S) increased, it s not the
                                            // same I-frame resent (RNR case)
            &&
            (!memcmp(p_data + 5,  // but the SET-PARAM data is the same
                     stpropnci_state.last_rx_param + 1,
                     (newParamLen < (int)sizeof(stpropnci_state.last_rx_param))
                         ? (newParamLen - 1)
                         : (sizeof(stpropnci_state.last_rx_param) - 1)))) {
          LOG_E("Same ANY-SET_PARAM received from eSE twice, maybe stuck");
          // abort(); // disable at the moment, some cases are abnormal but eSE
          // not stuck.
        } else {
          // save this param
          stpropnci_state.last_rx_param_len = newParamLen;
          memcpy(stpropnci_state.last_rx_param, p_data + 4,
                 newParamLen < (int)sizeof(stpropnci_state.last_rx_param)
                     ? newParamLen
                     : sizeof(stpropnci_state.last_rx_param));
          LOG_D("saved param: %02hhx", p_data[7]);
        }
      } else {
        // we received an I-frame but it is not ANY-SET-PARAM
        if (is_first_frag && (stpropnci_state.last_rx_param_len != 0)) {
          LOG_D(" clear saved param");
          stpropnci_state.last_rx_param_len = 0;
        }
      }
    }
  }

  if (p_data[0] > FWLOG_T_TxAct && p_data[0] <= FWLOG_T_TxIr) {
    // CLF sent this frame, compare and record.
    if ((data_len == stpropnci_state.last_tx_len) &&
        !memcmp(stpropnci_state.last_tx, p_data + 2,
                data_len < 7 ? data_len - 2 : 5)) {
      // identical with the last frame we sent
      stpropnci_state.last_tx_cnt++;
      if (stpropnci_state.last_tx_cnt >= 10) {
        // Send PROP_TEST_RESET_ST54J_SE then restart NFC
        LOG_E(
            "Same frame repeat on SWP, Start task disable/reset eSE, restart "
            "service");
        stpropnci_state.is_ese_stuck = true;
        // Send CMD to disable eSE
        NCI_MSG_BLD_HDR0(pp, NCI_MT_CMD, NCI_GID_EE_MANAGE);
        NCI_MSG_BLD_HDR1(pp, NCI_MSG_NFCEE_MODE_SET);
        paylen = pp++;
        UINT8_TO_STREAM(pp, 0x86);
        UINT8_TO_STREAM(pp, 0x00);

        *paylen = pp - (paylen + 1);
        *buflen = pp - buf;
        // send it back
        stpropnci_pump_post(MSG_DIR_TO_NFCC, stpropnci_state.tmpbuff,
                            *stpropnci_state.tmpbufflen,
                            stpropnci_cb_disable_ese_rsp);
      }
    } else {
      // different frame, store this one
      stpropnci_state.last_tx_cnt = 0;
      memcpy(stpropnci_state.last_tx, p_data + 2,
             data_len < 7 ? data_len - 2 : 5);
      stpropnci_state.last_tx_len = data_len;
    }
  }
}

/*******************************************************************************
**
** Function         stpropnci_cb_disable_ese_rsp
**
** Description      SWP was disabled with the eSE, now reset it.
**
** Returns          true if success
**
*******************************************************************************/
static bool stpropnci_cb_disable_ese_rsp(
    __attribute__((unused)) bool dir_from_upper, const uint8_t* payload,
    const uint16_t payloadlen, __attribute__((unused)) uint8_t mt,
    __attribute__((unused)) uint8_t gid, __attribute__((unused)) uint8_t oid) {
  uint8_t* buf = stpropnci_state.tmpbuff;
  uint16_t* buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;

  // Check status
  if (payload[3] != 0x00) {
    LOG_E(" status NOK");
  } else {
    // Stop eSE
    uint8_t ese_id[] = {0x86};
    // Send CMD to reset eSE
    NCI_MSG_BLD_HDR0(pp, NCI_MT_CMD, NCI_GID_PROP);
    NCI_MSG_BLD_HDR1(pp, ST_NCI_MSG_PROP_TEST);
    paylen = pp++;
    UINT8_TO_STREAM(pp, ST_NCI_PROP_TEST_RESET_ST54J_SE);
    ARRAY_TO_STREAM(pp, ese_id, sizeof(ese_id));

    *paylen = pp - (paylen + 1);
    *buflen = pp - buf;
    // send it back
    return stpropnci_pump_post(MSG_DIR_TO_NFCC, stpropnci_state.tmpbuff,
                               *stpropnci_state.tmpbufflen,
                               stpropnci_cb_reset_ese_rsp);
  }

  return true;
}

/*******************************************************************************
**
** Function         stpropnci_cb_reset_ese_rsp
**
** Description      eSE has been reset, now emit a fake core_reset_ntf to reset
*stack
**
** Returns          true if success
**
*******************************************************************************/
static bool stpropnci_cb_reset_ese_rsp(
    __attribute__((unused)) bool dir_from_upper, const uint8_t* payload,
    const uint16_t payloadlen, __attribute__((unused)) uint8_t mt,
    __attribute__((unused)) uint8_t gid, __attribute__((unused)) uint8_t oid) {
  uint8_t* buf = stpropnci_state.tmpbuff;
  uint16_t* buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;

  // Check status
  if (payload[3] != 0x00) {
    LOG_E(" status NOK");
  } else {
    // send it back
    stpropnci_state.is_ese_stuck = false;
    LOG_D("Send CORE_RESET_NTF for ESE stuck detected");
    return stpropnci_send_core_reset_ntf_recovery(0x00);
  }

  return true;
}

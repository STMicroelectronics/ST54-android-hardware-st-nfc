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
static bool stpropnci_cb_get_apdu_info(bool dir_from_upper,
                                       const uint8_t* payload,
                                       const uint16_t payloadlen, uint8_t mt,
                                       uint8_t gid, uint8_t oid) {
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
bool stpropnci_prop_st_hci_reassembly_cb(bool dir_from_upper,
                                         const uint8_t* payload,
                                         const uint16_t payloadlen, uint8_t mt,
                                         uint8_t gid, uint8_t oid) {
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
  int idx;

  for (idx = 0;; ++idx) {
    if (current_tlv_pos + 1 > payloadlen) break;
    current_tlv_length = payload[current_tlv_pos + 1] + 2;
    if (current_tlv_pos + current_tlv_length > payloadlen) break;

    // Check SWP CLT data
    // go to next TLV
    current_tlv_pos = current_tlv_pos + current_tlv_length;
  }
}

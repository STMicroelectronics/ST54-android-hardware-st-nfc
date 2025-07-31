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
#include <unistd.h>
#include <string.h>
#include <stpropnci-internal.h>
#include <nfc_api.h>

static void stpropnci_process_core_reset_ntf(const uint8_t *payload,
                                             const uint16_t payloadlen);

/*******************************************************************************
**
** Function         stpropnci_process_std
**
** Description      Called upon incoming messages with standard GID (CORE/RF/EE)
**
** Returns          true if message was handled and processing should stop.
**
*******************************************************************************/
bool stpropnci_process_std(bool inform_only, bool dir_from_upper,
                           const uint8_t *payload, const uint16_t payloadlen,
                           uint8_t mt, uint8_t gid, uint8_t oid) {
  bool handled = false;
  uint8_t *buf = stpropnci_state.tmpbuff;
  uint16_t *buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;

  stpropnci_tmpbuff_reset();

  if (inform_only) {
    // Process the updates as needed
    if ((mt == NCI_MT_NTF) && (gid == NCI_GID_CORE) &&
        (oid == NCI_MSG_CORE_RESET)) {
      stpropnci_process_core_reset_ntf(payload, payloadlen);
    }

    return false;
  }

  if (mt == NCI_MT_DATA) {
    // the gid is actually the connection id in this case
    switch (gid) {
      case NFC_RF_CONN_ID:
        if (dir_from_upper == MSG_DIR_FROM_STACK) {
          // save the timestamp
          (void)clock_gettime(CLOCK_MONOTONIC, &stpropnci_state.ts_last_rf_tx);
          if (stpropnci_state.is_reader_activation && (payloadlen == 3)) {
            stpropnci_state.is_tx_empty_iframe = true;
          }
        } else {
          // clear timestamp
          memset(&stpropnci_state.ts_last_rf_tx, 0,
                 sizeof(stpropnci_state.ts_last_rf_tx));

          if (stpropnci_state.is_reader_activation && (payloadlen == 3)) {
            if (stpropnci_state.is_tx_empty_iframe) {
              stpropnci_state.is_tx_empty_iframe = false;
            } else {
              // trash frame
              LOG_D("Discard received empty I Frame (not pres check)");
              handled = true;
            }
          }
        }
        break;

      case NFC_HCI_CONN_ID:
        break;

      case NFC_T4TNFCEE_CONN_ID:
        break;
    }

    return handled;
  }

  // Other cases, CMD/RSP/NTF
  switch (gid) {
    case NCI_GID_CORE:
      switch (oid) {
        case NCI_MSG_CORE_RESET:
          if (mt == NCI_MT_NTF) {
            stpropnci_process_core_reset_ntf(payload, payloadlen);
          }
          break;

        case NCI_MSG_CORE_GEN_ERR_STATUS:
          if (mt == NCI_MT_NTF) {
            if (payloadlen <= 3) {
              LOG_E("CORE_GENERIC_ERROR_NTF length too short: %d", payloadlen);
              break;
            }

            // check the error status
            switch (payload[3]) {
              case NCI_STATUS_ACTIVATION_FAILED:
                // Stop the field watchdog
                stpropnci_pump_watchdog_remove(WD_FIELD_ON_TOO_LONG);
                break;

              case ST_NCI_STATUS_PROP_BUFFER_OVERFLOW:
                LOG_E(
                    "NFCC has overflown (IRQ not fast enough?), trigger "
                    "recovery to ensure resync state");
                handled = stpropnci_send_core_reset_ntf_recovery(
                    ST_NCI_STATUS_PROP_BUFFER_OVERFLOW);
                break;

              case ST_NCI_STATUS_PROP_PLL_LOCK_ISSUE:
                if (HW_VERSION == HW_VERSION_ST21NFCD) {
                  LOG_E(
                      "PLL lock error (platform clock issue?), ST21NFCD cannot "
                      "recover it, trigger recovery");
                  handled = stpropnci_send_core_reset_ntf_recovery(
                      ST_NCI_STATUS_PROP_PLL_LOCK_ISSUE);
                }
                break;
            }
          }
          break;

        case NCI_MSG_CORE_SET_POWER_SUB_STATE:
          if (mt == NCI_MT_CMD) {
            if (payloadlen <= 3) {
              LOG_E("CORE_SET_POWER_SUB_STATE length too short: %d",
                    payloadlen);
              break;
            }
            // Going to screen off ?
            if (payload[3] == 0x01 || payload[3] == 0x03) {
              if (stpropnci_state.pwr_mon_isActiveRW) {
                // Start the watchdog for CLF power monitoring
                if (!stpropnci_pump_watchdog_add(WD_ACTIVE_RW_TOO_LONG, 5000)) {
                  LOG_E("Failed to add watchdog on PWR_MON_OFF, continue");
                }
              }
            }
          }
          break;

        case NCI_MSG_CORE_CONN_CREDITS:
          if ((payload[4] == NFC_HCI_CONN_ID) &&
              (stpropnci_state.hci_cr_cnt > 0)) {
            stpropnci_state.hci_cr_cnt--;
            // Do not send to stack
            handled = true;
          }
          break;

        default:
          // We are not interested in others
          break;
      }

      break;

    case NCI_GID_RF_MANAGE:
      switch (oid) {
        case NCI_MSG_RF_SET_ROUTING:
          if (mt == NCI_MT_CMD) {
            uint8_t idx = 5;
            uint8_t nb_entries = 0;
            uint8_t route_a = 0x00, route_b = 0x00, idx_a = 0, idx_b = 0,
                    idx_block, idx_f = 0, route_f = 0x00;
            // Check routing for listen tech
            while (nb_entries < payload[4]) {
              // Check if entry type if tech routing
              if ((payload[idx] & 0xF) == 0x00) {
                if (payload[idx + 4] == NCI_RF_TECHNOLOGY_A) {
                  idx_a = idx;
                  route_a = payload[idx + 2];
                } else if (payload[idx + 4] == NCI_RF_TECHNOLOGY_B) {
                  idx_b = idx;
                  route_b = payload[idx + 2];
                } else if (payload[idx + 4] == NCI_RF_TECHNOLOGY_F) {
                  idx_f = idx;
                  route_f = payload[idx + 2];
                }
              }
              idx += (payload[idx + 1] + 2);
              nb_entries++;
            }
            if (stpropnci_state.is_card_a_on) {
              LOG_D("Routing techA/B to NDEF-NFCEE");
              memcpy(pp, payload, payloadlen);
              // Route Tech to NDEF-NFCEE
              // All power states
              pp[idx_a + 2] = 0x10;
              pp[idx_a + 3] = 0x3B;
              pp[idx_b + 2] = 0x10;
              pp[idx_b + 3] = 0x3B;

              *buflen = payloadlen;
              // send it
              handled =
                  stpropnci_pump_post(MSG_DIR_TO_NFCC, stpropnci_state.tmpbuff,
                                      *stpropnci_state.tmpbufflen, nullptr);
            } else {
              memcpy(pp, payload, payloadlen);

              if ((route_a != route_b) && (idx_a != 0) && (idx_b != 0)) {
                LOG_D(
                    "route_a=0x%x, route_b=0x%x, not same route, block tech "
                    "routed to DH",
                    route_a, route_b);
                // If route is 0, means this tech was not supported by original
                // route. This is the one we want to block.
                if (route_a == 0x00) {
                  idx_block = idx_a;
                } else {
                  idx_block = idx_b;
                }
                pp[idx_block] |= 0x40;
                // No power states allowed
                pp[idx_block + 3] = 0x00;
              }

              if (!stpropnci_state.is_ese_felica_enabled) {
                if (route_f == 0x86 && idx_f != 0) {
                  LOG_D("Routing techF to DH");
                  // Route Tech F to DH
                  // Power states: 0x11 (switched ON, screen unlocked)
                  pp[idx_f + 2] = 0x00;
                  pp[idx_f + 3] = 0x11;
                }
              }

              *buflen = payloadlen;
              // send it
              handled =
                  stpropnci_pump_post(MSG_DIR_TO_NFCC, stpropnci_state.tmpbuff,
                                      *stpropnci_state.tmpbufflen, nullptr);
            }
          }
          break;

        case NCI_MSG_RF_DISCOVER:
          if (mt == NCI_MT_NTF) {
            // Stop the field watchdog
            stpropnci_pump_watchdog_remove(WD_FIELD_ON_TOO_LONG);
            // Stop the pwr_mon watchdog
            stpropnci_pump_watchdog_remove(WD_ACTIVE_RW_TOO_LONG);
            stpropnci_state.pwr_mon_errorCount = 0;
          }
          break;

        case NCI_MSG_RF_INTF_ACTIVATED:
          if (mt == NCI_MT_NTF) {
            // Stop the field watchdog
            stpropnci_pump_watchdog_remove(WD_FIELD_ON_TOO_LONG);
            // Stop the pwr_mon watchdog
            stpropnci_pump_watchdog_remove(WD_ACTIVE_RW_TOO_LONG);
            stpropnci_state.pwr_mon_errorCount = 0;

            // Check if activated in reader mode
            if ((payload[6] < NCI_DISCOVERY_TYPE_LISTEN_A)) {
              stpropnci_state.is_reader_activation = true;
            } else {
              stpropnci_state.is_reader_activation = false;
            }

            // Check custom polling activation
            if (payload[6] == NFC_CUST_PASSIVE_POLL_MODE) {
              int len_tp = payload[9] - 2;
              uint8_t rf_tech_mode = NFC_DISCOVERY_TYPE_POLL_A;

              // Only send the prop NTF once
              if (!stpropnci_state.is_rf_intf_cust_tx) {
                // Send received RF_INTF_ACTIVATED_NTF as prop OID NTF to ST OEM
                // extensions
                NCI_MSG_BLD_HDR0(pp, NCI_MT_NTF, NCI_GID_PROP);
                NCI_MSG_BLD_HDR1(pp, ST_PROP_NCI_OID);
                paylen = pp++;
                UINT8_TO_STREAM(pp, ST_PROP_RF_INTF_ACTIV_CUST_POLL_NTF);
                ARRAY_TO_STREAM(pp, payload + 3, payload[2]);
                *paylen = pp - (paylen + 1);
                *buflen = pp - buf;
                // send it
                stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                    *stpropnci_state.tmpbufflen, nullptr);
                stpropnci_state.is_rf_intf_cust_tx = true;
              }

              // reset pointer
              pp = buf;
              stpropnci_tmpbuff_reset();

              // Now we need to create STD RF_INTF_ACTIVATED_NTF
              if (payload[5] != NFC_PROTOCOL_UNKNOWN) {
                // Case CUST_POLL_STD_RESP
                rf_tech_mode = payload[10];
              } else {
                // Case CUST_POLL_NOSTD_RESP
                switch (payload[10]) {
                  case PROP_A_POLL:
                    rf_tech_mode = NFC_DISCOVERY_TYPE_POLL_A;
                    break;
                  case PROP_B_POLL:
                    rf_tech_mode = NFC_DISCOVERY_TYPE_POLL_B;
                    break;
                  case PROP_F_POLL:
                    rf_tech_mode = NFC_DISCOVERY_TYPE_POLL_F;
                    break;
                  case PROP_V_POLL:
                    rf_tech_mode = NFC_DISCOVERY_TYPE_POLL_V;
                    break;
                  case PROP_B_NOEOFSOF_POLL:
                    rf_tech_mode = NFC_DISCOVERY_TYPE_POLL_B;
                    break;
                  case PROP_B_NOSOF_POLL:
                    rf_tech_mode = NFC_DISCOVERY_TYPE_POLL_B;
                    break;
                  default:
                    LOG_E("Unknown RF tech mode: 0x%x", payload[10]);
                    break;
                }
              }

              NCI_MSG_BLD_HDR0(pp, NCI_MT_NTF, NCI_GID_RF_MANAGE);
              NCI_MSG_BLD_HDR1(pp, NCI_MSG_RF_INTF_ACTIVATED);
              paylen = pp++;

              UINT8_TO_STREAM(pp, payload[3]);    // 3 - RF disc id ID
              UINT8_TO_STREAM(pp, payload[4]);    // 4 - RF interface
              UINT8_TO_STREAM(pp, payload[5]);    // 5 - RF protocol
              UINT8_TO_STREAM(pp, rf_tech_mode);  // 6 - RF tech mode
              UINT8_TO_STREAM(pp, payload[7]);    // 7 - max data payload size
              UINT8_TO_STREAM(pp, payload[8]);    // 8 - init nb credits
              UINT8_TO_STREAM(pp, len_tp);        // 9 - length RF tech param
              ARRAY_TO_STREAM(pp, payload + 12,
                              len_tp);  // 10 - RF tech param
              UINT8_TO_STREAM(pp,
                              rf_tech_mode);  // 10+n - data ex tch and mode
              ARRAY_TO_STREAM(
                  pp, payload + 13 + len_tp,
                  payload[2] - 10 - len_tp);  // 11+n - remaining data

              *paylen = pp - (paylen + 1);
              *buflen = pp - buf;
              // send it
              handled =
                  stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                      *stpropnci_state.tmpbufflen, nullptr);
            }
          }
          break;

        case NCI_MSG_RF_DEACTIVATE:
          if (mt == NCI_MT_CMD) {
            // If we sent RF data recently, ensure some time before forwarding.
            if (stpropnci_state.ts_last_rf_tx.tv_sec != 0 ||
                stpropnci_state.ts_last_rf_tx.tv_nsec != 0) {
              struct timespec now;
              (void)clock_gettime(CLOCK_MONOTONIC, &now);

              // add 10ms to last TX
              stpropnci_state.ts_last_rf_tx.tv_nsec += 10000000LL;
              if (stpropnci_state.ts_last_rf_tx.tv_nsec >= 1000000000LL) {
                stpropnci_state.ts_last_rf_tx.tv_sec += 1;
                stpropnci_state.ts_last_rf_tx.tv_nsec -= 1000000000LL;
              }

              // check if this delay is already passed or not.
              if ((stpropnci_state.ts_last_rf_tx.tv_sec > now.tv_sec) ||
                  ((stpropnci_state.ts_last_rf_tx.tv_sec == now.tv_sec) &&
                   (stpropnci_state.ts_last_rf_tx.tv_nsec > now.tv_nsec))) {
                // We wait for the remaining time.
                long long remaining =
                    (stpropnci_state.ts_last_rf_tx.tv_sec - now.tv_sec) *
                    1000000000LL;
                remaining +=
                    stpropnci_state.ts_last_rf_tx.tv_nsec - now.tv_nsec;
                // in ms
                remaining /= 1000000LL;
                remaining += 1;
                LOG_D("Waiting for %d ms before sending the deactivate cmd",
                      (int)remaining);
                usleep(remaining * 1000);
              }

              // clear timestamp
              memset(&stpropnci_state.ts_last_rf_tx, 0,
                     sizeof(stpropnci_state.ts_last_rf_tx));
            }
          }
          break;

        case NCI_MSG_RF_FIELD:
          if (mt == NCI_MT_NTF) {
            if (payloadlen <= 3) {
              LOG_E("NCI_MSG_RF_FIELD length too short: %d", payloadlen);
              break;
            }
            if (payload[3] == 0x01) {
              // FIELD ON
              // This watchdog was started only if STNFC_REMOTE_FIELD_TIMER in
              // config file before. We enable it only for ST54J at the moment,
              // it can be updated later.
              if (HW_VERSION == HW_VERSION_ST54J) {
                if (!stpropnci_pump_watchdog_add(WD_FIELD_ON_TOO_LONG, 20000)) {
                  LOG_E("Failed to add watchdog on NCI_MSG_RF_FIELD, continue");
                }
              }
            } else {
              // FIELD OFF
              stpropnci_pump_watchdog_remove(WD_FIELD_ON_TOO_LONG);
            }
          }
          break;

        case NCI_MSG_RF_EE_ACTION:
          // In case of proprietary trigger, remap to standard AID trigger and
          // generate a custom ST notification.
          if (mt == NCI_MT_NTF) {
            if (payloadlen < 6) {
              LOG_E("NCI_MSG_RF_EE_ACTION length too short: %d", payloadlen);
              break;
            }
            if (payload[4] == 0x11) {
              // This is ST NFC custom trigger format with both AID and SW.
              // We generate a custom NCI NTF for extensions and
              // remap to regular AID trigger for the stack.

              // Generate the custom frame first.
              NCI_MSG_BLD_HDR0(pp, NCI_MT_NTF, NCI_GID_PROP);
              NCI_MSG_BLD_HDR1(pp, ST_PROP_NCI_OID);
              paylen = pp++;
              UINT8_TO_STREAM(pp, ST_PROP_NCI_NFCEE_ACTION_NTF_AID_WITH_SW);
              ARRAY_TO_STREAM(pp, payload + 3, payloadlen - 3);

              *paylen = pp - (paylen + 1);
              *buflen = pp - buf;
              // send it
              handled =
                  stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                      *stpropnci_state.tmpbufflen, nullptr);
              if (!handled) {
                LOG_E(
                    "Failed to post notification, stop processing of "
                    "NFCEE_ACTION_NTF");
                break;
              }

              // reset pointer
              pp = buf;
              stpropnci_tmpbuff_reset();

              // Create fake notif with trigger = AID
              NCI_MSG_BLD_HDR0(pp, NCI_MT_NTF, NCI_GID_RF_MANAGE);
              NCI_MSG_BLD_HDR1(pp, NCI_MSG_RF_EE_ACTION);
              paylen = pp++;

              UINT8_TO_STREAM(pp, payload[3]);  // NFCEE ID
              UINT8_TO_STREAM(pp, 0x00);        // trigger: force AID
              ARRAY_TO_STREAM(pp, payload + 7,
                              payload[7] + 1);  // AID length + AID

              *paylen = pp - (paylen + 1);
              *buflen = pp - buf;
              // send it
              handled =
                  stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                      *stpropnci_state.tmpbufflen, nullptr);
            }
          }
          break;

        case NCI_MSG_RF_EE_DISCOVERY_REQ:
          if (mt == NCI_MT_NTF) {
            uint8_t idx = 0;
            if (payloadlen <= NFC_EE_DISCOVER_ENTRY_LEN) {
              LOG_E("NCI_MSG_RF_EE_DISCOVERY_REQ length too short: %d",
                    payloadlen);
              break;
            }
            for (int i = 0; i < payload[3]; i++) {
              idx = 0xFF;
              // Check if info for this NFCEE Id already stored
              for (int j = 0; j < stpropnci_state.nb_ee_info; j++) {
                if (stpropnci_state.ee_info[j].nfcee_id == payload[6 + i * 5]) {
                  idx = j;
                  break;
                }
              }
              if (idx == 0xFF) {
                idx = stpropnci_state.nb_ee_info;
                stpropnci_state.ee_info[idx].nfcee_id = payload[6 + i * 5];
                stpropnci_state.nb_ee_info++;
              }
              if (payload[7 + i * 5] == NCI_DISCOVERY_TYPE_LISTEN_A) {
                if (payload[8 + i * 5] == NFC_PROTOCOL_T2T) {
                  if (payload[4 + i * 5] == NFC_EE_DISC_OP_ADD) {
                    stpropnci_state.ee_info[idx].la |= NFC_PROTO_T2T_MASK;
                  } else {
                    stpropnci_state.ee_info[idx].la &= ~NFC_PROTO_T2T_MASK;
                  }
                } else if (payload[8 + i * 5] == NCI_PROTOCOL_ISO_DEP) {
                  if (payload[4 + i * 5] == NFC_EE_DISC_OP_ADD) {
                    stpropnci_state.ee_info[idx].la |= NFC_PROTO_T4T_MASK;
                  } else {
                    stpropnci_state.ee_info[idx].la &= ~NFC_PROTO_T4T_MASK;
                  }
                }
              } else if (payload[7 + i * 5] == NCI_DISCOVERY_TYPE_LISTEN_B) {
                if (payload[4 + i * 5] == NFC_EE_DISC_OP_ADD) {
                  stpropnci_state.ee_info[idx].lb |= NFC_PROTO_T4T_MASK;
                } else {
                  stpropnci_state.ee_info[idx].lb &= ~NFC_PROTO_T4T_MASK;
                }
              } else if (payload[7 + i * 5] == NCI_DISCOVERY_TYPE_LISTEN_F) {
                if (payload[4 + i * 5] == NFC_EE_DISC_OP_ADD) {
                  stpropnci_state.ee_info[idx].lf |= NFC_PROTO_T3T_MASK;
                } else {
                  stpropnci_state.ee_info[idx].lf &= ~NFC_PROTO_T3T_MASK;
                }
              }
            }
            LOG_D("nb_ee_info=0x%x", stpropnci_state.nb_ee_info);
            for (int i = 0; i < stpropnci_state.nb_ee_info; i++) {
              LOG_D("nfceeId=0x%x, la=0x%x, lb=0x%x, lf=0x%x",
                    stpropnci_state.ee_info[i].nfcee_id,
                    stpropnci_state.ee_info[i].la,
                    stpropnci_state.ee_info[i].lb,
                    stpropnci_state.ee_info[i].lf);
            }
          }
          break;

        default:
          // We are not interested in this one
          break;
      }

      break;

    case NCI_GID_EE_MANAGE:
      switch (oid) {
        case NCI_MSG_NFCEE_MODE_SET:
          if (mt == NCI_MT_CMD) {
            if (payloadlen < 2) {
              LOG_E("NFCEE_MODE_SET_CMD length too short: %d", payloadlen);
              break;
            }
            LOG_I("NFCEE_MODE_SET_CMD: nfceeId=0x%x", payload[3]);
            // Get NFCEE ID
            if (payload[4] == 0x01) {
              stpropnci_state.wait_nfcee_ntf = true;
            }
            stpropnci_state.waiting_nfcee_id = payload[3];
          } else if (mt == NCI_MT_NTF) {
            if (payload[3] == 0x00) {
              LOG_I("NFCEE_MODE_SET_NTF: status=0x%x", payload[3]);
              // activation
              if (stpropnci_state.wait_nfcee_ntf) {
                stpropnci_state
                    .active_nfcee_ids[stpropnci_state.nb_active_nfcees] =
                    stpropnci_state.waiting_nfcee_id;
                stpropnci_state.nb_active_nfcees++;
                if (stpropnci_state.waiting_nfcee_id == 0x86) {
                  // Calling NFCEE_POWER_AND_LINK_CTRL_CMD to set SWP always ON
                  // Create fake notif with trigger = AID
                  NCI_MSG_BLD_HDR0(pp, NCI_MT_CMD, NCI_GID_EE_MANAGE);
                  NCI_MSG_BLD_HDR1(pp, NCI_MSG_NFCEE_POWER_LINK_CTRL);
                  paylen = pp++;

                  UINT8_TO_STREAM(
                      pp, stpropnci_state.waiting_nfcee_id);  // NFCEE ID
                  UINT8_TO_STREAM(pp, 0x03);  // trigger: force AID

                  *paylen = pp - (paylen + 1);
                  *buflen = pp - buf;
                  // send it
                  (void)stpropnci_pump_post(
                      MSG_DIR_TO_NFCC, stpropnci_state.tmpbuff,
                      *stpropnci_state.tmpbufflen, stpropnci_cb_block_rsp);
                }
              } else {
                // deactivation
                for (int i = 0; i < stpropnci_state.nb_active_nfcees; i++) {
                  if (stpropnci_state.active_nfcee_ids[i] ==
                      stpropnci_state.waiting_nfcee_id) {
                    for (int j = i; j < stpropnci_state.nb_active_nfcees - 1;
                         j++) {
                      stpropnci_state.active_nfcee_ids[j] =
                          stpropnci_state.active_nfcee_ids[j + 1];
                    }
                    stpropnci_state.nb_active_nfcees--;
                  }
                }
              }
            }
            stpropnci_state.wait_nfcee_ntf = false;
            if (stpropnci_state.is_ese_stuck) {
              // Drop NTF due to handle recovery
              handled = true;
            }
          }
          break;
        case NCI_MSG_NFCEE_POWER_LINK_CTRL:
          NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_EE_MANAGE);
          NCI_MSG_BLD_HDR1(pp, NCI_MSG_NFCEE_POWER_LINK_CTRL);
          paylen = pp++;
          UINT8_TO_STREAM(pp, NFC_STATUS_OK);  // NFCEE ID

          *paylen = pp - (paylen + 1);
          *buflen = pp - buf;
          // send it
          handled =
              stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                  *stpropnci_state.tmpbufflen, nullptr);
          break;
        default:
          break;
      }
      break;

    default:
      // Unexpected GID, unhandled.
      LOG_E("Unexpected GID: 0x%02hhx", gid);
      break;
  }

  return handled;
}

/*******************************************************************************
**
** Function         stpropnci_process_core_reset_ntf
**
** Description      Save the information from a core reset ntf (chip type, fw
*version, ...)
**
** Returns          n/a
**
*******************************************************************************/
static void stpropnci_process_core_reset_ntf(const uint8_t *payload,
                                             const uint16_t payloadlen) {
  if (payloadlen <= 8) {
    LOG_E("CORE_RESET_NTF length too short: %d", payloadlen);
    return;
  }

  // CORE_RESET_NTF ; copy the manuf data in the structure
  uint8_t trigger = payload[3];
  uint8_t manuf_id = payload[6];
  uint8_t manuf_len = payload[7];

  if (manuf_id != 0x02) {
    LOG_E("CORE_RESET_NTF ignored, not ST: %02hhx", manuf_id);
    return;
  }

  switch (trigger) {
    case 0x00:
      // Unrecoverable error -- this may be forged message, ignore it

      break;
    case 0xA0:  // after PROP_SET_NFC_MODE
      switch (payload[7 + manuf_len]) {
        case 0x00:
          stpropnci_state.clf_mode = stpropnci_state::CLF_MODE_ROUTER_DISABLED;
          break;
        case 0x01:
          stpropnci_state.clf_mode = stpropnci_state::CLF_MODE_ROUTER_ENABLED;
          break;
        case 0x02:
          stpropnci_state.clf_mode =
              stpropnci_state::CLF_MODE_ROUTER_USBCHARGING;
          break;
        default:
          // Unexpected trigger, ignore
          LOG_E("Unexpected mode: 0x%02hhx", payload[7 + manuf_len]);
          break;
      }
      [[fallthrough]];  // also save FW information
    case 0x01:          // end of boot
    case 0x02:          // after core_reset_cmd
      stpropnci_state.manu_specific_info_len = manuf_len;
      if (manuf_len > sizeof(stpropnci_state.manu_specific_info)) {
        stpropnci_state.manu_specific_info_len =
            sizeof(stpropnci_state.manu_specific_info);
      }
      memcpy(stpropnci_state.manu_specific_info, &payload[8],
             stpropnci_state.manu_specific_info_len);
      break;
    case 0xA2:  // Loader mode
      stpropnci_state.clf_mode = stpropnci_state::CLF_MODE_LOADER;
      break;
    default:
      // Unexpected trigger, ignore
      LOG_E("Unexpected trigger: 0x%02hhx", trigger);
      break;
  }
  // Done
}

/*******************************************************************************
**
** Function         stpropnci_send_core_reset_ntf_recovery
**
** Description      Generic method to build and post a simple core reset
*notification
**                  with an abnormal status code, so the stack will trigger a
*recovery.
**
** Returns          true if the message was posted, false otherwise.
**
*******************************************************************************/
bool stpropnci_send_core_reset_ntf_recovery(uint8_t hint) {
  bool handled = false;
  uint8_t *buf = stpropnci_state.tmpbuff;
  uint16_t *buflen = stpropnci_state.tmpbufflen;
  uint8_t *pp = buf, *paylen;

  stpropnci_tmpbuff_reset();

  LOG_I("Generating a CORE_RESET_NTF (hint: %02hhx)", hint);

  NCI_MSG_BLD_HDR0(pp, NCI_MT_NTF, NCI_GID_CORE);
  NCI_MSG_BLD_HDR1(pp, NCI_MSG_CORE_RESET);
  paylen = pp++;

  // use hint if it falls in the For Proprietary Use range, otherwise reset
  // trigger 0.
  UINT8_TO_STREAM(pp, hint >= 0xA0 ? hint : 0x00);
  UINT8_TO_STREAM(pp, 0x01);  // configuration status
  UINT8_TO_STREAM(pp, 0x20);  // NCI version
  UINT8_TO_STREAM(pp, 0x02);  // Manuf ID
  UINT8_TO_STREAM(pp, 0x00);  // Manuf Data len

  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;
  // send it back
  handled = stpropnci_pump_post(MSG_DIR_TO_STACK, stpropnci_state.tmpbuff,
                                *stpropnci_state.tmpbufflen, nullptr);

  return handled;
}

/*******************************************************************************
**
** Function         stpropnci_cb_passthrough_rsp
**
** Description      If we let a command passthrough, let the rsp as well.
**
** Returns          true
**
*******************************************************************************/
bool stpropnci_cb_passthrough_rsp(__attribute__((unused)) bool dir_from_upper,
                                  const uint8_t *payload,
                                  const uint16_t payloadlen,
                                  __attribute__((unused)) uint8_t mt,
                                  __attribute__((unused)) uint8_t gid,
                                  __attribute__((unused)) uint8_t oid) {
  return stpropnci_pump_post(MSG_DIR_TO_STACK, payload, payloadlen, nullptr);
}

/*******************************************************************************
**
** Function         stpropnci_cb_block_rsp
**
** Description      For commands generated in this lib, block corresponding
*responses.
**
** Returns          true
**
*******************************************************************************/
bool stpropnci_cb_block_rsp(__attribute__((unused)) bool dir_from_upper,
                            __attribute__((unused)) const uint8_t *payload,
                            __attribute__((unused)) const uint16_t payloadlen,
                            __attribute__((unused)) uint8_t mt,
                            __attribute__((unused)) uint8_t gid,
                            __attribute__((unused)) uint8_t oid) {
  // Drop this response, don t forward.
  return true;
}

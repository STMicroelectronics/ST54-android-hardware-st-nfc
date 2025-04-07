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

    return false;
  }

  if (mt == NCI_MT_DATA) {
    // the gid is actually the connection id in this case
    switch (gid) {
      case NFC_RF_CONN_ID:
        if (dir_from_upper == MSG_DIR_FROM_STACK) {
          // save the timestamp
          (void)clock_gettime(CLOCK_MONOTONIC, &stpropnci_state.ts_last_rf_tx);
        } else {
          // clear timestamp
          memset(&stpropnci_state.ts_last_rf_tx, 0,
                 sizeof(stpropnci_state.ts_last_rf_tx));
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
            if (payloadlen <= 8) {
              LOG_E("CORE_RESET_NTF length too short: %d", payloadlen);
              break;
            }

            // CORE_RESET_NTF ; copy the manuf data in the structure
            uint8_t trigger = payload[3];
            uint8_t manuf_id = payload[6];
            uint8_t manuf_len = payload[7];

            if (manuf_id != 0x02) {
              LOG_E("CORE_RESET_NTF ignored, not ST: %02hhx", manuf_id);
              break;
            }

            switch (trigger) {
              case 0x00:
                // Unrecoverable error

                break;
              case 0x01:  // end of boot
              case 0x02:  // after core_reset_cmd
                stpropnci_state.manu_specific_info_len = manuf_len;
                if (manuf_len > sizeof(stpropnci_state.manu_specific_info)) {
                  stpropnci_state.manu_specific_info_len =
                      sizeof(stpropnci_state.manu_specific_info);
                }
                memcpy(stpropnci_state.manu_specific_info, &payload[8],
                       stpropnci_state.manu_specific_info_len);
                break;
              case 0xA0:  // after PROP_SET_NFC_MODE
                switch (payload[8 + manuf_len]) {
                  case 0x00:
                    stpropnci_state.clf_mode =
                        stpropnci_state::CLF_MODE_ROUTER_DISABLED;
                    break;
                  case 0x01:
                    stpropnci_state.clf_mode =
                        stpropnci_state::CLF_MODE_ROUTER_ENABLED;
                    break;
                  case 0x02:
                    stpropnci_state.clf_mode =
                        stpropnci_state::CLF_MODE_ROUTER_USBCHARGING;
                    break;
                  default:
                    // Unexpected trigger, ignore
                    LOG_E("Unexpected mode: 0x%02hhx", payload[8 + manuf_len]);
                    break;
                }
                break;
              case 0xA2:  // Loader mode
                stpropnci_state.clf_mode = stpropnci_state::CLF_MODE_LOADER;
                break;
              default:
                // Unexpected trigger, ignore
                LOG_E("Unexpected trigger: 0x%02hhx", trigger);
                break;
            }
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
bool stpropnci_cb_passthrough_rsp(bool dir_from_upper, const uint8_t *payload,
                                  const uint16_t payloadlen, uint8_t mt,
                                  uint8_t gid, uint8_t oid) {
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
bool stpropnci_cb_block_rsp(bool dir_from_upper, const uint8_t *payload,
                            const uint16_t payloadlen, uint8_t mt, uint8_t gid,
                            uint8_t oid) {
  // Drop this response, don t forward.
  return true;
}

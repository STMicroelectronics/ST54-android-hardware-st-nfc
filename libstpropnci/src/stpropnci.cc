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

int stpropnci_loglvl = 0;
struct stpropnci_state stpropnci_state;

static pthread_mutex_t reentry_lock = PTHREAD_MUTEX_INITIALIZER;
static bool isInitialized = false;

/*******************************************************************************
**
** Function         stpropnci_init
**
** Description      Initialize the library and registers the outgoing_cb of the
**                  caller.
**
** Params:
**   - loglvl :  0: nothing;  1: important data only; 2: everything
**   - cb     : the callback that will be used for sending out messages from the
**              lib
**
** Returns          true if the initialization is successful, false otherwise.
**
*******************************************************************************/
bool stpropnci_init(int loglvl, outgoing_cb_t cb) {
  (void)pthread_mutex_lock(&reentry_lock);
  stpropnci_loglvl = loglvl;
#ifndef STPROPNCI_VENDOR
#define VARIANT "product"
#else
#define VARIANT "vendor"
#endif
  LOG_I(
      "(re)Initializing (version:25Q2-BP2A-20251010-Mainline-25W41p0, "
      "variant:" VARIANT "), log:%d",
      loglvl);

  memset(&stpropnci_state, 0, sizeof(stpropnci_state));
  // We use the msgPool sentinel as temp storage.
  stpropnci_state.tmpbuff = stpropnci_state.pumpstate.msgPool.payload;
  stpropnci_state.tmpbufflen = &stpropnci_state.pumpstate.msgPool.payloadlen;

  isInitialized = true;
  stpropnci_state.outCb = cb;

  if (!stpropnci_pump_init()) {
    LOG_E("Failed to initialize pump");
    (void)pthread_mutex_unlock(&reentry_lock);
    return false;
  }

  if (!stpropnci_modcb_init()) {
    LOG_E("Failed to initialize modcb");
    (void)pthread_mutex_unlock(&reentry_lock);
    return false;
  }

  // read from configuration file
  std::string felicaValue =
      stpropnci_cfg_read_value(STPROPNCI_CFG_FELICA_ESE_SUPPORT);
  if (felicaValue == STPROPNCI_CFG__true) {
    stpropnci_state.is_ese_felica_enabled = true;
  } else {
    // false = default value
    stpropnci_state.is_ese_felica_enabled = false;
  }

  (void)pthread_mutex_unlock(&reentry_lock);
  return true;
}

/*******************************************************************************
**
** Function         stpropnci_change_log_level
**
** Description      Update current log level.
**
** Params:
**   - loglvl :  0: nothing;  1: important data only; 2: everything
**
** Returns          -
**
*******************************************************************************/
void stpropnci_change_log_level(int loglvl) {
  (void)pthread_mutex_lock(&reentry_lock);
  stpropnci_loglvl = loglvl;
  (void)pthread_mutex_unlock(&reentry_lock);
}

/*******************************************************************************
**
** Function         stpropnci_change_config
**
** Description      Update a configuration at runtime
**
** Params:
**
** Returns          -
**
*******************************************************************************/
void stpropnci_change_config(const char* config_key, const char* config_value) {
  /* Behavior depends on the config_key being updated, this only accepts known
   * configs */
  if (!strncmp(STPROPNCI_CFG_FELICA_ESE_SUPPORT, config_key,
               strlen(STPROPNCI_CFG_FELICA_ESE_SUPPORT))) {
    if (!strncmp(STPROPNCI_CFG__true, config_value,
                 strlen(STPROPNCI_CFG__true))) {
      stpropnci_state.is_ese_felica_enabled = true;
    } else {
      // false = default value
      stpropnci_state.is_ese_felica_enabled = false;
    }
    LOG_D("Updated stpropnci_state.is_ese_felica_enabled : %s",
          stpropnci_state.is_ese_felica_enabled ? "true" : "false");
    // store the updated value
    stpropnci_cfg_write_value(STPROPNCI_CFG_FELICA_ESE_SUPPORT,
                              stpropnci_state.is_ese_felica_enabled
                                  ? STPROPNCI_CFG__true
                                  : STPROPNCI_CFG__false);
    return;
  } else if (strncmp(STPROPNCI_CFG_FIELD_ON_TOO_LONG_TIMER, config_key,
                     strlen(STPROPNCI_CFG_FIELD_ON_TOO_LONG_TIMER))) {
    if (!strncmp(STPROPNCI_CFG__true, config_value,
                 strlen(STPROPNCI_CFG__true))) {
      stpropnci_state.use_field_on_too_long_timer = true;
    } else {
      // false = default value
      stpropnci_state.use_field_on_too_long_timer = false;
    }
    LOG_D("Updated stpropnci_state.use_field_on_too_long_timer : %s",
          stpropnci_state.use_field_on_too_long_timer ? "true" : "false");
    return;
  } else if (strncmp(STPROPNCI_CFG_FIELD_ON_AFTER_SCREEN_OFF_TIMER, config_key,
                     strlen(STPROPNCI_CFG_FIELD_ON_AFTER_SCREEN_OFF_TIMER))) {
    if (!strncmp(STPROPNCI_CFG__true, config_value,
                 strlen(STPROPNCI_CFG__true))) {
      stpropnci_state.use_field_on_too_long_after_screen_off_timer = true;
    } else {
      // false = default value
      stpropnci_state.use_field_on_too_long_after_screen_off_timer = false;
    }
    LOG_D(
        "Updated "
        "stpropnci_state.use_field_on_too_long_after_screen_off_timer : %s",
        stpropnci_state.use_field_on_too_long_after_screen_off_timer ? "true"
                                                                     : "false");
    return;
  }
  LOG_E("Unsupported config, ignored: %s", config_key);
}

/*******************************************************************************
**
** Function         stpropnci_tmpbuff_reset
**
** Description      Simple helper function that clears the temporary storage of
**                  messages.
**
** Returns          none
**
*******************************************************************************/
void stpropnci_tmpbuff_reset() {
  // We only reset the len value, no need to memset.
  *stpropnci_state.tmpbufflen = 0;
}

/*******************************************************************************
**
** Function         stpropnci_deinit
**
** Description      Caller can call this when NFC is disabled, so resources may
**                  be freed.
**
** Returns          none
**
*******************************************************************************/
void stpropnci_deinit() {
  (void)pthread_mutex_lock(&reentry_lock);
  LOG_D("Deinitializing");
  isInitialized = false;
  stpropnci_modcb_fini();
  stpropnci_pump_fini();
  (void)pthread_mutex_unlock(&reentry_lock);
}

/*******************************************************************************
**
** Function         stpropnci_process
**
** Description      Process an NCI message.
**                  This function is not reentrant; it will be blocking until a
**                  previous call has
**                  returned.
**
** Parameters
**  - dir_from_upper: if true, the payload is a CMD or DATA and coming from the
**                    stack.
**                    if false, it is RSP, NTF, or DATA and coming from NFCC.
**  - payload: a buffer in the caller memory space.
**             The memory can be freed after this function returns.
**  - payloadlen: the length of data inside payload buffer.
**
** Returns          true if the message has been processed and caller can
**                  discard it,
**                  false if caller should forward it directly.
**
*******************************************************************************/
bool stpropnci_process(bool dir_from_upper, const uint8_t* payload,
                       const uint16_t payloadlen) {
  bool ret = false;
  uint8_t mt, pbf, gid, oid;

  (void)pthread_mutex_lock(&reentry_lock);
  if (!isInitialized) {
    LOG_E(
        "Cannot call stpropnci_process before stpropnci_init! No processing.");
    (void)pthread_mutex_unlock(&reentry_lock);
    return ret;
  }
  if (!stpropnci_state.passthrough_mode) {
    if (payloadlen > 3) {
      LOG_D("Processing (hdr:%02hhx%02hhx%02hhx%02hhx)", payload[0], payload[1],
            payload[2], payload[3]);
    } else {
      LOG_D("Processing (hdr:%02hhx%02hhx%02hhx)", payload[0], payload[1],
            payload[2]);
    }
  }
  if (dir_from_upper == MSG_DIR_FROM_NFCC) {
    // pass to pump first in case this acknowledges a sent message
    stpropnci_pump_got(payload, payloadlen, &ret);
  }

  // if no cb registered with the cmd already handled the response,
  // is there a generic module cb ?
  if (!ret) {
    const uint8_t* p = payload;
    NCI_MSG_PRS_HDR0(p, mt, pbf, gid);
    NCI_MSG_PRS_HDR1(p, oid);

    // passthrough mode ?
    if (stpropnci_state.passthrough_mode) {
      // Only accept a command to set passthrough, anything else is not
      // processed.
      if ((mt != NCI_MT_CMD) || (gid != NCI_GID_PROP) ||
          (oid != ST_PROP_NCI_OID) ||
          (payload[3] != ST_PROP_NCI_SET_LIB_PASSTHOUGH)) {
        // passthrough mode: do nothing.
        if (dir_from_upper == MSG_DIR_FROM_NFCC) {
          // post rsp & ntf to have proper logging in stpropnci_cb
          ret =
              stpropnci_pump_post(dir_from_upper, payload, payloadlen, nullptr);
        }
        (void)pthread_mutex_unlock(&reentry_lock);
        return ret;
      }
    }

    // if a submodule callback handles it, stop here
    ret = stpropnci_modcb_process(dir_from_upper, payload, payloadlen, mt, gid,
                                  oid);
  }

  // otherwise, pass it to the modules normally
  if (!ret) {
    if ((mt != NCI_MT_DATA) && (gid == NCI_GID_PROP)) {
      ret = stpropnci_process_prop(false, dir_from_upper, payload, payloadlen,
                                   mt, oid);
    } else {
      ret = stpropnci_process_std(false, dir_from_upper, payload, payloadlen,
                                  mt, gid, oid);
    }
  }

  // if no module consumed it, we still process it to have the timer management.
  if (!ret) {
    ret = stpropnci_pump_post(dir_from_upper, payload, payloadlen, nullptr);
  }

  (void)pthread_mutex_unlock(&reentry_lock);
  return ret;
}

/*******************************************************************************
**
** Function         stpropnci_inform
**
** Description      Just let the library know about a message but no handling
**                  expected.
**                  This is used by the HAL in its own wrapper processing.
**                  This function is not reentrant; it will be blocking until
**                  a previous call has returned.
**
** Parameters
**  - dir_from_upper: if true, the payload is a CMD or DATA and coming from the
**                    stack.
**                    if false, it is RSP, NTF, or DATA and coming from NFCC.
**  - payload: a buffer in the caller memory space.
**             The memory can be freed after this function returns.
**  - payloadlen: the length of data inside payload buffer.
**
** Returns          none
**
*******************************************************************************/
void stpropnci_inform(bool dir_from_upper, const uint8_t* payload,
                      const uint16_t payloadlen) {
  uint8_t mt, pbf, gid, oid;
  const uint8_t* p;

  (void)pthread_mutex_lock(&reentry_lock);
  if (!isInitialized) {
    LOG_E("Cannot call stpropnci_inform before stpropnci_init! No processing.");
    (void)pthread_mutex_unlock(&reentry_lock);
    return;
  }
  if (stpropnci_state.passthrough_mode) {
    // just ignore
    (void)pthread_mutex_unlock(&reentry_lock);
    return;
  }

  if (payloadlen > 3) {
    LOG_D("Processing (hdr:%02hhx%02hhx%02hhx%02hhx)", payload[0], payload[1],
          payload[2], payload[3]);
  } else {
    LOG_D("Processing (hdr:%02hhx%02hhx%02hhx)", payload[0], payload[1],
          payload[2]);
  }

  p = payload;
  NCI_MSG_PRS_HDR0(p, mt, pbf, gid);
  NCI_MSG_PRS_HDR1(p, oid);

  if (gid == NCI_GID_PROP) {
    stpropnci_process_prop(true, dir_from_upper, payload, payloadlen, mt, oid);
  } else {
    stpropnci_process_std(true, dir_from_upper, payload, payloadlen, mt, gid,
                          oid);
  }

  (void)pthread_mutex_unlock(&reentry_lock);
}

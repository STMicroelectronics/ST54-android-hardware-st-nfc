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

/*******************************************************************************
**
** Function         stpropnci_process_prop
**
** Description      Called upon incoming messages with PROP GID,
**                  dispatch to submodules based on OID
**
** Returns          true if message was handled and processing should stop.
**
*******************************************************************************/
bool stpropnci_process_prop(bool inform_only, bool dir_from_upper,
                            const uint8_t *payload, const uint16_t payloadlen,
                            uint8_t mt, uint8_t oid) {
  bool ret = false;

  switch (oid) {
    case NCI_MSG_PROP_ANDROID:
      return stpropnci_process_prop_android(inform_only, dir_from_upper,
                                            payload, payloadlen, mt, oid);
      break;

    case ST_PROP_NCI_OID:
    case ST_NCI_MSG_PROP:
    case ST_NCI_MSG_PROP_TEST:
    case ST_NCI_MSG_PROP_LOADER:
    case ST_NCI_MSG_PROP_PWR_MON_RW_ON_NTF:
    case ST_NCI_MSG_PROP_PWR_MON_RW_OFF_NTF:
    case ST_NCI_MSG_PROP_RF_OBSERVE_MODE_SUSPENDED:
    case ST_NCI_MSG_PROP_RF_OBSERVE_MODE_RESUMED:
      return stpropnci_process_prop_st(inform_only, dir_from_upper, payload,
                                       payloadlen, mt, oid);
      break;
  }

  return ret;
}

/*******************************************************************************
**
** Function         stpropnci_build_prop_status_rsp
**
** Description      Generic method to build a simple response with prop GID and
**                  a subOID and status byte only.
**
** Returns          none
**
*******************************************************************************/
void stpropnci_build_prop_status_rsp(uint8_t *buf, uint16_t *buflen,
                                     uint8_t oid, uint8_t suboid,
                                     uint8_t status) {
  uint8_t *pp = buf, *paylen;

  NCI_MSG_BLD_HDR0(pp, NCI_MT_RSP, NCI_GID_PROP);
  NCI_MSG_BLD_HDR1(pp, oid);
  paylen = pp++;
  UINT8_TO_STREAM(pp, suboid);
  UINT8_TO_STREAM(pp, status);
  *paylen = pp - (paylen + 1);
  *buflen = pp - buf;
}

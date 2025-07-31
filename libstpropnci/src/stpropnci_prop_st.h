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

#ifndef STPROPNCI_PROP_ST_H
#define STPROPNCI_PROP_ST_H

#include <nci_defs.h>
#include <stpropnci.h>

/* ST proprietary NCI definitions */

/* Proprietary status codes */
#define ST_NCI_STATUS_TM_NCI_RF_MIFARE_LIB_ERROR 0xE0
#define ST_NCI_STATUS_PROP_BUFFER_OVERFLOW 0xE1
#define ST_NCI_STATUS_PROP_COLLISION_AVOIDANCE 0xE2
#define ST_NCI_STATUS_PROP_FALSE_TAG_DETECTION 0xE3
#define ST_NCI_STATUS_PROP_TAG_DETECTION 0xE5
#define ST_NCI_STATUS_PROP_PLL_LOCK_ISSUE 0xE6
#define ST_NCI_STATUS_PROP_RF_FIELD_ON_DETECTED 0xE7

/* Proprietary NCI parameters */
#define ST_NCI_PARAM_ID_TAGDET_INTERVAL 0xA1
#define ST_NCI_PARAM_ID_RWTD_GUARD 0xA2
#define ST_NCI_PARAM_ID_RF_DONT_ANSWER_PASSIVE_LISTEN 0xA3
#define ST_NCI_PARAM_ID_RF_SET_LISTEN_IOT_SEQ 0xA4
#define ST_NCI_PARAM_ID_TEMPORARY_FORCED_SAK 0xA5
#define ST_NCI_PARAM_ID_DMP_CONTROL 0xA8
#define ST_NCI_PARAM_ID_TEMPORARY_FORWARD_ISO_OVER_CLT 0xA9
#define ST_NCI_PARAM_ID_DIS_LPTD 0xAA

/* ST Prop OID */
#define ST_NCI_MSG_PROP 0x02
/* ST Prop subOIDs */
#define ST_NCI_PROP_GET_NFC_MODE 0x01
#define ST_NCI_PROP_SET_NFC_MODE 0x02
#define ST_NCI_PROP_GET_CONFIG 0x03
#define ST_NCI_PROP_GET_CONFIG__ESE_ATTR_ID 0x0B
#define ST_NCI_PROP_SET_CONFIG 0x04
#define ST_NCI_PROP_EMVCO_PCD_MODE 0x05
#define ST_NCI_PROP_NFC_FW_UPDATE 0x06
#define ST_NCI_PROP_SET_DUAL_MATCHING_CMD 0x07
#define ST_NCI_PROP_DISCONNECT_DH 0x08
#define ST_NCI_PROP_NFCEE_POWER_CNTRL 0x09
#define ST_NCI_PROP_APPLY_RF_CONFIG 0x0A
#define ST_NCI_PROP_STOP_PRODUCTION_MODE_PULSE 0x10
#define ST_NCI_PROP_GET_FIELD_INFO 0x12
#define ST_NCI_PROP_RAW_RF_MODE_CTRL 0x13
#define ST_NCI_PROP_GPIO_CONFIGURE_AS_OUTPUT 0x15
#define ST_NCI_PROP_GPIO_SET_OUTPUT 0x16
#define ST_NCI_PROP_RAW_RF_MODE_AUTH 0x17
#define ST_NCI_PROP_LOG 0x20
#define ST_NCI_PROP_GET_PERSO_DATA 0x22
#define ST_NCI_PROP_PULSE_PATTERN_DETECTED 0x23

/* Proprietary registers ID */
#define ST_NCI_PROP__CONFIG_SUBSET__NFCC_CONFIG 0x01
#define ST_NCI_PROP__CONFIG_SUBSET__HW_CONFIG 0x02

/* types of FW logs */
#define FWLOG_T_firstRx 0x04
#define FWLOG_T_dynParamUsed 0x07
#define FWLOG_T_CETx 0x08
#define FWLOG_T_CERx 0x09
#define FWLOG_T_RWTx 0x0A
#define FWLOG_T_RWRx 0x0B
#define FWLOG_T_Active_A 0x0C
#define FWLOG_T_Sleep_A 0x0E
#define FWLOG_T_fieldOn 0x10
#define FWLOG_T_fieldOff 0x11
#define FWLOG_T_fieldSenseStopped 0x17
#define FWLOG_T_fieldLevel 0x18
#define FWLOG_T_CERxError 0x19
#define FWLOG_T_RWRxError 0x1A
#define FWLOG_T_TxAct 0x30
#define FWLOG_T_TxCtrl 0x31
#define FWLOG_T_TxI 0x32
#define FWLOG_T_TxIr 0x33
#define FWLOG_T_TxSwpClt 0x34
#define FWLOG_T_RxAct 0x35
#define FWLOG_T_RxCtrl 0x36
#define FWLOG_T_RxI 0x37
#define FWLOG_T_RxErr 0x38
#define FWLOG_T_RxSwpClt 0x39
#define FWLOG_T_SwpDeact 0x3B
#define FWLOG_T_Idle 0x45
#define FWLOG_T_LogOverwrite 0xFF

/* ST Prop Test OID */
#define ST_NCI_MSG_PROP_TEST 0x03
/* ST Prop Test subOIDs */
#define ST_NCI_PROP_TEST_RESET_SYNC_ID 0x00
#define ST_NCI_PROP_TEST_RESET_ST54J_SE 0x01
#define ST_NCI_PROP_TEST_READ_VCC_UICC_CLASS 0x03
#define ST_NCI_PROP_TEST_LOADER_PRODUCT_INFO 0x07
#define ST_NCI_PROP_TEST_READER_CFG 0xB0
#define ST_NCI_PROP_TEST_CARD_CFG 0xB1
#define ST_NCI_PROP_TEST_DATA 0xB2
#define ST_NCI_PROP_TEST_FIELD 0xB3
#define ST_NCI_PROP_TEST_RFI_GET 0xB5
#define ST_NCI_PROP_TEST_ADJUST_AND_WRITE_PHASE 0xB7
#define ST_NCI_PROP_READ_RF_REGISTER 0xB8
#define ST_NCI_PROP_WRITE_RF_MASK_REGISTER 0xB9
#define ST_NCI_PROP_TEST_DATA_EXTENDED 0xBB
#define ST_NCI_PROP_TEST_WRITE_CUSTOM_DATA 0xBE
#define ST_NCI_PROP_TEST_GET_CUSTOM_DATA 0xBF
#define ST_NCI_PROP_TEST_PHASE_TRIM_UPDATE 0xC6
#define ST_NCI_PROP_TEST_GET_MEASUREMENT 0xC9
#define ST_NCI_PROP_TEST_PROD_TEST_V3 0xCC
#define ST_NCI_PROP_TEST_ANT_DIAG_V3 0xCD
#define ST_NCI_PROP_TEST_RFI_GET_EXT 0xCE
#define ST_NCI_PROP_TEST_LOOPBACK 0xCF
#define ST_NCI_PROP_TEST_FIELD_ADJ_POWER 0xD0

/* ST Prop loader OID */
#define ST_NCI_MSG_PROP_LOADER 0x04

/* ST Prop monitoring OID */
#define ST_NCI_MSG_PROP_PWR_MON_RW_ON_NTF 0x05
#define ST_NCI_MSG_PROP_PWR_MON_RW_OFF_NTF 0x06

/* ST Prop OIDs related to exit frame */
#define ST_NCI_MSG_PROP_RF_SET_OBSERVE_MODE_EXIT_FRAME 0x19
#define ST_NCI_MSG_PROP_RF_GET_OBSERVE_MODE_EXIT_FRAME 0x1A
#define ST_NCI_MSG_PROP_RF_OBSERVE_MODE_SUSPENDED 0x1B
#define ST_NCI_MSG_PROP_RF_OBSERVE_MODE_RESUMED 0x1C

/* ST Prop OIDs related to custom polling */
#define ST_NCI_MSG_PROP_RF_SET_CUST_PASSIVE_POLL_FRAME 0x1D
#define ST_NCI_MSG_PROP_RF_GET_CUST_PASSIVE_POLL_FRAME 0x1E

/* These ones are not proprietary but not defined in libnfc-nci */
#ifndef NCI_MSG_RF_SET_FORCED_NFCEE_ROUTING
#define NCI_MSG_RF_SET_FORCED_NFCEE_ROUTING 0x11
#endif
#ifndef NCI_MSG_RF_SET_LISTEN_OBSERVE_MODE
#define NCI_MSG_RF_SET_LISTEN_OBSERVE_MODE 0x16
#endif
#ifndef NCI_MSG_RF_GET_LISTEN_OBSERVE_MODE_STATE
#define NCI_MSG_RF_GET_LISTEN_OBSERVE_MODE_STATE 0x17
#endif
#ifndef NCI_MSG_RF_FRAME_INFO_NTF
#define NCI_MSG_RF_FRAME_INFO_NTF 0x18
#endif

/**************************
    ST NCI management
 **************************/
bool stpropnci_process_prop_st(bool inform_only, bool dir_from_upper,
                               const uint8_t* payload,
                               const uint16_t payloadlen, uint8_t mt,
                               uint8_t oid);

/*****************************************************************************/
/* Definitions for ST Proprietary NCI messages (between StNfcExtensionService
 * and HAL or compatibility layer)*/
/*****************************************************************************/
#define ST_PROP_NCI_OID 0x01

#define ST_PROP_NCI_SET_LIB_PASSTHOUGH 0x00
/* command: 1 byte : 00 (disabled) / 01 (enabled) */
/* response: no payload */
/* NTF: no ntf */

#define ST_PROP_NCI_GET_STPROPNCI_VERSION_SUBOID 0x01
/* command: no payload */
/* response: 2 bytes (=STPROPNCI_LIB_VERSION, MSB) */
/* NTF: 2 bytes (=STPROPNCI_LIB_VERSION, MSB), sent by HAL only. */

#define ST_PROP_NCI_GET_MANUF_DATA_SUBOID 0x02
/* command: no payload */
/* response: n bytes (=manufacturer data from CORE_RESET_NTF) */
/* no NTF */

#define ST_PROP_NCI_GET_NFCEE_ID_LIST 0x03
/* command: no payload */
/* response: nb nfcee, nfcee list */
/* no NTF */

#define ST_PROP_NCI_SETUP_ADPU_GATE 0x04
/* command: no payload */
/* response: Waiting time (2 bytes MSB) */
/* no NTF */

#define ST_PROP_NCI_TRANSCEIVE_ADPU_GATE 0x05
/* command: command bytes */
/* response: no payload */
/* ntf: payload empty if WTX or APDU + SW*/

#define ST_PROP_NCI_NFCEE_ACTION_NTF_AID_WITH_SW 0x06
/* no CMD */
/* no RSP */
/* NTF : same payload as RF_NFCEE_ACTION_NTF with trigger == 0x11 */

#define ST_PROP_NCI_RAW_JNI_SEQ 0x07
/* command: byte + byte array (parameters of RawJniSeq)*/
/* rsp: always OK */
/* NTF: bytes returned by RawJniSeq */

#define ST_PROP_NCI_SKIP_MIFARE 0x08
/* command: status ON/OFF*/
/* rsp: always OK */
/* no NTF */

#define ST_PROP_EMULATE_NFC_A_CARD_1 0x09
/* command: command bytes */
/* rsp: OK/KO */
/* no NTF */

#define ST_PROP_EMULATE_NFC_A_CARD_2 0x10
/* command: on/off */
/* rsp: OK */
/* no NTF */

#define ST_PROP_STORE_MIFARE_TOKEN 0x11
/* command: on/off */
/* rsp: OK */
/* NTF: bytes stored */

#define ST_PROP_SET_FELICA_CARD_ENABLED 0x12
/* command: on/off */
/* rsp: OK */
/* no NTF */

#define ST_PROP_SET_RF_CUSTOM_POLL_FRAME 0x13
/* command: on/off - RF frames*/
/* rsp: OK */
/* no NTF */

#define ST_PROP_RF_INTF_ACTIV_CUST_POLL_NTF 0x14
/* no cmd */
/* no rsp */
/* NTF: payload of RF_INTF_ACTIVATED_NTF */

#endif  // STPROPNCI_PROP_ST_H

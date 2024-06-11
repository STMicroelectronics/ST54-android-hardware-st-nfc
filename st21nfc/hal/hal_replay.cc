/** ----------------------------------------------------------------------
 *
 * Copyright (C) 2016 ST Microelectronics S.A.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 ----------------------------------------------------------------------*/
#define LOG_TAG "NfcHal"

#include <android-base/properties.h>
#include <ctype.h>
#include <hardware/nfc.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "android_logmsg.h"
#include "halcore_private.h"
#include "st21nfc_dev.h"

extern void DispHal(const char* title, const void* data, size_t length);

/**************************************************************************************************
 *
 *                                      Private API Declaration
 *
 **************************************************************************************************/

static void* HalReplayThread(void* arg);
static pthread_t replayThreadHandle = (pthread_t)NULL;

#define MAX_FRAME_SIZE 255
#define MAX_LINE_LENGTH 1024

#define END_OF_FILE 0
#define FOUND_RX 1
#define FOUND_TX 2
#define END_OF_REPLAY 3

FILE* mReplayFile;
uint8_t mRxData[MAX_LINE_LENGTH];
int mRxDataSize = 0;
unsigned long long mRxTimeMs = 0, mTxTimeMs = 0;
bool mHalReplay = false;

#define REPLAY_INIT_OFF 0
#define REPLAY_INIT_FILE 1
#define REPLAY_INIT_AUTO 2
#define REPLAY_INIT_DONE 3
int mReplayInitStatus = REPLAY_INIT_OFF;
uint8_t mTxData[MAX_LINE_LENGTH];
int mTxDataSize = 0;

uint8_t mExpTxData[MAX_LINE_LENGTH];
int mExpTxDataSize = 0;
bool mUnexpectedTxData = false;
bool mIsEmbeddedTx = false;

bool mIsNextRx = false;
int mRxCnt = 0;
uint8_t mActiveHciNfceeBitmap = 0x00;

sem_t mTxSem;

bool mIsError = false;

fpos_t mFilePos;

/*** Auto replay data ***/
uint8_t mCoreResetNtfInit[] = {
    0x60, 0x00, 0x1f, 0x01, 0x01, 0x20, 0x02, 0x1a, 0x05, 0x02, 0x03, 0x13,
    0x94, 0x35, 0x01, 0x05, 0x00, 0x00, 0x44, 0x64, 0xd6, 0x00, 0x00, 0x79,
    0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xb2, 0x52, 0x01};
uint8_t mCoreResetRsp[] = {0x40, 0x00, 0x01, 0x00};
uint8_t mCoreResetNtfReset[] = {
    0x60, 0x00, 0x1f, 0x02, 0x01, 0x20, 0x02, 0x1a, 0x05, 0x02, 0x03, 0x13,
    0x94, 0x35, 0x01, 0x05, 0x00, 0x00, 0x44, 0x64, 0xd6, 0x00, 0x00, 0x79,
    0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xb2, 0x52, 0x01};
uint8_t mCoreInitRsp[] = {0x40, 0x01, 0x18, 0x00, 0x1a, 0x7e, 0x06, 0x00, 0x01,
                          0x00, 0x04, 0xff, 0xff, 0x00, 0x0c, 0x01, 0x05, 0x01,
                          0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x90, 0x00};
uint8_t mCoreCreditsNtfHci[] = {0x60, 0x06, 0x03, 0x01, 0x01, 0x01};
uint8_t mPropRsp11[] = {
    0x4f, 0x02, 0x44, 0x00, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00, 0x08, 0x0d,
    0x08, 0x05, 0x03, 0xe8, 0x06, 0x40, 0x10, 0x00, 0x04, 0x04, 0x04, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x02, 0x02, 0x01, 0x01,
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x80, 0xb0, 0x71, 0x10, 0x34,
    0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x40, 0x40, 0x10, 0x00, 0x40, 0x00,
    0x6d, 0x1c, 0x75, 0x5f, 0x06, 0x78, 0x05, 0x00, 0x00, 0x00, 0x00};
uint8_t mPropRsp02[] = {0x4f, 0x02, 0x28, 0x00, 0x01, 0x00, 0x24, 0xa0, 0xd2,
                        0x0d, 0x13, 0x88, 0x01, 0xf4, 0x04, 0x02, 0x1e, 0x1e,
                        0xff, 0x08, 0x02, 0x03, 0x02, 0x00, 0x07, 0x00, 0x05,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x04, 0x00, 0x08, 0x04, 0x09};
uint8_t mPropRsp01[] = {0x4f, 0x02, 0x0c, 0x00, 0x01, 0x00, 0x08, 0x22,
                        0x17, 0x06, 0x06, 0x36, 0x0c, 0x88, 0x88};
uint8_t mPropRsp14[] = {
    0x4f, 0x02, 0x96, 0x00, 0x01, 0x00, 0x92, 0x01, 0x02, 0x00, 0x0a, 0x01,
    0x00, 0x00, 0x00, 0x0f, 0x00, 0x1e, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t mPropRsp08[] = {0x4f, 0x02, 0x10, 0x00, 0x01, 0x00, 0x0c,
                        0xbf, 0x01, 0xef, 0x00, 0x00, 0x00, 0xc1,
                        0xc2, 0xc3, 0x00, 0x3d, 0x00};

uint8_t mPropRsp09[] = {0x4f, 0x02, 0x03, 0x00, 0x00};

uint8_t mPropSetNfcModeRsp[] = {0x4f, 0x02, 0x01, 0x00};
uint8_t mCoreResetNtfModeSet[] = {
    0x60, 0x00, 0x1f, 0xa0, 0x01, 0x20, 0x02, 0x1a, 0x05, 0x02, 0x03, 0x13,
    0x94, 0x35, 0x01, 0x05, 0x00, 0x00, 0x44, 0x64, 0xd6, 0x00, 0x00, 0x79,
    0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xb2, 0x52, 0x01};
uint8_t mCoreSetConfigRsp[] = {0x40, 0x02, 0x02, 0x00, 0x00};
uint8_t mRfDiscoverMapRsp[] = {0x41, 0x00, 0x01, 0x00};
uint8_t mNfceeDiscoverRsp[] = {0x42, 0x00, 0x02, 0x00, 0x03};
uint8_t mNfceeDiscoverNtf81[] = {0x62, 0x00, 0x08, 0x81, 0x01, 0x00,
                                 0x01, 0x03, 0x01, 0x02, 0x00};
uint8_t mNfceeDiscoverNtf86[] = {0x62, 0x00, 0x08, 0x86, 0x01, 0x00,
                                 0x01, 0x03, 0x01, 0xc0, 0x00};
uint8_t mNfceeDiscoverNtf10[] = {0x62, 0x00, 0x0e, 0x10, 0x01, 0x01,
                                 0x00, 0x01, 0x04, 0x06, 0x00, 0x20,
                                 0x00, 0x00, 0x3b, 0x01, 0x00};
uint8_t mDataHciRspOk[] = {0x01, 0x00, 0x02, 0x81, 0x80};
uint8_t mDataHciRspSessionId[] = {0x01, 0x00, 0x0a, 0x81, 0x80, 0xff, 0xff,
                                  0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t mDataHciRspHostListNone[] = {0x01, 0x00, 0x04, 0x81, 0x80, 0x00, 0x01};
uint8_t mCoreGetConfigRsp52[] = {0x40, 0x03, 0x05, 0x00,
                                 0x01, 0x52, 0x01, 0x10};
uint8_t mCoreSetPowerSubStateRsp[] = {0x40, 0x09, 0x01, 0x00};
uint8_t mNfceeModeSetRsp[] = {0x42, 0x01, 0x01, 0x00};
uint8_t mNfceeModeSetNtf[] = {0x62, 0x01, 0x01, 0x00};
uint8_t mDataHciHotPlugNtfSim[] = {0x01, 0x00, 0x04, 0x81, 0x43, 0x02, 0x01};
uint8_t mRfNfceeDiscoveryReqNtfSim[] = {0x61, 0x0a, 0x06, 0x01, 0x00,
                                        0x03, 0x81, 0x81, 0x04};
uint8_t mDataHciRspHostListSim[] = {0x01, 0x00, 0x05, 0x81,
                                    0x80, 0x00, 0x02, 0x01};
uint8_t mDataHciRspHostListESe[] = {0x01, 0x00, 0x05, 0x81,
                                    0x80, 0x00, 0xc0, 0x01};
uint8_t mPropRspGateSim[] = {
    0x4f, 0x02, 0x40, 0x00, 0x01, 0x01, 0x3c, 0x02, 0x23, 0x00, 0x23, 0x23,
    0x06, 0x01, 0x02, 0x87, 0xc9, 0x23, 0x00, 0x02, 0x21, 0x00, 0x21, 0x21,
    0x06, 0x01, 0x03, 0xf6, 0xc9, 0x23, 0x00, 0x02, 0x13, 0x00, 0x13, 0x13,
    0x06, 0x01, 0x04, 0x92, 0x01, 0x00, 0x20, 0x02, 0x11, 0x00, 0x11, 0x11,
    0x06, 0x01, 0x05, 0x7c, 0x12, 0x00, 0x20, 0x02, 0x41, 0x01, 0x41, 0x3e,
    0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t mDataHciHotPlugNtfEse[] = {0x01, 0x00, 0x04, 0x81, 0x43, 0xc0, 0x01};
uint8_t mRfNfceeDiscoveryReqNtfEse[] = {
    0x61, 0x0a, 0x10, 0x03, 0x00, 0x03, 0x86, 0x82, 0x03, 0x00,
    0x03, 0x86, 0x80, 0x04, 0x00, 0x03, 0x86, 0x81, 0x04};
uint8_t mDataHciRspHostListFull[] = {0x01, 0x00, 0x06, 0x81, 0x80,
                                     0x00, 0x02, 0xc0, 0x01};
uint8_t mPropRspGateEse[] = {
    0x4f, 0x02, 0x34, 0x00, 0x01, 0x01, 0x30, 0xc0, 0x41, 0x01, 0x41,
    0x5e, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x23, 0x00,
    0x23, 0x23, 0x06, 0x01, 0x02, 0xd1, 0xc9, 0x23, 0x00, 0xc0, 0x21,
    0x00, 0x21, 0x21, 0x06, 0x01, 0x03, 0x32, 0xca, 0x23, 0x00, 0xc0,
    0x24, 0x00, 0x24, 0x24, 0x06, 0x01, 0x04, 0x56, 0xca, 0x23, 0x00};
uint8_t mRfNfceeDiscoveryReqNtfNdefNfcee[] = {0x61, 0x0a, 0x0b, 0x02, 0x00,
                                              0x03, 0x10, 0x80, 0x04, 0x00,
                                              0x03, 0x10, 0x81, 0x04};
uint8_t mCoreConnCreateRsp[] = {0x40, 0x04, 0x04, 0x00, 0xff, 0x00, 0x02};
uint8_t mCoreCreditsNtfNdefNfcee[] = {0x60, 0x06, 0x03, 0x01, 0x02, 0x01};
uint8_t mNfceePwrAndLinkCtrlRsp[] = {0x42, 0x03, 0x01, 0x00};
uint8_t mRfSetRoutingTableRsp[] = {0x41, 0x01, 0x01, 0x00};
uint8_t mRfDiscoverRsp[] = {0x41, 0x03, 0x01, 0x00};
uint8_t mRfDeactivateIdleRsp[] = {0x41, 0x06, 0x01, 0x00};
uint8_t mRfFieldInfoNtfOff[] = {0x61, 0x07, 0x01, 0x00};

/**************************************************************************************************
 *
 *                                      Private API Definition
 *
 **************************************************************************************************/

/*****************************************************************************/
/***** HalOpenReplayFile *****/
/*****************************************************************************/
bool HalOpenReplayFile() {
  mReplayFile = fopen("/vendor/etc/hal_replay.txt", "rb");
  if (mReplayFile == NULL) {
    STLOG_HAL_E("HalOpenReplayFile() - Error opening file.");
    return false;
  }
  STLOG_HAL_V("HalOpenReplayFile() - done");
  return true;
}

/*****************************************************************************/
/***** HalReplayAuto *****/
/*****************************************************************************/
int HalReplayAuto() {
  uint8_t* dataPtr = nullptr;
  bool isEnd = false;

  if (mIsNextRx) {
    switch (mTxData[0]) {
      case 0x00:
        // RF data
        break;
      case 0x01:
        // HCI data
        if (mRxCnt) {
          dataPtr = mCoreCreditsNtfHci;
          mRxDataSize = sizeof(mCoreCreditsNtfHci);
          mIsNextRx = false;
          break;
        }
        switch (mTxData[4]) {
          case 0x03:
            // OPEN ADMIN
            dataPtr = mDataHciRspOk;
            mRxDataSize = sizeof(mDataHciRspOk);
            break;
          case 0x02:
            // GET_PARAM
            switch (mTxData[5]) {
              case 0x01:
                // SESSION_ID
                dataPtr = mDataHciRspSessionId;
                mRxDataSize = sizeof(mDataHciRspSessionId);
                break;
              case 0x04:
                // HOST_LIST
                if (mActiveHciNfceeBitmap == 0x00) {
                  dataPtr = mDataHciRspHostListNone;
                  mRxDataSize = sizeof(mDataHciRspHostListNone);
                } else if (mActiveHciNfceeBitmap == 0x01) {
                  dataPtr = mDataHciRspHostListSim;
                  mRxDataSize = sizeof(mDataHciRspHostListSim);
                } else if (mActiveHciNfceeBitmap == 0x02) {
                  dataPtr = mDataHciRspHostListESe;
                  mRxDataSize = sizeof(mDataHciRspHostListESe);
                } else if (mActiveHciNfceeBitmap == 0x03) {
                  dataPtr = mDataHciRspHostListFull;
                  mRxDataSize = sizeof(mDataHciRspHostListFull);
                }
                break;
            }
            break;
          case 0x01:
            // WHITE_LIST
            dataPtr = mDataHciRspOk;
            mRxDataSize = sizeof(mDataHciRspOk);
            break;
        }
        mRxCnt = 1;
        break;
      case 0x02:
        // NDEF-NFCEE data
        break;
      case 0x20:
        switch (mTxData[1]) {
          case 0x00:
            // Send CORE_RESET_RSP
            if (mRxCnt == 0) {
              dataPtr = mCoreResetRsp;
              mRxDataSize = sizeof(mCoreResetRsp);
              mRxCnt = 1;
            } else {
              mActiveHciNfceeBitmap = 0x00;
              dataPtr = mCoreResetNtfReset;
              mRxDataSize = sizeof(mCoreResetNtfReset);
              mIsNextRx = false;
            }
            break;
          case 0x01:
            // Send CORE_INIT_RSP
            if (mRxCnt == 0) {
              dataPtr = mCoreInitRsp;
              mRxDataSize = sizeof(mCoreInitRsp);
              mRxCnt = 1;
            } else {
              dataPtr = mCoreCreditsNtfHci;
              mRxDataSize = sizeof(mCoreCreditsNtfHci);
              mIsNextRx = false;
            }
            break;
          case 0x02:
            // Send CORE_SET_CONFIG_RSP
            if (mRxCnt == 0) {
              dataPtr = mCoreSetConfigRsp;
              mRxDataSize = sizeof(mCoreSetConfigRsp);
              int idx = 4;
              for (int i = 0; i < mTxData[3]; i++) {
                // Check if RF_FIELD_INFO_NTf requested
                if ((mTxData[idx] == 0x80) && (mTxData[idx + 2] == 0x01)) {
                  mIsNextRx = true;
                  mRxCnt++;
                  break;
                } else {
                  mIsNextRx = false;
                }
                idx += (2 + mTxData[idx + 1]);
              }
            } else {
              dataPtr = mRfFieldInfoNtfOff;
              mRxDataSize = sizeof(mRfFieldInfoNtfOff);
              mIsNextRx = false;
            }
            break;
          case 0x03:
            // Send CORE_GET_CONFIG_RSP
            dataPtr = mCoreGetConfigRsp52;
            mRxDataSize = sizeof(mCoreGetConfigRsp52);
            mIsNextRx = false;
            break;
          case 0x09:
            // Send CORE_SET_POWER_SUB_STATE_RSP
            dataPtr = mCoreSetPowerSubStateRsp;
            mRxDataSize = sizeof(mCoreSetPowerSubStateRsp);
            mIsNextRx = false;
            break;
          case 0x04:
            if (mRxCnt == 0) {
              // Send CORE_CONN_CREATE_RSP
              dataPtr = mCoreConnCreateRsp;
              mRxDataSize = sizeof(mCoreConnCreateRsp);
              mRxCnt = 1;
            } else {
              dataPtr = mCoreCreditsNtfNdefNfcee;
              mRxDataSize = sizeof(mCoreCreditsNtfNdefNfcee);
              mIsNextRx = false;
            }
            break;
        }
        break;
      case 0x2f:
        switch (mTxData[1]) {
          case 0x02:
            switch (mTxData[3]) {
              case 0x02:
                if (mRxCnt == 0) {
                  dataPtr = mPropSetNfcModeRsp;
                  mRxDataSize = sizeof(mPropSetNfcModeRsp);
                  mRxCnt = 1;
                } else {
                  dataPtr = mCoreResetNtfModeSet;
                  mRxDataSize = sizeof(mCoreResetNtfModeSet);
                  mIsNextRx = false;
                }
                break;
              case 0x03:
                switch (mTxData[4]) {
                  case 0x0a:
                    // Send PIPE_List SIM
                    dataPtr = mPropRspGateSim;
                    mRxDataSize = sizeof(mPropRspGateSim);
                    mIsNextRx = false;
                    break;
                  case 0x0b:
                    // Send PIPE_List eSE
                    dataPtr = mPropRspGateEse;
                    mRxDataSize = sizeof(mPropRspGateEse);
                    mIsNextRx = false;
                    break;
                  default:
                    switch (mTxData[5]) {
                      case 0x11:
                        dataPtr = mPropRsp11;
                        mRxDataSize = sizeof(mPropRsp11);
                        break;
                      case 0x02:
                        dataPtr = mPropRsp02;
                        mRxDataSize = sizeof(mPropRsp02);
                        break;
                      case 0x01:
                        dataPtr = mPropRsp01;
                        mRxDataSize = sizeof(mPropRsp01);
                        break;
                      case 0x14:
                        dataPtr = mPropRsp14;
                        mRxDataSize = sizeof(mPropRsp14);
                        break;
                      case 0x08:
                        dataPtr = mPropRsp08;
                        mRxDataSize = sizeof(mPropRsp08);
                        break;
                    }
                    mIsNextRx = false;
                    break;
                }
                break;
              case 0x04:
                dataPtr = mPropRsp09;
                mRxDataSize = sizeof(mPropRsp09);
                mIsNextRx = false;
                break;
              default:
                STLOG_HAL_E("HalReplayAuto() - Unknown prop command");
                isEnd = true;
                break;
            }
            break;
        }
        break;
      case 0x21:
        switch (mTxData[1]) {
          case 0x00:
            // Send RF_DISCOVER_MAP_RSP
            dataPtr = mRfDiscoverMapRsp;
            mRxDataSize = sizeof(mRfDiscoverMapRsp);
            mIsNextRx = false;
            break;
          case 0x01:
            // Send RF_SET_ROUTING_TABLE_RSP
            dataPtr = mRfSetRoutingTableRsp;
            mRxDataSize = sizeof(mRfSetRoutingTableRsp);
            mIsNextRx = false;
            break;
          case 0x02:
            break;
          case 0x03:
            // Send RF_DISCOVER_RSP
            dataPtr = mRfDiscoverRsp;
            mRxDataSize = sizeof(mRfDiscoverRsp);
            mIsNextRx = false;
            isEnd = true;
            break;
          case 0x04:
            break;
          case 0x06:
            // Send RF_DEACTVATE_RSP
            dataPtr = mRfDeactivateIdleRsp;
            mRxDataSize = sizeof(mRfDeactivateIdleRsp);
            mIsNextRx = false;
            isEnd = true;
            break;
        }
        break;
      case 0x22:
        switch (mTxData[1]) {
          case 0x00:
            // Send NFCEE_DISCOVER_RSP
            if (mRxCnt == 0) {
              dataPtr = mNfceeDiscoverRsp;
              mRxDataSize = sizeof(mNfceeDiscoverRsp);
            } else if (mRxCnt == 1) {
              // Send NFCEE_DISCOVER_NTF
              dataPtr = mNfceeDiscoverNtf81;
              mRxDataSize = sizeof(mNfceeDiscoverNtf81);
            } else if (mRxCnt == 2) {
              // Send NFCEE_DISCOVER_NTF
              dataPtr = mNfceeDiscoverNtf86;
              mRxDataSize = sizeof(mNfceeDiscoverNtf86);
            } else {
              // Send NFCEE_DISCOVER_NTF
              dataPtr = mNfceeDiscoverNtf10;
              mRxDataSize = sizeof(mNfceeDiscoverNtf10);
              mIsNextRx = false;
            }
            mRxCnt++;
            break;
          case 0x01:
            if (mRxCnt == 0) {
              // Send NFCEE_MODE_SET_RSP
              dataPtr = mNfceeModeSetRsp;
              mRxDataSize = sizeof(mNfceeModeSetRsp);
            } else if (mRxCnt == 1) {
              // Send NFCEE_MODE_SET_NTF
              dataPtr = mNfceeModeSetNtf;
              mRxDataSize = sizeof(mNfceeModeSetNtf);
            } else if (mRxCnt == 2) {
              usleep(100);
              // Send HCI HOT_PLUG
              if (mTxData[3] == 0x81) {
                mActiveHciNfceeBitmap |= 0x01;
                dataPtr = mDataHciHotPlugNtfSim;
                mRxDataSize = sizeof(mDataHciHotPlugNtfSim);
              } else if (mTxData[3] == 0x86) {
                mActiveHciNfceeBitmap |= 0x02;
                dataPtr = mDataHciHotPlugNtfEse;
                mRxDataSize = sizeof(mDataHciHotPlugNtfEse);
              } else if (mTxData[3] == 0x10) {
                dataPtr = mRfNfceeDiscoveryReqNtfNdefNfcee;
                mRxDataSize = sizeof(mRfNfceeDiscoveryReqNtfNdefNfcee);
                mIsNextRx = false;
              }
            } else {
              // Send RF_NFCEE_DISCOVERY_REQ_NTF
              if (mTxData[3] == 0x81) {
                dataPtr = mRfNfceeDiscoveryReqNtfSim;
                mRxDataSize = sizeof(mRfNfceeDiscoveryReqNtfSim);
              } else if (mTxData[3] == 0x86) {
                dataPtr = mRfNfceeDiscoveryReqNtfEse;
                mRxDataSize = sizeof(mRfNfceeDiscoveryReqNtfEse);
              }
              mIsNextRx = false;
            }
            mRxCnt++;
            break;
          case 0x03:
            // Send NFCEE_POWER_AND_LINK_CTRL_RSP
            dataPtr = mNfceePwrAndLinkCtrlRsp;
            mRxDataSize = sizeof(mNfceePwrAndLinkCtrlRsp);
            mIsNextRx = false;
            break;
        }
        break;
    }
  } else {
    mRxCnt = 0;
    return FOUND_TX;
  }

  if (dataPtr != nullptr) {
    memcpy(mRxData, dataPtr, mRxDataSize);
  } else {
    STLOG_HAL_E("%s; No Rx data found for transmission, exiting", __func__);
    return END_OF_FILE;
  }

  if (isEnd && (mReplayInitStatus == REPLAY_INIT_AUTO)) {
    STLOG_HAL_D("%s; !!!! End of auto init, continuing with replay file !!!!",
                __func__);
    return END_OF_REPLAY;
  } else {
    return FOUND_RX;
  }
}

/*****************************************************************************/
/***** HalGetNextTxData *****/
/*****************************************************************************/
void HalGetNextTxData(char* line) {
  int i, byte_count = 0;
  // Skip one line => If just read Tx line, need to move to next one
  // No to get it twice
  fgets(line, MAX_LINE_LENGTH, mReplayFile);
  while (fgets(line, MAX_LINE_LENGTH, mReplayFile) != NULL) {
    if (strstr(line, " Tx ") != NULL) {
      char* token = strtok(line, " ");
      while (token != NULL) {
        if (strcmp(token, "Tx") == 0) {
          for (i = 0; i < 3; i++) {
            token = strtok(NULL, " ");
            sscanf(token, "%02X", (int*)&mExpTxData[byte_count++]);
          }
          mExpTxDataSize = mExpTxData[2] + 3;
          token = strtok(NULL, " ");
          while (byte_count < mExpTxDataSize) {
            if ((token != NULL) && (!isspace(*token))) {
              sscanf(token, "%02X", (int*)&mExpTxData[byte_count++]);
            }
            token = strtok(NULL, " ");
            if ((token == NULL) && (byte_count < mExpTxDataSize)) {
              fgets(line, MAX_LINE_LENGTH, mReplayFile);
              if (strstr(line, " tx ") != NULL) {
                token = strtok(line, " ");
                while (token != NULL) {
                  if (strcmp(token, "tx") == 0) {
                    token = strtok(NULL, " ");
                    break;
                  }
                  token = strtok(NULL, " ");
                }
              }
            }
          }
          break;
        }
        token = strtok(NULL, " ");
      }
    }
  }
  STLOG_HAL_V("%s; mExpTxData[] = 0x%x 0x%x", __func__, mExpTxData[0],
              mExpTxData[1]);
}

/*****************************************************************************/
/***** extract_frame *****/
/*****************************************************************************/
void extract_frame(char* line, bool isTx) {
  int hour = 0, minute = 0, second = 0, millisecond = 0, i;
  int byte_count = 0;
  char* token = strtok(line, " ");
  char* time_str = strtok(NULL, " ");
  sscanf(time_str, "%d:%d:%d.%3d", &hour, &minute, &second, &millisecond);

  if (isTx) {
    mTxTimeMs = (hour * 3600 + minute * 60 + second) * 1000 + millisecond;
  } else {
    mRxDataSize = 0;
    mRxTimeMs = (hour * 3600 + minute * 60 + second) * 1000 + millisecond;

    while (token != NULL) {
      if (strcmp(token, "Rx") == 0) {
        for (i = 0; i < 3; i++) {
          token = strtok(NULL, " ");
          sscanf(token, "%02X", (int*)&mRxData[byte_count++]);
        }
        mRxDataSize = mRxData[2] + 3;
        token = strtok(NULL, " ");
        while (byte_count < mRxDataSize) {
          if ((token != NULL) && (!isspace(*token))) {
            sscanf(token, "%02X", (int*)&mRxData[byte_count++]);
          }
          token = strtok(NULL, " ");
          if ((token == NULL) && (byte_count < mRxDataSize)) {
            fgets(line, MAX_LINE_LENGTH, mReplayFile);
            if (strstr(line, " rx ") != NULL) {
              token = strtok(line, " ");
              while (token != NULL) {
                if (strcmp(token, "rx") == 0) {
                  token = strtok(NULL, " ");
                  break;
                }
                token = strtok(NULL, " ");
              }
            } else if (strstr(line, " Tx ") != NULL) {
              mIsEmbeddedTx = true;
            }
          }
        }
        break;
      }
      token = strtok(NULL, " ");
    }
  }
}

/*****************************************************************************/
/***** HalGetNextFrameInfo *****/
/*****************************************************************************/
int HalGetNextFrameInfo() {
  char line[MAX_LINE_LENGTH];
  int rslt = END_OF_FILE;

  // If automatic init or unexpected data
  if ((mReplayInitStatus == REPLAY_INIT_AUTO) || mUnexpectedTxData) {
    rslt = HalReplayAuto();
    if (rslt == END_OF_REPLAY) {
      mReplayInitStatus = REPLAY_INIT_DONE;
      HalOpenReplayFile();
      rslt = FOUND_RX;
    }
    if (mUnexpectedTxData) {
      mUnexpectedTxData = false;
    }
    return rslt;
  }

  while (fgets(line, MAX_LINE_LENGTH, mReplayFile) != NULL) {
    if (strstr(line, " Rx ") != NULL) {
      // Process Rx data
      STLOG_HAL_V("%s; processing Rx: %s", __func__, line);

      mIsEmbeddedTx = false;
      fgetpos(mReplayFile, &mFilePos);

      extract_frame(line, false);

      if (mReplayInitStatus == REPLAY_INIT_OFF) {
        if ((mRxData[0] != 0x60) && (mRxData[1] != 0x00)) {
          STLOG_HAL_D("%s; !!!! Using auto init !!!!", __func__);
          mReplayInitStatus = REPLAY_INIT_AUTO;
          fclose(mReplayFile);
          mRxDataSize = sizeof(mCoreResetNtfInit);
          memcpy(mRxData, mCoreResetNtfInit, mRxDataSize);
          mRxTimeMs = 0;
          mIsNextRx = false;
        } else {
          mReplayInitStatus = REPLAY_INIT_FILE;
        }
      }

      STLOG_HAL_V("%s; mRxDataSize: 0x%x", __func__, mRxDataSize);
      STLOG_HAL_V("%s; mRxTimeMs: %llu", __func__, mRxTimeMs);

      // If Tx data embedded in Rx data frame, move line ptr
      if (mIsEmbeddedTx) {
        STLOG_HAL_V("%s; Found embedded Tx data, moving back cursor", __func__);
        fsetpos(mReplayFile, &mFilePos);
      }

      rslt = FOUND_RX;
      break;
    }

    // Process tx data
    if (strstr(line, " Tx ") != NULL) {
      STLOG_HAL_V("%s; expecting Tx: %s", __func__, line);
      extract_frame(line, true);
      STLOG_HAL_V("%s; mTxTimeMs: %llu", __func__, mTxTimeMs);
      rslt = FOUND_TX;
      break;
    }
  }
  // Check next Tx data
  if (mExpTxDataSize == 0) {
    fgetpos(mReplayFile, &mFilePos);
    HalGetNextTxData(line);
    fsetpos(mReplayFile, &mFilePos);
  }
  return rslt;
}

/*****************************************************************************/
/***** HalCheckTxData *****/
/*****************************************************************************/
void HalCheckTxData() {
  // if (mReplayInitStatus != REPLAY_INIT_AUTO) {
  mUnexpectedTxData = false;
  STLOG_HAL_V("%s; mExpTxData[] = 0x%x 0x%x, mTxData[] = 0x%x 0x%x", __func__,
              mExpTxData[0], mExpTxData[1], mTxData[0], mTxData[1]);
  // Check this data is the one we are expecting
  if (memcmp(mExpTxData, mTxData, mExpTxDataSize) != 0) {
    mTxTimeMs = 0;
    // Checking specific cases
    if ((mTxData[0] == 0x21) && (mTxData[1] == 0x01)) {
      STLOG_HAL_V(
          "%s; Tx data: RF_SET_LISTEN_MODE_ROUTING_CMD command but different "
          "content",
          __func__);
      return;
    } else if ((mTxData[0] == mExpTxData[0]) && (mTxData[1] == mExpTxData[1]) &&
               (mTxData[2] == mExpTxData[2])) {
      STLOG_HAL_V("%s; Tx data: Same NCI command but different payload",
                  __func__);
      return;
    } else if ((mTxData[0] == 0x21) && (mTxData[1] == 0x03)) {
      STLOG_HAL_V(
          "%s; Tx data: RF_DISCOVER_CMD command but different "
          "content",
          __func__);
      return;
    } else if ((mTxData[0] == 0x21) && (mTxData[1] == 0x04) &&
               (mExpTxData[0] == 0x21) && (mExpTxData[1] == 0x06)) {
      STLOG_HAL_E(
          "%s; !!!!! Tx data: Expected RF_DEACTIVATE_CMD but received "
          "RF_DISCOVER_SELECT_CMD,  POLL_BAIL_OUT_MODE should be set to 1 in "
          "libnfc-hal-st.conf file !!!!",
          __func__);
      mIsError = true;
    } else if ((mTxData[0] == 0x21) && (mTxData[1] == 0x06) &&
               (mExpTxData[0] == 0x21) && (mExpTxData[1] == 0x04)) {
      STLOG_HAL_E(
          "%s; !!!!! Tx data: Expected RF_DISCOVER_SELECT_CMD but received "
          "RF_DEACTIVATE_CMD, POLL_BAIL_OUT_MODE should be set to 0 in "
          "libnfc-hal-st.conf file !!!!",
          __func__);
      mIsError = true;
    }
    STLOG_HAL_V("%s; Received unexpected Tx data", __func__);
    mUnexpectedTxData = true;
    mIsNextRx = true;
    mRxCnt = 0;
  }
  // else {
  //   mExpTxDataSize = 0;
  // }
  // }
}

/**************************************************************************************************
 *
 *                                     State Machine
 *
 **************************************************************************************************/
static void* HalReplayThread(void* arg) {
  HalInstance* inst = (HalInstance*)arg;
  int waitingTime = 0;

  STLOG_HAL_D("%s; Enter", __func__);

  while (true) {
    if (mIsError) {
      return NULL;
    }

    int rslt = HalGetNextFrameInfo();
    switch (rslt) {
      case END_OF_FILE:
        STLOG_HAL_D("%s; !!!!!!  Reached EOF   !!!!!!", __func__);
        return NULL;
      case FOUND_RX:
        if (mTxTimeMs == 0) {
          waitingTime = 0;
        } else {
          waitingTime = mRxTimeMs - mTxTimeMs;
          // Check that waiting time is not too log, threshold 5s
          if (waitingTime < 0) {
            waitingTime = 50;
          } else if (waitingTime > 5000) {
            waitingTime = 5000;
          }
        }

        STLOG_HAL_V("%s; Waiting %d ms to post Rx Data", __func__, waitingTime);
        usleep(waitingTime * 1000);
        mTxTimeMs = mRxTimeMs;
        STLOG_HAL_V("%s; Posting Rx Data", __func__);
        HalSendUpstream(inst, mRxData, mRxDataSize);
        break;
      case FOUND_TX:
        STLOG_HAL_V("%s; Waiting Tx Data (txSem)", __func__);
        sem_wait(&mTxSem);
        STLOG_HAL_V("%s; unblocked txSem ", __func__);
        mExpTxDataSize = 0;
        // HalCheckTxData();
        break;
      default:
        break;
    }
  }

  STLOG_HAL_D("%s; Exit", __func__);
}

/**************************************************************************************************
 *
 *                                      Public API Entry-Points
 *
 **************************************************************************************************/

/**
 * Connection to the HAL Core layer.
 * Set-up HAL context and create HAL worker thread.
 * <p>@param context NFC NCI device context, NFC callbacks for control/data, HAL
 * handle
 * @param callback HAL callback function pointer
 * @param flags Configure if debug and trace allowed, trace level
 */
void HalReplayInit(HalInstance* inst) {
  STLOG_HAL_V("%s; enter", __func__);

  mReplayInitStatus = REPLAY_INIT_OFF;
  // Open file
  if (!HalOpenReplayFile()) {
    return;
  }

  if (0 != sem_init(&mTxSem, 0, 0)) {
    STLOG_HAL_E("%s; txSem init failed", __func__);
    free(inst);
    return;
  }

  mIsError = false;
  mTxTimeMs = mRxTimeMs = 0;
  mTxDataSize = mExpTxDataSize = 0;
  mRxDataSize = 0;
  mUnexpectedTxData = false;

  pthread_create(&replayThreadHandle, NULL, HalReplayThread, inst);

  STLOG_HAL_V("%s; exit", __func__);
}

/**
 * Disconnection of the HAL protocol layer.
 * Send message to stop the HAL worker thread and wait for it to finish. Free
 * resources.
 * @param hHAL HAL handle
 */
void HalReplayClose() {
  // Cleanup and exit
  sem_destroy(&mTxSem);

  fclose(mReplayFile);

  STLOG_HAL_D("HalDestroy done\n");
}

/**
 * Event handler for HAL message
 * @param inst HAL instance
 * @param e HAL event
 */
void HalReplayTxData(uint8_t* data, int length) {
  DispHal("TX DATA HAL", data, length);

  memcpy(mTxData, data, length);
  mTxDataSize = length;

  if (mReplayInitStatus == REPLAY_INIT_AUTO) {
    mIsNextRx = true;
    mRxCnt = 0;
  } else {
    HalCheckTxData();
  }

  STLOG_HAL_V("%s; unblocking txSem", __func__);
  sem_post(&mTxSem);
}

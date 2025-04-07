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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "android_logmsg.h"
#include "halcore_private.h"
#include "st21nfc_dev.h"

extern void DispHal(const char* title, const void* data, size_t length);

// File containing the log to replay
#define FILE_TO_REPLAY "/vendor/etc/hal_replay.txt"
#define FILE_TO_REPLAY_STARTUP "/vendor/etc/hal_replay_startup.txt"

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
HalInstance* mHalReplayInst = NULL;

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
    0x60, 0x00, 0x1f, 0x01, 0x01, 0x20, 0x02, 0x1a, 0x06, 0x03, 0x02, 0x01,
    0x07, 0x63, 0x03, 0x02, 0x01, 0x00, 0x44, 0x38, 0x88, 0x00, 0x00, 0xce,
    0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, 0x8c, 0x01};
uint8_t mCoreResetRsp[] = {0x40, 0x00, 0x01, 0x00};
uint8_t mCoreResetNtfReset[] = {
    0x60, 0x00, 0x1f, 0x02, 0x01, 0x20, 0x02, 0x1a, 0x06, 0x03, 0x02, 0x01,
    0x07, 0x63, 0x03, 0x02, 0x01, 0x00, 0x44, 0x38, 0x88, 0x00, 0x00, 0xce,
    0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, 0x8c, 0x01};
uint8_t mCoreInitRsp[] = {0x40, 0x01, 0x1a, 0x00, 0x2a, 0x7e, 0x06, 0x00,
                          0x01, 0x00, 0x04, 0xff, 0xff, 0x00, 0x0c, 0x01,
                          0x05, 0x01, 0x01, 0x02, 0x02, 0x01, 0x02, 0x03,
                          0x00, 0x00, 0x00, 0x90, 0x00};
uint8_t mCoreCreditsNtfHci[] = {0x60, 0x06, 0x03, 0x01, 0x01, 0x01};
uint8_t mPropRsp11[] = {
    0x4f, 0x02, 0x4c, 0x00, 0x01, 0x00, 0x48, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x05, 0x03, 0xe8, 0x06, 0x40, 0x11, 0x00, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x02, 0x02, 0x01, 0x01,
    0x01, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0xb0, 0x71, 0x10, 0x34,
    0x00, 0x32, 0x00, 0x00, 0x00, 0x54, 0x40, 0x40, 0x10, 0x00, 0x40, 0x00,
    0x6d, 0x1c, 0x75, 0x5f, 0x06, 0x00, 0x00, 0x00, 0x78, 0x00, 0x05, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t mPropRsp02[] = {
    0x4f, 0x02, 0x34, 0x00, 0x01, 0x00, 0x30, 0xa0, 0x82, 0x0d, 0x13,
    0x88, 0x01, 0xf4, 0x04, 0x00, 0x00, 0x00, 0xff, 0x08, 0x02, 0x03,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x04, 0x00, 0xc9, 0x07, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t mPropRsp01[] = {0x4f, 0x02, 0x18, 0x00, 0x01, 0x00, 0x14, 0x20, 0x15,
                        0x06, 0x06, 0x06, 0x0c, 0x88, 0x88, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
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
uint8_t mPropRsp08[] = {0x4f, 0x02, 0x1c, 0x00, 0x01, 0x00, 0x18, 0x3f,
                        0x00, 0x2d, 0x03, 0x00, 0x00, 0xc1, 0xc2, 0xe2,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

uint8_t mPropRsp09[] = {0x4f, 0x02, 0x03, 0x00, 0x00};

uint8_t mPropSetNfcModeRsp[] = {0x4f, 0x02, 0x01, 0x00};
uint8_t mCoreResetNtfModeSet[] = {
    0x60, 0x00, 0x1f, 0xa0, 0x01, 0x20, 0x02, 0x1a, 0x06, 0x03, 0x02, 0x01,
    0x07, 0x63, 0x03, 0x02, 0x01, 0x00, 0x44, 0x38, 0x88, 0x00, 0x00, 0xce,
    0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, 0x8c, 0x01};
uint8_t mCoreSetConfigRsp[] = {0x40, 0x02, 0x02, 0x00, 0x00};
uint8_t mRfDiscoverMapRsp[] = {0x41, 0x00, 0x01, 0x00};
uint8_t mNfceeDiscoverRsp[] = {0x42, 0x00, 0x02, 0x00, 0x02};
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
uint8_t mPropAndroidCapsRsp[] = {0x4f, 0x0c, 0x0e, 0x00, 0x00, 0x00,
                                 0x00, 0x03, 0x00, 0x01, 0x01, 0x01,
                                 0x01, 0x01, 0x03, 0x01, 0x00};

/**************************************************************************************************
 *
 *                                      Private API Definition
 *
 **************************************************************************************************/

/*****************************************************************************/
/***** HalOpenReplayFile *****/
/*****************************************************************************/
bool HalOpenReplayFile() {
  mReplayFile = fopen(FILE_TO_REPLAY, "rb");
  if (mReplayFile == NULL) {
    STLOG_HAL_E("HalOpenReplayFile() - Error opening file.");
    return false;
  }
  STLOG_HAL_V("HalOpenReplayFile() - done");
  return true;
}

/*****************************************************************************/
/***** HalOpenReplayFileStartup *****/
/*****************************************************************************/
bool HalOpenReplayFileStartup() {
  FILE* startupFile = fopen(FILE_TO_REPLAY_STARTUP, "rb");
  if (startupFile == NULL) {
    STLOG_HAL_E("HalOpenReplayFileStartup() - no startup file available.");
    return false;
  }
  STLOG_HAL_V("HalOpenReplayFileStartup() - success");
  fclose(mReplayFile);
  mReplayFile = startupFile;
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
          case 0x0c:
            dataPtr = mPropAndroidCapsRsp;
            mRxDataSize = sizeof(mPropAndroidCapsRsp);
            mIsNextRx = false;
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
              mRxCnt++;
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
              usleep(40);
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
  char* save_ptr = line;
  fgetpos(mReplayFile, &mFilePos);
  do {
    if (strstr(line, " Tx ") != NULL) {
      char* token = strtok_r(line, " ", &save_ptr);
      while (token != NULL) {
        if (strcmp(token, "Tx") == 0) {
          for (i = 0; i < 3; i++) {
            token = strtok_r(NULL, " ", &save_ptr);
            if (token != NULL)
              sscanf(token, "%02X", (int*)&mExpTxData[byte_count++]);
            else
              break;
          }
          mExpTxDataSize = mExpTxData[2] + 3;
          token = strtok_r(NULL, " ", &save_ptr);
          while (byte_count < mExpTxDataSize) {
            if ((token != NULL) && (!isspace(*token))) {
              sscanf(token, "%02X", (int*)&mExpTxData[byte_count++]);
            }
            token = strtok_r(NULL, " ", &save_ptr);
            if ((token == NULL) && (byte_count < mExpTxDataSize)) {
              fgets(line, MAX_LINE_LENGTH, mReplayFile);
              if (strstr(line, " tx ") != NULL) {
                token = strtok_r(line, " ", &save_ptr);
                while (token != NULL) {
                  if (strcmp(token, "tx") == 0) {
                    token = strtok_r(NULL, " ", &save_ptr);
                    break;
                  }
                  token = strtok_r(NULL, " ", &save_ptr);
                }
              }
            }
          }
          break;
        }
        token = strtok_r(NULL, " ", &save_ptr);
      }
      // We had found a Tx line, we can stop going through the lines
      break;
    }
  } while (fgets(line, MAX_LINE_LENGTH, mReplayFile) != NULL);

  // restore position in the file
  fsetpos(mReplayFile, &mFilePos);
  STLOG_HAL_V("%s; mExpTxData[] = 0x%x 0x%x", __func__, mExpTxData[0],
              mExpTxData[1]);
}

/*****************************************************************************/
/***** extract_frame *****/
/*****************************************************************************/
void extract_frame(char* line, bool isTx) {
  int hour = 0, minute = 0, second = 0, millisecond = 0, i;
  int byte_count = 0;
  char* save_ptr = line;
  char* token = strtok_r(line, " ", &save_ptr);
  char* time_str = strtok_r(NULL, " ", &save_ptr);
  if (time_str != NULL)
    sscanf(time_str, "%d:%d:%d.%3d", &hour, &minute, &second, &millisecond);

  if (isTx) {
    mTxTimeMs = (hour * 3600 + minute * 60 + second) * 1000 + millisecond;
  } else {
    mRxDataSize = 0;
    mRxTimeMs = (hour * 3600 + minute * 60 + second) * 1000 + millisecond;

    fgetpos(mReplayFile, &mFilePos);
    while (token != NULL) {
      if (strcmp(token, "Rx") == 0) {
        for (i = 0; i < 3; i++) {
          token = strtok_r(NULL, " ", &save_ptr);
          if (token != NULL)
            sscanf(token, "%02X", (int*)&mRxData[byte_count++]);
          else
            break;
        }
        mRxDataSize = mRxData[2] + 3;
        token = strtok_r(NULL, " ", &save_ptr);
        while (byte_count < mRxDataSize) {
          if ((token != NULL) && (!isspace(*token))) {
            sscanf(token, "%02X", (int*)&mRxData[byte_count++]);
          }
          token = strtok_r(NULL, " ", &save_ptr);
          if ((token == NULL) && (byte_count < mRxDataSize)) {
            fgets(line, MAX_LINE_LENGTH, mReplayFile);
            if (strstr(line, " rx ") != NULL) {
              token = strtok_r(line, " ", &save_ptr);
              while (token != NULL) {
                if (strcmp(token, "rx") == 0) {
                  token = strtok_r(NULL, " ", &save_ptr);
                  break;
                }
                token = strtok_r(NULL, " ", &save_ptr);
              }
            } else if (strstr(line, " Tx ") != NULL) {
              mIsEmbeddedTx = true;
            }
          }
        }
        break;
      }
      token = strtok_r(NULL, " ", &save_ptr);
    }
    // Restore the position at just after initial line read
    fsetpos(mReplayFile, &mFilePos);
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
      {
        // replace the content in the logcat otherwise the parser is lost
        char linefordump[MAX_LINE_LENGTH];
        strncpy(linefordump, line, sizeof(linefordump));
        for (int i = 0;
             (i < (int)sizeof(linefordump) - 1) && (linefordump[i] != '\0');
             i++) {
          if (linefordump[i] == 'R' && linefordump[i + 1] == 'x') {
            linefordump[i] = '<';
            linefordump[i + 1] = '-';
          }
          if ((linefordump[i] == '\r') || (linefordump[i] == '\n')) {
            linefordump[i] = ' ';
          }
        }
        STLOG_HAL_V("%s; processing incoming frame: %s", __func__, linefordump);
      }

      mIsEmbeddedTx = false;

      extract_frame(line, false);

      if (mReplayInitStatus == REPLAY_INIT_OFF) {
        if ((mRxData[0] != 0x60) && (mRxData[1] != 0x00)) {
          // We need a boot sequence first. Do we have an init boot file ?
          if (HalOpenReplayFileStartup()) {
            STLOG_HAL_D("%s; !!!! Using init file !!!!", __func__);
            mReplayInitStatus = REPLAY_INIT_FILE_STARTUP;
            continue;
          } else {
            STLOG_HAL_D("%s; !!!! Using auto init !!!!", __func__);
            mReplayInitStatus = REPLAY_INIT_AUTO;
            fclose(mReplayFile);
            mRxDataSize = sizeof(mCoreResetNtfInit);
            memcpy(mRxData, mCoreResetNtfInit, mRxDataSize);
            mRxTimeMs = 0;
            mIsNextRx = false;
          }
        } else {
          STLOG_HAL_D("%s; !!!! Using init from scenario !!!!", __func__);
          mReplayInitStatus = REPLAY_INIT_FILE;
        }
      }

      STLOG_HAL_V("%s; mRxDataSize: 0x%x", __func__, mRxDataSize);
      STLOG_HAL_V("%s; mRxTimeMs: %llu", __func__, mRxTimeMs);

      rslt = FOUND_RX;
      break;
    }

    // Process tx data
    if (strstr(line, " Tx ") != NULL) {
      {
        // replace the content in the logcat otherwise the parser is lost
        char linefordump[MAX_LINE_LENGTH];
        strncpy(linefordump, line, sizeof(linefordump));
        for (int i = 0;
             (i < (int)sizeof(linefordump) - 1) && (linefordump[i] != '\0');
             i++) {
          if (linefordump[i] == 'T' && linefordump[i + 1] == 'x') {
            linefordump[i] = '-';
            linefordump[i + 1] = '>';
          }
          if ((linefordump[i] == '\r') || (linefordump[i] == '\n')) {
            linefordump[i] = ' ';
          }
        }
        STLOG_HAL_V("%s; expecting Tx: %s", __func__, linefordump);
      }
      extract_frame(line, true);
      STLOG_HAL_V("%s; mTxTimeMs: %llu", __func__, mTxTimeMs);
      rslt = FOUND_TX;
      break;
    }
  }

  if (rslt == END_OF_FILE && mReplayInitStatus == REPLAY_INIT_FILE_STARTUP) {
    /* Ok, now we will move to regular sequence */
    fclose(mReplayFile);
    mReplayInitStatus = REPLAY_INIT_DONE;
    STLOG_HAL_V("%s; End of %s, now go to %s", __func__, FILE_TO_REPLAY_STARTUP,
                FILE_TO_REPLAY);
    HalOpenReplayFile();
    rslt = FOUND_RX;
    if (mUnexpectedTxData) {
      mUnexpectedTxData = false;
    }
  }

  // Check next Tx data
  if (mExpTxDataSize == 0) {
    HalGetNextTxData(line);
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

  if (mExpTxDataSize != mTxDataSize) {
    mUnexpectedTxData = true;
  } else {
    for (int i = 0; i < mExpTxDataSize; i++) {
      if (mExpTxData[i] != mTxData[i]) {
        mUnexpectedTxData = true;
        break;
      }
    }
  }

  // Check this data is the one we are expecting
  if (mUnexpectedTxData) {
    mTxTimeMs = 0;
    // Checking specific cases
    if ((mTxData[0] == 0x21) && (mTxData[1] == 0x01)) {
      STLOG_HAL_V(
          "%s; Tx data: RF_SET_LISTEN_MODE_ROUTING_CMD command but different "
          "content",
          __func__);
      // return;
    } else if ((mTxData[0] == mExpTxData[0]) && (mTxData[1] == mExpTxData[1]) &&
               (mTxData[2] == mExpTxData[2])) {
      STLOG_HAL_V("%s; Tx data: Same NCI command but different payload",
                  __func__);
      // return;
    } else if ((mTxData[0] == 0x21) && (mTxData[1] == 0x03)) {
      STLOG_HAL_V(
          "%s; Tx data: RF_DISCOVER_CMD command but different "
          "content",
          __func__);
    } else if ((mTxData[0] == 0x21) && (mTxData[1] == 0x04) &&
               (mExpTxData[0] == 0x21) && (mExpTxData[1] == 0x06)) {
      STLOG_HAL_E(
          "%s; !!!!! Tx data: Expected RF_DEACTIVATE_CMD but received "
          "RF_DISCOVER_SELECT_CMD,  POLL_BAIL_OUT_MODE seems supported in "
          "original stack !!!!",
          __func__);
      mIsError = true;
    } else if ((mTxData[0] == 0x21) && (mTxData[1] == 0x06) &&
               (mExpTxData[0] == 0x21) && (mExpTxData[1] == 0x04)) {
      STLOG_HAL_E(
          "%s; !!!!! Tx data: Expected RF_DISCOVER_SELECT_CMD but received "
          "RF_DEACTIVATE_CMD, POLL_BAIL_OUT_MODE behavior of stack is "
          "unexpected !!!!",
          __func__);
      mIsError = true;
    }
    STLOG_HAL_V("%s; Received unexpected Tx data", __func__);
    mIsNextRx = true;
    mRxCnt = 0;
  }
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

  mHalReplayInst = inst;

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
  // Log message Hal to Replay
  DispHal("TX DATA H2R", data, length);

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

/**
 * If the NFC service died, we should reset HAL replay state
 */
void HalReplayOnDeath() {
  STLOG_HAL_V("%s; enter", __func__);

  if (replayThreadHandle != (pthread_t)NULL) {
    void* ret;
    mIsError = true;
    STLOG_HAL_V("%s; waiting thread terminates", __func__);
    pthread_join(replayThreadHandle, &ret);
    STLOG_HAL_V("%s; done", __func__);
    replayThreadHandle = (pthread_t)NULL;

    HalReplayClose();
    HalReplayInit(mHalReplayInst);
  }
}
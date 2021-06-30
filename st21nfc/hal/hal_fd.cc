/******************************************************************************
 *
 *  Copyright (C) 2018 ST Microelectronics S.A.
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
 *
 ******************************************************************************/
#define LOG_TAG "NfcHalFd"
#include "hal_fd.h"
#include <cutils/properties.h>
#include <errno.h>
#include <hardware/nfc.h>
#include <string.h>
#include <unistd.h>
#include "android_logmsg.h"
#include "halcore.h"
/* Initialize fw info structure pointer used to access fw info structure */
FWInfo *mFWInfo = NULL;
FILE *mFwFileBin;
FILE *mCustomFileBin;
FILE *mCustomFileTxt;
fpos_t mPos;
fpos_t mPosInit;
uint8_t mBinData[260];
bool mRetry = true;
bool mCustomParamFailed = false;
bool mCustomParamDone = false;
uint8_t *pCmd;
int mFWRecovCount = 0;
char mApduAuthent[24];
static const uint8_t propNfcModeSetCmdOn[] = {0x2f, 0x02, 0x02, 0x02, 0x01};
static const uint8_t coreInitCmd[] = {0x20, 0x01, 0x02, 0x00, 0x00};
static const uint8_t NciPropNfcFwUpdate[] = {0x2F, 0x02, 0x05, 0x06,
                                             0x00, 0x01, 0x02, 0x03};
static const uint8_t ApduActivateLoader[] = {0x2F, 0x04, 0x07, 0x80, 0xA6,
                                             0x00, 0x00, 0x02, 0xA1, 0xA0};

// static const uint8_t ApduEraseFlashLoaderRecovery[] =
//  { 0x2F, 0x04, 0x06, 0x80, 0x0C, 0x00, 0x00, 0x01, 0x04 };
static const uint8_t ApduEraseFlashLoaderPart1[] = {
    0x2F, 0x04, 0x06, 0x80, 0x0C, 0x00, 0x00, 0x01, 0x01};
static const uint8_t ApduEraseFlashLoaderPart2[] = {
    0x2F, 0x04, 0x06, 0x80, 0x0C, 0x00, 0x00, 0x01, 0x02};
static const uint8_t ApduEraseNfcFull[] = {0x2F, 0x04, 0x06, 0x80, 0x0C,
                                           0x00, 0x00, 0x01, 0x03};
static uint8_t ApduEraseNfcKeepAppliAndNdef_54j[] = {
    0x2F, 0x04, 0x16, 0x80, 0x0C, 0x00, 0x00, 0x11, 0x05,
    0x00, 0x23, 0xDF, 0x00, 0x00, 0x23, 0xDF, 0xFF, 0x00,
    0x23, 0xE0, 0x00, 0x00, 0x23, 0xFF, 0xFF};
static uint8_t ApduEraseNfcKeepAppliAndNdef_nfcd[] = {
    0x2F, 0x04, 0x16, 0x80, 0x0C, 0x00, 0x00, 0x11, 0x05,
    0x00, 0x13, 0xDF, 0x00, 0x00, 0x13, 0xDF, 0xFF, 0x00,
    0x13, 0xE0, 0x00, 0x00, 0x13, 0xFF, 0xFF};

static const uint8_t ApduExitLoadMode[] = {0x2F, 0x04, 0x06, 0x80, 0xA0,
                                           0x00, 0x00, 0x01, 0x01};

hal_fd_state_e mHalFDState = HAL_FD_STATE_AUTHENTICATE;

int loader_patch_version = -1;
int loader_patch_cmd_nb;
char loader_patch_AuthKeyId;
const char **loader_patch;
const char *loader_patch_size_tab;
uint8_t *pCmdLd;
int ld_count = 0;
extern const int loader_RA7_patch_version;
extern const int loader_RA7_patch_cmd_nb;
extern const char loader_RA7_patch_AuthKeyId;
extern const char *loader_RA7_patch[];
extern const char loader_RA7_patch_size_tab[];
extern const int loader_RA9_patch_version;
extern const int loader_RA9_patch_cmd_nb;
extern const char loader_RA9_patch_AuthKeyId;
extern const char *loader_RA9_patch[];
extern const char loader_RA9_patch_size_tab[];

void SendExitLoadMode(HALHANDLE mmHalHandle);
extern void hal_wrapper_update_complete();

static int ascii2hex(char c) {
  int res = -1;

  if ((c >= '0') && (c <= '9')) {
    res = c - '0';
  } else if ((c >= 'A') && (c <= 'F')) {
    res = c - 'A' + 10;
  } else if ((c >= 'a') && (c <= 'f')) {
    res = c - 'a' + 10;
  }

  return res;
}

static const char *get_fw_default_name() {
  if ((mFWInfo->chipHwVersion == HW_ST54J) && (mFWInfo->chipAuthKeyId == 1)) {
    return "st54j_fw.bin";
  } else if ((mFWInfo->chipHwVersion == HW_NFCD) &&
             (mFWInfo->chipAuthKeyId == 1)) {
    return "st21nfc_fw.bin";
  } else if ((mFWInfo->chipHwVersion == HW_NFCD) &&
             (mFWInfo->chipAuthKeyId == 2)) {
    return "st21nfc_fw7.bin";
  } else {
    // default
    return "st21nfc_fw.bin";
  }
}

static const char *get_fw_default_cfg_name() {
  if (mFWInfo->chipHwVersion == HW_ST54J) {
    return "st54j_conf.txt";
  } else if (mFWInfo->chipHwVersion == HW_NFCD) {
    return "st21nfc_conf.txt";
  } else {
    // default
    return "st21nfc_conf.txt";
  }
}

/**
 * Open firmware and config file and parse their content
 * Returns a bitmask of what is available and fills the information
 * in mFWInfo->file*
 */
static void hal_fd_load_files() {
  char FwPath[256];
  char ConfPath[256];
  char fwBinName[256];
  char fwConfName[256];
  STLOG_HAL_D("  %s - enter", __func__);

  if (!GetStrValue(NAME_STNFC_FW_PATH_STORAGE, (char *)FwPath,
                   sizeof(FwPath))) {
    STLOG_HAL_D(
        "%s - FW path not found in conf. use default location "
        "/vendor/firmware/ "
        "\n",
        __func__);
    strlcpy(FwPath, "/vendor/firmware/", sizeof(FwPath));
  }

  if (!GetStrValue(NAME_STNFC_FW_BIN_NAME, (char *)fwBinName,
                   sizeof(fwBinName))) {
    // st21nfc_fw.bin or st21nfc_fw7.bin or st54j_fw.bin
    const char *defaultfwfile = get_fw_default_name();
    STLOG_HAL_D(
        "%s - FW binary file name not found in conf. use default name "
        "%s \n",
        __func__, defaultfwfile);
    strlcpy(fwBinName, defaultfwfile, sizeof(fwBinName));
  }

  if (!GetStrValue(NAME_STNFC_FW_CONF_NAME, (char *)fwConfName,
                   sizeof(fwConfName))) {
    const char *defaultcfgfile = get_fw_default_cfg_name();
    STLOG_HAL_D(
        "%s - FW config file name not found in conf. use default name "
        "/vendor/etc/%s\n",
        __func__, defaultcfgfile);
    strlcpy(fwConfName, "/vendor/etc/", sizeof(fwConfName));
    strlcat(fwConfName, defaultcfgfile, sizeof(fwConfName));
  }

  // Getting information about FW patch, if any
  strlcpy(ConfPath, FwPath, sizeof(ConfPath));
  strlcat(FwPath, fwBinName, sizeof(FwPath));
  if (fwConfName[0] == '/') {
    // absolute path
    strlcpy(ConfPath, fwConfName, sizeof(ConfPath));
  } else {
    // relative to STNFC_FW_PATH_STORAGE
    strlcat(ConfPath, fwConfName, sizeof(ConfPath));
  }
  STLOG_HAL_D("%s - FW update file = %s", __func__, FwPath);
  STLOG_HAL_D("%s - FW config file = %s", __func__, ConfPath);

  // Check if FW patch binary file is present
  if ((mFwFileBin = fopen((char *)FwPath, "r")) == NULL) {
    STLOG_HAL_D("%s - %s not detected", __func__, fwBinName);
  } else {
    STLOG_HAL_D("%s - %s file detected\n", __func__, fwBinName);

    fread(mBinData, sizeof(uint8_t), 4, mFwFileBin);
    mFWInfo->fileFwVersion =
        mBinData[0] << 24 | mBinData[1] << 16 | mBinData[2] << 8 | mBinData[3];

    fread(mApduAuthent, sizeof(uint8_t), 24, mFwFileBin);
    // We use the last byte of the auth command to discriminate at the moment.
    // it can be extended in case of conflict later.
    switch (mApduAuthent[23]) {
      case 0x43:
        mFWInfo->fileHwVersion = HW_NFCD;
        mFWInfo->fileHwType = "generic";
        mFWInfo->fileAuthKeyId = 0x01;
        break;

      case 0xC7:
        mFWInfo->fileHwVersion = HW_NFCD;
        mFWInfo->fileHwType = "RA7";
        mFWInfo->fileAuthKeyId = 0x02;
        break;

      case 0xE9:
        mFWInfo->fileHwVersion = HW_ST54J;
        mFWInfo->fileHwType = "generic";
        mFWInfo->fileAuthKeyId = 0x01;
        break;
    }

    if (mFWInfo->fileHwVersion == 0) {
      STLOG_HAL_E("%s --> %s integrates unknown patch NFC FW -- rejected\n",
                  __func__, FwPath);
      fclose(mFwFileBin);
      mFwFileBin = NULL;
    } else {
      fgetpos(mFwFileBin, &mPosInit);

      STLOG_HAL_D(
          "%s --> %s integrates patch NFC FW version 0x%08X (r:%d,t:%s)\n",
          __func__, FwPath, mFWInfo->fileFwVersion, mFWInfo->fileHwVersion,
          mFWInfo->fileHwType);
    }
  }

  if ((mCustomFileBin = fopen((char *)ConfPath, "r")) != NULL) {
    char conf_line[600];
    uint16_t fwconf_crc = 0;
    if (fwConfName[strlen(fwConfName) - 1] == 't') {
      mCustomFileTxt = mCustomFileBin;
      mCustomFileBin = NULL;
      STLOG_HAL_D("text configuration detected\n");
      fgets(conf_line, sizeof conf_line, mCustomFileTxt);
      if ((conf_line[0] == 'R') && (conf_line[11] == 'C') &&
          (conf_line[12] == 'R')) {
        fwconf_crc = ascii2hex(conf_line[21]) |
                     ((ascii2hex(conf_line[20]) << 4) & 0xF0) |
                     ((ascii2hex(conf_line[19]) << 8) & 0xF00) |
                     ((ascii2hex(conf_line[18]) << 12) & 0xF000);
        mFWInfo->fileCustVersion = fwconf_crc;
        STLOG_HAL_D("-> txt configuration CRC 0x%04X \n",
                    mFWInfo->fileCustVersion);
      } else {
        STLOG_HAL_E("text configuration invalid content\n");
        fclose(mCustomFileTxt);
        mCustomFileTxt = NULL;
      }
    } else if (fwConfName[strlen(fwConfName) - 1] == 'n') {
      fread(mBinData, sizeof(uint8_t), 2, mCustomFileBin);
      mFWInfo->fileCustVersion = mBinData[0] << 8 | mBinData[1];
      STLOG_HAL_D("-> bin configuration CRC 0x%04X \n",
                  mFWInfo->fileCustVersion);
    } else {
      STLOG_HAL_E("configuration file name not recognized\n");
      fclose(mCustomFileBin);
      mCustomFileBin = NULL;
    }
  } else {
    STLOG_HAL_D("custom configuration not detected\n");
  }
}

/**
 */
int hal_fd_init() {
  STLOG_HAL_D("  %s - enter", __func__);

  // Initializing structure holding FW patch details
  mFWInfo = (FWInfo *)malloc(sizeof(FWInfo));
  if (mFWInfo == NULL) {
    STLOG_HAL_E("%s: malloc failed", __func__);
    return -1;
  }

  memset(mFWInfo, 0, sizeof(FWInfo));
  mFWInfo->fileHwType = "unknown";
  mFwFileBin = NULL;
  mCustomFileBin = NULL;
  mCustomFileTxt = NULL;

  return 0;
}

void hal_fd_close() {
  STLOG_HAL_D("  %s -enter", __func__);
  mCustomParamFailed = false;
  if (mFWInfo != NULL) {
    free(mFWInfo);
    mFWInfo = NULL;
  }
  if (mFwFileBin != NULL) {
    fclose(mFwFileBin);
    mFwFileBin = NULL;
  }
  if (mCustomFileBin != NULL) {
    fclose(mCustomFileBin);
    mCustomFileBin = NULL;
  }
  if (mCustomFileTxt != NULL) {
    fclose(mCustomFileTxt);
    mCustomFileTxt = NULL;
  }
}

/**
 * Parse CORE_RESET_NTF and decide what's to be done
 * @return FU_* instruction
 */

uint8_t ft_cmd_HwReset(uint8_t *pdata, uint8_t *clf_mode, bool force) {
  STLOG_HAL_D("  %s - execution", __func__);

  // parse the CORE_RESET_NTF firstly.
  if ((pdata[1] == 0x0) && (pdata[3] == 0x1)) {
    STLOG_HAL_D("-> Router Mode NCI_CORE_RESET_NTF received after HW Reset");

    /* retrieve HW Version from NCI_CORE_RESET_NTF */
    mFWInfo->chipHwVersion = pdata[8];
    STLOG_HAL_D("   HwVersion = 0x%02X", mFWInfo->chipHwVersion);
    mFWInfo->chipHwRevision = pdata[9];
    STLOG_HAL_D("   HwRevision = 0x%02X", mFWInfo->chipHwRevision);

    /* retrieve Authentication Key ID from NCI_CORE_RESET_NTF */
    mFWInfo->chipAuthKeyId =
        (pdata[25] << 24) | (pdata[26] << 16) | (pdata[27] << 8) | pdata[28];
    STLOG_HAL_D("   pAuthKeyId = 0x%08X", mFWInfo->chipAuthKeyId);

    /* retrieve FW Version from NCI_CORE_RESET_NTF */
    mFWInfo->chipFwVersion =
        (pdata[10] << 24) | (pdata[11] << 16) | (pdata[12] << 8) | pdata[13];
    STLOG_HAL_D("   FwVersion = 0x%08X", mFWInfo->chipFwVersion);

    /* retrieve Loader Version from NCI_CORE_RESET_NTF */
    mFWInfo->chipLoaderVersion =
        (pdata[14] << 16) | (pdata[15] << 8) | pdata[16];
    STLOG_HAL_D("   LoaderVersion = 0x%06X", mFWInfo->chipLoaderVersion);

    /* retrieve Customer Version from NCI_CORE_RESET_NTF */
    mFWInfo->chipCustVersion = (pdata[31] << 8) | pdata[32];
    STLOG_HAL_D("   CustomerVersion = 0x%04X", mFWInfo->chipCustVersion);

    *clf_mode = FT_CLF_MODE_ROUTER;
  } else if ((pdata[2] == 0x39) && (pdata[3] == 0xA1)) {
    STLOG_HAL_D("-> Loader Mode NCI_CORE_RESET_NTF received after HW Reset");

    /* deduce HW Version from Factory Loader version 16.17.18 */
    // RA6 : 020000
    // RA7 : 020200
    // RA8 : 020100
    // RA9 : 020300
    // 54J : 010?00
    if (pdata[16] == 0x01) {
      mFWInfo->chipHwVersion = HW_ST54J;
      mFWInfo->chipHwRevision = 0xFF;  // unknown:FF, Rev A: 00; B: 02; C: 03
      if (pdata[17] == 0x00 || pdata[17] == 0x01) {
        mFWInfo->chipHwRevision = 0x00;  // WA0, WA1
      } else if (pdata[17] == 0x03 || pdata[17] == 0x04 || pdata[17] == 0x05) {
        mFWInfo->chipHwRevision = 0x02;  // WA2, WA3, WA4, WA5
      } else if (pdata[17] == 0x06) {
        mFWInfo->chipHwRevision = 0x03;  // WA6
      }
    } else if (pdata[16] == 0x02) {
      mFWInfo->chipHwVersion = HW_NFCD;
      mFWInfo->chipHwRevision = 0xFF;  // unknown:FF, Rev C: 03; D: 04
      if (pdata[17] == 0x00) {
        mFWInfo->chipHwRevision = 0x03;  // RA6
      } else if (pdata[17] == 0x02 || pdata[17] == 0x03) {
        mFWInfo->chipHwRevision = 0x04;  // RA7, RA9  (skip RA8)
      }
    }

    STLOG_HAL_D("   HwVersion = 0x%02X", mFWInfo->chipHwVersion);
    STLOG_HAL_D("   HwRevision = 0x%02X", mFWInfo->chipHwRevision);
    mFWInfo->chipFwVersion = 0;  // make sure FW will be updated.

    /* retrieve Authentication Key ID from NCI_CORE_RESET_NTF */
    mFWInfo->chipAuthKeyId =
        (pdata[54] << 24) | (pdata[53] << 16) | (pdata[52] << 8) | pdata[51];
    STLOG_HAL_D("   pAuthKeyId = 0x%08X", mFWInfo->chipAuthKeyId);

    /* Identify the Active loader. Normally only one should be detected*/
    if (pdata[11] == 0xA0) {
      mFWInfo->chipLoaderVersion =
          (pdata[8] << 16) | (pdata[9] << 8) | pdata[10];
      STLOG_HAL_D("         - Most recent loader activated, revision 0x%06X",
                  mFWInfo->chipLoaderVersion);
    }
    if (pdata[15] == 0xA0) {
      mFWInfo->chipLoaderVersion =
          (pdata[12] << 16) | (pdata[13] << 8) | pdata[14];
      STLOG_HAL_D("         - Least recent loader activated, revision 0x%06X",
                  mFWInfo->chipLoaderVersion);
    }
    if (pdata[19] == 0xA0) {
      mFWInfo->chipLoaderVersion =
          (pdata[16] << 16) | (pdata[17] << 8) | pdata[18];
      STLOG_HAL_D("         - Factory loader activated, revision 0x%06X",
                  mFWInfo->chipLoaderVersion);
    }

    *clf_mode = FT_CLF_MODE_LOADER;
  } else {
    STLOG_HAL_E(
        "%s --> ERROR: wrong NCI_CORE_RESET_NTF received after HW Reset",
        __func__);
    *clf_mode = FT_CLF_MODE_ERROR;
    return FU_ERROR;
  }

  // do we have a loader for this chip ?
  if (mFWInfo->chipHwVersion == HW_NFCD) {
    if (mFWInfo->chipAuthKeyId == 0x01 && mFWInfo->chipHwRevision == 0x04) {
      // RA9 is supported
      loader_patch_version = loader_RA9_patch_version;
      loader_patch_cmd_nb = loader_RA9_patch_cmd_nb;
      loader_patch_AuthKeyId = loader_RA9_patch_AuthKeyId;
      loader_patch = loader_RA9_patch;
      loader_patch_size_tab = loader_RA9_patch_size_tab;
    } else if (mFWInfo->chipAuthKeyId == 0x02 &&
               mFWInfo->chipHwRevision == 0x04) {
      // RA7 is supported
      loader_patch_version = loader_RA7_patch_version;
      loader_patch_cmd_nb = loader_RA7_patch_cmd_nb;
      loader_patch_AuthKeyId = loader_RA7_patch_AuthKeyId;
      loader_patch = loader_RA7_patch;
      loader_patch_size_tab = loader_RA7_patch_size_tab;
    }
  }  // no loader update for ST54J at the moment.

  // If the firmware file is not already open, try to read it/
  if ((mFwFileBin == NULL) && (mCustomFileTxt == NULL) &&
      (mCustomFileBin == NULL)) {
    hal_fd_load_files();
  }

  if (loader_patch_version != -1) {
    // can we update the loader ?
    if (((loader_patch_version & 0xFFFF00) ==
         (mFWInfo->chipLoaderVersion & 0xFFFF00)) &&
        ((uint32_t)loader_patch_version > mFWInfo->chipLoaderVersion)) {
      STLOG_HAL_D("Loader update available, do this first.\n");
      return FU_UPDATE_LOADER;
    }
  }

  if ((mFWInfo->chipHwVersion != HW_NFCD) &&
      (mFWInfo->chipHwVersion != HW_ST54J)) {
    // This version is not supported yet.
    STLOG_HAL_D("No update for this hardware version.\n");
    return (*clf_mode == FT_CLF_MODE_ROUTER) ? FU_NOTHING_TO_DO : FU_ERROR;
  }

  // If we are in loader mode and no FW available, error
  if ((*clf_mode == FT_CLF_MODE_LOADER) &&
      ((mFwFileBin == NULL) ||
       (mFWInfo->chipHwVersion != mFWInfo->fileHwVersion) ||
       (mFWInfo->chipAuthKeyId != mFWInfo->fileAuthKeyId))) {
    STLOG_HAL_D("Loader mode and no applicable FW patch available.\n");
    return FU_ERROR;
  }

  // Should we update the firmware ?
  if ((mFwFileBin != NULL) &&
      (mFWInfo->chipHwVersion == mFWInfo->fileHwVersion) &&
      (mFWInfo->chipAuthKeyId == mFWInfo->fileAuthKeyId) &&
      (force || (mFWInfo->fileFwVersion != mFWInfo->chipFwVersion))) {
    STLOG_HAL_D("FW patch needs to be applied.\n");
    return FU_UPDATE_FW;
  }

  // Should we update the config ?
  if ((mFWInfo->fileCustVersion != 0) &&
      (mFWInfo->chipCustVersion != mFWInfo->fileCustVersion) &&
      (mFWInfo->chipCustVersion != 0xEFAC /* DTA */)) {
    STLOG_HAL_D("%s - Need to apply new custom configuration settings\n",
                __func__);
    return (mCustomParamFailed) ? FU_ERROR : FU_UPDATE_PARAMS;
  }

  STLOG_HAL_D("%s - Nothing to do\n", __func__);
  return FU_NOTHING_TO_DO;
} /* ft_cmd_HwReset */

void ExitHibernateHandler(HALHANDLE mHalHandle, uint16_t data_len,
                          uint8_t *p_data) {
  STLOG_HAL_D("%s - Enter", __func__);
  if (data_len < 3) {
    STLOG_HAL_E("%s - Error, too short data (%d)", __func__, data_len);
    return;
  }
  switch (p_data[0]) {
    case 0x40:  //
      STLOG_HAL_D("%s - hibernate_exited = %d ", __func__,
                  mFWInfo->hibernate_exited);

      // CORE_INIT_RSP
      if ((p_data[1] == 0x1) && (p_data[3] == 0x0) &&
          (mFWInfo->hibernate_exited == 0)) {
        // Send PROP_NFC_MODE_SET_CMD(ON)
        if (!HalSendDownstream(mHalHandle, propNfcModeSetCmdOn,
                               sizeof(propNfcModeSetCmdOn))) {
          STLOG_HAL_E("%s - SendDownstream failed", __func__);
        }
      } else if ((p_data[1] == 0x1) && (p_data[3] == 0x0) &&
                 (mFWInfo->hibernate_exited == 1)) {
        STLOG_HAL_D(
            "%s - send NCI_PROP_NFC_FW_UPDATE_CMD and use 100 ms timer for "
            "each cmd from here",
            __func__);

        if (!HalSendDownstreamTimer(mHalHandle, NciPropNfcFwUpdate,
                                    sizeof(NciPropNfcFwUpdate),
                                    FW_TIMER_DURATION)) {
          STLOG_HAL_E("%s  SendDownstream failed", __func__);
        }
      } else if (p_data[3] != 0x00) {
        STLOG_HAL_D("%s - Wrong response. Retry HW reset", __func__);
        I2cResetPulse();
        hal_wrapper_set_state(HAL_WRAPPER_STATE_OPEN);
      }
      break;

    case 0x4f:  //
      if ((p_data[1] == 0x02) && (p_data[3] == 0x00) &&
          (mFWInfo->hibernate_exited == 1)) {
        STLOG_HAL_D("%s - NCI_PROP_NFC_FW_RSP : loader mode", __func__);
        I2cResetPulse();
        hal_wrapper_set_state(HAL_WRAPPER_STATE_OPEN);
      } else if (p_data[3] != 0x00) {
        STLOG_HAL_D("%s - Wrong response. Retry HW reset", __func__);
        I2cResetPulse();
        hal_wrapper_set_state(HAL_WRAPPER_STATE_OPEN);
      }
      break;
    case 0x60:  //
      if (p_data[3] == 0x2) {
        STLOG_HAL_D("%s - CORE_RESET_NTF : after core_reset_cmd", __func__);

        if (!HalSendDownstream(mHalHandle, coreInitCmd, sizeof(coreInitCmd))) {
          STLOG_HAL_E("%s - SendDownstream failed", __func__);
        }
      } else if (p_data[3] == 0xa0) {
        mFWInfo->hibernate_exited = 1;
        STLOG_HAL_D("%s - hibernate_exited = %d ", __func__,
                    mFWInfo->hibernate_exited);

        if (!HalSendDownstream(mHalHandle, coreInitCmd, sizeof(coreInitCmd))) {
          STLOG_HAL_E("%s - SendDownstream failed", __func__);
        }
      }
      break;
  }
}

void resetHandlerState() {
  STLOG_HAL_D("%s", __func__);
  mHalFDState = HAL_FD_STATE_AUTHENTICATE;
}

void LdUpdateHandler(HALHANDLE mHalHandle, uint16_t data_len, uint8_t *p_data) {
  STLOG_HAL_D("%s : Enter state = %d", __func__, mHalFDState);
  HalSendDownstreamStopTimer(mHalHandle);

  switch (mHalFDState) {
    case HAL_FD_STATE_AUTHENTICATE:  // we receive response to GET ATR
      STLOG_HAL_D("%s - mHalFDState = HAL_FD_STATE_AUTHENTICATE", __func__);
      if ((p_data[data_len - 2] == 0x90) && (p_data[data_len - 1] == 0x00)) {
        STLOG_HAL_D("%s - send APDU_AUTHENTICATION_CMD", __func__);
        if (!HalSendDownstreamTimer(mHalHandle, (uint8_t *)mApduAuthent,
                                    sizeof(mApduAuthent), FW_TIMER_DURATION)) {
          STLOG_HAL_E("%s - SendDownstream failed", __func__);
        }
        mHalFDState = HAL_LD_STATE_ERASE_FLASH1;
      } else {
        STLOG_HAL_D("%s : LD flash not succeeded", __func__);
        SendExitLoadMode(mHalHandle);
      }
      break;
    case HAL_LD_STATE_ERASE_FLASH1:  // 1
      STLOG_HAL_D("%s - mHalFDState = HAL_LD_STATE_ERASE_FLASH1", __func__);

      if ((p_data[0] == 0x4f) && (p_data[1] == 0x04)) {
        if ((p_data[data_len - 2] == 0x90) && (p_data[data_len - 1] == 0x00)) {
          STLOG_HAL_D("  %s : send APDU_ERASE_FLASH_LOADER (area 1)", __func__);
          if (!HalSendDownstreamTimer(mHalHandle, ApduEraseFlashLoaderPart1,
                                      sizeof(ApduEraseFlashLoaderPart1),
                                      FW_TIMER_DURATION)) {
            STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
          }
          mHalFDState = HAL_LD_STATE_ERASE_FLASH2;
        } else {
          STLOG_HAL_D("%s : FW flash not succeeded", __func__);
          SendExitLoadMode(mHalHandle);
        }
      }
      break;
    case HAL_LD_STATE_ERASE_FLASH2:  // 2
      STLOG_HAL_D("%s - mHalFDState = HAL_LD_STATE_ERASE_FLASH2", __func__);

      if ((p_data[0] == 0x4f) && (p_data[1] == 0x04)) {
        if ((p_data[data_len - 2] == 0x90) && (p_data[data_len - 1] == 0x00)) {
          STLOG_HAL_D("  %s : send APDU_ERASE_FLASH_LOADER (area 2)", __func__);
          if (!HalSendDownstreamTimer(mHalHandle, ApduEraseFlashLoaderPart2,
                                      sizeof(ApduEraseFlashLoaderPart2),
                                      FW_TIMER_DURATION)) {
            STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
          }
          mHalFDState = HAL_FD_STATE_SEND_RAW_APDU;
          pCmdLd = (uint8_t *)loader_patch;
        } else {
          STLOG_HAL_D("%s : FW flash not succeeded", __func__);
          SendExitLoadMode(mHalHandle);
        }
      }
      break;

    case HAL_FD_STATE_SEND_RAW_APDU:  // 2
      if ((p_data[0] == 0x4f) && (p_data[1] == 0x04)) {
        if ((p_data[data_len - 2] == 0x90) && (p_data[data_len - 1] == 0x00)) {
          ALOGD("%s : ld ld_count = %d", __func__, ld_count);
          if (ld_count < loader_patch_cmd_nb) {
            if (!HalSendDownstreamTimer(mHalHandle, pCmdLd,
                                        loader_patch_size_tab[ld_count],
                                        FW_TIMER_DURATION)) {
              ALOGE("NFC-NCI HAL: %s  SendDownstream failed!", __func__);
            }
            pCmdLd += loader_patch_size_tab[ld_count];
            ld_count++;
          } else if (ld_count == loader_patch_cmd_nb) {
            STLOG_HAL_D("  %s : send APDU_ACTIVATE_LOADER", __func__);
            if (!HalSendDownstreamTimer(mHalHandle, ApduActivateLoader,
                                        sizeof(ApduActivateLoader),
                                        FW_TIMER_DURATION)) {
              STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
            }
            ld_count++;
          } else {
            ALOGD("%s : EOF of loader", __func__);
            ld_count = 0;
            SendExitLoadMode(mHalHandle);
          }
        } else {
          STLOG_HAL_D("%s : LD flash not succeeded", __func__);
          SendExitLoadMode(mHalHandle);
        }
      }
      break;

    case HAL_FD_STATE_EXIT_APDU:  // 2
      if ((p_data[data_len - 2] == 0x90) && (p_data[data_len - 1] == 0x00)) {
        I2cResetPulse();
        hal_wrapper_set_state(HAL_WRAPPER_STATE_OPEN);
        mHalFDState = HAL_FD_STATE_AUTHENTICATE;
      } else {
        I2cResetPulse();
        hal_wrapper_set_state(HAL_WRAPPER_STATE_OPEN);
        mHalFDState = HAL_FD_STATE_AUTHENTICATE;
      }
      break;

    default:
      STLOG_HAL_D("%s : FW flash not succeeded", __func__);
      SendExitLoadMode(mHalHandle);
      break;
  }
}

void UpdateHandler(HALHANDLE mHalHandle, uint16_t data_len, uint8_t *p_data) {
  STLOG_HAL_D("%s : Enter state = %d", __func__, mHalFDState);
  HalSendDownstreamStopTimer(mHalHandle);

  switch (mHalFDState) {
    case HAL_FD_STATE_AUTHENTICATE:
      STLOG_HAL_D("%s - mHalFDState = HAL_FD_STATE_AUTHENTICATE", __func__);

      if ((p_data[data_len - 2] == 0x90) && (p_data[data_len - 1] == 0x00)) {
        STLOG_HAL_D("%s - send APDU_AUTHENTICATION_CMD", __func__);
        if (!HalSendDownstreamTimer(mHalHandle, (uint8_t *)mApduAuthent,
                                    sizeof(mApduAuthent), FW_TIMER_DURATION)) {
          STLOG_HAL_E("%s - SendDownstream failed", __func__);
        }
        mHalFDState = HAL_FD_STATE_ERASE_FLASH;
      } else {
        STLOG_HAL_D("%s - FW flash not succeeded", __func__);
        SendExitLoadMode(mHalHandle);
      }
      break;

    case HAL_FD_STATE_ERASE_FLASH:  // 1
      STLOG_HAL_D("%s - mHalFDState = HAL_FD_STATE_ERASE_FLASH", __func__);

      if ((p_data[0] == 0x4f) && (p_data[1] == 0x04)) {
        if ((p_data[data_len - 2] == 0x90) && (p_data[data_len - 1] == 0x00)) {
          if (mFWInfo->chipHwVersion == HW_NFCD) {
            if (mFWInfo->chipHwRevision == 0x04) {
              // RA7, RA9
              STLOG_HAL_D(
                  " %s - send APDU_ERASE_FLASH_CMD (keep appli and NDEF areas)",
                  __func__);
              if (!HalSendDownstreamTimer(
                      mHalHandle, ApduEraseNfcKeepAppliAndNdef_nfcd,
                      sizeof(ApduEraseNfcKeepAppliAndNdef_nfcd),
                      FW_TIMER_DURATION)) {
                STLOG_HAL_E("%s - SendDownstream failed", __func__);
              }
            } else if (mFWInfo->chipHwRevision == 0x03) {
              // RA6, loader does not support partial erase
              STLOG_HAL_D(
                  " %s - send APDU_ERASE_FLASH_CMD (erase all NFC memory)",
                  __func__);
              if (!HalSendDownstreamTimer(mHalHandle, ApduEraseNfcFull,
                                          sizeof(ApduEraseNfcFull),
                                          FW_TIMER_DURATION)) {
                STLOG_HAL_E("%s - SendDownstream failed", __func__);
              }
            }
          } else if (mFWInfo->chipHwVersion == HW_ST54J) {
            STLOG_HAL_D(
                " %s - send APDU_ERASE_FLASH_CMD (keep appli and NDEF areas)",
                __func__);
            if (!HalSendDownstreamTimer(
                    mHalHandle, ApduEraseNfcKeepAppliAndNdef_54j,
                    sizeof(ApduEraseNfcKeepAppliAndNdef_54j),
                    FW_TIMER_DURATION)) {
              STLOG_HAL_E("%s - SendDownstream failed", __func__);
            }
          }

          fsetpos(mFwFileBin, &mPosInit);  // reset pos in stream

          mHalFDState = HAL_FD_STATE_SEND_RAW_APDU;

        } else {
          STLOG_HAL_D("%s - FW flash not succeeded", __func__);
          SendExitLoadMode(mHalHandle);
        }
      }
      break;

    case HAL_FD_STATE_SEND_RAW_APDU:  // 3
      STLOG_HAL_D("%s - mHalFDState = HAL_FD_STATE_SEND_RAW_APDU", __func__);
      if ((p_data[0] == 0x4f) && (p_data[1] == 0x04)) {
        if ((p_data[data_len - 2] == 0x90) && (p_data[data_len - 1] == 0x00)) {
          mRetry = true;

          fgetpos(mFwFileBin, &mPos);  // save current position in stream
          if ((fread(mBinData, sizeof(uint8_t), 3, mFwFileBin) == 3) &&
              (fread(mBinData + 3, sizeof(uint8_t), mBinData[2], mFwFileBin) ==
               mBinData[2])) {
            if (!HalSendDownstreamTimer(mHalHandle, mBinData, mBinData[2] + 3,
                                        FW_TIMER_DURATION)) {
              STLOG_HAL_E("%s - SendDownstream failed", __func__);
            }
          } else {
            STLOG_HAL_D("%s - EOF of FW binary", __func__);
            SendExitLoadMode(mHalHandle);
          }
        } else if (mRetry == true) {
          STLOG_HAL_D("%s - Last Tx was NOK. Retry", __func__);
          mRetry = false;
          fsetpos(mFwFileBin, &mPos);
          if ((fread(mBinData, sizeof(uint8_t), 3, mFwFileBin) == 3) &&
              (fread(mBinData + 3, sizeof(uint8_t), mBinData[2], mFwFileBin) ==
               mBinData[2])) {
            if (!HalSendDownstreamTimer(mHalHandle, mBinData, mBinData[2] + 3,
                                        FW_TIMER_DURATION)) {
              STLOG_HAL_E("%s - SendDownstream failed", __func__);
            }
            fgetpos(mFwFileBin, &mPos);  // save current position in stream
          } else {
            STLOG_HAL_D("%s - EOF of FW binary", __func__);
            SendExitLoadMode(mHalHandle);
          }
        } else {
          STLOG_HAL_D("%s - FW flash not succeeded.", __func__);
          I2cResetPulse();
          SendExitLoadMode(mHalHandle);
        }
      }
      break;

    case HAL_FD_STATE_EXIT_APDU:  // 2
      STLOG_HAL_D("%s - mHalFDState = HAL_FD_STATE_EXIT_APDU", __func__);
      if ((p_data[data_len - 2] != 0x90) || (p_data[data_len - 1] != 0x00)) {
        STLOG_HAL_D(
            "%s - Error exiting loader mode, i.e. a problem occured during FW "
            "update",
            __func__);
      }

      I2cResetPulse();
      hal_wrapper_set_state(HAL_WRAPPER_STATE_OPEN);
      mHalFDState = HAL_FD_STATE_AUTHENTICATE;
      break;

    default:
      STLOG_HAL_D("%s - mHalFDState = unknown", __func__);
      STLOG_HAL_D("%s - FW flash not succeeded", __func__);
      SendExitLoadMode(mHalHandle);
      break;
  }
}

/**
 * ASCII to Hexadecimal conversion (whole line)
 * @param input, a \0-terminated string with ASCII bytes representation (e.g. 01
 * 23 45). Spaces are allowed, but must be aligned on bytes boundaries.
 * @param pCmd, converted bytes are stored here.
 * @param maxLen, storage size of pCmd
 * @param pcmdlen, how many bytes have been written upon return.
 * @return 0 on success, -1 on failure */
static int convstr2hex(char *input, uint8_t *pCmd, int maxLen,
                       uint16_t *pcmdlen) {
  char *in = input;
  int c;
  *pcmdlen = 0;

  while ((in[0] != '\0') && (in[1] != '\0') &&
         (*pcmdlen < maxLen))  // we need at least 2 characters left
  {
    // Skip white spaces
    if (in[0] == ' ' || in[0] == '\t' || in[0] == '\r' || in[0] == '\n') {
      in++;
      continue;
    }

    // Is MSB char a valid HEX value ?
    c = ascii2hex(*in);
    if (c < 0) {
      STLOG_HAL_E("    Error: invalid character (%x,'%c')\n", *in, *in);
      return -1;
    }
    // Store it
    pCmd[*pcmdlen] = c << 4;
    in++;

    // Is LSB char a valid HEX value ?
    c = ascii2hex(*in);
    if (c < 0) {
      STLOG_HAL_E("    Error: invalid character (%x,'%c')\n", *in, *in);
      return -1;
    }
    // Store it
    pCmd[*pcmdlen] |= c;
    in++;
    (*pcmdlen)++;
  }

  if (*pcmdlen == maxLen) {
    STLOG_HAL_D("    Warning: input conversion may be truncated\n");
  }

  return 0;
}

int ft_FwConfConvertor(char *string_cmd, uint8_t pCmd[256], uint16_t *pcmdlen) {
  uint16_t converted;
  int res = convstr2hex(string_cmd, pCmd + 3, 256 - 3, &converted);
  if (res < 0) {
    *pcmdlen = 0;
    return 0;
  }
  // We should be able to propagate an error here, TODO: if (res < 0) ....
  pCmd[0] = 0x2F;
  pCmd[1] = 0x02;
  pCmd[2] = converted;
  *pcmdlen = converted + 3;
  return 1;
}
// parse st21nfc_conf.txt until next command to send.
// return 1 if a command was found, 0 if EOF
int getNextCommandInTxt(uint8_t *cmd, uint16_t *sz) {
  int ret = 0;
  // f_cust_txt is already opened and 1st line read
  char conf_line[600];

  while (fgets(conf_line, sizeof conf_line, mCustomFileTxt) != NULL) {
    if (!strncmp(conf_line, "NCI_SEND_PROP", sizeof("NCI_SEND_PROP") - 1)) {
      STLOG_HAL_V("%s : parse %s", __func__, conf_line);
      ret = ft_FwConfConvertor((char *)conf_line + 20, cmd, sz);
      break;
    } else if (!strncmp(conf_line, "NCI_DIRECT_CTRL",
                        sizeof("NCI_DIRECT_CTRL") - 1)) {
      STLOG_HAL_V("%s : parse %s", __func__, conf_line);
      ret = ft_FwConfConvertor((char *)conf_line + 22, cmd, sz);
      break;
    } else {
      // any other, we ignore
      STLOG_HAL_V("%s : ignore %s", __func__, conf_line);
    }
  }

  return ret;
}
void ApplyCustomParamHandler(HALHANDLE mHalHandle, uint16_t data_len,
                             uint8_t *p_data) {
  STLOG_HAL_D("%s - Enter ", __func__);
  if (data_len < 3) {
    STLOG_HAL_E("%s : Error, too short data (%d)", __func__, data_len);
    return;
  }

  if (mCustomFileTxt != NULL) {
    uint8_t txtCmd[MAX_BUFFER_SIZE];
    uint16_t txtCmdLen = 0;

    switch (p_data[0]) {
      case 0x40:  //
        // CORE_RESET_RSP
        if ((p_data[1] == 0x0) && (p_data[3] == 0x0)) {
          // do nothing
        } else if ((p_data[1] == 0x1) && (p_data[3] == 0x0)) {
          if (mFWInfo->hibernate_exited == 0) {
            // Send a NFC mode on .
            if (!HalSendDownstream(mHalHandle, propNfcModeSetCmdOn,
                                   sizeof(propNfcModeSetCmdOn))) {
              STLOG_HAL_E("%s - SendDownstream failed", __func__);
            }
            // CORE_INIT_RSP
          } else if (mFWInfo->hibernate_exited == 1) {
            if (getNextCommandInTxt(txtCmd, &txtCmdLen)) {
              if (!HalSendDownstream(mHalHandle, txtCmd, txtCmdLen)) {
                STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
              }
            }
          }

        } else {
          STLOG_HAL_D("%s - Error in custom param application", __func__);
          mCustomParamFailed = true;
          I2cResetPulse();
          hal_wrapper_set_state(HAL_WRAPPER_STATE_OPEN);
        }
        break;

      case 0x4f:
        if (mFWInfo->hibernate_exited == 1) {
          // Check if an error has occured for PROP_SET_CONFIG_CMD
          if (p_data[3] != 0x00) {
            STLOG_HAL_D("%s - Error in custom file, retry", __func__);
            // should we need to limit number of retry ? to be decided if this
            // error is found
            usleep(5000);
            if (!HalSendDownstream(mHalHandle, txtCmd, txtCmdLen)) {
              STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
            }
          } else if (getNextCommandInTxt(txtCmd, &txtCmdLen)) {
            if (!HalSendDownstream(mHalHandle, txtCmd, txtCmdLen)) {
              STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
            }
          } else {
            STLOG_HAL_D("%s - EOF of custom file", __func__);
            mCustomParamDone = true;
            I2cResetPulse();
          }
        }
        break;

      case 0x60:  //
        if (p_data[1] == 0x0) {
          if (p_data[3] == 0xa0) {
            mFWInfo->hibernate_exited = 1;
          }
          if (!HalSendDownstream(mHalHandle, coreInitCmd,
                                 sizeof(coreInitCmd))) {
            STLOG_HAL_E("%s - SendDownstream failed", __func__);
          }

        } else if ((p_data[1] == 0x6) && mCustomParamDone) {
          mCustomParamDone = false;
          hal_wrapper_update_complete();
        }
        break;
    }

  } else if (mCustomFileBin != NULL) {
    switch (p_data[0]) {
      case 0x40:  //
        // CORE_RESET_RSP
        if ((p_data[1] == 0x0) && (p_data[3] == 0x0)) {
          // do nothing
        } else if ((p_data[1] == 0x1) && (p_data[3] == 0x0)) {
          if (mFWInfo->hibernate_exited == 0) {
            // Send a NFC mode on .
            if (!HalSendDownstream(mHalHandle, propNfcModeSetCmdOn,
                                   sizeof(propNfcModeSetCmdOn))) {
              STLOG_HAL_E("%s - SendDownstream failed", __func__);
            }
            // CORE_INIT_RSP
          } else if (mFWInfo->hibernate_exited == 1) {
            if ((fread(mBinData, sizeof(uint8_t), 3, mCustomFileBin)) &&
                (fread(mBinData + 3, sizeof(uint8_t), mBinData[2],
                       mCustomFileBin))) {
              if (!HalSendDownstream(mHalHandle, mBinData, mBinData[2] + 3)) {
                STLOG_HAL_E("%s - SendDownstream failed", __func__);
              }
            }
          }

        } else {
          STLOG_HAL_D("%s - Error in custom param application", __func__);
          mCustomParamFailed = true;
          I2cResetPulse();
          hal_wrapper_set_state(HAL_WRAPPER_STATE_OPEN);
        }
        break;

      case 0x4f:
        if (mFWInfo->hibernate_exited == 1) {
          if ((fread(mBinData, sizeof(uint8_t), 3, mCustomFileBin) == 3) &&
              (fread(mBinData + 3, sizeof(uint8_t), mBinData[2],
                     mCustomFileBin) == mBinData[2])) {
            if (!HalSendDownstream(mHalHandle, mBinData, mBinData[2] + 3)) {
              STLOG_HAL_E("%s - SendDownstream failed", __func__);
            }
          } else {
            STLOG_HAL_D("%s - EOF of custom file", __func__);
            mCustomParamDone = true;
            I2cResetPulse();
          }

          // Check if an error has occured for PROP_SET_CONFIG_CMD
          // Only log a warning, do not exit code
          if (p_data[3] != 0x00) {
            STLOG_HAL_D("%s - Error in custom file, continue anyway", __func__);
          }
        }
        break;

      case 0x60:  //
        if (p_data[1] == 0x0) {
          if (p_data[3] == 0xa0) {
            mFWInfo->hibernate_exited = 1;
          }
          if (!HalSendDownstream(mHalHandle, coreInitCmd,
                                 sizeof(coreInitCmd))) {
            STLOG_HAL_E("%s - SendDownstream failed", __func__);
          }

        } else if ((p_data[1] == 0x6) && mCustomParamDone) {
          mCustomParamDone = false;
          hal_wrapper_update_complete();
        }
        break;
    }
  }
}

void SendExitLoadMode(HALHANDLE mmHalHandle) {
  STLOG_HAL_D("%s - Send APDU_EXIT_LOAD_MODE_CMD", __func__);

  if (!HalSendDownstreamTimer(mmHalHandle, ApduExitLoadMode,
                              sizeof(ApduExitLoadMode), FW_TIMER_DURATION)) {
    STLOG_HAL_E("%s - SendDownstream failed", __func__);
  }
  mHalFDState = HAL_FD_STATE_EXIT_APDU;
}

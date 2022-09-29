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
#define LOG_TAG "NfcHalAuth"
#include <dlfcn.h>
#include <string.h>
#include "hal_auth.h"
#include "android_logmsg.h"
#include "halcore.h"

static bool lib_resolved = false;
static bool lib_resolved_failed = false;
static void* mHandle = NULL;
static int (*p_AuthLogVersionImpl)() = NULL;
static bool (*p_AuthCheckCoreResetNtfImpl)(uint8_t*, bool) = NULL;
static void (*p_AuthHandlerImpl)(HALHANDLE, uint16_t, uint8_t*,
                                 hal_wrapper_state_e*) = NULL;
static void (*p_AuthCheckConfigCommandImpl)(uint8_t*, uint16_t) = NULL;

bool AuthCheckCoreResetNtf(uint8_t* pdata, bool params_update_needed) {
  int lib_abi = -1;
  if (lib_resolved_failed) {
    // No need to retry, we already failed.
    return false;
  }

  if (!lib_resolved) {
    mHandle = dlopen("libstnfc-auth.so", RTLD_NOW);
    // Check if the library is found
    if (mHandle) {
      // resolve all the functions
      STLOG_HAL_D("%s: Loaded library", __func__);
      p_AuthLogVersionImpl = (int (*)())dlsym(mHandle, "AuthLogVersionImpl");
      if (!p_AuthLogVersionImpl) {
        STLOG_HAL_E("%s: Failed to resolve function: %s", __func__, dlerror());
        lib_resolved_failed = true;
        return false;
      }
      p_AuthCheckCoreResetNtfImpl =
          (bool (*)(uint8_t*, bool))dlsym(mHandle, "AuthCheckCoreResetNtfImpl");
      if (!p_AuthCheckCoreResetNtfImpl) {
        STLOG_HAL_E("%s: Failed to resolve function: %s", __func__, dlerror());
        lib_resolved_failed = true;
        return false;
      }
      p_AuthHandlerImpl =
          (void (*)(HALHANDLE, uint16_t, uint8_t*, hal_wrapper_state_e*))dlsym(
              mHandle, "AuthHandlerImpl");
      if (!p_AuthHandlerImpl) {
        STLOG_HAL_E("%s: Failed to resolve function: %s", __func__, dlerror());
        lib_resolved_failed = true;
        return false;
      }
      p_AuthCheckConfigCommandImpl = (void (*)(uint8_t*, uint16_t))dlsym(
          mHandle, "AuthCheckConfigCommandImpl");
      if (!p_AuthCheckConfigCommandImpl) {
        STLOG_HAL_E("%s: Failed to resolve function: %s", __func__, dlerror());
        lib_resolved_failed = true;
        return false;
      }
      // Check ABI version
      lib_abi = (*p_AuthLogVersionImpl)();
      if (lib_abi != 1) {
        STLOG_HAL_E("%s: Unsupported library version", __func__);
        lib_resolved_failed = true;
        return false;
      }
      lib_resolved = true;
    } else {
      STLOG_HAL_D("%s: libstnfc-auth.so not loaded: %s", __func__, dlerror());
    }
  }

  if (!lib_resolved) {
    // No library
    lib_resolved_failed = true;
    return false;
  }

  // call AuthCheckCoreResetNtfImpl
  return (*p_AuthCheckCoreResetNtfImpl)(pdata, params_update_needed);
}

void AuthHandler(HALHANDLE mHalHandle, uint16_t data_len, uint8_t* p_data,
                 hal_wrapper_state_e* next_state) {
  // We cannot be called if we returned false in AuthCheckCoreResetNtf
  if (!lib_resolved) {
    STLOG_HAL_E("%s: while lib_resolved was false", __func__);
    abort();
  }

  // call AuthHandlerImpl
  (*p_AuthHandlerImpl)(mHalHandle, data_len, p_data, next_state);
}

void AuthCheckConfigCommand(uint8_t* p_data, uint16_t data_len) {
  if (!lib_resolved) {
    // Nothing to do
    return;
  }

  // call AuthCheckConfigCommandImpl
  (*p_AuthCheckConfigCommandImpl)(p_data, data_len);
}

void AuthCheckUnload() {
  if (lib_resolved) {
    STLOG_HAL_D("%s: Unloading libstnfc-auth.so", __func__);
    p_AuthLogVersionImpl = NULL;
    p_AuthCheckCoreResetNtfImpl = NULL;
    p_AuthHandlerImpl = NULL;
    p_AuthCheckConfigCommandImpl = NULL;
    (void)dlclose(mHandle);
    mHandle = NULL;
    lib_resolved = false;
  }
}
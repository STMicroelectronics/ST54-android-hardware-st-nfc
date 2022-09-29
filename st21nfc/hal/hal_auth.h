/** ----------------------------------------------------------------------
 *
 * Copyright (C) 2018 ST Microelectronics S.A.
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

#ifndef HAL_AUTH_H_
#define HAL_AUTH_H_

#include "halcore.h"

// These functions behave as if no update is needed if no libstnfcauth.so is
// found

// return true if AUTH process is maybe needed.
bool AuthCheckCoreResetNtf(uint8_t* pdata, bool params_update_needed);

// Called in state HAL_WRAPPER_STATE_AUTH
void AuthHandler(HALHANDLE mHalHandle, uint16_t data_len, uint8_t* p_data,
                 hal_wrapper_state_e* next_state);

// Call while apply a configuration script to the CLF
void AuthCheckConfigCommand(uint8_t* p_data, uint16_t data_len);

// Call at the end of HAL opening if you want to unload the lib
void AuthCheckUnload();

#endif  // HAL_AUTH_H_

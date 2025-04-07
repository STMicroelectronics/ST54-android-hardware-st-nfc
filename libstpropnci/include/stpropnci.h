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

#ifndef STPROPNCI_H
#define STPROPNCI_H

#include <stdint.h>

// b15..12: flavour; b11..0: version
// flavours: 0: base ST stack.
#define STPROPNCI_LIB_VERSION 0x0001

/***************/
/* Library API */
/***************/

/*
 * outgoing_cb_t callback:
 *
 * Caller must provide a function for this library to send a message.
 * This function may be called from the same thread that called
 * stpropnci_process or another thread. Up to the caller to implement a message
 * queue to change threads if needed.
 *
 * dir_to_nfcc: if true, the payload is a CMD or DATA and shall be sent to the
 * NFCC. If false, it is RSP, NTF, or DATA and to be passed to the stack.
 * payload: a buffer in the library memory space. The memory will be freed after
 * this callback returns. payloadlen: the length of data inside payload buffer.
 *
 * returns: none.
 */
typedef void (*outgoing_cb_t)(bool dir_to_nfcc, uint8_t* payload,
                              uint16_t payloadlen);

#define MSG_DIR_TO_STACK false
#define MSG_DIR_TO_NFCC true

/*
 * stpropnci_init:
 *
 * Initialize the library and registers the outgoing_cb of the caller.
 *
 * loglvl: 0: no logs at all. 1: information and errors. 2: debug
 * cb: method that will send outgoing messages.
 *
 * returns: true if the initialization is successful, false otherwise.
 */
bool stpropnci_init(int loglvl, outgoing_cb_t cb);

/*
 * stpropnci_deinit:
 *
 * Caller can call this when NFC is disabled, so resources may be freed.
 *
 */
void stpropnci_deinit();

/*
 * stpropnci_process:
 *
 * Process an NCI message.
 * This function is not reentrant; it will be blocking until a previous call has
 * returned.
 *
 * dir_from_upper: if true, the payload is a CMD or DATA and coming from the
 * stack. if false, it is RSP, NTF, or DATA and coming from NFCC. payload: a
 * buffer in the caller memory space. The memory can be freed after this
 * function returns. payloadlen: the length of data inside payload buffer.
 *
 * returns: true if the message has been processed and caller can discard it,
 * false if caller should forward it directly.
 */
bool stpropnci_process(bool dir_from_upper, const uint8_t* payload,
                       const uint16_t payloadlen);

#define MSG_DIR_FROM_STACK true
#define MSG_DIR_FROM_NFCC false

/*
 * stpropnci_inform:
 *
 * Just let the library know about a message but no handling expected.
 * This is used by the HAL in its own wrapper processing.
 *
 * This function is not reentrant; it will be blocking until a previous call has
 * returned.
 *
 * dir_from_upper: if true, the payload is a CMD or DATA and coming from the
 * stack. if false, it is RSP, NTF, or DATA and coming from NFCC. payload: a
 * buffer in the caller memory space. The memory can be freed after this
 * function returns. payloadlen: the length of data inside payload buffer.
 *
 * returns: n/a
 */
void stpropnci_inform(bool dir_from_upper, const uint8_t* payload,
                      const uint16_t payloadlen);

#endif  // STPROPNCI_H

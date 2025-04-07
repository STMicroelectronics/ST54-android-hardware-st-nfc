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
#include <stdlib.h>
#include <stpropnci-internal.h>

/*******************************************************************************
**
** Function         stpropnci_modcb_init
**
** Description      Initialize the callback module
**
** Returns          true if init is ok, false in case of error
**
*******************************************************************************/
bool stpropnci_modcb_init() {
  (void)pthread_mutex_init(&stpropnci_state.modcbstate.modcb_mtx, nullptr);
  return true;
}

/*******************************************************************************
**
** Function         stpropnci_modcb_fini
**
** Description      Deinitialize the callback module, free all resources
**
** Returns          none
**
*******************************************************************************/
void stpropnci_modcb_fini() {
  void* tret = nullptr;
  int ret = 0;
  msg_t* m;

  // Empty the list
  (void)pthread_mutex_lock(&stpropnci_state.modcbstate.modcb_mtx);
  while (modcblist_t* m = stpropnci_state.modcbstate.modcblist.next) {
    // unlist
    stpropnci_state.modcbstate.modcblist.next = m->next;
    // free
    free(m);
  }
  while (modcblist_t* m = stpropnci_state.modcbstate.modcbpool.next) {
    // unlist
    stpropnci_state.modcbstate.modcbpool.next = m->next;
    // free
    free(m);
  }
  (void)pthread_mutex_unlock(&stpropnci_state.modcbstate.modcb_mtx);

  (void)pthread_mutex_destroy(&stpropnci_state.modcbstate.modcb_mtx);

  // We are done.
}

/*******************************************************************************
**
** Function         modcblist_get
**
** Description      provide a new modcblist_t item, either from pool or allocate
**                  it
**
** Returns          the new modcblist_t or nullptr in case of error
**
*******************************************************************************/
static modcblist_t* modcblist_get() {
  modcblist_t* m = nullptr;

  /* get first from pool if any */
  (void)pthread_mutex_lock(&stpropnci_state.modcbstate.modcb_mtx);
  m = stpropnci_state.modcbstate.modcbpool.next;
  if (m != nullptr) {
    /* unlink in pool */
    stpropnci_state.modcbstate.modcbpool.next = m->next;
  }
  (void)pthread_mutex_unlock(&stpropnci_state.modcbstate.modcb_mtx);

  /* If the pool was empty, allocate an item */
  if (m == nullptr) {
    m = (modcblist_t*)malloc(sizeof(modcblist_t));
  }
  /* If we got an item, clean it */
  if (m != nullptr) {
    memset(m, 0, sizeof(modcblist_t));
  } else {
    LOG_E("Failed to allocate memory for registering a callback");
  }
  return m;
}

/*******************************************************************************
**
** Function         modcblist_put
**
** Description      return a modcblist_t item to the pool.
**
** Returns          none
**
*******************************************************************************/
static void modcblist_put(modcblist_t* m) {
  (void)pthread_mutex_lock(&stpropnci_state.modcbstate.modcb_mtx);
  m->next = stpropnci_state.modcbstate.modcbpool.next;
  stpropnci_state.modcbstate.modcbpool.next = m;
  (void)pthread_mutex_unlock(&stpropnci_state.modcbstate.modcb_mtx);
}

/*******************************************************************************
**
** Function         stpropnci_modcb_register
**
** Description      Register a callback function to be called on incoming
**                  messages based on matching mt/gid/oid/suboid.
**
** Returns          true if the registration succeeded.
**
*******************************************************************************/
bool stpropnci_modcb_register(module_cb_t cb, bool match_mt, uint8_t mt,
                              bool match_gid, uint8_t gid, bool match_oid,
                              uint8_t oid, bool match_suboid, uint8_t suboid) {
  modcblist_t* li = modcblist_get();

  if (li == nullptr) {
    // registration failed
    return false;
  }

  li->cb = cb;
  li->must_match_mt = match_mt;
  li->mt = mt;
  li->must_match_gid = match_gid;
  li->gid = gid;
  li->must_match_oid = match_oid;
  li->oid = oid;
  li->must_match_suboid = match_suboid;
  li->suboid = suboid;

  /* add in the list. The list is not ordered, add in head for faster */
  (void)pthread_mutex_lock(&stpropnci_state.modcbstate.modcb_mtx);
  li->next = stpropnci_state.modcbstate.modcblist.next;
  stpropnci_state.modcbstate.modcblist.next = li;
  (void)pthread_mutex_unlock(&stpropnci_state.modcbstate.modcb_mtx);

  // done
  return true;
}

/*******************************************************************************
**
** Function         stpropnci_modcb_unregister
**
** Description      Unregister a callback previously registered.
**
** Returns          none.
**
*******************************************************************************/
void stpropnci_modcb_unregister(module_cb_t cb) {
  modcblist_t* li = &stpropnci_state.modcbstate.modcblist;
  modcblist_t* unlinked = nullptr;

  /* search and unlink if found */
  (void)pthread_mutex_lock(&stpropnci_state.modcbstate.modcb_mtx);
  while (li->next != nullptr) {
    // li->next may be the item we would unlink
    if (li->next->cb == cb) {
      unlinked = li->next;
      li->next = unlinked->next;
      unlinked->next = nullptr;
      break;
    }
    li = li->next;
  }
  (void)pthread_mutex_unlock(&stpropnci_state.modcbstate.modcb_mtx);

  /* if we unlinked an item, return it to the pool */
  if (unlinked != nullptr) {
    modcblist_put(unlinked);
  }

  // done
}

#define MAX_CBS 10

/*******************************************************************************
**
** Function         stpropnci_modcb_process
**
** Description      Called upon incoming messages, calls matching registered
**                  callbacks.
**
** Returns          true if a callback handled the message and processing should
**                  stop.
**
*******************************************************************************/
bool stpropnci_modcb_process(bool dir_from_upper, const uint8_t* payload,
                             const uint16_t payloadlen, uint8_t mt, uint8_t gid,
                             uint8_t oid) {
  modcblist_t* li = &stpropnci_state.modcbstate.modcblist;
  modcblist_t* prev = nullptr;
  module_cb_t cbs[MAX_CBS];
  int nbcb = 0, i;

  bool handled = false;
  uint8_t suboid = 0;

  if (gid == NCI_GID_PROP) {
    switch (oid) {
      case ST_NCI_MSG_PROP:
      case ST_NCI_MSG_PROP_TEST:
        // ref ST54L datasheet
        switch (mt) {
          case NCI_MT_CMD:
            // cmd code is 1st byte of payload
            suboid = payload[3];
            break;
          case NCI_MT_NTF:
            // status followed by subcode
            suboid = payload[4];
            break;
          case NCI_MT_RSP:
          default:
            // no suboid
            suboid = 0x00;
        }
        break;
      case ST_NCI_MSG_PROP_LOADER:
      case ST_NCI_MSG_PROP_PWR_MON_RW_ON_NTF:
      case ST_NCI_MSG_PROP_PWR_MON_RW_OFF_NTF:
        // loader and monitoring has special format, there is no suboid
        suboid = 0x00;
        break;

      case NCI_MSG_PROP_ANDROID:
        suboid = payload[3];
        break;
    }
  }

  (void)pthread_mutex_lock(&stpropnci_state.modcbstate.modcb_mtx);
  while ((li->next != nullptr) && (handled == false)) {
    prev = li;
    li = li->next;

    /* Do we need to call this cb ? */
    if (li->must_match_mt && (li->mt != mt)) {
      continue;
    }
    if (li->must_match_gid && (li->gid != gid)) {
      continue;
    }
    if (li->must_match_oid && (li->oid != oid)) {
      continue;
    }
    if (li->must_match_suboid && (li->suboid != suboid)) {
      continue;
    }

    /* We'll need to call it; save the address and continue */
    cbs[nbcb++] = li->cb;
    if (nbcb == MAX_CBS) {
      LOG_E("Too many callbacks may match, discarding some");
      nbcb--;
    }
  }
  (void)pthread_mutex_unlock(&stpropnci_state.modcbstate.modcb_mtx);

  /* Now call each matching cb until one processes the message */
  for (i = 0; i < nbcb; i++) {
    handled = (*cbs[i])(dir_from_upper, payload, payloadlen, mt, gid, oid);
    if (handled) {
      break;
    }
  }

  return handled;
}

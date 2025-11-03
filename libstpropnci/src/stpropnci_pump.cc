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
#include <unistd.h>
#include <stpropnci-internal.h>

// How many seconds after sending do we consider a message was lost ?
#define DELAY_FOR_ACK_MS 700

// when we need to emulate a critical error so NFC service will restart
uint8_t abnormal_core_reset_ntf[] = {0x60, 0x00, 0x05, 0x00,
                                     0x01, 0x20, 0x02, 0x00};
uint16_t abnormal_core_reset_ntf_len = sizeof(abnormal_core_reset_ntf);

/*******************************************************************************
**
** Function         message_*
**
** Description      Set of helper functions to manage msg_t queue and items.
**                  These functions must be called with the appropriate mutex
**                  locked.
**
** Returns          *
**
*******************************************************************************/
// add in queue in first position
static void message_push_first(msg_t* queue, int* ctr, msg_t* m) {
  m->next = queue->next;
  queue->next = m;
  *ctr += 1;
}

// add in queue in last position
static void message_push_last(msg_t* queue, int* ctr, msg_t* m) {
  msg_t* p = queue;
  while (p->next != nullptr) {
    p = p->next;
  }
  p->next = m;
  m->next = nullptr;
  *ctr += 1;
}

// remove from queue in first position
static msg_t* message_pop_first(msg_t* queue, int* ctr) {
  msg_t* r = queue->next;
  if (r != nullptr) {
    queue->next = r->next;
    r->next = nullptr;
    *ctr -= 1;
  }
  return r;
}

// remove first message that meets criterya
static msg_t* message_pop_first_except(msg_t* queue, int* ctr,
                                       bool skip_cmd_to_nfcc,
                                       bool skip_data_to_nfcc) {
  msg_t* prev = queue;
  msg_t* m = nullptr;
  while ((m = prev->next) != nullptr) {
    uint8_t mt = (m->payload[0] & NCI_MT_MASK) >> NCI_MT_SHIFT;

    if ((m->dir_to_nfcc == MSG_DIR_TO_NFCC) &&
        ((skip_cmd_to_nfcc && (mt == NCI_MT_CMD)) ||
         (skip_data_to_nfcc && (mt == NCI_MT_DATA)))) {
      // we skip this one, go to next in queue
      prev = m;
      continue;
    }

    /* other cases, we pop this message */
    break;
  }

  if (m != nullptr) {
    prev->next = m->next;
    m->next = nullptr;
    *ctr -= 1;
  }
  return m;
}

// remove from queue in last position
__attribute__((unused)) static msg_t* message_pop_last(msg_t* queue, int* ctr) {
  msg_t *p = queue, *r = nullptr;
  if (p->next == nullptr) {
    // queue is empty
    return r;
  }
  while (p->next->next != nullptr) {
    p = p->next;
  }
  r = p->next;
  p->next = nullptr;
  *ctr -= 1;
  return r;
}

// remove from queue if CMD matching gid/oid
static msg_t* message_pop_cmd(msg_t* queue, int* ctr, uint8_t gid,
                              uint8_t oid) {
  msg_t* p = queue;
  msg_t* r;
  do {
    r = p->next;
    if (r == nullptr) {
      break;
    }
    if ((((r->payload[0] & NCI_MT_MASK) >> NCI_MT_SHIFT) == NCI_MT_CMD) &&
        ((r->payload[0] & NCI_GID_MASK) == gid) &&
        ((r->payload[1] & NCI_OID_MASK) == oid)) {
      break;
    }
  } while ((p = p->next) != nullptr);

  if (r != nullptr) {
    // Matching message was found in the queue, dequeue it
    p->next = r->next;
    *ctr -= 1;
    r->next = nullptr;
  }

  return r;
}

// remove from queue if DATA matching connid
static msg_t* message_pop_data(msg_t* queue, int* ctr, uint8_t connid) {
  msg_t* p = queue;
  msg_t* r;
  do {
    r = p->next;
    if (r == nullptr) {
      break;
    }
    if ((((r->payload[0] & NCI_MT_MASK) >> NCI_MT_SHIFT) == NCI_MT_DATA) &&
        ((r->payload[0] & NCI_CID_MASK) == connid)) {
      break;
    }
  } while ((p = p->next) != nullptr);

  if (r != nullptr) {
    // Matching message was found in the queue, dequeue it
    p->next = r->next;
    *ctr -= 1;
    r->next = nullptr;
  }

  return r;
}

// Get a new msg_t buffer from pool if any, or allocate it, or return null
static msg_t* message_pool_get() {
  msg_t* m;
  (void)pthread_mutex_lock(&stpropnci_state.pumpstate.pump_pool_mtx);
  m = message_pop_first(&stpropnci_state.pumpstate.msgPool,
                        &stpropnci_state.pumpstate.msgPool_ctr);
  (void)pthread_mutex_unlock(&stpropnci_state.pumpstate.pump_pool_mtx);
  if (m == nullptr) {
    m = (msg_t*)malloc(sizeof(msg_t));
    if (m == nullptr) {
      LOG_E("Failed to allocate memory");
      return nullptr;
    }
    memset(m, 0, sizeof(msg_t));
  }
  return m;
}

// Return a msg_t to pool
static void message_pool_put(msg_t* m) {
  memset(m, 0, sizeof(*m));
  (void)pthread_mutex_lock(&stpropnci_state.pumpstate.pump_pool_mtx);
  message_push_first(&stpropnci_state.pumpstate.msgPool,
                     &stpropnci_state.pumpstate.msgPool_ctr, m);
  (void)pthread_mutex_unlock(&stpropnci_state.pumpstate.pump_pool_mtx);
}

/*******************************************************************************
**
** Function         ts*
**
** Description      Set of helper functions to facilitate struct timespec
**                  operations
**
** Returns          *
**
*******************************************************************************/
// Compare two timespecs, returns >0 if 'a' is later than 'b'
static int tscmp(struct timespec a, struct timespec b) {
  if (a.tv_sec == b.tv_sec)
    return (int)(a.tv_nsec - b.tv_nsec);
  else
    return (int)(a.tv_sec - b.tv_sec);
}

// add ms to ts
static void tsadd(struct timespec* t, int ms) {
  t->tv_sec += ms / 1000;
  ms = ms % 1000;
  t->tv_nsec += (1000000LL * (long long)ms);
  if (t->tv_nsec >= 1000000000LL) {
    t->tv_sec += 1;
    t->tv_nsec -= 1000000000LL;
  }
}

// substract ms from ts
static void tssub(struct timespec* t, int ms) {
  t->tv_sec -= ms / 1000;
  ms = ms % 1000;
  if (t->tv_nsec < (1000000LL * (long long)ms)) {
    t->tv_sec -= 1;
    t->tv_nsec += 1000000000LL;
  }
  t->tv_nsec -= (1000000LL * (long long)ms);
}

/*******************************************************************************
**
** Function         wd*
**
** Description      Set of helper functions to facilitate watchdog_t
**
** Returns          *
**
*******************************************************************************/
static watchdog_t* wd_pop_first(watchdog_t* queue) {
  watchdog_t* r = queue->next;
  if (r != nullptr) {
    queue->next = r->next;
    r->next = nullptr;
  }
  return r;
}

static void wd_push_first(watchdog_t* queue, watchdog_t* w) {
  w->next = queue->next;
  queue->next = w;
}

// Insert a watchdog item in an ordered list (ts_expire INC)
// lock is assumed to be held already
static void wd_insert_ordered(watchdog_t* queue, watchdog_t* w) {
  watchdog_t* prev = queue;
  while ((prev->next != nullptr) &&
         (tscmp(prev->next->ts_expire, w->ts_expire) < 0)) {
    prev = prev->next;
  }
  w->next = prev->next;
  prev->next = w;
}

// Any wd of type 'e' in 'from' list will be delisted and listed in 'to'
static void wd_move_matching(watchdog_t* from, watchdog_t* to,
                             watchdog_event_t e) {
  while (from->next != nullptr) {
    watchdog_t* w = from->next;
    if (w->event == e) {
      // delist
      from->next = w->next;
      // relist
      wd_push_first(to, w);
    } else {
      from = w;
    }
  }
}

// Get a watchdog_t from pool and initialize its content
static watchdog_t* wd_pool_get(watchdog_event_t e, int delay) {
  watchdog_t* ret = nullptr;

  (void)pthread_mutex_lock(&stpropnci_state.pumpstate.pump_pool_mtx);
  ret = wd_pop_first(&stpropnci_state.pumpstate.wdPool);
  (void)pthread_mutex_unlock(&stpropnci_state.pumpstate.pump_pool_mtx);

  if (ret == nullptr) {
    // Alloc the watchdog structure. we could use a pool if performance needs
    ret = (watchdog_t*)malloc(sizeof(watchdog_t));
    if (ret == nullptr) {
      LOG_E("Failed to allocate memory");
      return nullptr;
    }
  }

  if (ret != nullptr) {
    memset(ret, 0, sizeof(watchdog_t));
    ret->event = e;
    (void)clock_gettime(CLOCK_MONOTONIC, &ret->ts_expire);
    tsadd(&ret->ts_expire, delay);
  }

  return ret;
}

// Return a watchdog_t to pool
static void wd_pool_put(watchdog_t* w) {
  (void)pthread_mutex_lock(&stpropnci_state.pumpstate.pump_pool_mtx);
  wd_push_first(&stpropnci_state.pumpstate.wdPool, w);
  (void)pthread_mutex_unlock(&stpropnci_state.pumpstate.pump_pool_mtx);
}

/*******************************************************************************
**
** Function         message_pump_thr
**
** Description      The function of the pump thread that sends the messages
**                  posted and manages eventual retransmits when a message
**                  is not ack'd
**
** Returns          (ignored)
**
*******************************************************************************/
static void* message_pump_thr(__attribute__((unused)) void* st) {
  LOG_D("starting");
  (void)pthread_mutex_lock(&stpropnci_state.pumpstate.pump_mtx);
  do {
    msg_t* m;
    struct timespec t;
    bool timed = false;
    bool skip_cmd = false;
    bool skip_data = false;
    bool updated = false;
    int ctr_start = stpropnci_state.pumpstate.toSend_ctr;

    // check which messages are pending
    for (m = stpropnci_state.pumpstate.toAck.next; m != nullptr; m = m->next) {
      uint8_t mt = (m->payload[0] & NCI_MT_MASK) >> NCI_MT_SHIFT;
      if (mt == NCI_MT_CMD) {
        // a cmd is pending, don t send a new one
        skip_cmd = true;
      }
      if (mt == NCI_MT_DATA) {
        // a data is pending, don t send a new one
        skip_data = true;
      }
    }

    // send any outgoing message
    while ((m = message_pop_first_except(&stpropnci_state.pumpstate.toSend,
                                         &stpropnci_state.pumpstate.toSend_ctr,
                                         skip_cmd, skip_data)) != nullptr) {
      updated = true;

      // Unlock while sending responses but not commands.
      if (!m->dir_to_nfcc) {
        (void)pthread_mutex_unlock(&stpropnci_state.pumpstate.pump_mtx);
      }
      // send this message
      stpropnci_state.outCb(m->dir_to_nfcc, m->payload, m->payloadlen);
      // relock
      if (!m->dir_to_nfcc) {
        (void)pthread_mutex_lock(&stpropnci_state.pumpstate.pump_mtx);
      }

      // save the message in case we may need to resend it
      if (m->dir_to_nfcc) {
        // update the timestamp
        (void)clock_gettime(CLOCK_MONOTONIC, &m->ts);

        // store in toAck queue
        message_push_last(&stpropnci_state.pumpstate.toAck,
                          &stpropnci_state.pumpstate.toAck_ctr, m);

      } else {
        // We don't keep the messages sent to upper layers
        message_pool_put(m);
      }
    }

    // is there any unacked message reaching expiry ?
    if (stpropnci_state.pumpstate.toAck.next != nullptr) {
      (void)clock_gettime(CLOCK_MONOTONIC, &t);
      tssub(&t, DELAY_FOR_ACK_MS);
      // if the message was sent earlier than t, it is expired
      if (tscmp(stpropnci_state.pumpstate.toAck.next->ts, t) < 0) {
        updated = true;
        m = message_pop_first(&stpropnci_state.pumpstate.toAck,
                              &stpropnci_state.pumpstate.toAck_ctr);

        // if this is RF data message
        if (m->payload[0] == 0x00) {
          // if there was a rf_deactivate_ntf when the data was sent
          // note: t value is around the time the message was posted here.
          if (stpropnci_state.ts_last_rf_deact_ntf.tv_sec != 0) {
            tssub(&t,
                  10);  // add some margin for processing and transmission time
            if (tscmp(stpropnci_state.ts_last_rf_deact_ntf, t) > 0) {
              // last deactivation happened since this data was sent
              LOG_D(
                  "RF data message was not acked, but a deactivate ntf was "
                  "received around the same time, so ignore it.");
              message_pool_put(m);
              continue;
            }
          }
        }

        if (!m->retried) {
          // enqueue it for sending next
          LOG_D("Message was not acked (once): %02hhx%02hhx%02hhx, resend",
                m->payload[0], m->payload[1], m->payload[2]);
          m->retried = true;
          message_push_first(&stpropnci_state.pumpstate.toSend,
                             &stpropnci_state.pumpstate.toSend_ctr, m);
          // loop now so it is handled quickly
          continue;
        } else {
          LOG_E(
              "Message was not acked (twice): %02hhx%02hhx%02hhx, emulate "
              "CORE_RESET_NTF",
              m->payload[0], m->payload[1], m->payload[2]);

          if (((m->payload[0] & NCI_MT_MASK) >> NCI_MT_SHIFT) == NCI_MT_DATA) {
            // In case of DATA message, send a fake CORE_RESET_NTF.
            // Not needed in case of CMD, the core stack will take care of it.
            // Not using stpropnci_send_core_reset_ntf_recovery() here to avoid
            // complex lock management.

            // Unlock while sending.
            (void)pthread_mutex_unlock(&stpropnci_state.pumpstate.pump_mtx);
            // send a critical core reset error to upper
            stpropnci_state.outCb(false, abnormal_core_reset_ntf,
                                  abnormal_core_reset_ntf_len);
            // relock
            (void)pthread_mutex_lock(&stpropnci_state.pumpstate.pump_mtx);
          }

          message_pool_put(m);
        }
      }
    }

    // Is there a watchdog expiring ?
    if (stpropnci_state.pumpstate.toWatch.next != nullptr) {
      (void)clock_gettime(CLOCK_MONOTONIC, &t);
      if (tscmp(stpropnci_state.pumpstate.toWatch.next->ts_expire, t) < 0) {
        updated = true;
        watchdog_t* w = wd_pop_first(&stpropnci_state.pumpstate.toWatch);
        LOG_E("Watchdog (type %d) expired, generating CORE_RESET_NTF",
              w->event);
        wd_pool_put(w);

        // Unlock while sending.
        (void)pthread_mutex_unlock(&stpropnci_state.pumpstate.pump_mtx);
        // send a critical core reset error to upper
        stpropnci_state.outCb(false, abnormal_core_reset_ntf,
                              abnormal_core_reset_ntf_len);
        // relock
        (void)pthread_mutex_lock(&stpropnci_state.pumpstate.pump_mtx);
      }
    }

    if (stpropnci_state.pumpstate.mustExit) {
      // stop order came while we were sending.
      break;
    }
    if (stpropnci_state.pumpstate.toSend.next != nullptr) {
      if ((!updated) && (ctr_start == stpropnci_state.pumpstate.toSend_ctr)) {
        // no change in lists, wait 1ms before loop
        // otherwise if there was an update, a new message was queued while we
        // were processing, we skip the wait and loop directly.
        (void)pthread_mutex_unlock(&stpropnci_state.pumpstate.pump_mtx);
        usleep(1000);
        (void)pthread_mutex_lock(&stpropnci_state.pumpstate.pump_mtx);
      }
      continue;
    }

    if (stpropnci_state.pumpstate.toAck.next != nullptr) {
      t = stpropnci_state.pumpstate.toAck.next->ts;
      tsadd(&t, DELAY_FOR_ACK_MS);
      timed = true;
    }

    if (stpropnci_state.pumpstate.toWatch.next != nullptr) {
      if (timed) {
        // Check if watchdog comes first
        if (tscmp(stpropnci_state.pumpstate.toWatch.next->ts_expire, t) < 0) {
          t = stpropnci_state.pumpstate.toWatch.next->ts_expire;
        }
      } else {
        t = stpropnci_state.pumpstate.toWatch.next->ts_expire;
        timed = true;
      }
    }

    if (timed) {
      // Wait until at most expiry of the next message
      (void)pthread_cond_timedwait(&stpropnci_state.pumpstate.pump_cnd,
                                   &stpropnci_state.pumpstate.pump_mtx, &t);
    } else {
      // just wait until awaken
      (void)pthread_cond_wait(&stpropnci_state.pumpstate.pump_cnd,
                              &stpropnci_state.pumpstate.pump_mtx);
    }
  } while (!stpropnci_state.pumpstate.mustExit);
  (void)pthread_mutex_unlock(&stpropnci_state.pumpstate.pump_mtx);
  LOG_D("exiting");
  return NULL;
}

/*******************************************************************************
**
** Function         stpropnci_pump_post
**
** Description      Enqueue a message for sending by the pump thread
**
** Returns          true if message was queued successfully.
**
*******************************************************************************/
bool stpropnci_pump_post(bool dir_to_nfcc, const uint8_t* payload,
                         uint16_t payloadlen, module_cb_t rspcb) {
  msg_t* m;
  int msgPool_ctr, toSend_ctr, toAck_ctr;
  if (payloadlen > MAX_NCI_MESSAGE_LEN) {
    LOG_E("Message is too long: %u", payloadlen);
    return false;
  }
  m = message_pool_get();
  if (m == nullptr) {
    return false;
  }
  memcpy(&m->payload, payload, payloadlen);
  m->payloadlen = payloadlen;
  m->dir_to_nfcc = dir_to_nfcc;
  m->rspcb = rspcb;

  (void)pthread_mutex_lock(&stpropnci_state.pumpstate.pump_mtx);
  message_push_last(&stpropnci_state.pumpstate.toSend,
                    &stpropnci_state.pumpstate.toSend_ctr, m);
  msgPool_ctr = stpropnci_state.pumpstate.msgPool_ctr;
  toSend_ctr = stpropnci_state.pumpstate.toSend_ctr;
  toAck_ctr = stpropnci_state.pumpstate.toAck_ctr;
  (void)pthread_mutex_unlock(&stpropnci_state.pumpstate.pump_mtx);
  (void)pthread_cond_signal(&stpropnci_state.pumpstate.pump_cnd);

  if ((msgPool_ctr > 20) || (toSend_ctr > 10) || (toAck_ctr > 10)) {
    LOG_E("Unexpected many messages queued: %d/%d/%d", msgPool_ctr, toSend_ctr,
          toAck_ctr);
  }

  return true;
}

/*******************************************************************************
**
** Function         stpropnci_pump_watchdog_add
**
** Description      Start a watchdog timer for an event.
**                  If this is not cleared before ms later,
**                  a fake core_reset_ntf will be generated to start recovery.
**
** Returns          true if watchdog was queued successfully.
**
*******************************************************************************/
bool stpropnci_pump_watchdog_add(watchdog_event_t t, int ms) {
  watchdog_t* w = wd_pool_get(t, ms);
  if (w == nullptr) {
    LOG_E("Failed to retrieve a watchdog_t from pool, no memory ?");
    return false;
  }
  (void)pthread_mutex_lock(&stpropnci_state.pumpstate.pump_mtx);
  wd_insert_ordered(&stpropnci_state.pumpstate.toWatch, w);
  (void)pthread_mutex_unlock(&stpropnci_state.pumpstate.pump_mtx);
  (void)pthread_cond_signal(&stpropnci_state.pumpstate.pump_cnd);
  return true;
}

/*******************************************************************************
**
** Function         stpropnci_pump_watchdog_remove
**
** Description      Clear all matching watchdogs registered with above function
**
** Returns          none
**
*******************************************************************************/
void stpropnci_pump_watchdog_remove(watchdog_event_t t) {
  watchdog_t toFree = {.next = nullptr};
  watchdog_t* w = nullptr;
  (void)pthread_mutex_lock(&stpropnci_state.pumpstate.pump_mtx);
  wd_move_matching(&stpropnci_state.pumpstate.toWatch, &toFree, t);
  (void)pthread_mutex_unlock(&stpropnci_state.pumpstate.pump_mtx);
  while ((w = wd_pop_first(&toFree)) != nullptr) {
    wd_pool_put(w);
  }
}

/*******************************************************************************
**
** Function         stpropnci_pump_got
**
** Description      Called upon reception of a message from NFCC, to match
**                  previously sent commands or data that are waiting their
**                  ack'd.
**
** Returns          none
**
*******************************************************************************/
void stpropnci_pump_got(const uint8_t* payload, uint16_t payloadlen,
                        bool* handled) {
  msg_t* m = nullptr;

  uint8_t mt = (payload[0] & NCI_MT_MASK) >> NCI_MT_SHIFT;

  if (mt == NCI_MT_RSP) {
    // check if we have a corresponding CMD GID/OID to ack.
    (void)pthread_mutex_lock(&stpropnci_state.pumpstate.pump_mtx);
    m = message_pop_cmd(&stpropnci_state.pumpstate.toAck,
                        &stpropnci_state.pumpstate.toAck_ctr,
                        payload[0] & NCI_GID_MASK, payload[1] & NCI_OID_MASK);
    (void)pthread_mutex_unlock(&stpropnci_state.pumpstate.pump_mtx);
    if (m != nullptr) {
      if (m->rspcb != nullptr) {
        const uint8_t* p = payload;
        uint8_t pbf, gid, oid;
        NCI_MSG_PRS_HDR0(p, mt, pbf, gid);
        NCI_MSG_PRS_HDR1(p, oid);

        *handled =
            (*m->rspcb)(MSG_DIR_FROM_NFCC, payload, payloadlen, mt, gid, oid);
      }
      message_pool_put(m);
    }
  } else if (mt == NCI_MT_NTF) {
    // Only care for CORE_CONN_CREDIT here
    if (((payload[0] & NCI_GID_MASK) == NCI_GID_CORE) &&
        ((payload[1] & NCI_OID_MASK) == NCI_MSG_CORE_CONN_CREDITS)) {
      // check if we have a DATA packet with this conn ID to ack.
      if (payloadlen == 6) {
        (void)pthread_mutex_lock(&stpropnci_state.pumpstate.pump_mtx);
        m = message_pop_data(&stpropnci_state.pumpstate.toAck,
                             &stpropnci_state.pumpstate.toAck_ctr, payload[4]);
        (void)pthread_mutex_unlock(&stpropnci_state.pumpstate.pump_mtx);
        if (m != nullptr) {
          message_pool_put(m);
        }
      } else {
        // ST FW only returns 1 conn credit at a time currently.
        LOG_E("Unexpected CORE_CONN_CREDITS message data");
      }
    }
  }
  // we are not interested in other cases

  return;
}

/*******************************************************************************
**
** Function         stpropnci_pump_init
**
** Description      Initializes the pump module and starts the thread.
**
** Returns          true if init is successful.
**
*******************************************************************************/
bool stpropnci_pump_init() {
  int ret = 0;
  pthread_condattr_t attr;

  (void)pthread_mutex_init(&stpropnci_state.pumpstate.pump_mtx, nullptr);
  (void)pthread_mutex_init(&stpropnci_state.pumpstate.pump_pool_mtx, nullptr);

  (void)pthread_condattr_init(&attr);
  (void)pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  (void)pthread_cond_init(&stpropnci_state.pumpstate.pump_cnd, &attr);
  (void)pthread_condattr_destroy(&attr);

  ret = pthread_create(&stpropnci_state.pumpstate.pump_thr, nullptr,
                       message_pump_thr, nullptr);
  if (ret != 0) {
    LOG_E("Failed to create thread: %s", strerror(ret));
    return false;
  }

  return true;
}

/*******************************************************************************
**
** Function         stpropnci_pump_fini
**
** Description      Deinitializes the pump module, stops the thread, frees the
**                  resources.
**
** Returns          none
**
*******************************************************************************/
void stpropnci_pump_fini() {
  void* tret = nullptr;
  int ret = 0;
  msg_t* m;
  watchdog_t* w;

  // Ensure we wake up the thread so it can see mustExit
  (void)pthread_mutex_lock(&stpropnci_state.pumpstate.pump_mtx);
  stpropnci_state.pumpstate.mustExit = true;
  (void)pthread_cond_signal(&stpropnci_state.pumpstate.pump_cnd);
  (void)pthread_mutex_unlock(&stpropnci_state.pumpstate.pump_mtx);

  // Wait for the thread to exit
  ret = pthread_join(stpropnci_state.pumpstate.pump_thr, &tret);
  if (0 != ret) {
    LOG_E("Failed to join thread: %s", strerror(ret));
  }

  // Discard all pending messages.
  while ((m = message_pop_first(&stpropnci_state.pumpstate.toSend,
                                &stpropnci_state.pumpstate.toSend_ctr)) !=
         nullptr) {
    LOG_D("Drop outgoing msg: %02hhx%02hhx%02hhx", m->payload[0], m->payload[1],
          m->payload[2]);
    free(m);
  }
  while ((m = message_pop_first(&stpropnci_state.pumpstate.toAck,
                                &stpropnci_state.pumpstate.toAck_ctr)) !=
         nullptr) {
    LOG_D("Drop un-acked sent msg: %02hhx%02hhx%02hhx", m->payload[0],
          m->payload[1], m->payload[2]);
    free(m);
  }
  while ((m = message_pop_first(&stpropnci_state.pumpstate.msgPool,
                                &stpropnci_state.pumpstate.msgPool_ctr)) !=
         nullptr) {
    free(m);
  }
  while ((w = wd_pop_first(&stpropnci_state.pumpstate.toWatch)) != nullptr) {
    free(w);
  }
  while ((w = wd_pop_first(&stpropnci_state.pumpstate.wdPool)) != nullptr) {
    free(w);
  }

  // Destroy mutex and cond
  (void)pthread_cond_destroy(&stpropnci_state.pumpstate.pump_cnd);
  (void)pthread_mutex_destroy(&stpropnci_state.pumpstate.pump_mtx);
  (void)pthread_mutex_destroy(&stpropnci_state.pumpstate.pump_pool_mtx);

  // We are done.
}

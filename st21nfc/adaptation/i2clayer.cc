/** ----------------------------------------------------------------------
 *
 * Copyright (C) 2013 ST Microelectronics S.A.
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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/input.h> /* not required for all builds */
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "android_logmsg.h"
#include "halcore.h"
#include "halcore_private.h"

//------- from st21nfc.h in kernel driver
#define ST21NFC_MAGIC 0xEA

#define ST21NFC_GET_WAKEUP _IOR(ST21NFC_MAGIC, 0x01, unsigned int)
#define ST21NFC_PULSE_RESET _IOR(ST21NFC_MAGIC, 0x02, unsigned int)
#define ST21NFC_SET_POLARITY_RISING _IOR(ST21NFC_MAGIC, 0x03, unsigned int)
#define ST21NFC_SET_POLARITY_FALLING _IOR(ST21NFC_MAGIC, 0x04, unsigned int)
#define ST21NFC_SET_POLARITY_HIGH _IOR(ST21NFC_MAGIC, 0x05, unsigned int)
#define ST21NFC_SET_POLARITY_LOW _IOR(ST21NFC_MAGIC, 0x06, unsigned int)

#define ST21NFC_CLK_DISABLE_UNPREPARE _IO(ST21NFC_MAGIC, 0x0A)
/*
#define ST21NFC_GET_WAKEUP _IO(ST21NFC_MAGIC, 0x01)
#define ST21NFC_PULSE_RESET _IO(ST21NFC_MAGIC, 0x02)
#define ST21NFC_SET_POLARITY_RISING _IO(ST21NFC_MAGIC, 0x03)
#define ST21NFC_SET_POLARITY_FALLING _IO(ST21NFC_MAGIC, 0x04)
#define ST21NFC_SET_POLARITY_HIGH _IO(ST21NFC_MAGIC, 0x05)
#define ST21NFC_SET_POLARITY_LOW _IO(ST21NFC_MAGIC, 0x06)
*/
#define ST21NFC_GET_POLARITY _IO(ST21NFC_MAGIC, 0x07)
#define ST21NFC_RECOVERY _IO(ST21NFC_MAGIC, 0x08)

#define ST21NFC_USE_ESE _IOW(ST21NFC_MAGIC, 0x09, unsigned int)
//------- end from st21nfc.h in kernel driver
#define LINUX_DBGBUFFER_SIZE 300

static int fidI2c = 0;
static int cmdPipe[2] = {0, 0};
static int is4bytesheader = 0;
static bool recovery_mode = false;
static bool resetPulseDone = false;

static struct pollfd event_table[2];
static pthread_t threadHandle = (pthread_t)NULL;
pthread_mutex_t i2ctransport_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t i2cguard_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t i2cguard_write = PTHREAD_MUTEX_INITIALIZER;

/**************************************************************************************************
 *
 *                                      Private API Declaration
 *
 **************************************************************************************************/

static int i2cSetPolarity(int fid, bool low, bool edge);
static int i2cResetPulse(int fid);
static int i2cRecovery(int fid);
static int i2cRead(int fid, uint8_t* pvBuffer, int length);
static int i2cGetGPIOState(int fid);
static int i2cWrite(int fd, const uint8_t* pvBuffer, int length);

/**************************************************************************************************
 *
 *                                      Public API Entry-Points
 *
 **************************************************************************************************/

/**
 * Worker thread for I2C data processing.
 * On exit of this thread, destroy the HAL thread instance.
 * @param arg  Handle of the HAL layer
 */
static void* I2cWorkerThread(void* arg) {
  bool closeThread = false;
  HALHANDLE hHAL = (HALHANDLE)arg;
  STLOG_HAL_D("echo thread started...\n");
  bool readOk = false;

  do {
    event_table[0].fd = fidI2c;
    event_table[0].events = POLLIN;
    event_table[0].revents = 0;

    event_table[1].fd = cmdPipe[0];
    event_table[1].events = POLLIN;
    event_table[1].revents = 0;

    STLOG_HAL_V("echo thread go to sleep...\n");

    int poll_status = poll(event_table, 2, -1);

    if (-1 == poll_status) {
      poll_status = errno;
      STLOG_HAL_E("error in poll call : %d - %s\n", poll_status,
                  strerror(poll_status));
      if ((poll_status == EINTR) || (poll_status == EAGAIN)) continue;

      // other errors, we stop.
      break;
    }

    if (event_table[0].revents & POLLIN) {
      STLOG_HAL_V("echo thread wakeup from chip...\n");

      // enforce no read during or after reset
      (void)pthread_mutex_lock(&i2cguard_mtx);
      (void)pthread_mutex_unlock(&i2cguard_mtx);

      uint8_t buffer[300];
      int count = 0;

      do {
        if (!recovery_mode) {
          // load first four bytes:
          int hdrsz = is4bytesheader ? 4 : 3;
          int extra = 0;  // did we read past the header?
          int bytesRead = i2cRead(fidI2c, buffer, hdrsz);

          if (bytesRead == hdrsz) {
            if ((hdrsz == 3) && (buffer[0] == 0x7E) && resetPulseDone) {
              is4bytesheader = 1;  // read 4 bytes until next reset
              bytesRead = i2cRead(fidI2c, buffer + 3,
                                  1);  // read the third byte of header
              if (bytesRead != 1) {
                STLOG_HAL_E("Failed to read last byte\n");
              }
              hdrsz = 4;
            }

            if ((hdrsz == 4) && (buffer[0] != 0x7E)) {
              extra = 1;  // we read 1 payload byte already
            } else if (hdrsz == 4) {
              // we got dummy 7e, discard and continue as if not there.
              buffer[0] = buffer[1];
              buffer[1] = buffer[2];
              buffer[2] = buffer[3];
            }
            if ((buffer[0] != 0x7E) && (buffer[1] != 0x7E)) {
              readOk = true;
            } else {
              if (buffer[1] != 0x7E) {
                STLOG_HAL_W(
                    "Idle data: 2nd byte is 0x%02x, reading next byte\n",
                    buffer[1]);
                buffer[0] = buffer[1];
                buffer[1] = buffer[2];
                bytesRead = i2cRead(fidI2c, buffer + 2, 1);
                if (bytesRead == 1) {
                  readOk = true;
                } else {
                  STLOG_HAL_E("Failed to read last byte\n");
                }
              } else if (buffer[2] != 0x7E) {
                STLOG_HAL_W(
                    "Idle data: 3rd byte is 0x%02x, reading next 2 bytes\n",
                    buffer[2]);
                buffer[0] = buffer[2];
                bytesRead = i2cRead(fidI2c, buffer + 1, 2);
                if (bytesRead == 2) {
                  readOk = true;
                } else {
                  STLOG_HAL_E("Failed to read last 2 bytes\n");
                }
              } else {
                STLOG_HAL_W("received idle data\n");
              }
            }

            // in loader mode, extra 7E byte is not supported, so need to skip
            // duplicate 1st byte that happens on 4F answers
            if ((readOk == true) && (extra == 0) && (buffer[0] == 0x4F) &&
                (buffer[1] == 0x4F)) {
              // overwrite the duplicate byte
              buffer[1] = buffer[2];
              // read the actual length byte
              bytesRead = i2cRead(fidI2c, buffer + 2, 1);
              if (bytesRead != 1) {
                readOk = false;
                STLOG_HAL_E("Failed to read last byte after duplicate\n");
              }
            }

            if (readOk == true) {
              resetPulseDone = false;
              int remaining = buffer[2];
              bytesRead = 0;

              // read and pass to HALCore
              if (remaining - extra > 0) {
                bytesRead =
                    i2cRead(fidI2c, buffer + 3 + extra, remaining - extra);
              }
              if (bytesRead == remaining - extra) {
                DispHal("RX DATA", buffer, 3 + extra + bytesRead);
                HalSendUpstream(hHAL, buffer, 3 + extra + bytesRead);
              } else {
                readOk = false;
                STLOG_HAL_E(
                    "! didn't read expected bytes from "
                    "i2c,bytesRead=%d,remaining=%d,extra=%d,is4bytesheader=%"
                    "d\n",
                    bytesRead, remaining, extra, is4bytesheader);
              }
            } else {
              STLOG_HAL_W(
                  "!readOk; bytesRead=%d, buffer: 0x%02x 0x%02x 0x%02x\n",
                  bytesRead, buffer[0], buffer[1], buffer[2]);
            }

          } else {
            STLOG_HAL_E("! didn't read %d requested bytes from i2c\n", hdrsz);
          }

          readOk = false;
          memset(buffer, 0xca, sizeof(buffer));
        }
        /* read while we have data available, up to 2 times then allow writes */
      } while ((i2cGetGPIOState(fidI2c) == 1) && (count++ < 2));
    }

    if (event_table[1].revents & POLLIN) {
      STLOG_HAL_V("thread received command.. \n");

      char cmd = 0;
      int ret = read(cmdPipe[0], &cmd, 1);
      if (ret != 1) {
        STLOG_HAL_E("! Error, wrong read size\n");
        continue;
      }

      switch (cmd) {
        case 'X':
          STLOG_HAL_D("received close command\n");
          if (-1 == ioctl(fidI2c, ST21NFC_CLK_DISABLE_UNPREPARE, NULL)) {
            STLOG_HAL_E("ioctl(ST21NFC_CLK_DISABLE_UNPREPARE) failed\n");
          }
          closeThread = true;
          break;

        case 'W': {
          size_t length;
          uint8_t buffer[MAX_BUFFER_SIZE];
          STLOG_HAL_V("received write command\n");
          int ret = read(cmdPipe[0], &length, sizeof(length));
          if (ret != sizeof(length)) {
            STLOG_HAL_E("! Error, wrong read size\n");
            break;
          }
          if (length <= MAX_BUFFER_SIZE) {
            read(cmdPipe[0], buffer, length);
            i2cWrite(fidI2c, buffer, length);
          } else {
            STLOG_HAL_E(
                "! received bigger data than expected!! Data not transmitted "
                "to NFCC \n");
            size_t bytes_read = 1;
            // Read all the data to empty but do not use it as not expected
            while ((bytes_read > 0) && (length > 0)) {
              bytes_read = read(cmdPipe[0], buffer, MAX_BUFFER_SIZE);
              length = length - bytes_read;
            }
          }
        } break;
      }
    }

  } while (!closeThread);

  close(fidI2c);
  close(cmdPipe[0]);
  close(cmdPipe[1]);

  // Stop here if we got a serious error above.
  assert(closeThread);

  HalDestroy(hHAL);
  STLOG_HAL_D("thread exit\n");
  return 0;
}

/**
 * Put command into queue for worker thread to process it.
 * @param x Command 'X' to close I2C layer or 'W' to write data down to I2C
 * layer followed by data frame
 * @param len Size of command or data
 * @return
 */
int I2cWriteCmd(const uint8_t* x, size_t len) {
  return write(cmdPipe[1], x, len);
}

/**
 * Initialize the I2C layer.
 * @param dev NFC NCI device context, NFC callbacks for control/data, HAL handle
 * @param callb HAL Core callback upon reception on I2C
 * @param pHandle HAL context handle
 */
bool I2cOpenLayer(void* dev, HAL_CALLBACK callb, HALHANDLE* pHandle) {
  uint32_t NoDbgFlag = HAL_FLAG_DEBUG;
  uint8_t DummyByte;
  (void)pthread_mutex_lock(&i2ctransport_mtx);
  fidI2c = open("/dev/st21nfc", O_RDWR);
  if (fidI2c < 0) {
    STLOG_HAL_W("unable to open /dev/st21nfc  (%s) \n", strerror(errno));
    (void)pthread_mutex_unlock(&i2ctransport_mtx);
    return false;
  }
  int result = -1;
  result = read(fidI2c, &DummyByte, 1);

  i2cSetPolarity(fidI2c, false, false);
  i2cResetPulse(fidI2c);

  if ((pipe(cmdPipe) == -1)) {
    STLOG_HAL_W("unable to open cmdpipe\n");
    (void)pthread_mutex_unlock(&i2ctransport_mtx);
    return false;
  }

  *pHandle = HalCreate(dev, callb, NoDbgFlag);

  if (!*pHandle) {
    STLOG_HAL_E("failed to create NFC HAL Core \n");
    (void)pthread_mutex_unlock(&i2ctransport_mtx);
    return false;
  }

  (void)pthread_mutex_unlock(&i2ctransport_mtx);

  return (pthread_create(&threadHandle, NULL, I2cWorkerThread, *pHandle) == 0);
}

/**
 * Terminates the I2C layer.
 */
void I2cCloseLayer() {
  uint8_t cmd = 'X';
  int ret;
  ALOGD("%s: enter\n", __func__);

  (void)pthread_mutex_lock(&i2ctransport_mtx);

  if (threadHandle == (pthread_t)NULL) {
    (void)pthread_mutex_unlock(&i2ctransport_mtx);
    return;
  }

  (void)pthread_mutex_lock(&i2cguard_write);
  I2cWriteCmd(&cmd, sizeof(cmd));
  (void)pthread_mutex_unlock(&i2cguard_write);

  /* wait for terminate */
  ret = pthread_join(threadHandle, (void**)NULL);
  if (ret != 0) {
    ALOGE("%s: failed to wait for thread (%d)", __func__, ret);
  }
  threadHandle = (pthread_t)NULL;
  (void)pthread_mutex_unlock(&i2ctransport_mtx);
}

/**
 * Terminates the I2C layer.
 */
void I2cResetPulse() {
  ALOGD("%s: enter\n", __func__);

  (void)pthread_mutex_lock(&i2ctransport_mtx);

  i2cResetPulse(fidI2c);
  (void)pthread_mutex_unlock(&i2ctransport_mtx);
}
void I2cRecovery() {
  ALOGD("%s: enter\n", __func__);

  (void)pthread_mutex_lock(&i2ctransport_mtx);
  recovery_mode = true;
  i2cRecovery(fidI2c);
  recovery_mode = false;
  (void)pthread_mutex_unlock(&i2ctransport_mtx);
}

extern "C" void I2cRecoveryFactory() { I2cRecovery(); }

/**************************************************************************************************
 *
 *                                      Private API Definition
 *
 **************************************************************************************************/
/**
 * Call the st21nfc driver to adjust wake-up polarity.
 * @param fid File descriptor for NFC device
 * @param low Polarity (HIGH or LOW)
 * @param edge Polarity (RISING or FALLING)
 * @return Result of IOCTL system call (0 if ok)
 */
static int i2cSetPolarity(int fid, bool low, bool edge) {
  int result;
  unsigned int io_code;

  if (low) {
    if (edge) {
      io_code = ST21NFC_SET_POLARITY_FALLING;
    } else {
      io_code = ST21NFC_SET_POLARITY_LOW;
    }

  } else {
    if (edge) {
      io_code = ST21NFC_SET_POLARITY_RISING;
    } else {
      io_code = ST21NFC_SET_POLARITY_HIGH;
    }
  }

  if (-1 == (result = ioctl(fid, io_code, NULL))) {
    result = -1;
  }

  return result;
} /* i2cSetPolarity*/

/**
 * Call the st21nfc driver to generate a 30ms pulse on RESET line.
 * @param fid File descriptor for NFC device
 * @return Result of IOCTL system call (0 if ok)
 */
static int i2cResetPulse(int fid) {
  int result;

  (void)pthread_mutex_lock(&i2cguard_mtx);
  if (-1 == (result = ioctl(fid, ST21NFC_PULSE_RESET, NULL))) {
    result = -1;
  }
  STLOG_HAL_D("! i2cResetPulse!!, result = %d", result);
  usleep(3000);  // wait for the CLF to boot before enable read
  resetPulseDone = true;
  (void)pthread_mutex_unlock(&i2cguard_mtx);
  is4bytesheader = 0;  // reset the flag
  return result;
} /* i2cResetPulse*/

/**
 * Call the st21nfc driver to generate pulses on RESET line to get a recovery.
 * @param fid File descriptor for NFC device
 * @return Result of IOCTL system call (0 if ok)
 */
static int i2cRecovery(int fid) {
  int result;
  uint8_t cmd = 'n';

  if (-1 == (result = ioctl(fid, ST21NFC_RECOVERY, NULL))) {
    result = -1;
  }
  STLOG_HAL_D("! i2cRecovery!!, result = %d", result);

  (void)pthread_mutex_lock(&i2cguard_write);
  // send NOOP to the I2CWorkerThread to re-enter in poll and rearm the IRQ
  // handler
  I2cWriteCmd(&cmd, sizeof(cmd));
  (void)pthread_mutex_unlock(&i2cguard_write);

  return result;
} /* i2cRecovery*/

/**
 * Signal kernel driver that the NFCC may or may not use the eSE
 * This is required to manage SE power finely when SPI is connected.
 * In other cases, this information is not used.
 */
int i2cNfccMayUseEse(int use) {
  int result;
  int se_needed = (use ? 1 : 0);

  if (-1 == (result = ioctl(fidI2c, ST21NFC_USE_ESE, &se_needed))) {
    result = -1;
  }
  STLOG_HAL_D("i2cNfccMayUseEse(%d), result = %d", use, result);
  return result;
} /* i2cNfccMayUseEse */

/**
 * Write data to st21nfc, on failure do max 3 retries.
 * @param fid File descriptor for NFC device
 * @param pvBuffer Data to write
 * @param length Data size
 * @return 0 if bytes written, -1 if error
 */
struct timespec sTsPrev = {.tv_sec = 0, .tv_nsec = 0};
static int sMs = 0;
static pthread_mutex_t sTsLock = PTHREAD_MUTEX_INITIALIZER;

void i2cSetTimeBetweenCmds(int ms) {
  STLOG_HAL_D("i2cSetTimeBetweenCmds(%d)", ms);
  (void)pthread_mutex_lock(&sTsLock);
  sMs = ms;
  (void)pthread_mutex_unlock(&sTsLock);
}

static int i2cWrite(int fid, const uint8_t* pvBuffer, int length) {
  int retries = 0;
  int result = 0;
  int halfsecs = 0;

  (void)pthread_mutex_lock(&sTsLock);
  if (sMs != 0) {
    if (sTsPrev.tv_sec != 0) {
      // enforce a delay of sMs between sending two commands,
      // we update sTsPrev to next slot to send
      if (sTsPrev.tv_nsec >= (1000000000L - (sMs * 1000000L))) {
        sTsPrev.tv_nsec = sTsPrev.tv_nsec + (sMs * 1000000L) - 1000000000L;
        sTsPrev.tv_sec += 1;
      } else {
        sTsPrev.tv_nsec += (sMs * 1000000L);
      }
      // we need to send command at new sTsPrev.
      clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &sTsPrev, NULL);
    }
    clock_gettime(CLOCK_MONOTONIC, &sTsPrev);
  }
  (void)pthread_mutex_unlock(&sTsLock);

redo:
  while (retries < 3) {
    result = write(fid, pvBuffer, length);

    if (result < 0) {
      char msg[LINUX_DBGBUFFER_SIZE];

      strerror_r(errno, msg, LINUX_DBGBUFFER_SIZE);
      if (retries > 0) {
        STLOG_HAL_W("! i2cWrite!!, errno is '%s'", msg);
      } else {
        STLOG_HAL_D("! i2cWrite!!, errno is '%s'", msg);
      }
      usleep(4000);
      retries++;
    } else if (result > 0) {
      result = 0;
      return result;
    } else {
      STLOG_HAL_W("write on i2c failed, retrying\n");
      usleep(4000);
      retries++;
    }
  }
  /* If we're here, we failed to write to NFCC. Retry after 500ms because some
  CPUs have shown such long unavailability sometimes */
  if (halfsecs < 4) {
    usleep(500000);
    halfsecs++;
    retries = 0;
    goto redo;
  }
  /* The CLF did not recover, give up */
  return -1;
} /* i2cWrite */

/**
 * Read data from st21nfc, on failure do max 3 retries.
 *
 * @param fid File descriptor for NFC device
 * @param pvBuffer Buffer where to copy read data
 * @param length Data size to read
 * @return Length of read data, -1 if error
 */
static int i2cRead(int fid, uint8_t* pvBuffer, int length) {
  int retries = 0;
  int result = -1;

  while ((retries < 3) && (result < 0)) {
    result = read(fid, pvBuffer, length);

    if (result == -1) {
      int e = errno;
      if (e == EAGAIN) {
        /* File is nonblocking, and no data is available.
         * This is not an error condition!
         */
        result = 0;
        STLOG_HAL_D(
            "## i2cRead - got EAGAIN. No data available. return 0 bytes");
      } else {
        /* unexpected result */
        char msg[LINUX_DBGBUFFER_SIZE];
        strerror_r(e, msg, LINUX_DBGBUFFER_SIZE);
        STLOG_HAL_W("## i2cRead returns %d errno %d (%s)", result, e, msg);
      }
    }

    if (result < 0) {
      if (retries < 3) {
        /* delays are different and increasing for the three retries. */
        static const uint8_t delayTab[] = {2, 3, 5};
        int delay = delayTab[retries];

        retries++;
        STLOG_HAL_W("## i2cRead retry %d/3 in %d milliseconds.", retries,
                    delay);
        usleep(delay * 1000);
        continue;
      }
    }
  }
  return result;
} /* i2cRead */

/**
 * Get the activation status of wake-up pin from st21nfc.
 *  The decision 'active' depends on selected polarity.
 *  The decision is handled inside the driver(st21nfc).
 * @param fid File descriptor for NFC device
 * @return
 *  Result < 0:     Error condition
 *  Result > 0:     Pin active
 *  Result = 0:     Pin not active
 */
static int i2cGetGPIOState(int fid) {
  int result;

  if (-1 == (result = ioctl(fid, ST21NFC_GET_WAKEUP, NULL))) {
    result = -1;
  }

  return result;
} /* i2cGetGPIOState */

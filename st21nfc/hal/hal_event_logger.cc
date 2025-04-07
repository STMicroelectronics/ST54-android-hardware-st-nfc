/*
 * Copyright (C) 2025 The Android Open Source Project
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
 */

#include "hal_event_logger.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <cstring>
#include <ctime>

#include "config.h"
#include "hal_config.h"

#define TIMESTAMP_BUFFER_SIZE 64
#define HAL_LOG_FILE_SIZE 32 * 1024 * 1024
#define HAL_MEM_BUFFER_SIZE 256 * 1024

HalEventLogger& HalEventLogger::getInstance() {
  static HalEventLogger nfc_event_eventLogger;
  return nfc_event_eventLogger;
}
HalEventLogger& HalEventLogger::log() {
  struct timespec tv;
  clock_gettime(CLOCK_REALTIME, &tv);
  time_t rawtime = tv.tv_sec;
  struct tm* timeinfo;
  char buffer[TIMESTAMP_BUFFER_SIZE];
  char timestamp[TIMESTAMP_BUFFER_SIZE];
  timeinfo = localtime(&rawtime);
  int milliseconds = tv.tv_nsec / 1000000;
  strftime(buffer, sizeof(buffer), "%m-%d %H:%M:%S", timeinfo);
  sprintf(timestamp, "%s.%03d", buffer, milliseconds);
  if (ss.str().size() > HAL_MEM_BUFFER_SIZE) {
    std::string currentString = ss.str();
    currentString =
        currentString.substr(currentString.size() - HAL_MEM_BUFFER_SIZE);
    std::ostringstream newBuffer;
    newBuffer << currentString;
    newBuffer << timestamp << ": ";
    ss.str("");
    ss.clear();
    ss << newBuffer.str();
  } else {
    ss << timestamp << ": ";
  }
  return getInstance();
}

void HalEventLogger::initialize() {
  LOG(DEBUG) << __func__;
  unsigned long num = 0;
  char HalLogPath[256];

  if (GetNumValue(NAME_HAL_EVENT_LOG_DEBUG_ENABLED, &num, sizeof(num))) {
    logging_enabled = (num == 1) ? true : false;
  }
  LOG(INFO) << __func__ << " logging_enabled: " << logging_enabled;
  if (!logging_enabled) {
    return;
  }
  if (!GetStrValue(NAME_HAL_EVENT_LOG_STORAGE, (char*)HalLogPath,
                   sizeof(HalLogPath))) {
    LOG(WARNING) << __func__
                 << " HAL log path not found in conf. use default location "
                    "/data/vendor/nfc";
    strcpy(HalLogPath, "/data/vendor/nfc");
  }
  EventFilePath = HalLogPath;
  EventFilePath += "/hal_event_log.txt";
}

void HalEventLogger::store_log() {
  LOG(DEBUG) << __func__;
  if (!logging_enabled) return;
  std::ofstream logFile;
  if (std::filesystem::exists(EventFilePath) &&
      std::filesystem::file_size(EventFilePath) > HAL_LOG_FILE_SIZE) {
    logFile.open(EventFilePath, std::ios::out | std::ios::trunc);
  } else {
    logFile.open(EventFilePath, std::ios::app);
  }
  if (logFile.is_open()) {
    logFile << ss.rdbuf();
    logFile.close();
    ss.str("");
    ss.clear();
  } else {
    LOG(ERROR) << __func__ << " EventEventLogger: Log file " << EventFilePath
               << " couldn't be opened! errno: " << errno;
  }
}

void HalEventLogger::dump_log(int fd) {
  LOG(DEBUG) << __func__;
  if (!logging_enabled) return;
  std::ostringstream oss;
  if (std::filesystem::exists(EventFilePath) &&
      std::filesystem::file_size(EventFilePath) > 0) {
    std::ifstream readFile(EventFilePath);
    if (readFile.is_open()) {
      oss << readFile.rdbuf() << ss.str();
      readFile.close();
    } else {
      LOG(ERROR) << __func__ << " EventEventLogger: Failed to open log file "
                 << EventFilePath << " for reading!";
      oss << ss.str();
    }
  } else {
    LOG(INFO) << __func__ << " EventEventLogger: Log file " << EventFilePath
              << " not exists or no content";
    oss << ss.str();
  }

  dprintf(fd, "===== Nfc HAL Event Log =====\n");
  ::android::base::WriteStringToFd(oss.str(), fd);
  dprintf(fd, "===== Nfc HAL Event Log =====\n");
  fsync(fd);
}
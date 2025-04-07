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

#pragma once

#include <fstream>
#include <sstream>
#include <string>

class HalEventLogger {
 public:
  static HalEventLogger& getInstance();
  HalEventLogger& log();
  void dump_log(int fd);
  void initialize();
  void store_log();

  template <typename T>
  HalEventLogger& operator<<(const T& value) {
    ss << value;
    return *this;
  }
  HalEventLogger& operator<<(std::ostream& (*manip)(std::ostream&)) {
    if (manip == static_cast<std::ostream& (*)(std::ostream&)>(std::endl)) {
      ss << std::endl;
    }
    return *this;
  }

 private:
  HalEventLogger() {}
  HalEventLogger(const HalEventLogger&) = delete;
  HalEventLogger& operator=(const HalEventLogger&) = delete;
  std::stringstream ss;
  bool logging_enabled;
  std::string EventFilePath;
};
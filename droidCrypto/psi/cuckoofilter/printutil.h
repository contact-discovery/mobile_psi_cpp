/* Copyright (C) 2013, Carnegie Mellon University and Intel Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#ifndef CUCKOO_FILTER_PRINTUTIL_H_
#define CUCKOO_FILTER_PRINTUTIL_H_

#include <string>

namespace cuckoofilter {
class PrintUtil {
 public:
  static std::string bytes_to_hex(const char *data, size_t len) {
    std::string hexstr = "";
    static const char hexes[] = "0123456789ABCDEF ";

    for (size_t i = 0; i < len; i++) {
      unsigned char c = data[i];
      hexstr.push_back(hexes[c >> 4]);
      hexstr.push_back(hexes[c & 0xf]);
      hexstr.push_back(hexes[16]);
    }
    return hexstr;
  }

  static std::string bytes_to_hex(const std::string &s) {
    return bytes_to_hex((const char *)s.data(), s.size());
  }

 private:
  PrintUtil();
};  // class PrintUtil

}  // namespace cuckoofilter

#endif  // CUCKOO_FILTER_PRINTUTIL_H_

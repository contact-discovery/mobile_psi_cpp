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
 *
 *  Modified by Daniel Kales, 2019
 *  * added serialize/deserialize functions
 *  * added interface to get hasher parameters
 */
#ifndef CUCKOO_FILTER_CUCKOO_FILTER_H_
#define CUCKOO_FILTER_CUCKOO_FILTER_H_

#include <assert.h>
#include <sys/param.h>
#include <algorithm>

#include "debug.h"
#include "hashutil.h"
#include "packedtable.h"
#include "printutil.h"
#include "singletable.h"

namespace cuckoofilter {
// status returned by a cuckoo filter operation
enum Status {
  Ok = 0,
  NotFound = 1,
  NotEnoughSpace = 2,
  NotSupported = 3,
};

// maximum number of cuckoo kicks before claiming failure
const size_t kMaxCuckooCount = 500;

// A cuckoo filter class exposes a Bloomier filter interface,
// providing methods of Add, Delete, Contain. It takes three
// template parameters:
//   ItemType:  the type of item you want to insert
//   bits_per_item: how many bits each item is hashed into
//   TableType: the storage of table, SingleTable by default, and
// PackedTable to enable semi-sorting
template <typename ItemType, size_t bits_per_item,
          template <size_t> class TableType = SingleTable,
          typename HashFamily = TwoIndependentMultiplyShift>
class CuckooFilter {
  // Storage of items
  TableType<bits_per_item> *table_;

  // Number of items stored
  size_t num_items_;

  typedef struct {
    size_t index;
    uint32_t tag;
    bool used;
  } VictimCache;

  VictimCache victim_;

  HashFamily hasher_;

  inline size_t IndexHash(uint32_t hv) const {
    // table_->num_buckets is always a power of two, so modulo can be replaced
    // with
    // bitwise-and:
    return hv & (table_->NumBuckets() - 1);
  }

  inline uint32_t TagHash(uint32_t hv) const {
    uint32_t tag;
    tag = hv & ((1ULL << bits_per_item) - 1);
    tag += (tag == 0);
    return tag;
  }

  inline void GenerateIndexTagHash(const ItemType &item, size_t *index,
                                   uint32_t *tag) const {
    const uint64_t hash = hasher_(item);
    *index = IndexHash(hash >> 32);
    *tag = TagHash(hash);
  }

  inline size_t AltIndex(const size_t index, const uint32_t tag) const {
    // NOTE(binfan): originally we use:
    // index ^ HashUtil::BobHash((const void*) (&tag), 4)) & table_->INDEXMASK;
    // now doing a quick-n-dirty way:
    // 0x5bd1e995 is the hash constant from MurmurHash2
    return IndexHash((uint32_t)(index ^ (tag * 0x5bd1e995)));
  }

  Status AddImpl(const size_t i, const uint32_t tag);

  // load factor is the fraction of occupancy
  double LoadFactor() const { return 1.0 * Size() / table_->SizeInTags(); }

  double BitsPerItem() const { return 8.0 * table_->SizeInBytes() / Size(); }

 public:
  explicit CuckooFilter(const size_t max_num_keys)
      : num_items_(0), victim_(), hasher_() {
    size_t assoc = 3;
    size_t num_buckets =
        upperpower2(std::max<uint64_t>(1, max_num_keys / assoc));
    double frac = (double)max_num_keys / num_buckets / assoc;
    if (frac > 0.96) {
      num_buckets <<= 1;
    }
    victim_.used = false;
    table_ = new TableType<bits_per_item>(num_buckets);
  }

  ~CuckooFilter() { delete table_; }

  void SetTwoIndependentMultiplyShiftParams(
      std::vector<unsigned __int128> params) {
    hasher_.setParams(params);
  }
  std::vector<unsigned __int128> GetTwoIndependentMultiplyShiftParams() {
    return hasher_.getParams();
  };
  // Add an item to the filter.
  Status Add(const ItemType &item);

  // Report if the item is inserted, with false positive rate.
  Status Contain(const ItemType &item) const;

  // Delete an key from the filter
  Status Delete(const ItemType &item);

  /* methods for providing stats  */
  // summary infomation
  std::string Info() const;

  std::vector<uint8_t> serialize() const;
  void deserialize(const std::vector<uint8_t> &data);
  std::vector<uint8_t> serialize(size_t part_size, size_t start) const;
  void deserialize(const std::vector<uint8_t> &data, size_t start);

  // number of current inserted items;
  size_t Size() const { return num_items_; }

  // size of the filter in bytes.
  size_t SizeInBytes() const { return table_->SizeInBytes(); }

  // size of the filter in tags.
  size_t SizeInTags() const { return table_->SizeInTags(); }
};

template <typename ItemType, size_t bits_per_item,
          template <size_t> class TableType, typename HashFamily>
Status CuckooFilter<ItemType, bits_per_item, TableType, HashFamily>::Add(
    const ItemType &item) {
  size_t i;
  uint32_t tag;

  if (victim_.used) {
    return NotEnoughSpace;
  }

  GenerateIndexTagHash(item, &i, &tag);
  return AddImpl(i, tag);
}

template <typename ItemType, size_t bits_per_item,
          template <size_t> class TableType, typename HashFamily>
Status CuckooFilter<ItemType, bits_per_item, TableType, HashFamily>::AddImpl(
    const size_t i, const uint32_t tag) {
  size_t curindex = i;
  uint32_t curtag = tag;
  uint32_t oldtag;

  for (uint32_t count = 0; count < kMaxCuckooCount; count++) {
    bool kickout = count > 0;
    oldtag = 0;
    if (table_->InsertTagToBucket(curindex, curtag, kickout, oldtag)) {
      num_items_++;
      return Ok;
    }
    if (kickout) {
      curtag = oldtag;
    }
    curindex = AltIndex(curindex, curtag);
  }

  victim_.index = curindex;
  victim_.tag = curtag;
  victim_.used = true;
  return Ok;
}

template <typename ItemType, size_t bits_per_item,
          template <size_t> class TableType, typename HashFamily>
Status CuckooFilter<ItemType, bits_per_item, TableType, HashFamily>::Contain(
    const ItemType &key) const {
  bool found = false;
  size_t i1, i2;
  uint32_t tag;

  GenerateIndexTagHash(key, &i1, &tag);
  i2 = AltIndex(i1, tag);

  assert(i1 == AltIndex(i2, tag));

  found = victim_.used && (tag == victim_.tag) &&
          (i1 == victim_.index || i2 == victim_.index);

  if (found || table_->FindTagInBuckets(i1, i2, tag)) {
    return Ok;
  } else {
    return NotFound;
  }
}

template <typename ItemType, size_t bits_per_item,
          template <size_t> class TableType, typename HashFamily>
Status CuckooFilter<ItemType, bits_per_item, TableType, HashFamily>::Delete(
    const ItemType &key) {
  size_t i1, i2;
  uint32_t tag;

  GenerateIndexTagHash(key, &i1, &tag);
  i2 = AltIndex(i1, tag);

  if (table_->DeleteTagFromBucket(i1, tag)) {
    num_items_--;
    goto TryEliminateVictim;
  } else if (table_->DeleteTagFromBucket(i2, tag)) {
    num_items_--;
    goto TryEliminateVictim;
  } else if (victim_.used && tag == victim_.tag &&
             (i1 == victim_.index || i2 == victim_.index)) {
    // num_items_--;
    victim_.used = false;
    return Ok;
  } else {
    return NotFound;
  }
TryEliminateVictim:
  if (victim_.used) {
    victim_.used = false;
    size_t i = victim_.index;
    uint32_t tag = victim_.tag;
    AddImpl(i, tag);
  }
  return Ok;
}

template <typename ItemType, size_t bits_per_item,
          template <size_t> class TableType, typename HashFamily>
std::string CuckooFilter<ItemType, bits_per_item, TableType, HashFamily>::Info()
    const {
  std::stringstream ss;
  ss << "CuckooFilter Status:\n"
     << "\t\t" << table_->Info() << "\n"
     << "\t\tKeys stored: " << Size() << "\n"
     << "\t\tLoad factor: " << LoadFactor() << "\n"
     << "\t\tHashtable size: " << (table_->SizeInBytes() >> 10) << " KB\n";
  if (Size() > 0) {
    ss << "\t\tbit/key:   " << BitsPerItem() << "\n";
  } else {
    ss << "\t\tbit/key:   N/A\n";
  }
  return ss.str();
}
template <typename ItemType, size_t bits_per_item,
          template <size_t> class TableType, typename HashFamily>
std::vector<uint8_t> CuckooFilter<ItemType, bits_per_item, TableType,
                                  HashFamily>::serialize() const {
  static_assert(bits_per_item == 32,
                "serialize only implemented for 32 bit fingerprints");
  uint64_t size = table_->SizeInTags();
  std::vector<uint8_t> positions(16 + (size + 7) / 8, 0);
  positions.reserve(positions.size() + table_->SizeInTags() * LoadFactor() * 4);
  *(uint64_t *)(&positions[0]) = num_items_;
  *(uint64_t *)(&positions[8]) = size;
  uint32_t *buckets = (uint32_t *)table_->Data();
  for (uint64_t i = 0; i < size; i++, buckets++) {
    if (*buckets != 0) {
      positions[16 + (i / 8)] |= 1 << (i % 8);
      positions.insert(positions.end(), (uint8_t *)buckets,
                       ((uint8_t *)buckets) + 4);
    }
  }
  return positions;
}
template <typename ItemType, size_t bits_per_item,
          template <size_t> class TableType, typename HashFamily>
void CuckooFilter<ItemType, bits_per_item, TableType, HashFamily>::deserialize(
    const std::vector<uint8_t> &positions) {
  static_assert(bits_per_item == 32,
                "serialize only implemented for 32 bit fingerprints");
  num_items_ = *(uint64_t *)(&positions[0]);
  uint64_t size = *(uint64_t *)(&positions[8]);
  uint32_t *buckets = (uint32_t *)table_->Data();
  uint64_t counter = 0;
  for (uint64_t i = 0; i < size; i++, buckets++) {
    if (positions[16 + (i / 8)] & (1 << (i % 8))) {
      *buckets = *(uint32_t *)(&positions[16 + (size + 7) / 8 + counter * 4]);
      counter++;
    }
  }
}

template <typename ItemType, size_t bits_per_item,
          template <size_t> class TableType, typename HashFamily>
std::vector<uint8_t> CuckooFilter<ItemType, bits_per_item, TableType,
                                  HashFamily>::serialize(size_t part_size,
                                                         size_t start) const {
  static_assert(bits_per_item == 32,
                "serialize only implemented for 32 bit fingerprints");
  uint64_t size = MIN(part_size, table_->SizeInTags() - start);
  std::vector<uint8_t> positions(16 + (size + 7) / 8, 0);
  positions.reserve(positions.size() + size * LoadFactor() * 4);
  *(uint64_t *)(&positions[0]) = num_items_;
  *(uint64_t *)(&positions[8]) = size;
  uint32_t *buckets = (uint32_t *)table_->Data();
  buckets += start;
  for (uint64_t i = 0; i < size; i++, buckets++) {
    if (*buckets != 0) {
      positions[16 + ((i) / 8)] |= 1 << ((i) % 8);
      positions.insert(positions.end(), (uint8_t *)buckets,
                       ((uint8_t *)buckets) + 4);
    }
  }
  return positions;
}
template <typename ItemType, size_t bits_per_item,
          template <size_t> class TableType, typename HashFamily>
void CuckooFilter<ItemType, bits_per_item, TableType, HashFamily>::deserialize(
    const std::vector<uint8_t> &positions, size_t start) {
  static_assert(bits_per_item == 32,
                "serialize only implemented for 32 bit fingerprints");
  num_items_ = *(uint64_t *)(&positions[0]);
  uint64_t size = *(uint64_t *)(&positions[8]);
  uint32_t *buckets = (uint32_t *)table_->Data();
  buckets += start;
  uint64_t counter = 0;
  for (uint64_t i = 0; i < size; i++, buckets++) {
    if (positions[16 + ((i) / 8)] & (1 << ((i) % 8))) {
      *buckets = *(uint32_t *)(&positions[16 + (size + 7) / 8 + counter * 4]);
      counter++;
    }
  }
}
}  // namespace cuckoofilter
#endif  // CUCKOO_FILTER_CUCKOO_FILTER_H_

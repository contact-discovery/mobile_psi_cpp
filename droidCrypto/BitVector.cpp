#include <droidCrypto/BitVector.h>
#include <sstream>
#include <cstring>
#include <iomanip>

/** Array which stores the bytes which are reversed. For example, the hexadecimal 0x01 is when reversed becomes 0x80.  */
static const uint8_t REVERSE_BYTE_ORDER[256] = { 0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0, 0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8,
                                                 0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8, 0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4, 0x0C, 0x8C,
                                                 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC, 0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2,
                                                 0x72, 0xF2, 0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA, 0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96,
                                                 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6, 0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE, 0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1,
                                                 0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1, 0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9, 0x05, 0x85,
                                                 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5, 0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD,
                                                 0x7D, 0xFD, 0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3, 0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B,
                                                 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB, 0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7, 0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF,
                                                 0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF };
namespace droidCrypto {


    BitVector::BitVector(std::string data)
        :
        mData(nullptr),
        mNumBits(0),
        mAllocBytes(0)
    {
        fromString(data);

    }

    BitVector::BitVector(BitVector&& rref)
        :
        mData(rref.mData),
        mNumBits(rref.mNumBits),
        mAllocBytes(rref.mAllocBytes)
    {
        rref.mData = nullptr;
        rref.mAllocBytes = 0;
        rref.mNumBits = 0;
    }

    BitVector::BitVector(uint8_t * data, uint64_t length)
        :
        mData(nullptr),
        mNumBits(0),
        mAllocBytes(0)
    {
        append(data, length, 0);
    }

    void BitVector::assign(const block& b)
    {
        reset(128);
        memcpy(mData, (uint8_t*)&(b), sizeBytes());
    }

    void BitVector::assign(const BitVector& K)
    {
        reset(K.mNumBits);
        memcpy(mData, K.mData, sizeBytes());
    }

    void BitVector::append(uint8_t* data, uint64_t length, uint64_t offset)
    {

        auto bitIdx = mNumBits;
        auto destOffset = mNumBits % 8;
        auto destIdx = mNumBits / 8;
        auto srcOffset = offset % 8;
        auto srcIdx = offset / 8;
        auto byteLength = (length + 7) / 8;

        resize(mNumBits + length);

        static const uint8_t masks[8] = { 1,2,4,8,16,32,64,128 };

        // if we have to do bit shifting, copy bit by bit
        if (srcOffset || destOffset)
        {

            //TODO("make this more efficient");
            for (uint64_t i = 0; i < length; ++i, ++bitIdx, ++offset)
            {
                uint8_t bit = data[offset / 8] & masks[offset % 8];
                (*this)[bitIdx] = bit;
            }
        }
        else
        {
            memcpy(mData + destIdx, data + srcIdx, byteLength);
        }
    }
    void BitVector::appendREV(uint8_t* data, uint64_t length, uint64_t offset)
    {

        auto destOffset = mNumBits % 8;
        auto destIdx = mNumBits / 8;
        auto srcOffset = offset % 8;
        auto srcIdx = offset / 8;
        auto byteLength = (length + 7) / 8;

        resize(mNumBits + length);


        // if we have to do bit shifting, copy bit by bit
        if (srcOffset || destOffset)
        {
            throw std::runtime_error("this is not supported with appendREV yet");
        }
        else
        {
            for(size_t i = 0; i < byteLength; i++) {
               mData[destIdx+i] = REVERSE_BYTE_ORDER[data[srcIdx+i]];
            }
        }
    }

    void BitVector::reserve(uint64_t bits)
    {
        uint64_t curBits = mNumBits;
        resize(bits);

        mNumBits = curBits;
    }

    void BitVector::resize(uint64_t newSize)
    {
        uint64_t new_nbytes = (newSize + 7) / 8;

        if (mAllocBytes < new_nbytes)
        {
            uint8_t* tmp = new uint8_t[new_nbytes]();
            mAllocBytes = new_nbytes;

            memcpy(tmp, mData, sizeBytes());

            if (mData)
                delete[] mData;

            mData = tmp;
        }
        mNumBits = newSize;
    }

    void BitVector::reset(uint64_t new_nbits)
    {
        uint64_t newSize = (new_nbits + 7) / 8;

        if (newSize > mAllocBytes)
        {
            if (mData)
                delete[] mData;

            mData = new uint8_t[newSize]();
            mAllocBytes = newSize;
        }
        else
        {
            memset(mData, 0, newSize);
        }

        mNumBits = new_nbits;
    }

    void BitVector::copy(const BitVector& src, uint64_t idx, uint64_t length)
    {
        resize(0);
        append(src.mData, length, idx);
    }


    BitVector& BitVector::operator=(const BitVector& K)
    {
        if (this != &K) { assign(K); }
        return *this;
    }

    uint8_t BitVector::get8BitsAligned(const uint64_t idx) const
    {
        if (idx >= mNumBits || idx % 8 != 0) throw std::runtime_error("rt error at " LOCATION);
        return mData[(idx / 8)];
    }

    BitReference BitVector::operator[](const uint64_t idx) const
    {
        if (idx >= mNumBits) throw std::runtime_error("rt error at " LOCATION);
        return BitReference(mData + (idx / 8), static_cast<uint8_t>(idx % 8));
    }

//    std::ostream& operator<<(std::ostream& out, const BitReference& bit)
//    {
//        out << (u32)bit;
//        return out;
//    }


    BitVector BitVector::operator^(const BitVector& B)const
    {
        BitVector ret(*this);

        ret ^= B;

        return ret;
    }

    BitVector BitVector::operator&(const BitVector & B) const
    {
        BitVector ret(*this);

        ret &= B;

        return ret;
    }

    BitVector BitVector::operator|(const BitVector & B) const
    {
        BitVector ret(*this);

        ret |= B;

        return ret;
    }

    BitVector BitVector::operator~() const
    {
        BitVector ret(*this);

        for (uint64_t i = 0; i < sizeBytes(); i++)
            ret.mData[i] = ~mData[i];

        return ret;
    }


    void BitVector::operator&=(const BitVector & A)
    {
        for (uint64_t i = 0; i < sizeBytes(); i++)
        {
            mData[i] &= A.mData[i];
        }
    }

    void BitVector::operator|=(const BitVector & A)
    {
        for (uint64_t i = 0; i < sizeBytes(); i++)
        {
            mData[i] |= A.mData[i];
        }
    }

    void BitVector::operator^=(const BitVector& A)
    {
        if (mNumBits != A.mNumBits) throw std::runtime_error("rt error at " LOCATION);
        for (uint64_t i = 0; i < sizeBytes(); i++)
        {
            mData[i] ^= A.mData[i];
        }
    }
    void BitVector::fromString(std::string data)
    {
        resize(data.size());

        for (uint64_t i = 0; i < size(); ++i)
        {
#ifndef NDEBUG
            if (uint8_t(data[i] - '0') > 1) throw std::runtime_error("");
#endif

            (*this)[i] = data[i] - '0';
        }

    }


    bool BitVector::equals(const BitVector& rhs) const
    {

        if (mNumBits != rhs.mNumBits)
            return false;

        uint64_t lastByte = sizeBytes() - 1;
        for (uint64_t i = 0; i < lastByte; i++)
        {
            if (mData[i] != rhs.mData[i]) { return false; }
        }

        // numBits = 4
        // 00001010
        // 11111010
        //     ^^^^ compare these

        uint64_t rem = mNumBits & 7;
        uint8_t mask = ((uint8_t)-1) >> (8 - rem);
        if ((mData[lastByte] & mask) != (rhs.mData[lastByte] & mask))
            return false;

        return true;
    }

    BitIterator BitVector::begin() const
    {
        return BitIterator(mData, 0);
    }

    BitIterator BitVector::end() const
    {
        return BitIterator(mData + (mNumBits >> 3), mNumBits & 7);
    }

    void BitVector::nChoosek(uint64_t n, uint64_t k, PRNG & prng)
    {
        reset(n);
        // wiki: Reservoir sampling


        memset(data(), uint8_t(-1), k / 8);
        for (uint64_t i = k - 1; i >= (k & (~3)); --i)
            (*this)[i] = 1;


        for (uint64_t i = k; i < n; ++i)
        {
            uint64_t j = prng.get<uint64_t>() % i;

            if (j < k)
            {
                uint8_t b = (*this)[j];
                (*this)[j] = 0;
                (*this)[i] = b;
            }
        }
    }

    uint64_t BitVector::hammingWeight() const
    {
        //TODO("make sure top bits are cleared");
        uint64_t ham(0);
        for (uint64_t i = 0; i < sizeBytes(); ++i)
        {
            uint8_t b = data()[i];
            while (b)
            {
                ++ham;
                b &= b - 1;
            }
        }
        return ham;
    }


    uint8_t BitVector::parity()
    {
        uint8_t bit = 0;

        uint64_t lastByte = mNumBits / 8;
        for (uint64_t i = 0; i < lastByte; i++)
        {

            bit ^= (mData[i] & 1); // bit 0
            bit ^= ((mData[i] >> 1) & 1); // bit 1
            bit ^= ((mData[i] >> 2) & 1); // bit 2
            bit ^= ((mData[i] >> 3) & 1); // bit 3
            bit ^= ((mData[i] >> 4) & 1); // bit 4
            bit ^= ((mData[i] >> 5) & 1); // bit 5
            bit ^= ((mData[i] >> 6) & 1); // bit 6
            bit ^= ((mData[i] >> 7) & 1); // bit 7
        }

        uint64_t lastBits = mNumBits - lastByte * 8;
        for (uint64_t i = 0; i < lastBits; i++)
        {
            bit ^= (mData[lastByte] >> i) & 1;
        }

        return bit;
    }
    void BitVector::pushBack(uint8_t bit)
    {
        if (size() == capacity())
        {
            reserve(size() * 2);
        }

        resize(size() + 1);

        back() = bit;
    }
    void BitVector::randomize(PRNG& G)
    {
        G.get(mData, sizeBytes());
    }

    std::string BitVector::hex() const
    {
        std::stringstream s;

        s << std::hex;
        for (unsigned int i = 0; i < sizeBytes(); i++)
        {
            s << std::setw(2) << std::setfill('0') << int(mData[i]);
        }

        return s.str();
    }

    std::string BitVector::hexREV() const
    {
        std::stringstream s;

        s << std::hex;
        for (uint64_t i = sizeBytes(); i; i--)
        {
            s << std::setw(2) << std::setfill('0') << int(mData[i-1]);
        }

        return s.str();
    }

    std::ostream & operator<<(std::ostream & out, const BitVector & vec)
    {
        //for (i64 i = static_cast<i64>(val.size()) - 1; i > -1; --i)
        //{
        //    in << (u32)val[i];
        //}

        //return in;
        for (uint64_t i = 0; i < vec.size(); ++i)
        {
            out << char('0' + (uint8_t)vec[i]);
        }

        return out;
    }

}

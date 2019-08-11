#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <droidCrypto/Defines.h>
#include <string>
namespace droidCrypto
{

    class PRNG;
    class LinearCode
    {
    public:
        static const uint16_t sLinearCodePlainTextMaxSize;

        LinearCode();
        ~LinearCode();
        LinearCode(const LinearCode& cp);


        void loadTxtFile(const std::string& fileName);
        void loadTxtFile(std::istream& in);

        void load(const unsigned char* data, uint64_t size);

        void loadBinFile(const std::string& fileName);
        void loadBinFile(std::istream& in);

        // outputs a c file contains an char array containing the binary data. e.g. bch511.h
        void writeBinCppFile(const std::string& fileName, const std::string & name);

        void writeBinFile(const std::string& fileName);
        void writeBinFile(std::ostream& out);



        void writeTextFile(const std::string& fileName);
        void writeTextFile(std::ostream& out);



        void random(PRNG& prng, uint64_t inputSize, uint64_t outputSize);

        void generateMod8Table();

        uint64_t mU8RowCount, mPow2CodeSize, mPlaintextU8Size;
        uint64_t mCodewordBitSize;
        std::vector<block> mG;
        std::vector<block> mG8;

        inline uint64_t codewordBitSize() const
        {
            return mCodewordBitSize;
        }

        inline uint64_t codewordBlkSize() const
        {
            return (codewordBitSize() + 127) / 128;
        }
        inline uint64_t plaintextBitSize() const
        {
            return mG.size() / codewordBlkSize();
        }
        inline uint64_t plaintextBlkSize() const
        {
            return (plaintextBitSize() + 127) / 128;
        }

        inline uint64_t plaintextU8Size() const
        {
            return mPlaintextU8Size;
        }

        inline uint64_t codewordU8Size() const
        {
            return (codewordBitSize() + 7) / 8;
        }



        void encode(const span<block>& plaintext,const span<block>& codeword);
        void encode(const span<uint8_t>& plaintext, const span<uint8_t>& codeword);
        void encode(uint8_t* plaintext, uint8_t* codeword);

        void encode_bch511(uint8_t* plaintext, uint8_t* codeword);

    };

}

#pragma once

#include <jni.h>
#include <droidCrypto/gc/circuits/Circuit.h>

#define AES_STATE_COLS 4
#define AES_STATE_ROWS 4
#define AES_ROUNDS 10
#define AES_STATE_SIZE 16
#define AES_BYTES 16
#define AES_EXP_KEY_BITS 1408
#define AES_EXP_KEY_BYTES AES_EXP_KEY_BITS/8

namespace droidCrypto {
    class GCEnv;

    class AESCircuit : public Circuit{
        public:
            AESCircuit(ChannelWrapper& chan) : Circuit(chan, 1408, 128, 128) {}

        protected:

            std::vector<WireLabel> computeFunction(const std::vector<WireLabel>& inputA, const std::vector<WireLabel>& inputB, GCEnv& env) override;
            std::vector<WireLabel> AddAESRoundKey(const std::vector<WireLabel>& val, const std::vector<WireLabel>& key, size_t keyaddr, GCEnv& env);
            std::vector<WireLabel> Mul2(std::vector<WireLabel>& element, GCEnv& env);
            std::vector<std::vector<WireLabel> > PutAESMixColumnGate(std::vector<std::vector<WireLabel> >& rows, GCEnv& env);
            std::vector<WireLabel> PutAESSBoxGate(std::vector<WireLabel>& input, GCEnv& env);

    };

    class SIMDAESCircuit : public SIMDCircuit{
        public:
            SIMDAESCircuit(ChannelWrapper& chan) : SIMDCircuit(chan, 1408, 128, 128) {}

        protected:

            std::vector<SIMDWireLabel> computeFunction(const std::vector<WireLabel>& inputA, const std::vector<SIMDWireLabel>& inputB, SIMDGCEnv& env) override;
            std::vector<SIMDWireLabel> AddAESRoundKey(const std::vector<SIMDWireLabel>& val, const std::vector<WireLabel>& key, size_t keyaddr, SIMDGCEnv& env);
            std::vector<SIMDWireLabel> Mul2(std::vector<SIMDWireLabel>& element, SIMDGCEnv& env);
            std::vector<std::vector<SIMDWireLabel> > PutAESMixColumnGate(std::vector<std::vector<SIMDWireLabel> >& rows, SIMDGCEnv& env);
            std::vector<SIMDWireLabel> PutAESSBoxGate(std::vector<SIMDWireLabel>& input, SIMDGCEnv& env);

    };

    class SIMDAESCircuitPhases : public SIMDCircuitPhases{
    public:
        SIMDAESCircuitPhases(ChannelWrapper& chan) : SIMDCircuitPhases(chan, 1408, 128, 128) {}

    protected:

        std::vector<SIMDWireLabel> computeFunction(const std::vector<WireLabel>& inputA, const std::vector<SIMDWireLabel>& inputB, SIMDGCEnv& env) override;
        std::vector<SIMDWireLabel> AddAESRoundKey(const std::vector<SIMDWireLabel>& val, const std::vector<WireLabel>& key, size_t keyaddr, SIMDGCEnv& env);
        std::vector<SIMDWireLabel> Mul2(std::vector<SIMDWireLabel>& element, SIMDGCEnv& env);
        std::vector<std::vector<SIMDWireLabel> > PutAESMixColumnGate(std::vector<std::vector<SIMDWireLabel> >& rows, SIMDGCEnv& env);
        std::vector<SIMDWireLabel> PutAESSBoxGate(std::vector<SIMDWireLabel>& input, SIMDGCEnv& env);

    };
}

extern "C"
JNIEXPORT void JNICALL Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_garbleAES(
    JNIEnv *env, jobject /*this*/, jobject channel);

extern "C"
JNIEXPORT void JNICALL Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_evaluateAES(
    JNIEnv *env, jobject /*this*/, jobject channel);

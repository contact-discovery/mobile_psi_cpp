#pragma once

#include <jni.h>
#include <droidCrypto/gc/circuits/Circuit.h>

namespace droidCrypto {
    class GCEnv;
    class SIMDGCEnv;

    class TestCircuit : public Circuit{
        public:
            TestCircuit(ChannelWrapper& chan) : Circuit(chan, 1, 1, 1) {}

        protected:

            std::vector<WireLabel> computeFunction(const std::vector<WireLabel>& inputA, const std::vector<WireLabel>& inputB, GCEnv& env) override;

    };

#define BIT_NUMBER (1)
    class SIMDTestCircuit : public SIMDCircuit{
    public:
        SIMDTestCircuit(ChannelWrapper& chan) : SIMDCircuit(chan, BIT_NUMBER, BIT_NUMBER, 1) {}

    protected:

        std::vector<SIMDWireLabel> computeFunction(const std::vector<SIMDWireLabel>& inputA, const std::vector<SIMDWireLabel>& inputB, SIMDGCEnv& env) override;

    };
}

extern "C"
JNIEXPORT void JNICALL Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_garble(
    JNIEnv *env, jobject /*this*/, jobject channel);

extern "C"
JNIEXPORT void JNICALL Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_evaluate(
    JNIEnv *env, jobject /*this*/, jobject channel);

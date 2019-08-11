#include <droidCrypto/gc/circuits/TestCircuit.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/utils/Log.h>
#include <droidCrypto/BitVector.h>
#include <droidCrypto/gc/HalfGate.h>
#include <droidCrypto/gc/WireLabel.h>
#include <assert.h>


namespace droidCrypto {

    std::vector<WireLabel> TestCircuit::computeFunction(const std::vector<WireLabel>& inputA, const std::vector<WireLabel>& inputB, GCEnv& env) {
       std::vector<WireLabel> outputs;
       outputs.push_back(env.AND(inputA[0], inputB[0]));
       return outputs;
    }

    std::vector<SIMDWireLabel>
    SIMDTestCircuit::computeFunction(const std::vector<SIMDWireLabel> &inputA,
                                     const std::vector<SIMDWireLabel> &inputB, SIMDGCEnv &env) {

        assert(inputA.size() == BIT_NUMBER);
        assert(inputB.size() == BIT_NUMBER);

        for(const SIMDWireLabel& wl : inputA) {
            for(size_t i = 0; i < wl.bytes.size(); i++) {
                BitVector a;
                a.assign(wl.bytes[i]);
                Log::v("GC", "A%d: %s", i, a.hex().c_str());
            }
        }

        for(const SIMDWireLabel& wl : inputB) {
            for(size_t i = 0; i < wl.bytes.size(); i++) {
                BitVector a;
                a.assign(wl.bytes[i]);
                Log::v("GC", "B%d: %s", i, a.hex().c_str());
            }
        }

        SIMDWireLabel a = env.AND(inputA[0], inputB[0]);
//        for(int i = 1; i < BIT_NUMBER; i++) {
//            SIMDWireLabel b = env.XOR(inputA[i], inputB[i]);
//            a = env.AND(a, b);
//        }
        std::vector<SIMDWireLabel> outputs;
        outputs.push_back(a);
        return outputs;
    }
}

void Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_garble(
    JNIEnv *env, jobject /*this*/, jobject channel) {

//    droidCrypto::JavaChannelWrapper chan(env, channel);
    droidCrypto::CSocketChannel chan("127.0.0.1", 1234, 1);
    droidCrypto::BitVector a;
    for(int i = 0; i < BIT_NUMBER; i++)
        a.pushBack(0);
    droidCrypto::BitVector b;
    for(int i = 0; i < BIT_NUMBER; i++)
        b.pushBack(1);

//    droidCrypto::TestCircuit circ(chan);
//    circ.garble(a);
//    circ.garble(b);
//    circ.garble(a);
//    circ.garble(b);

    std::vector<droidCrypto::BitVector> aa;
    aa.push_back(a);
    aa.push_back(b);
    aa.push_back(a);
    aa.push_back(b);
    droidCrypto::SIMDTestCircuit circ(chan);
    circ.garbleSIMD(aa);

}

void Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_evaluate(
    JNIEnv *env, jobject /*this*/, jobject channel) {

//    droidCrypto::JavaChannelWrapper chan(env, channel);
    droidCrypto::CSocketChannel chan("127.0.0.1", 1234, 0);
    droidCrypto::BitVector a;
    for(int i = 0; i < BIT_NUMBER; i++)
        a.pushBack(0);
    droidCrypto::BitVector b;
    for(int i = 0; i < BIT_NUMBER; i++)
        b.pushBack(1);

//    droidCrypto::TestCircuit circ(chan);
//    droidCrypto::BitVector o00 = circ.evaluate(a);
//    droidCrypto::BitVector o10 = circ.evaluate(a);
//    droidCrypto::BitVector o01 = circ.evaluate(b);
//    droidCrypto::BitVector o11 = circ.evaluate(b);
    std::vector<droidCrypto::BitVector> aa;
    aa.push_back(a);
    aa.push_back(a);
    aa.push_back(b);
    aa.push_back(b);
    droidCrypto::SIMDTestCircuit circ(chan);
    std::vector<droidCrypto::BitVector> outputs = circ.evaluateSIMD(aa);

    for(int i = 0; i < 4; i++)
        droidCrypto::Log::v("GC", "tt%d: %s", i, outputs[i].hex().c_str());

}

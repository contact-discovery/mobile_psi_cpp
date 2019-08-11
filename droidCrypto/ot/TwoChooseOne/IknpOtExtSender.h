#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include <droidCrypto/ot/TwoChooseOne/OTExtInterface.h>
#include <droidCrypto/BitVector.h>
#include <droidCrypto/PRNG.h>

#include <jni.h>
#include <array>

namespace droidCrypto {

    class IknpOtExtSender :
        public OtExtSender
    {
    public:

        virtual ~IknpOtExtSender() {}

        std::array<PRNG, gOtExtBaseOtCount> mGens;
        BitVector mBaseChoiceBits;
        std::unique_ptr<OtExtSender> split() override;

        bool hasBaseOts() const override
        {
            return mBaseChoiceBits.size() > 0;
        }

        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices) override;


        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            ChannelWrapper& chan) override;

    };
}

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_example_mobile_1psi_droidCrypto_OT_IknpOTExtSender
 * Method:    init
 * Signature: (Ljava/nio/ByteBuffer;byte])J
 */
JNIEXPORT jlong JNICALL Java_com_example_mobile_1psi_droidCrypto_OT_IknpOTExtSender_init
  (JNIEnv *, jobject, jobject, jbyteArray);

/*
 * Class:     com_example_mobile_1psi_droidCrypto_OT_IknpOTExtSender
 * Method:    send
 * Signature: (JLjava/nio/ByteBuffer;Lcom/example/mobile_1psi/droidCrypto/Networking/Channel;)V
 */
JNIEXPORT void JNICALL Java_com_example_mobile_1psi_droidCrypto_OT_IknpOTExtSender_send
  (JNIEnv *, jobject, jlong, jobject, jobject);

/*
 * Class:     com_example_mobile_1psi_droidCrypto_OT_IknpOTExtSender
 * Method:    deleteNativeObj
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_example_mobile_1psi_droidCrypto_OT_IknpOTExtSender_deleteNativeObj
  (JNIEnv *, jobject, jlong);


JNIEXPORT void JNICALL Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_IKNPSend(JNIEnv*, jobject);

#ifdef __cplusplus
}
#endif

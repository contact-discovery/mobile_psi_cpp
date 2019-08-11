#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <droidCrypto/ot/TwoChooseOne/OTExtInterface.h>
#include <array>
#include <droidCrypto/PRNG.h>

namespace droidCrypto
{

    class IknpDotExtReceiver :
        public OtExtReceiver
    {
    public:
        IknpDotExtReceiver()
            :mHasBase(false)
        {}

        bool hasBaseOts() const override
        {
            return mHasBase;
        }

        //LinearCode mCode;
        bool mHasBase;
        std::vector<std::array<PRNG, 2>> mGens;

        void setBaseOts(
            span<std::array<block, 2>> baseSendOts)override;


        std::unique_ptr<OtExtReceiver> split() override;

        void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            ChannelWrapper& chl/*,
            std::atomic<u64>& doneIdx*/)override;


    };

}

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_example_mobile_1psi_droidCrypto_OT_IknpDoTExtReceiver
 * Method:    init
 * Signature: (Ljava/nio/ByteBuffer;)J
 */
JNIEXPORT jlong JNICALL Java_com_example_mobile_1psi_droidCrypto_OT_IknpDoTExtReceiver_init
        (JNIEnv *, jobject, jobject);

/*
 * Class:     com_example_mobile_1psi_droidCrypto_OT_IknpOTExtReceiver
 * Method:    recv
 * Signature: (JLjava/nio/ByteBuffer;Ljava/nio/ByteBuffer;Lcom/example/mobile_1psi/droidCrypto/Networking/Channel;)V
 */
JNIEXPORT void JNICALL Java_com_example_mobile_1psi_droidCrypto_OT_IknpDoTExtReceiver_recv
        (JNIEnv *, jobject, jlong, jobject, jbyteArray, jobject);

/*
 * Class:     com_example_mobile_1psi_droidCrypto_OT_IknpOTExtReceiver
 * Method:    deleteNativeObj
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_example_mobile_1psi_droidCrypto_OT_IknpDoTExtReceiver_deleteNativeObj
        (JNIEnv *, jobject, jlong);


JNIEXPORT void JNICALL Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_IKNPDotRecv(JNIEnv*, jobject);

#ifdef __cplusplus
}
#endif

#pragma once

#include <droidCrypto/Defines.h>
#include <droidCrypto/BitVector.h>
#include <droidCrypto/Curve.h>
#include <droidCrypto/ot/TwoChooseOne/OTExtInterface.h>
#include <jni.h>

namespace droidCrypto {
    class ChannelWrapper;

    class NaorPinkas : public OtSender, public OtReceiver {

    public:
        NaorPinkas() = default;

        virtual void receive(const BitVector& choices, span<block> messages, PRNG& prng, ChannelWrapper& chan);
        virtual void send(span<std::array<block, 2>> messages, PRNG& prng, ChannelWrapper& chan);
    };


    namespace NaorPinkasStandalone {
        typedef struct {
            EllipticCurve& curve;
            EccNumber& alpha;
            std::vector<EccPoint>& pC;
        } sendParams;

        void receive(const BitVector& choices, span<block> messages, PRNG& prng, const std::vector<uint8_t>& recvBuff,
                        std::vector<uint8_t>& sendBuff);

        void sendPart1(PRNG& prng, std::vector<uint8_t>& sendBuff, sendParams& curveParams);
        void sendPart2(span<std::array<block, 2>> messages, PRNG& prng, const std::vector<uint8_t>& recvBuff,
                        sendParams& curveParams);
    }
}

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_example_mobile_1psi_droidCrypto_OT_NaorPinkas
 * Method:    recv
 * Signature: (JLjava/nio/ByteBuffer;Ljava/nio/ByteBuffer;Lcom/example/mobile_1psi/droidCrypto/Networking/Channel;)V
 */
JNIEXPORT void JNICALL Java_com_example_mobile_1psi_droidCrypto_OT_NaorPinkas_recv
  (JNIEnv *, jobject, jobject, jbyteArray, jobject);

/*
 * Class:     com_example_mobile_1psi_droidCrypto_OT_NaorPinkas
 * Method:    send
 * Signature: (JLjava/nio/ByteBuffer;Lcom/example/mobile_1psi/droidCrypto/Networking/Channel;)V
 */
JNIEXPORT void JNICALL Java_com_example_mobile_1psi_droidCrypto_OT_NaorPinkas_send
  (JNIEnv *, jobject, jobject, jobject);

#ifdef __cplusplus
}
#endif

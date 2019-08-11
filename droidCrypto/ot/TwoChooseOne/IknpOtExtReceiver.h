#pragma once
// This file and the associated implementation has been placed in the public
// domain, waiving all copyright. No restrictions are placed on its use.
#include <droidCrypto/PRNG.h>
#include <droidCrypto/ot/TwoChooseOne/OTExtInterface.h>

#include <jni.h>
#include <array>

namespace droidCrypto {

class IknpOtExtReceiver : public OtExtReceiver {
 public:
  IknpOtExtReceiver() : mHasBase(false) {}

  virtual ~IknpOtExtReceiver() {}

  bool hasBaseOts() const override { return mHasBase; }

  bool mHasBase;
  std::array<std::array<PRNG, 2>, gOtExtBaseOtCount> mGens;

  void setBaseOts(span<std::array<block, 2>> baseSendOts) override;
  std::unique_ptr<OtExtReceiver> split() override;

  void receive(const BitVector &choices, span<block> messages, PRNG &prng,
               ChannelWrapper &chan) override;
};
}  // namespace droidCrypto

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_example_mobile_1psi_droidCrypto_OT_IknpOTExtReceiver
 * Method:    init
 * Signature: (Ljava/nio/ByteBuffer;)J
 */
JNIEXPORT jlong JNICALL
Java_com_example_mobile_1psi_droidCrypto_OT_IknpOTExtReceiver_init(JNIEnv *, jobject,
                                                              jobject);

/*
 * Class:     com_example_mobile_1psi_droidCrypto_OT_IknpOTExtReceiver
 * Method:    recv
 * Signature:
 * (JLjava/nio/ByteBuffer;Ljava/nio/ByteBuffer;Lcom/example/mobile_1psi/droidCrypto/Networking/Channel;)V
 */
JNIEXPORT void JNICALL
Java_com_example_mobile_1psi_droidCrypto_OT_IknpOTExtReceiver_recv(JNIEnv *, jobject,
                                                              jlong, jobject,
                                                              jbyteArray,
                                                              jobject);

/*
 * Class:     com_example_mobile_1psi_droidCrypto_OT_IknpOTExtReceiver
 * Method:    deleteNativeObj
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_example_mobile_1psi_droidCrypto_OT_IknpOTExtReceiver_deleteNativeObj(
    JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL
Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_IKNPRecv(JNIEnv *, jobject);

#ifdef __cplusplus
}
#endif

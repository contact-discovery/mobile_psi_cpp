#pragma once

#include <droidCrypto/gc/circuits/Circuit.h>
#include <droidCrypto/utils/graycode.h>
#include <jni.h>

extern "C" {
#include <droidCrypto/lowmc/lowmc.h>
#include <droidCrypto/lowmc/lowmc_128_128_192.h>
#include <droidCrypto/lowmc/lowmc_128_128_208.h>
#include <droidCrypto/lowmc/lowmc_128_128_21.h>
#include <droidCrypto/lowmc/lowmc_128_128_23.h>
#include <droidCrypto/lowmc/lowmc_128_128_287.h>
#include <droidCrypto/lowmc/lowmc_128_128_32.h>
#include <droidCrypto/lowmc/lowmc_192_192_413.h>
#include <droidCrypto/lowmc/lowmc_256_256_537.h>
}

namespace droidCrypto {
// round to nearest square for optimal window size
constexpr uint32_t FOUR_RUSSIAN_WINDOW_SIZE = 8;
class GCEnv;

//    class LowMCCircuit : public Circuit{
//        public:
//            struct LowMCParams {
//                uint32_t nsboxes;
//                uint32_t keysize;
//                uint32_t blocksize;
//                uint32_t data;
//                uint32_t nrounds;
//            };
//
//            static constexpr LowMCParams stp = { 49, 80, 256, 64, 12 };
//            static constexpr LowMCParams ltp = { 63, 128, 256, 128, 14 };
//
//            static constexpr LowMCParams param1 = { 25, 128, 128, 32, 11 };
//            static constexpr LowMCParams param2 = { 1, 128, 128, 32, 192 };
//            static constexpr LowMCParams param3 = { 25, 128, 128, 128, 20 };
//            static constexpr LowMCParams param4 = { 1, 128, 128, 128, 287 };
//            static constexpr LowMCParams params = param1;
//            LowMCCircuit(ChannelWrapper& chan);
//
//        protected:
//
//            virtual std::vector<WireLabel> computeFunction(const
//            std::vector<WireLabel>& inputA, const std::vector<WireLabel>&
//            inputB, GCEnv& env);
//
//            void LowMCAddRoundKey(std::vector<WireLabel>& val, const
//            std::vector<WireLabel>& key, uint32_t locmcstatesize, uint32_t
//            round, GCEnv& env); void LowMCXORConstants(std::vector<WireLabel>&
//            state, uint32_t lowmcstatesize, GCEnv& env); void
//            LowMCPutSBoxLayer(std::vector<WireLabel>& input, uint32_t
//            numsboxes, uint32_t statesize, GCEnv& env); void
//            LowMCPutSBox(WireLabel& o1, WireLabel& o2, WireLabel& o3, GCEnv&
//            env); void FourRussiansMatrixMult(std::vector<WireLabel>& state,
//            uint32_t lowmcstatesize, GCEnv& env);
//
//            GrayCode mGrayCode;
//            uint32_t m_constCtr;
//            uint32_t m_linCtr;
//            BitVector m_roundconst;
//            BitVector m_linlayer;
//    };

class SIMDLowMCCircuit : public SIMDCircuit {
 public:
  // params_{sboxes}_{datacomplexity}
  static constexpr const lowmc_t *params_1_32 = &lowmc_128_128_192;
  static constexpr const lowmc_t *params_1_64 = &lowmc_128_128_208;
  static constexpr const lowmc_t *params_1_128 = &lowmc_128_128_287;
  static constexpr const lowmc_t *params_10_32 = &lowmc_128_128_21;
  static constexpr const lowmc_t *params_10_64 = &lowmc_128_128_23;
  static constexpr const lowmc_t *params_10_128 = &lowmc_128_128_32;
  static constexpr const lowmc_t *params_1_192 = &lowmc_192_192_413;
  static constexpr const lowmc_t *params_1_256 = &lowmc_256_256_537;
  static constexpr const lowmc_t *params = params_1_64;

  SIMDLowMCCircuit(ChannelWrapper &chan);

 protected:
  std::vector<SIMDWireLabel> computeFunction(
      const std::vector<WireLabel> &inputA,
      const std::vector<SIMDWireLabel> &inputB, SIMDGCEnv &env) override;

  void LowMCAddRoundKey(std::vector<SIMDWireLabel> &val,
                        const std::vector<WireLabel> &key,
                        uint32_t locmcstatesize, uint32_t round,
                        SIMDGCEnv &env);
  void FourRussiansMatrixMult(std::vector<SIMDWireLabel> &state,
                              const mzd_local_t *mat, SIMDGCEnv &env);
  void LowMCMult(std::vector<SIMDWireLabel> &val, const mzd_local_t *mat,
                 SIMDGCEnv &env);

  void LowMCPutSBoxLayer(std::vector<SIMDWireLabel> &input, SIMDGCEnv &env);
  void LowMCPutSBox(SIMDWireLabel &o1, SIMDWireLabel &o2, SIMDWireLabel &o3,
                    SIMDGCEnv &env);
  void LowMCAddRoundKeyMult(std::vector<SIMDWireLabel> &val,
                            const std::vector<WireLabel> &key,
                            const mzd_local_t *keymat, SIMDGCEnv &env);
  void LowMCXORConstant(std::vector<SIMDWireLabel> &state,
                        const mzd_local_t *constant, SIMDGCEnv &env);
  std::vector<WireLabel> LowMCPrecomputeNLPart(std::vector<WireLabel> &key,
                                               SIMDGCEnv &env);
  void LowMCAddRRK(std::vector<SIMDWireLabel> &val,
                   const std::vector<WireLabel> &nl_part, uint32_t round,
                   SIMDGCEnv &env);
  void LowMCRLLMult(std::vector<SIMDWireLabel> &val, uint32_t round,
                    SIMDGCEnv &env);

  GrayCode mGrayCode;
};

class SIMDLowMCCircuitPhases : public SIMDCircuitPhases {
 public:
  // params_{sboxes}_{datacomplexity}
  static constexpr const lowmc_t *params_1_32 = &lowmc_128_128_192;
  static constexpr const lowmc_t *params_1_64 = &lowmc_128_128_208;
  static constexpr const lowmc_t *params_1_128 = &lowmc_128_128_287;
  static constexpr const lowmc_t *params_10_32 = &lowmc_128_128_21;
  static constexpr const lowmc_t *params_10_64 = &lowmc_128_128_23;
  static constexpr const lowmc_t *params_10_128 = &lowmc_128_128_32;
  static constexpr const lowmc_t *params_1_192 = &lowmc_192_192_413;
  static constexpr const lowmc_t *params_1_256 = &lowmc_256_256_537;
  static constexpr const lowmc_t *params = params_1_64;

  SIMDLowMCCircuitPhases(ChannelWrapper &chan);

 protected:
  std::vector<SIMDWireLabel> computeFunction(
      const std::vector<WireLabel> &inputA,
      const std::vector<SIMDWireLabel> &inputB, SIMDGCEnv &env) override;
  void LowMCAddRoundKey(std::vector<SIMDWireLabel> &val,
                        const std::vector<WireLabel> &key,
                        uint32_t locmcstatesize, uint32_t round,
                        SIMDGCEnv &env);
  void FourRussiansMatrixMult(std::vector<SIMDWireLabel> &state,
                              const mzd_local_t *mat, SIMDGCEnv &env);
  void LowMCMult(std::vector<SIMDWireLabel> &val, const mzd_local_t *mat,
                 SIMDGCEnv &env);

  void LowMCPutSBoxLayer(std::vector<SIMDWireLabel> &input, SIMDGCEnv &env);
  void LowMCPutSBox(SIMDWireLabel &o1, SIMDWireLabel &o2, SIMDWireLabel &o3,
                    SIMDGCEnv &env);
  void LowMCAddRoundKeyMult(std::vector<SIMDWireLabel> &val,
                            const std::vector<WireLabel> &key,
                            const mzd_local_t *keymat, SIMDGCEnv &env);
  void LowMCXORConstant(std::vector<SIMDWireLabel> &state,
                        const mzd_local_t *constant, SIMDGCEnv &env);
  std::vector<WireLabel> LowMCPrecomputeNLPart(std::vector<WireLabel> &key,
                                               SIMDGCEnv &env);
  void LowMCAddRRK(std::vector<SIMDWireLabel> &val,
                   const std::vector<WireLabel> &nl_part, uint32_t round,
                   SIMDGCEnv &env);
  void LowMCRLLMult(std::vector<SIMDWireLabel> &val, uint32_t round,
                    SIMDGCEnv &env);

  GrayCode mGrayCode;
};
}  // namespace droidCrypto

extern "C" JNIEXPORT void JNICALL
Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_garbleLowMC(
    JNIEnv *env, jobject /*this*/, jobject channel);

extern "C" JNIEXPORT void JNICALL
Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_evaluateLowMC(
    JNIEnv *env, jobject /*this*/, jobject channel);

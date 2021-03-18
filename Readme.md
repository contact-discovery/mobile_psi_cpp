# C++ Library for Mobile Private Contact Discovery

C++ library implementing several OPRF protocols and using them for Private Set Intersection

## Requirements

* JAVA JNI libaries
* C++ compiler supporting C++14

## Build instructions

```bash
git submodule update --init # pull GSL and RELIC
mkdir build && cd build
cmake ..
make -j
```

## Test programs

In the `droidCrypto/tests` directory, some basic tests and example programs can be found.

e.g., `droidCrypto/tests/test_psi_oprf_lowmc` runs the Garbled-Circuit based PSI protocol based on LowMC

In terminal 1:
```bash
droidCrypto/tests/test_psi_oprf_lowmc 0 20
```

In terminal 2:

```bash
droidCrypto/tests/test_psi_oprf_lowmc 1 10
```

This performs a set intersection using 2^{20} elements on the server (0) side and 2^{10} elements on the client (1) side. Only the item with index 0 is common for both sets, so the client program should only print "Intersection C0" (errors may occur based on the parameters of the cuckoo filter, but the default parameters should have an error probablity of 2^{-30}).

## Disclaimer

This code is provided as a experimental implementation for testing purposes and should not be used in a productive environment. We cannot guarantee security and correctness.

## Android Test Application

We provide a small benchmarking application for modern Android phones at [mobile_psi_android](https://github.com/contact-discovery/mobile_psi_android).

## Acknowledgements

This project uses several other projects as building blocks.

* The OT code is based on the public domain library [libOTe](https://github.com/osu-crypto/libOTe) by Peter Rindal.
* Elliptic Curve operations are implemented using [MIRACL](https://github.com/miracl/MIRACL).
* Some of the binary circuits are based on ones from [ABY](https://github.com/encryptogroup/ABY).
* The garbled circuit interface is inspired by [FlexSC](https://github.com/wangxiao1254/FlexSC).
* The used cuckoo filter implementation is [cuckoofilter](https://github.com/efficient/cuckoofilter).
* The implementation of LowMC is based on [Picnic](https://github.com/IAIK/Picnic).


## References

 * **_Mobile Private Contact Discovery at Scale_** by Daniel Kales ([TU Graz](https://www.iaik.tugraz.at/content/about_iaik/people/kales_daniel/)), Christian Rechberger ([TU Graz](https://www.iaik.tugraz.at/content/about_iaik/people/rechberger_christian/)), Thomas Schneider ([TU Darmstadt](https://www.encrypto.de/tschneider)), Matthias Senker ([TU Darmstadt](https://www.encrypto.de/)), and Christian Weinert ([TU Darmstadt](https://www.encrypto.de/cweinert)) in [28. USENIX Security Symposium (USENIX Security'19)](https://www.usenix.org/conference/usenixsecurity19). Paper available on **[ePrint](https://eprint.iacr.org/2019/517)**.

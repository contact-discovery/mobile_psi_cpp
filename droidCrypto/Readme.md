# C++ library for Garbled Circuit evaluation and Private Set Intersection

## Requirements

* JAVA JNI libaries
* C++ compiler supporting C++14


## Build instructions

```bash
make build && cd build
cmake ..
make -j
```

## Test programs

In the `tests` directory, some basic tests and example programs can be found.

e.g., `tests/test_psi_oprf` runs the Garbled-Circuit based PSI protocol based on LowMC (or AES, selectable using a define).

In terminal 1:
```bash
tests/test_psi_oprf 0 20
```

In terminal 2:

```bash
tests/test_psi_oprf 1 10
```

This performs a set intersection using 2^{20} elements on the server (0) side and 2^{10} elements on the client (1) side. Only the item with index 0 is common for both sets, so the client program should only print "Intersection C0" (errors may occur based on the parameters of the cuckoo filter, but the default parameters should have an error probablity of 2^{-30}).

## Acknowledgements

The OT code is based on the public domain library [libOTe](https://github.com/osu-crypto/libOTe) by Peter Rindal.

## References

Publications for some of the other implemented protocols.

Ágnes Kiss, Jian Liu, Thomas Schneider, N. Asokan, Benny Pinkas: Private Set Intersection for Unequal Set Sizes with Mobile Applications. [[eprint]](https://eprint.iacr.org/2017/670)

Amanda C. Davi Resende, Diego F. Aranha: Unbalanced Approximate Private Set Intersection. [[eprint]](https://eprint.iacr.org/2017/677)

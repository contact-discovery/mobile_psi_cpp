
#include <iostream>
#include <cstring>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/psi/OPRFAESPSIServer.h>
#include <droidCrypto/psi/OPRFAESPSIClient.h>
#include <droidCrypto/SecureRandom.h>
#include "droidCrypto/BitVector.h"
#include "droidCrypto/utils/Log.h"
#include "droidCrypto/utils/Utils.h"

int main(int argc, char** argv) {

    if(argc != 3) {
        std::cout << "usage: " << argv[0] << " {role=0,1} {log2(num_inputs)}" << std::endl;
        return -1;
    }
    int exp = std::stoi(std::string(argv[2]));
    if(0 > exp || exp > 32) {
        std::cout << "log2(num_inputs) should be between 0 and 32" << std::endl;
        return -1;
    }
    size_t num_inputs = 1ULL << exp;
    if(strcmp("0", argv[1]) == 0) {
        //server
        droidCrypto::CSocketChannel chan(nullptr, 8000, true);

        droidCrypto::OPRFAESPSIServer server(chan, 1);
        std::vector<droidCrypto::block> elements;
        elements.push_back(droidCrypto::toBlock((const uint8_t*)"ffffffff88888888"));
        droidCrypto::SecureRandom rnd;
        for(size_t i = 1; i < num_inputs; i++) {
            elements.push_back(rnd.randBlock());
        }
        server.doPSI(elements);
    }
    else if(strcmp("1", argv[1]) == 0) {
        //client
        droidCrypto::CSocketChannel chan("127.0.0.1", 8000, false);

        droidCrypto::OPRFAESPSIClient client(chan);
        std::vector<droidCrypto::block> elements;
        elements.push_back(droidCrypto::toBlock((const uint8_t*)"ffffffff88888888"));
        droidCrypto::SecureRandom rnd;
        for(size_t i = 1; i < num_inputs; i++) {
            elements.push_back(rnd.randBlock());
        }

        client.doPSI(elements);
    }
    else {
        std::cout << "usage: " << argv[0] << " {0,1}" << std::endl;
        return -1;
    }
    return 0;
}
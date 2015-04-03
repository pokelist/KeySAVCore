#pragma once

#include "pack.h"

namespace KeySAVCore
{
    class Pkx
    {
        public:
            PACKED_STRUCT_WITH_PARAM(struct PkxData
                    {
                    }, data)

        private: 
            template<std::size_t N> std::array<unsigned char, N> shuffleArray(std::array<unsigned char, N>&, unsigned int sv);
            static unsigned int LCRNG(unsigned int seed);

        public:
            template<std::size_t N> void decrypt(std::array<unsigned char, N>&, std::array<unsigned char, N>&);
            template<std::size_t N> void encrypt(std::array<unsigned char, N>&, std::array<unsigned char, N>&);
            template<std::size_t N> bool verifyCHK(std::array<unsigned char, N>&);
            static unsigned char getDloc(unsigned int ec);
            std::string toJson(void);
    }
}

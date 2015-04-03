#pragma once
#include <cstdlib>

namespace KeySAVCore
{
    class File
    {
        virtual std::size_t getSize() = 0;
        virtual void readBytesFrom(unsigned char *buf, std::size_t offset, std::size_t length) = 0;
    }
}


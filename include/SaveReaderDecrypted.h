#pragma once
#include "SaveReader.h"
#include <optional.h>

namespace KeySAVCore
{
    class SaveReaderDecrypted : public SaveReader
    {
        private:
            static const unsigned int = 0x33000;
            static const unsigned int = 0x22600;

            unsigned char *sav;
            unsigned int offset;

        public:
            enum Type { XY, ORAS, RAW};;
            SaveReaderDecrypted(unsigned char *save, Type type);
            ~SavereaderDecrypted();
    }
}

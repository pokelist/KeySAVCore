#pragma once
#include "SaveReader.h"

namespace KeySAVCore
{
    class SaveReaderEncrypted : public SaveReader
    {
        private:
            static unsigned char[232] zeroes, ezeroes;

            unsigned char *sav;
            SaveKey& key;
            unsigned char activeSlot;
            std::string _keyName;

            std::array<unsigned char, 232> getPkxRaw(unsigned int pos, unsigned char slot, bool& ghost);
    }
}



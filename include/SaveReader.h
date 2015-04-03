#pragma once

#include "Pkx.h"
#include <optional.h>

namespace KeySAVCore
{
    class SaveReader
    {
        public:
            virtual std::string getKeyName(void) = 0;
            virtual unsigned int getUnlockedSlots(void) = 0;
            virtual void scanSlots(unsigned int from, unsigned int to) = 0;
            virtual void scanSlots() = 0;
            virtual void scanSlots(unsigned int pos) = 0;

            virtual std::experimental::optional<Pkx> getPkx(unsigned int pos) = 0;
    }
}


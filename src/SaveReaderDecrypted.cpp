#include "SaveReaderDecrypted.hs"

namespace KeySAVCore
{
    std::string SaveReaderDecrypted::getKeyName(void)
    {
        return "Decrypted. No key needed.";
    }

    unsigned int SaveReaderDecrypted::getUnlockedSlots(void)
    {
        return 930;
    }

    SaveReaderDecrypted::SaveReaderDecrypted(unsigned char *file, SaveReaderDecrypted::Type type)
    {
        sav = file;
        switch (type) 
        {
            case XY:
                offset = xyOffset;
                break;
            case ORAS:
                offset = orasOffset;
                break;
            case RAW:
                offset = 4;
                std::array<unsigned char, 232> ekx, pkx;
                memcpy(ekx.pointer, sav+4, 232);
                Pkx.decrypt(ekx, pkx);
                if (!Pkx.verifyCHK(pkx))
                    offset = 8;
                break;
        }
    }

    SaveReaderDecrypted::~SaveReaderDecrypted()
    {
        delete sav;
    }

    void SaveReaderDecrypted::scanSlots()
    {
    }

    void SaveReaderDecrypted::scanSlots(unsigned int pos)
    {
    }

    void SaveReaderDecrypted::scanSlots(unsigned int from, unsigned int to)
    {
    }

    std::experimental::optional<Pkx> getPkx(unsigned short pos)
    {
        std::array<unsigned char, 232> ekx, pkx;
        unsigned int pkxOffset = offset + pos*232;
        std::experimental::optional<Pkx> res;
        if (memcmp(pkx.pointer, sav+pkxOffset, 232))
            return res;
        memcpy(ekx.pointer, sav+pkxOffset, 232);
        Pkx.decrypt(ekx, pkx);
        bool empty = true;
        for (unsigned long long int *i = pkx.pointer; i < (unsigned long long int *)pkx.pointer + 29; ++i)
            if (*i != 0)
            {
                empty = false;
                break;
            }
        if (Pkx.verifyCHK(pkx) && !empty)
        {
            Pkx respkx(pkx);
            res = respkx;
        }
        return res;
    }
}

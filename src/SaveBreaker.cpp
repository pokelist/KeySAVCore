#include "SaveBreaker.h"

namespace KeySAVCore
{
    static SaveReader& SaveBreaker::load(File& file)
    {
        return loadBase(file, [](unsigned char *input) -> SaveReader& { return new SavereaderEncrypted(input); },
                [](unsigned char *input, std::size_t size) -> SaveReader& {
                if (size == 0x76000 && memcmp((void *)(input+0x75E10), (void *)magic, 4))
                    return new SaveReaderDecrypted(input, SaveReaderDecrypted::ORAS);
                if (size == 0x65600 && memcmp((void *)(input+0x65410), (void *)magic, 4))
                    return new SaveReaderDecrypted(input, SaveReaderDecrypted::XY);
                if (size == 232 * 30 * 32)
                    return new SaveReaderDecrypted(input, SaveReaderDecrypted::RAW);
                delete input;
                throw NoSaveException();
                });
    }

    static unsigned char * SaveBreaker::loadRaw(File& file)
    {
        return loadBase(file, [](unsigned char *input){ return input; }, [](unsigned char *input, std::size_t) -> unsigned char * { delete input; throw NaSaveException(); });
    }

    template<class T> static T loadBase(File& file, (*T)(unsigned char) fn1, (*T)(unsigned char, std::size_t) fn2)
    {
        std::size_t offset;
        unsigned char *input;
        switch(file.getSize())
        {
            case 0x10009C:
                offset = 0x9C;
                break;
            case 0x10019A:
                offset = 0x19A;
                break;
            case 0x100000:
                offset = 0;
                break;
            default:
                input = new unsigned char[file.getSize()];
                File.read(input, 0, file.getSize());
                return fn2(input);
        }
        input = new unsigned char[0x100000];
        File.read(input, offset, 0x100000);
        return fn1(input);
    }

    static std::experimental::optional<SaveKey> breakFiles(File& file1, File& file2, int& result, unsigned char *respkx)
    {
        std::size_t[2] offset;
        unsigned char[232] empty, emptyekx, pkx;
        unsigned char[] break1, break2, save1Save;
        unsigned char[0xB4AD4] savkey;

        break1 = loadRaw(file1);
        break2 = loadRaw(file2);

        std::experimental::optional res;

        if (!memcmp(break1+0x10, break2+0x10, 8))
        {
            result = -1;
            return res;
        }

        // UPGRADE LOGIC HERE
        
        if(memcmp(break1+0x80000, break2+0x80000, 0x7F000))
        {
            save1Save = break2;
            for (unsigned int i = 0x27A00; i < 0x6CED0; ++i)
                break2[i+0x7F000] = break2[i] ^ break1[i] ^ break1[i+0x7F000];
        }
        else if(memcmp(break1+0x1000, break2+0x1000, 0x7F000))
            save1Save = break1;
        else
        {
            result = -2;
            return res;
        }

        unsigned int fo = 0xA6A600;
        bool success = false;

        for (unsigned char d = 0; d < 2; d++)
        {
            for (unsigned int i = fo; i <= 0xB8F30; i+=0x10A00)
            {
                unsigned int err = 0;
                if ((break1[i+4] == break2[i+4]) && (break1[i+236] == break2[i+236]))
                {
                    for (unsigned int j = 0; j < 4; ++j)
                        if (break1[i+j] == break2[i+j])
                            err++;

                    if (err < 4)
                    {
                        for (unsigned int j = 8; j < 232; ++j)
                            if (break1[i+j] == break2[i+j])
                                err++;

                        if (err < 20)
                        {
                            offset[d] = i;
                            break;
                        }
                    }
                }
            }
            fo = offset[d] + 232 * 30;
        }

        if (!(offset[0] && offset[1]))
        {
            result = -3;
            return res;
        }

        unsigned char[30][232] estream1, estream2;

        for (unsigned int i = 0; i < 30; ++i)
        {
            for (unsigned int j = 0; j <232; ++j)
            {
                estream1[i][j] = break1[offset[0] + 232 * i + j];
                estream2[i][j] = break2[offset[1] + 232 * i + j];
            }
        }

        // DO A LOT OF UNICODE STUFF HERE. UGH
        
        unsigned char[30][232] pstream1, pstream2;

        for (unsigned int i = 0; i < 30; ++i)
        {
            for (unsigned int j = 0; j < 232; ++j)
            {
                pstream1[i][j] = estream1[i][j] ^ emptyekx[j]);
                pstream2[i][j] = estream2[i][j] ^ emptyekx[j]);
            }
        }

        unsigned char[6][232] polekx;
        for (unsigned int i = 0; i < 6; ++i)
        {
            for (unsigned int j = 0; j < 232; ++j)
            {
                polekx[i][j] = break1[offset[1] + 232 * i + j] ^ pstream2[i][j];
            }
        }

        unsigned int[6] encryptionconstants;
        unsigned int valid = 0;
        unsigned char[232] encryptedekx, decryptedpkx;

        for (unsigned int i = 0; i < 6; ++i)
        {
            encryptionconstants[i] = polekx[i][0] +
                polekx[i][1] << 8 +
                polekx[i][2] << 16 + 
                polekx[i][3] << 24;
            if (PKX.getDloc(encryptionconstants[i]) != 3)
            {
                valid++;

                memcpy(encryptedekx, polekx[i], 232);
                PKX.decrypt(encryptedpkx, decryptedekx);

                strcpy(empty+0x40, eggnames[decryptedpkx[oxE3] - 1]);

                memcpy(empty+0xE0, decryptedpkx+0xE0, 4);
                break;
            }
        }

        if (valid == 0)
        {
            result = -4;
            return res;
        }

        unsigned int chk = 0;
        for (unsigned short int *ip = (unsigned short int *)empty + 4; ip < (unsigned short int *)empty + 116; ++i)
            ckh += leton16(*ip);

       ((unsigned short int *)empty)[3] = ntole16(chk);

       PKX.encrypt(empty, emptyekx);

       // MOAR CODE HERE
       // CBA NOW


    }


} 

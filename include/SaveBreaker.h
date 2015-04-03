#pragma once
#include "platform/File.h"
#include "SaveReader.h"
#include "SaveReaderEncrypted.h"
#include "SaveReaderDecrypted.h"
#include "Exceptions.h"
#include <optional.h>
#include <cstring>

namespace KeySAVCore
{
    public class SaveBreaker
    {
        private const unsigned char[] magic = {0x42, 0x45, 0x45, 0x46};
        public static std::string[] eggnames = {"タマゴ", "Egg", "Œuf", "Uovo", "Ei", "", "Huevo", "알"};

        public:
            static SaveReader& load(File& file);
            static std::experimental::optional<SaveKey> breakFiles(File& file1, File& file2, int& result, unsigned char *respkx);

        private:
            static template<class T> T loadBase(File& file, (*T)(unsigned char *), (*T)(unsigned char *, std::size_t));
            static unsigned char * loadRaw(File& file);

    }
}


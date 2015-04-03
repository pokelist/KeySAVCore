#pragma once

#ifdef _MSC_VER
#define PACKED_STRUCT(sn) \
#pragma pack(push) \
#pragma pack(1) \
sn; \
#pragma pack(pop)
#define PACKED_STRUCT_WITH_PARAM(sn, param) \
#pragma pack(push) \
#pragma pack(1) \
sn param; \
#pragma pack(pop)
#else
#define PACKED_STRUCT(sn) \
sn __attribute__((packed));
#define PACKED_STRUCT_WITH_PARAM(sn, param) \
sn __attribute__((packed)) param;
#endif

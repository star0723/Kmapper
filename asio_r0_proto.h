#pragma once

#include <cstdint>

// ============================================================================
//   AsioR0 IPC protocol definitions
//
//   Wire format: request  = AsioR0Header (24 B) + payload
//                response = AsioR0Response (24 B) + payload
//   Byte order:  little-endian
//   Transport:   Windows named pipe, byte-stream mode
// ============================================================================

// --- Magic / version --------------------------------------------------------

constexpr uint32_t ASIO_R0_REQ_MAGIC     = 0x52303058;  // "X0R0" le
constexpr uint32_t ASIO_R0_RSP_MAGIC     = 0x52524F58;  // "XORR" le
constexpr uint32_t ASIO_R0_PROTO_VERSION = 1;

#define ASIO_R0_DEFAULT_PIPE    "\\\\.\\pipe\\asio_r0_probe"
#define ASIO_R0_DEFAULT_PIPE_W L"\\\\.\\pipe\\asio_r0_probe"

// --- Opcodes ----------------------------------------------------------------

constexpr uint32_t ASIO_OP_PING         = 0x00;
constexpr uint32_t ASIO_OP_ATTACH       = 0x01;
constexpr uint32_t ASIO_OP_READ         = 0x02;
constexpr uint32_t ASIO_OP_WRITE        = 0x03;
constexpr uint32_t ASIO_OP_GET_BASE     = 0x04;
constexpr uint32_t ASIO_OP_ALLOC        = 0x05;
constexpr uint32_t ASIO_OP_FREE         = 0x06;
constexpr uint32_t ASIO_OP_INJECT_DLL   = 0x07;
constexpr uint32_t ASIO_OP_ENUM_MODULES = 0x08;
constexpr uint32_t ASIO_OP_SCAN_AOB     = 0x09;
constexpr uint32_t ASIO_OP_SCAN_VALUE   = 0x0A;
constexpr uint32_t ASIO_OP_SCAN_NEXT    = 0x0B;
constexpr uint32_t ASIO_OP_HWBP_SET     = 0x0C;
constexpr uint32_t ASIO_OP_HWBP_CLEAR   = 0x0D;
constexpr uint32_t ASIO_OP_QUERY_REGION = 0x0E;
constexpr uint32_t ASIO_OP_ENUM_REGIONS = 0x0F;
constexpr uint32_t ASIO_OP_ENUM_PROCS   = 0x10;
constexpr uint32_t ASIO_OP_ENUM_THREADS = 0x11;
constexpr uint32_t ASIO_OP_FREE_MEM     = 0x12;
constexpr uint32_t ASIO_OP_SHUTDOWN     = 0xFF;

// --- Status codes -----------------------------------------------------------

constexpr int32_t ASIO_OK              = 0;
constexpr int32_t ASIO_ERR_BAD_MAGIC   = 1;
constexpr int32_t ASIO_ERR_BAD_OPCODE  = 2;
constexpr int32_t ASIO_ERR_BAD_PAYLOAD = 3;
constexpr int32_t ASIO_ERR_NOT_ATTACHED= 4;
constexpr int32_t ASIO_ERR_RESOLVE     = 5;
constexpr int32_t ASIO_ERR_PHYS_IO     = 6;
constexpr int32_t ASIO_ERR_VA_TO_PA    = 7;
constexpr int32_t ASIO_ERR_INTERNAL    = 8;
constexpr int32_t ASIO_ERR_NOMEM       = 9;

// --- Scan value types -------------------------------------------------------

constexpr uint8_t ASIO_SCAN_T_BYTE   = 0;
constexpr uint8_t ASIO_SCAN_T_WORD   = 1;
constexpr uint8_t ASIO_SCAN_T_DWORD  = 2;
constexpr uint8_t ASIO_SCAN_T_QWORD  = 3;
constexpr uint8_t ASIO_SCAN_T_FLOAT  = 4;
constexpr uint8_t ASIO_SCAN_T_DOUBLE = 5;

// --- Scan comparison operators ----------------------------------------------

constexpr uint8_t ASIO_SCAN_OP_EQ        = 0;
constexpr uint8_t ASIO_SCAN_OP_NEQ       = 1;
constexpr uint8_t ASIO_SCAN_OP_GT        = 2;
constexpr uint8_t ASIO_SCAN_OP_LT        = 3;
constexpr uint8_t ASIO_SCAN_OP_GE        = 4;
constexpr uint8_t ASIO_SCAN_OP_LE        = 5;
constexpr uint8_t ASIO_SCAN_OP_RANGE     = 6;
constexpr uint8_t ASIO_SCAN_OP_CHANGED   = 7;
constexpr uint8_t ASIO_SCAN_OP_UNCHANGED = 8;
constexpr uint8_t ASIO_SCAN_OP_INCREASED = 9;
constexpr uint8_t ASIO_SCAN_OP_DECREASED = 10;

// --- Hardware breakpoint conditions -----------------------------------------

constexpr uint8_t ASIO_HWBP_COND_EXEC   = 0;
constexpr uint8_t ASIO_HWBP_COND_WRITE  = 1;
constexpr uint8_t ASIO_HWBP_COND_ACCESS = 3;

// ============================================================================
//   Wire structures — all packed, little-endian
// ============================================================================

#pragma pack(push, 1)

// --- Header / Response ------------------------------------------------------

struct AsioR0Header {
    uint32_t magic;
    uint32_t version;
    uint32_t opcode;
    uint32_t reserved;
    uint64_t payload_len;
};
static_assert(sizeof(AsioR0Header) == 24, "AsioR0Header layout");

struct AsioR0Response {
    uint32_t magic;
    uint32_t version;
    int32_t  status;
    uint32_t reserved;
    uint64_t payload_len;
};
static_assert(sizeof(AsioR0Response) == 24, "AsioR0Response layout");

// --- ATTACH response --------------------------------------------------------

struct AsioR0AttachResp {
    uint64_t cr3;
    uint64_t image_base;
    uint64_t image_size;
};

// --- READ / WRITE requests --------------------------------------------------

struct AsioR0ReadReq {
    uint64_t va;
    uint64_t size;
};

struct AsioR0WriteReq {
    uint64_t va;
    uint64_t size;
    // followed by `size` bytes of data
};

// --- ALLOC request ----------------------------------------------------------

struct AsioR0AllocReq {
    uint64_t size;
    uint32_t protection;
    uint32_t reserved;
};

// --- SCAN_AOB ---------------------------------------------------------------

struct AsioR0ScanAobReq {
    uint64_t range_start;
    uint64_t range_end;
    uint32_t alignment;
    uint32_t max_hits;
    uint16_t pattern_len;
    uint16_t mask_len;
    uint32_t reserved;
    // followed by pattern_len bytes of pattern, then mask_len bytes of mask
};

struct AsioR0ScanAobResp {
    uint32_t hit_count;
    uint32_t truncated;
    // followed by hit_count * uint64_t VAs
};

// --- SCAN_VALUE / SCAN_NEXT -------------------------------------------------

struct AsioR0ScanValueReq {
    uint64_t range_start;
    uint64_t range_end;
    uint32_t alignment;
    uint32_t max_hits;
    uint8_t  value_type;
    uint8_t  scan_op;
    uint16_t reserved;
    uint64_t value_lo;
    uint64_t value_hi;
};

struct AsioR0ScanValueResp {
    uint32_t hit_count;
    uint32_t truncated;
    // followed by hit_count * uint64_t VAs
};

struct AsioR0ScanNextReq {
    uint8_t  scan_op;
    uint8_t  reserved[7];
    uint64_t value_lo;
    uint64_t value_hi;
};

// --- HWBP -------------------------------------------------------------------

struct AsioR0HwbpSetReq {
    uint64_t va;
    uint32_t tid;
    uint8_t  dr_index;    // 0-3
    uint8_t  condition;   // ASIO_HWBP_COND_*
    uint8_t  length;      // 1, 2, 4, or 8
    uint8_t  reserved;
};

struct AsioR0HwbpClearReq {
    uint32_t tid;
    uint8_t  dr_index;    // 0-3
    uint8_t  reserved[3];
};

// --- QUERY_REGION / ENUM_REGIONS --------------------------------------------

struct AsioR0QueryRegionReq {
    uint64_t va;
};

struct AsioR0QueryRegionResp {
    uint64_t allocation_base;
    uint64_t base;
    uint64_t region_size;
    uint32_t state;
    uint32_t protect;
    uint32_t _type;
    uint32_t allocation_protect;
};

struct AsioR0RegionEntry {
    uint64_t allocation_base;
    uint64_t base;
    uint64_t region_size;
    uint32_t state;
    uint32_t protect;
    uint32_t _type;
    uint32_t allocation_protect;
};

struct AsioR0RegionListResp {
    uint32_t count;
    uint32_t reserved;
    // followed by count * AsioR0RegionEntry
};

// --- ENUM_MODULES -----------------------------------------------------------

struct AsioR0ModuleListResp {
    uint32_t count;
    uint32_t reserved;
    // followed by count * (AsioR0ModuleEntry + name_len bytes of name)
};

struct AsioR0ModuleEntry {
    uint64_t base;
    uint64_t size;
    uint32_t name_len;
    uint32_t reserved;
    // followed by name_len bytes of UTF-8 module name
};

// --- ENUM_PROCS -------------------------------------------------------------

struct AsioR0ProcListResp {
    uint32_t count;
    uint32_t reserved;
    // followed by count * AsioR0ProcEntry
};

struct AsioR0ProcEntry {
    uint32_t pid;
    uint32_t reserved;
    char     name[16];
};

// --- ENUM_THREADS -----------------------------------------------------------

struct AsioR0ThreadListResp {
    uint32_t count;
    uint32_t reserved;
    // followed by count * AsioR0ThreadEntry
};

struct AsioR0ThreadEntry {
    uint32_t tid;
    uint32_t reserved;
    uint64_t start_address;
    uint64_t teb;
};

// --- FREE_MEM ---------------------------------------------------------------

struct AsioR0FreeReq {
    uint64_t va;
    uint64_t size;
};

#pragma pack(pop)

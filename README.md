# asio_kdmapper — R0 内存读写 + 驱动手动映射 + IPC 服务器

## 概述

asio_kdmapper 是一个利用 ASUS 签名漏洞驱动 (AsIO64.sys) 获取物理内存访问原语的用户态工具。在此基础上实现：

1. **内核驱动手动映射** (Manual Map) — 将任意 .sys 映射到内核非分页池并执行 DriverEntry
2. **R3 DLL 远程注入** — 通过 R0 APC + 线程劫持将 DLL 注入目标进程
3. **R0 IPC 服务器** (`--server`) — 通过命名管道对外暴露内核级内存读写、扫描、断点等原语

核心设计目标：**所有目标进程内存操作均通过 CR3 页表遍历 + 物理内存映射完成，不触发 NtReadVirtualMemory / NtWriteVirtualMemory 系统调用**。

---

## 架构

```
┌──────────────────────────────────────────────────────────────┐
│  用户态客户端 (CE / UEDumper / 自定义工具)                     │
│  → 命名管道 \\.\pipe\asio_r0_probe                            │
└──────────────────────────┬───────────────────────────────────┘
                           │ AsioR0Header + payload
┌──────────────────────────▼───────────────────────────────────┐
│  asio_kdmapper.exe (--server 模式)                            │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  AsioProvider 类 (核心抽象)                              │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │  物理内存层                                        │  │  │
│  │  │  MapPhysical / UnmapPhysical / ReadPhysical      │  │  │
│  │  │  WritePhysical / VirtualToPhysical               │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │  内核能力层                                        │  │  │
│  │  │  ReadKernelMemory / WriteKernelMemory            │  │  │
│  │  │  GetKernelModuleExport / AllocatePool / FreePool │  │  │
│  │  │  CallKernelFunction (SSDT hook → NtAddAtom)      │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │  目标进程层                                        │  │  │
│  │  │  ResolveTargetEprocess / ReadTargetCr3           │  │  │
│  │  │  TargetVtoP / ReadTargetPteRaw                   │  │  │
│  │  │  ReadTargetMem / WriteTargetMem (CR3 直读)       │  │  │
│  │  │  ReadTargetMemViaMdl / WriteTargetMemViaMdl      │  │  │
│  │  │  AllocateTargetUserMem / FreeTargetUserMem       │  │  │
│  │  │  ReadTargetPeb / ResolveTargetModuleBase         │  │  │
│  │  │  ResolveTargetExport                             │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │  扫描引擎层                                        │  │  │
│  │  │  HandleScanAob (AOB 模式扫描)                     │  │  │
│  │  │  HandleScanValue (类型化值扫描, 首次)              │  │  │
│  │  │  HandleScanNext (二次扫描, 服务端缓存)             │  │  │
│  │  │  HandleHwbpSet/Clear (硬件断点)                   │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────┬───────────────────────────────────┘
                           │ DeviceIoControl (kIoctlMapPhysical)
┌──────────────────────────▼───────────────────────────────────┐
│  AsIO64.sys (ASUS 签名驱动)                                   │
│  \\.\Asusgio → 物理内存映射                                    │
│  IOCTL 0xA040244C (Map) / 0xA0402450 (Unmap)                 │
└──────────────────────────────────────────────────────────────┘
```

---

## 核心能力详解

### 1. 物理内存读写

**AsioProvider::ReadPhysical / WritePhysical** (main.cpp:751-801)

所有物理内存操作以 4KB 页为粒度，每次通过 AsIO64 的 `MapPhysical` 将物理页映射到用户态虚拟地址，`memcpy` 后立即 `UnmapPhysical`。

```
ReadPhysical(物理地址, 缓冲区, 大小):
  while done < size:
    pageBase = 当前地址 & ~0xFFF
    chunk = min(剩余, 页内偏移到页尾)
    MapPhysical(pageBase) → mapped
    memcpy(out, mapped + offset, chunk)
    UnmapPhysical()
```

### 2. CR3 页表遍历 (VA → PA)

**AsioProvider::VirtualToPhysical** (main.cpp:850-886) — 内核 VA，使用系统 CR3

**TargetVtoP** (main.cpp:3235-3265) — 目标进程用户 VA，使用目标 CR3

两者逻辑相同：四级页表遍历 PML4 → PDPT → PD → PT，支持 1GB/2MB 大页。

```
TargetVtoP(cr3, va):
  table = cr3 & PhyAddressMask
  for level in 0..3:
    selector = (va >> (39 - level*9)) & 0x1FF
    entry = ReadPhysical(table + selector * 8)
    if not entry.present: return false
    if entry.PageSize:
      if level==1: return entry[1GB mask] + va[1GB offset]  // 1GB 大页
      if level==2: return entry[2MB mask] + va[2MB offset]  // 2MB 大页
    table = entry & PhyAddressMask
  return table + va[12-bit offset]  // 4KB 页
```

### 3. 内核函数调用 (SSDT Hook)

**AsioProvider::CallKernelFunction** (main.cpp:1074-1146)

通过临时 patch `ntoskrnl!NtAddAtom` 实现任意内核函数调用：

1. 解析 `NtAddAtom` 的真实 syscall 入口 (通过 SSDT walk 或 export prologue trace)
2. 用 `WriteToReadOnlyMemory` 将入口替换为 `mov rax, <target>; jmp rax` trampoline
3. 调用用户态 `NtAddAtom()` syscall → 跳转到目标内核函数
4. 恢复原始字节

**支持最多 4 个参数**，返回值通过 out 指针获取。

### 4. 目标进程内存读写 (EDR 不可见)

**ReadTargetMem** (main.cpp:3363-3385) / **WriteTargetMem** (main.cpp:3391-3413)

核心路径：CR3 页表遍历 → 物理地址 → 物理内存映射 → memcpy

```
ReadTargetMem(cr3, va, buffer, size):
  while done < size:
    physical = TargetVtoP(cr3, va + done)  // 读页表项
    ReadPhysical(physical, out + done, chunk)  // 物理内存读
```

**不经过的 API (EDR 无法检测):**
- `NtReadVirtualMemory` / `NtWriteVirtualMemory` (用户态 syscall)
- `MmCopyVirtualMemory` / `MiReadWriteVirtualMemory` (内核辅助函数)
- `KeStackAttachProcess` + `ZwReadVirtualMemory` 路径

**MDL 回退路径** (main.cpp:4896-5220):

当 CR3 页表遍历失败 (页面被换出 / demand-zero) 时，通过 SSDT hook 在内核中执行 shellcode：

```
KeStackAttachProcess(targetEprocess)
IoAllocateMdl(va, size)
MmProbeAndLockPages(mdl)
MmMapLockedPagesSpecifyCache(mdl) → kernelVa
memcpy(destBuf, kernelVa, size)
MmUnlockPages(mdl)
IoFreeMdl(mdl)
KeUnstackDetachProcess()
```

这些是 I/O 子系统标准 API，EDR 几乎不 hook (每秒有成千上万的合法驱动调用它们)。

### 5. 内核手动映射 (Manual Map)

**MapDriver** — 将 .sys 文件映射到内核非分页池：

1. 解析 PE，分配内核池 (`ExAllocatePoolWithTag`)
2. 复制 sections，处理重定位
3. 解析导入表 (通过 `GetKernelModuleExport` 遍历内核模块导出表)
4. 通过 `CallKernelFunction` 调用 `DriverEntry`

支持：
- `.pdata` 注册 (SEH 异常处理)
- Kernel DLL 模式 (`DllMain` 入口)
- 持久化模式 (`PersistDriver`)

### 6. R3 DLL 注入

**InjectDllRemoteR0Trigger** — 通过 R0 APC + 线程劫持注入：

1. 解析目标 PEB，定位 `kernel32.dll` 中的 `LoadLibraryA`
2. 在目标进程分配内存 (RW + RWX)
3. 写入 DLL 路径 + 上下文保存 trampoline
4. 挂起目标线程 → 获取 RIP → 写入 trampoline → 设置新 RIP → 恢复
5. trampoline: `pushfq; 保存寄存器; LoadLibraryA(path); 恢复寄存器; popfq; jmp origRip`

**反取证:**
- `ScrubInjectedHeaders` — 注入后擦除 PE 头 (MZ + NT headers + section table)

### 7. 进程 Dump

**DumpTargetMainImage** — 逐页读取目标进程主模块并保存为内存对齐 PE：

- 部分页面读取失败时填零 (反调试保护区域不会中断整个 dump)
- section headers 重写为 `PointerToRawData = VirtualAddress` (IDA/Ghidra 可直接加载)

### 8. 目标进程模块枚举

**通过 PEB 遍历 (R0-only, 无 syscall):**

```
ReadTargetPeb(eprocess) → PEB VA
PEB.Ldr → PEB_LDR_DATA
InLoadOrderModuleList → 遍历 LDR_DATA_TABLE_ENTRY
  +0x30 DllBase
  +0x40 SizeOfImage
  +0x58 BaseDllName (UNICODE_STRING)
```

**EPROCESS.PEB 偏移自动发现:** 通过自身 PEB 地址反推 EPROCESS 中 PEB 字段的偏移 (兼容不同 Windows 版本)。

---

## IPC 协议

### 传输层

- **协议:** Windows 命名管道，字节流模式
- **默认管道名:** `\\.\pipe\asio_r0_probe`
- **并发:** 单客户端，会话结束后重连
- **字节序:** 小端

### 报文格式

```
请求:  AsioR0Header (24字节) + payload
响应:  AsioR0Response (24字节) + payload
```

### Opcode 完整列表

| Opcode | 值 | 请求 Payload | 响应 Payload | 功能 |
|--------|------|-------------|-------------|------|
| `PING` | 0x00 | 无 | 无 | 连通性测试 |
| `ATTACH` | 0x01 | `u32 pid` | `{u64 cr3, u64 base, u64 size}` | 附加进程，获取 CR3/镜像基址/大小 |
| `READ` | 0x02 | `{u64 va, u64 size}` | `size` 字节原始数据 | 读目标进程内存 |
| `WRITE` | 0x03 | `{u64 va, u64 size}` + 数据 | `u64 written` | 写目标进程内存 |
| `GET_BASE` | 0x04 | 无 | `{u64 cr3, u64 base, u64 size}` | 获取当前附加信息 |
| `ALLOC` | 0x05 | `{u64 size, u32 prot}` | `u64 va` | 在目标进程分配内存 |
| `FREE` | 0x06 | `u64 va` | 无 | 释放目标进程内存 |
| `INJECT_DLL` | 0x07 | `u16 path_len` + UTF-8 路径 | `u64 remote_base` | 注入 DLL (线程劫持) |
| `ENUM_MODULES` | 0x08 | 无 | `{u32 count}` + entries | 枚举目标进程模块 (PEB 遍历) |
| `SCAN_AOB` | 0x09 | `AsioR0ScanAobReq` + pattern + mask | `{u32 hits}` + VAs | AOB 模式扫描 |
| `SCAN_VALUE` | 0x0A | `AsioR0ScanValueReq` | `{u32 hits}` + VAs | 类型化值扫描 (首次) |
| `SCAN_NEXT` | 0x0B | `AsioR0ScanNextReq` | `{u32 hits}` + VAs | 二次扫描 (服务端缓存) |
| `HWBP_SET` | 0x0C | `AsioR0HwbpSetReq` | 无 | 设置硬件断点 |
| `HWBP_CLEAR` | 0x0D | `AsioR0HwbpClearReq` | 无 | 清除硬件断点 |
| `SHUTDOWN` | 0xFF | 无 | 无 | 关闭服务器 |

### 错误码

| 码 | 含义 |
|----|------|
| 0 `ASIO_OK` | 成功 |
| 1 `BAD_MAGIC` | 请求 magic 不匹配 |
| 2 `BAD_OPCODE` | 未知 opcode |
| 3 `BAD_PAYLOAD` | payload 大小/格式错误 |
| 4 `NOT_ATTACHED` | 未 ATTACH 就执行 READ/WRITE 等 |
| 5 `RESOLVE` | EPROCESS/CR3/模块解析失败 |
| 6 `PHYS_IO` | 物理内存读写失败 |
| 7 `VA_TO_PA` | 页表遍历失败 (页不存在) |
| 8 `INTERNAL` | 内部错误 |
| 9 `NOMEM` | 内存分配失败 |

---

## 扫描引擎

### AOB 模式扫描 (SCAN_AOB)

- 范围: `[range_start, range_end)`
- 对齐: 1/4/8 字节
- pattern + mask: mask 非零字节必须精确匹配，零字节为通配符
- 1MB 分块读取，chunk 间重叠 `pattern_len-1` 字节防止跨块漏匹配
- 最大命中数: 1<<20 (约 100 万)
- **服务端不缓存结果** (一次性返回)

### 类型化值扫描 (SCAN_VALUE + SCAN_NEXT)

**首次扫描 (SCAN_VALUE):**
- 类型: byte / word / dword / qword / float / double
- 操作符: EQ / NEQ / GT / LT / GE / LE / RANGE
- float/double EQ 使用 epsilon=1e-3 (匹配 CE 的 "rounded" 行为)
- 1MB 分块，结果缓存在 `PipeSession::scanResults` (VA + prev_value)

**二次扫描 (SCAN_NEXT):**
- 操作符: 全部 (含 CHANGED / UNCHANGED / INCREASED / DECREASED)
- 逐地址读取当前值，与缓存的 prev_value 比较
- 结果更新缓存 (新的 prev_value = 当前值)

### 硬件断点 (HWBP)

- 通过 `GetThreadContext` / `SetThreadContext` 操作 DR0-DR3 + DR7
- 支持 EXEC / WRITE / ACCESS 条件
- 长度: 1 / 2 / 4 / 8 字节

---

## 命令行用法

```bash
# 服务器模式 (对外提供 IPC)
asio_kdmapper.exe --server

# 驱动手动映射
asio_kdmapper.exe <driver.sys> [param1] [param2]

# DLL 模式 (内核 DLL)
asio_kdmapper.exe --dll <dll.sys> [--export FuncName] [param1] [param2]

# R3 DLL 注入
asio_kdmapper.exe --inject <dll_path> --pid <target_pid>

# Dump 目标进程主模块
asio_kdmapper.exe --dump <output.bin> --pid <target_pid>

# 注入 + Dump 组合
asio_kdmapper.exe --inject <dll> --dump <dump.bin> --pid <pid> --scrub-headers
```

### 关键参数

| 参数 | 说明 |
|------|------|
| `--server` | 启动 IPC 服务器模式 |
| `--pipe <name>` | 自定义管道名 (默认 `\\.\pipe\asio_r0_probe`) |
| `--pid <N>` | 目标进程 PID |
| `--dll <path>` | 内核 DLL 模式 |
| `--export <name>` | 调用内核 DLL 的指定导出函数 |
| `--inject <path>` | R3 DLL 注入目标进程 |
| `--dump <path>` | Dump 目标进程主模块 |
| `--scrub-headers` | 注入后擦除 PE 头 |
| `--service <name>` | 自定义驱动服务名 |
| `--keep-asio` | 退出时不卸载 AsIO64 驱动 |

---

## 内存读写数据流 (完整)

```
客户端 ASIO_OP_READ {va, size}
  │
  ├─ 主路径: CR3 直读 (EDR 不可见)
  │  TargetVtoP(cr3, va)  ← ReadPhysical 读页表项
  │    → ReadPhysical(物理地址)  ← MapPhysical(IOCTL 0xA040244C)
  │      → memcpy(映射地址 + 页内偏移)
  │
  └─ 回退路径: MDL (CR3 遍历失败时)
     SSDT hook → NtAddAtom patch → shellcode in kernel pool
       → KeStackAttachProcess(targetEprocess)
       → IoAllocateMdl + MmProbeAndLockPages
       → MmMapLockedPagesSpecifyCache → memcpy
       → cleanup + detach
```

---

## EDR 对抗特性

| 特性 | 实现方式 |
|------|---------|
| 不调用 NtReadVirtualMemory | CR3 页表遍历 + 物理内存映射 |
| 不调用 NtWriteVirtualMemory | 同上 |
| 不创建目标进程句柄 (主路径) | `OpenProcess` 仅用于 MDL 回退 |
| 不调用 NtQueryVirtualMemory | PEB 遍历枚举模块 |
| 内核函数调用不走标准路径 | SSDT hook NtAddAtom |
| MDL 回退使用 I/O 标准 API | IoAllocateMdl/MmProbeAndLockPages (EDR 不 hook) |
| 注入后擦除 PE 头 | ScrubInjectedHeaders 清零 0x400 字节 |
| 目标模块解析通过 PEB | 不调用 EnumProcessModules |

---

## 构建

- **IDE:** Visual Studio 2022
- **C++ 标准:** C++17
- **平台:** x64
- **链接:** advapi32.lib
- **项目文件:** `asio_kdmapper.sln` / `asio_kdmapper.vcxproj`

---

## 关键代码位置

| 功能 | 文件:行 |
|------|---------|
| AsIO64 IOCTL 定义 | main.cpp:45-47 |
| MapPhysical / UnmapPhysical | main.cpp:690-749 |
| ReadPhysical / WritePhysical | main.cpp:751-801 |
| CR3 发现 (QueryPml4) | main.cpp:803-848 |
| 内核 VA→PA (VirtualToPhysical) | main.cpp:850-886 |
| 内核内存读写 | main.cpp:888-948 |
| 内核模块导出解析 | main.cpp:950-1032 |
| 内核池分配 | main.cpp:1034-1071 |
| CallKernelFunction (SSDT hook) | main.cpp:1074-1146 |
| NtAddAtom syscall 入口解析 | main.cpp:1160-1215 |
| KiServiceTable 定位 | main.cpp:1236-1510 |
| ntoskrnl 基址解析 | main.cpp:1538-1655 |
| PE 手动映射 (重定位/导入) | main.cpp:1657-2800 (approx) |
| EPROCESS 解析 | main.cpp:3161-3209 |
| 目标 CR3 读取 | main.cpp:3213-3230 |
| 目标 VA→PA (TargetVtoP) | main.cpp:3235-3265 |
| PTE 原始读取 | main.cpp:3280-3340 |
| 目标内存读/写 (CR3 直读) | main.cpp:3363-3413 |
| PE 头擦除 (反取证) | main.cpp:3424-3430 |
| PEB 偏移自动发现 | main.cpp:3473-3523 |
| PEB 模块枚举 | main.cpp:3572-3625 |
| 目标导出解析 | main.cpp:3700-3830 (approx) |
| 目标内存分配/释放 | main.cpp:4184-4380 (approx) |
| MDL 读 shellcode | main.cpp:4815-4885 |
| MDL 读回退 | main.cpp:4896-5050 (approx) |
| MDL 写 shellcode | main.cpp:5110 (approx) |
| MDL 写回退 | main.cpp:5116-5220 (approx) |
| DLL 注入 (线程劫持) | main.cpp:5563-5799 |
| 进程 Dump | main.cpp:4580-4682 |
| PipeSession 定义 | main.cpp:4697-4710 |
| HandleAttach | main.cpp:5270-5332 |
| HandleRead | main.cpp:5334-5405 |
| HandleWrite | main.cpp:5407-5460 |
| HandleScanAob | main.cpp:5870-5973 |
| HandleScanValue | main.cpp:6065-6155 |
| HandleScanNext | main.cpp:6158-6214 |
| HandleHwbpSet | main.cpp:6217-6275 |
| HandleHwbpClear | main.cpp:6277-6313 |
| ServeOneClient (分发循环) | main.cpp:6316-6470 |
| RunR0Server (管道服务器) | main.cpp:6475-6540 (approx) |
| 协议定义 | asio_r0_proto.h (216行) |

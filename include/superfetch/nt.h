#pragma once

#include <Windows.h>
#include <winternl.h>

namespace spf {

enum SUPERFETCH_INFORMATION_CLASS {
  SuperfetchRetrieveTrace         = 1,  // Query
  SuperfetchSystemParameters      = 2,  // Query
  SuperfetchLogEvent              = 3,  // Set
  SuperfetchGenerateTrace         = 4,  // Set
  SuperfetchPrefetch              = 5,  // Set
  SuperfetchPfnQuery              = 6,  // Query
  SuperfetchPfnSetPriority        = 7,  // Set
  SuperfetchPrivSourceQuery       = 8,  // Query
  SuperfetchSequenceNumberQuery   = 9,  // Query
  SuperfetchScenarioPhase         = 10, // Set
  SuperfetchWorkerPriority        = 11, // Set
  SuperfetchScenarioQuery         = 12, // Query
  SuperfetchScenarioPrefetch      = 13, // Set
  SuperfetchRobustnessControl     = 14, // Set
  SuperfetchTimeControl           = 15, // Set
  SuperfetchMemoryListQuery       = 16, // Query
  SuperfetchMemoryRangesQuery     = 17, // Query
  SuperfetchTracingControl        = 18, // Set
  SuperfetchTrimWhileAgingControl = 19,
  SuperfetchInformationMax        = 20
};

struct SUPERFETCH_INFORMATION {
  ULONG                        Version = 45;
  ULONG                        Magic   = 'kuhC';
  SUPERFETCH_INFORMATION_CLASS InfoClass;
  PVOID                        Data;
  ULONG                        Length;
};

struct MEMORY_FRAME_INFORMATION {
  ULONGLONG UseDescription  : 4;
  ULONGLONG ListDescription : 3;
  ULONGLONG Reserved0       : 1;
  ULONGLONG Pinned          : 1;
  ULONGLONG DontUse         : 48;
  ULONGLONG Priority        : 3;
  ULONGLONG Reserved        : 4;
};

struct FILEOFFSET_INFORMATION {
  ULONGLONG DontUse  : 9;
  ULONGLONG Offset   : 48;
  ULONGLONG Reserved : 7;
};

struct PAGEDIR_INFORMATION {
  ULONGLONG DontUse           : 9;
  ULONGLONG PageDirectoryBase : 48;
  ULONGLONG Reserved          : 7;
};

struct UNIQUE_PROCESS_INFORMATION {
  ULONGLONG DontUse          : 9;
  ULONGLONG UniqueProcessKey : 48;
  ULONGLONG Reserved         : 7;
};

struct MMPFN_IDENTITY {
  union {
    MEMORY_FRAME_INFORMATION   e1;
    FILEOFFSET_INFORMATION     e2;
    PAGEDIR_INFORMATION        e3;
    UNIQUE_PROCESS_INFORMATION e4;
  } u1;
  SIZE_T PageFrameIndex;
  union {
    struct {
      ULONG Image    : 1;
      ULONG Mismatch : 1;
    } e1;
    PVOID FileObject;
    PVOID UniqueFileObjectKey;
    PVOID ProtoPteAddress;
    PVOID VirtualAddress;
  } u2;
};

struct SYSTEM_MEMORY_LIST_INFORMATION {
  SIZE_T    ZeroPageCount;
  SIZE_T    FreePageCount;
  SIZE_T    ModifiedPageCount;
  SIZE_T    ModifiedNoWritePageCount;
  SIZE_T    BadPageCount;
  SIZE_T    PageCountByPriority[8];
  SIZE_T    RepurposedPagesByPriority[8];
  ULONG_PTR ModifiedPageCountPageFile;
};

struct PF_PFN_PRIO_REQUEST {
  ULONG                          Version;
  ULONG                          RequestFlags;
  SIZE_T                         PfnCount;
  SYSTEM_MEMORY_LIST_INFORMATION MemInfo;
  MMPFN_IDENTITY                 PageData[ANYSIZE_ARRAY];
};

struct PF_PHYSICAL_MEMORY_RANGE {
  ULONG_PTR BasePfn;
  ULONG_PTR PageCount;
};

struct PF_MEMORY_RANGE_INFO_V1 {
  ULONG Version = 1;
  ULONG RangeCount;
  PF_PHYSICAL_MEMORY_RANGE Ranges[ANYSIZE_ARRAY];
};

struct PF_MEMORY_RANGE_INFO_V2 {
  ULONG Version = 2;
  ULONG Flags;
  ULONG RangeCount;
  PF_PHYSICAL_MEMORY_RANGE Ranges[ANYSIZE_ARRAY];
};

inline constexpr ULONG SE_PROF_SINGLE_PROCESS_PRIVILEGE = 13;
inline constexpr ULONG SE_DEBUG_PRIVILEGE               = 20;

inline constexpr SYSTEM_INFORMATION_CLASS SystemSuperfetchInformation = SYSTEM_INFORMATION_CLASS(79);

extern "C" NTSYSAPI NTSTATUS RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

} // namespace spf

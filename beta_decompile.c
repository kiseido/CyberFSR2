typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef unsigned int    ImageBaseOffset32;
typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned long long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct _s__RTTIClassHierarchyDescriptor _s__RTTIClassHierarchyDescriptor, *P_s__RTTIClassHierarchyDescriptor;

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

struct _s__RTTIClassHierarchyDescriptor {
    dword signature;
    dword attributes; // bit flags
    dword numBaseClasses; // number of base classes (i.e. rtti1Count)
    ImageBaseOffset32 pBaseClassArray; // ref to BaseClassArray (RTTI 2)
};

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY _IMAGE_RUNTIME_FUNCTION_ENTRY, *P_IMAGE_RUNTIME_FUNCTION_ENTRY;

struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    ImageBaseOffset32 BeginAddress;
    ImageBaseOffset32 EndAddress;
    ImageBaseOffset32 UnwindInfoAddressOrData;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _s__RTTIBaseClassDescriptor _s__RTTIBaseClassDescriptor, *P_s__RTTIBaseClassDescriptor;

typedef struct PMD PMD, *PPMD;

struct PMD {
    int mdisp;
    int pdisp;
    int vdisp;
};

struct _s__RTTIBaseClassDescriptor {
    ImageBaseOffset32 pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    dword numContainedBases; // count of extended classes in BaseClassArray (RTTI 2)
    struct PMD where; // member displacement structure
    dword attributes; // bit flags
    ImageBaseOffset32 pClassHierarchyDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3) for class
};

typedef struct _s__RTTIBaseClassDescriptor RTTIBaseClassDescriptor;

typedef struct _s__RTTICompleteObjectLocator _s__RTTICompleteObjectLocator, *P_s__RTTICompleteObjectLocator;

struct _s__RTTICompleteObjectLocator {
    dword signature;
    dword offset; // offset of vbtable within class
    dword cdOffset; // constructor displacement offset
    ImageBaseOffset32 pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    ImageBaseOffset32 pClassDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3)
};

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

struct TypeDescriptor {
    void * pVFTable;
    void * spare;
    char name[0];
};

typedef unsigned short    wchar16;
typedef struct _s__RTTICompleteObjectLocator RTTICompleteObjectLocator;

typedef ulonglong __uint64;

typedef ulong DWORD;

typedef DWORD LCTYPE;

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void * LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef void * HANDLE;

typedef ulonglong ULONG_PTR;

typedef ushort WORD;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY * Flink;
    struct _LIST_ENTRY * Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION * CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (* PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT * PCONTEXT;

typedef void * PVOID;

typedef ulonglong DWORD64;

typedef union _union_54 _union_54, *P_union_54;

typedef struct _M128A _M128A, *P_M128A;

typedef struct _M128A M128A;

typedef struct _XSAVE_FORMAT _XSAVE_FORMAT, *P_XSAVE_FORMAT;

typedef struct _XSAVE_FORMAT XSAVE_FORMAT;

typedef XSAVE_FORMAT XMM_SAVE_AREA32;

typedef struct _struct_55 _struct_55, *P_struct_55;

typedef ulonglong ULONGLONG;

typedef longlong LONGLONG;

typedef uchar BYTE;

struct _M128A {
    ULONGLONG Low;
    LONGLONG High;
};

struct _XSAVE_FORMAT {
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
};

struct _struct_55 {
    M128A Header[2];
    M128A Legacy[8];
    M128A Xmm0;
    M128A Xmm1;
    M128A Xmm2;
    M128A Xmm3;
    M128A Xmm4;
    M128A Xmm5;
    M128A Xmm6;
    M128A Xmm7;
    M128A Xmm8;
    M128A Xmm9;
    M128A Xmm10;
    M128A Xmm11;
    M128A Xmm12;
    M128A Xmm13;
    M128A Xmm14;
    M128A Xmm15;
};

union _union_54 {
    XMM_SAVE_AREA32 FltSave;
    struct _struct_55 s;
};

struct _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union _union_54 u;
    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef char CHAR;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _struct_314 _struct_314, *P_struct_314;

struct _struct_314 {
    ULONGLONG Alignment;
    ULONGLONG Region;
};

typedef struct _struct_317 _struct_317, *P_struct_317;

struct _struct_317 {
    ULONGLONG Depth:16;
    ULONGLONG Sequence:48;
    ULONGLONG HeaderType:1;
    ULONGLONG Reserved:3;
    ULONGLONG NextEntry:60;
};

typedef struct _struct_316 _struct_316, *P_struct_316;

struct _struct_316 {
    ULONGLONG Depth:16;
    ULONGLONG Sequence:48;
    ULONGLONG HeaderType:1;
    ULONGLONG Init:1;
    ULONGLONG Reserved:2;
    ULONGLONG NextEntry:60;
};

typedef struct _struct_315 _struct_315, *P_struct_315;

struct _struct_315 {
    ULONGLONG Depth:16;
    ULONGLONG Sequence:9;
    ULONGLONG NextEntry:39;
    ULONGLONG HeaderType:1;
    ULONGLONG Init:1;
    ULONGLONG Reserved:59;
    ULONGLONG Region:3;
};

typedef struct _RUNTIME_FUNCTION _RUNTIME_FUNCTION, *P_RUNTIME_FUNCTION;

struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};

typedef struct _RUNTIME_FUNCTION * PRUNTIME_FUNCTION;

typedef enum _EXCEPTION_DISPOSITION {
    ExceptionContinueExecution=0,
    ExceptionContinueSearch=1,
    ExceptionNestedException=2,
    ExceptionCollidedUnwind=3
} _EXCEPTION_DISPOSITION;

typedef enum _EXCEPTION_DISPOSITION EXCEPTION_DISPOSITION;

typedef EXCEPTION_DISPOSITION (EXCEPTION_ROUTINE)(struct _EXCEPTION_RECORD *, PVOID, struct _CONTEXT *, PVOID);

typedef wchar_t WCHAR;

typedef WCHAR * LPWSTR;

typedef union _SLIST_HEADER _SLIST_HEADER, *P_SLIST_HEADER;

union _SLIST_HEADER {
    struct _struct_314 s;
    struct _struct_315 Header8;
    struct _struct_316 Header16;
    struct _struct_317 HeaderX64;
};

typedef WCHAR * LPCWSTR;

typedef struct _M128A * PM128A;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY _UNWIND_HISTORY_TABLE_ENTRY, *P_UNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY UNWIND_HISTORY_TABLE_ENTRY;

struct _UNWIND_HISTORY_TABLE_ENTRY {
    DWORD64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
};

typedef union _union_61 _union_61, *P_union_61;

typedef struct _struct_62 _struct_62, *P_struct_62;

struct _struct_62 {
    PM128A Xmm0;
    PM128A Xmm1;
    PM128A Xmm2;
    PM128A Xmm3;
    PM128A Xmm4;
    PM128A Xmm5;
    PM128A Xmm6;
    PM128A Xmm7;
    PM128A Xmm8;
    PM128A Xmm9;
    PM128A Xmm10;
    PM128A Xmm11;
    PM128A Xmm12;
    PM128A Xmm13;
    PM128A Xmm14;
    PM128A Xmm15;
};

union _union_61 {
    PM128A FloatingContext[16];
    struct _struct_62 s;
};

typedef union _union_63 _union_63, *P_union_63;

typedef ulonglong * PDWORD64;

typedef struct _struct_64 _struct_64, *P_struct_64;

struct _struct_64 {
    PDWORD64 Rax;
    PDWORD64 Rcx;
    PDWORD64 Rdx;
    PDWORD64 Rbx;
    PDWORD64 Rsp;
    PDWORD64 Rbp;
    PDWORD64 Rsi;
    PDWORD64 Rdi;
    PDWORD64 R8;
    PDWORD64 R9;
    PDWORD64 R10;
    PDWORD64 R11;
    PDWORD64 R12;
    PDWORD64 R13;
    PDWORD64 R14;
    PDWORD64 R15;
};

union _union_63 {
    PDWORD64 IntegerContext[16];
    struct _struct_64 s;
};

typedef struct _UNWIND_HISTORY_TABLE _UNWIND_HISTORY_TABLE, *P_UNWIND_HISTORY_TABLE;

typedef struct _UNWIND_HISTORY_TABLE * PUNWIND_HISTORY_TABLE;

struct _UNWIND_HISTORY_TABLE {
    DWORD Count;
    BYTE LocalHint;
    BYTE GlobalHint;
    BYTE Search;
    BYTE Once;
    DWORD64 LowAddress;
    DWORD64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[12];
};

typedef union _SLIST_HEADER * PSLIST_HEADER;

typedef CHAR * LPCSTR;

typedef CHAR * LPSTR;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS _KNONVOLATILE_CONTEXT_POINTERS, *P_KNONVOLATILE_CONTEXT_POINTERS;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS * PKNONVOLATILE_CONTEXT_POINTERS;

struct _KNONVOLATILE_CONTEXT_POINTERS {
    union _union_61 u;
    union _union_63 u2;
};

typedef EXCEPTION_ROUTINE * PEXCEPTION_ROUTINE;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef struct _DISPATCHER_CONTEXT _DISPATCHER_CONTEXT, *P_DISPATCHER_CONTEXT;

struct _DISPATCHER_CONTEXT {
};

typedef longlong INT_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
};

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME * LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef INT_PTR (* FARPROC)(void);

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef void * LPCVOID;

typedef HINSTANCE HMODULE;

typedef HANDLE HLOCAL;

typedef DWORD * PDWORD;

typedef uint UINT;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER64 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    pointer64 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    qword SizeOfStackReserve;
    qword SizeOfStackCommit;
    qword SizeOfHeapReserve;
    qword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 34404
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

struct IMAGE_NT_HEADERS64 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

typedef struct IMAGE_THUNK_DATA64 IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;

struct IMAGE_THUNK_DATA64 {
    qword StartAddressOfRawData;
    qword EndAddressOfRawData;
    qword AddressOfIndex;
    qword AddressOfCallBacks;
    dword SizeOfZeroFill;
    dword Characteristics;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef enum IMAGE_GUARD_FLAGS {
    IMAGE_GUARD_CF_INSTRUMENTED=256,
    IMAGE_GUARD_CFW_INSTRUMENTED=512,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT=1024,
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED=2048,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT=4096,
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION=8192,
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT=16384,
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION=32768,
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT=65536,
    IMAGE_GUARD_RF_INSTRUMENTED=131072,
    IMAGE_GUARD_RF_ENABLE=262144,
    IMAGE_GUARD_RF_STRICT=524288,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1=268435456,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2=536870912,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4=1073741824,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8=2147483648
} IMAGE_GUARD_FLAGS;

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
    word Flags;
    word Catalog;
    dword CatalogOffset;
    dword Reserved;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    dword AddressOfFunctions;
    dword AddressOfNames;
    dword AddressOfNameOrdinals;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

struct IMAGE_LOAD_CONFIG_DIRECTORY64 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    qword DeCommitFreeBlockThreshold;
    qword DeCommitTotalFreeThreshold;
    pointer64 LockPrefixTable;
    qword MaximumAllocationSize;
    qword VirtualMemoryThreshold;
    qword ProcessAffinityMask;
    dword ProcessHeapFlags;
    word CsdVersion;
    word DependentLoadFlags;
    pointer64 EditList;
    pointer64 SecurityCookie;
    pointer64 SEHandlerTable;
    qword SEHandlerCount;
    pointer64 GuardCFCCheckFunctionPointer;
    pointer64 GuardCFDispatchFunctionPointer;
    pointer64 GuardCFFunctionTable;
    qword GuardCFFunctionCount;
    enum IMAGE_GUARD_FLAGS GuardFlags;
    struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    pointer64 GuardAddressTakenIatEntryTable;
    qword GuardAddressTakenIatEntryCount;
    pointer64 GuardLongJumpTargetTable;
    qword GuardLongJumpTargetCount;
    pointer64 DynamicValueRelocTable;
    pointer64 CHPEMetadataPointer;
    pointer64 GuardRFFailureRoutine;
    pointer64 GuardRFFailureRoutineFunctionPointer;
    dword DynamicValueRelocTableOffset;
    word DynamicValueRelocTableSection;
    word Reserved1;
    pointer64 GuardRFVerifyStackPointerFunctionPointer;
    dword HotPatchTableOffset;
    dword Reserved2;
    qword Reserved3;
};

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char * _ptr;
    int _cnt;
    char * _base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char * _tmpfname;
};

typedef struct _iobuf FILE;

typedef int PMFN;

typedef struct _s_ThrowInfo _s_ThrowInfo, *P_s_ThrowInfo;

struct _s_ThrowInfo {
    uint attributes;
    PMFN pmfnUnwind;
    int pForwardCompat;
    int pCatchableTypeArray;
};

typedef struct _s_ThrowInfo ThrowInfo;

typedef char * va_list;

typedef struct MRECmpImpl MRECmpImpl, *PMRECmpImpl;

struct MRECmpImpl { // PlaceHolder Structure
};

typedef struct _Mbstatet _Mbstatet, *P_Mbstatet;

struct _Mbstatet { // PlaceHolder Structure
};


// WARNING! conflicting data type names: /Demangler/wchar_t - /wchar_t

typedef struct _Yarn<char> _Yarn<char>, *P_Yarn<char>;

struct _Yarn<char> { // PlaceHolder Structure
};

typedef struct codecvt<wchar_t,char,struct__Mbstatet> codecvt<wchar_t,char,struct__Mbstatet>, *Pcodecvt<wchar_t,char,struct__Mbstatet>;

struct codecvt<wchar_t,char,struct__Mbstatet> { // PlaceHolder Structure
};

typedef struct _Facet_base _Facet_base, *P_Facet_base;

struct _Facet_base { // PlaceHolder Structure
};

typedef struct _Locimp _Locimp, *P_Locimp;

struct _Locimp { // PlaceHolder Structure
};

typedef struct id id, *Pid;

struct id { // PlaceHolder Structure
};

typedef struct facet facet, *Pfacet;

struct facet { // PlaceHolder Structure
};

typedef int (* _onexit_t)(void);

typedef ulonglong size_t;

typedef int errno_t;

typedef size_t rsize_t;




void FUN_180001020(void)

{
  _Mtx_init_in_situ(&DAT_18041ec00,2);
  atexit(&LAB_180010580);
  return;
}



undefined4 * FUN_180001050(ulonglong param_1)

{
  ulonglong local_res8 [4];
  
  local_res8[0] = param_1 & 0xffffffff00000000;
  FUN_180001080(param_1,local_res8);
  return &DAT_18041ebc0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 *
FUN_180001080(undefined8 param_1,undefined4 *param_2,undefined8 param_3,undefined8 param_4)

{
  undefined4 *puVar1;
  
  puVar1 = &DAT_18041ebc0;
  DAT_18041ebc0 = *param_2;
  DAT_18041ebc8 = (void *)0x0;
  DAT_18041ebd0 = 0;
  DAT_18041ebc8 = operator_new(0x20);
  *(void **)DAT_18041ebc8 = DAT_18041ebc8;
  *(void **)((longlong)DAT_18041ebc8 + 8) = DAT_18041ebc8;
  DAT_18041ebd8 = 0;
  _DAT_18041ebe0 = ZEXT816(0);
  DAT_18041ebf0 = 7;
  DAT_18041ebf8 = 8;
  DAT_18041ebc0 = 0x3f800000;
  FUN_180002464(&DAT_18041ebd8,0x10,DAT_18041ebc8,param_4,puVar1);
  return &DAT_18041ebc0;
}



undefined * FUN_180001124(undefined8 param_1,undefined (*param_2) [16])

{
  undefined auVar1 [16];
  longlong lVar2;
  undefined4 local_38 [4];
  undefined *local_28;
  undefined local_18 [16];
  
  local_28 = &DAT_18041ec60;
  local_38[0] = 0;
  FUN_18000119c(param_1,local_38);
  auVar1 = *param_2;
  for (lVar2 = SUB168(auVar1,0); lVar2 != SUB168(auVar1 >> 0x40,0); lVar2 = lVar2 + 0x28) {
    FUN_180007f34(param_1,local_18,lVar2);
  }
  return &DAT_18041ec60;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined *
FUN_18000119c(undefined8 param_1,undefined4 *param_2,undefined8 param_3,undefined8 param_4)

{
  undefined *puVar1;
  
  puVar1 = &DAT_18041ec60;
  _DAT_18041ec60 = *param_2;
  DAT_18041ec68 = (void *)0x0;
  DAT_18041ec70 = 0;
  DAT_18041ec68 = operator_new(0x38);
  *(void **)DAT_18041ec68 = DAT_18041ec68;
  *(void **)((longlong)DAT_18041ec68 + 8) = DAT_18041ec68;
  DAT_18041ec78 = 0;
  _DAT_18041ec80 = ZEXT816(0);
  DAT_18041ec90 = 7;
  DAT_18041ec98 = 8;
  _DAT_18041ec60 = 0x3f800000;
  FUN_180002464(&DAT_18041ec78,0x10,DAT_18041ec68,param_4,puVar1);
  return &DAT_18041ec60;
}



void ** FUN_180001334(void **param_1,undefined2 param_2)

{
  void *pvVar1;
  void *pvVar2;
  code *pcVar3;
  size_t _Size;
  void **ppvVar4;
  void *pvVar5;
  void *_Dst;
  ulonglong uVar6;
  
  pvVar1 = param_1[2];
  if (pvVar1 < param_1[3]) {
    param_1[2] = (void *)((longlong)pvVar1 + 1);
    if ((void *)0x7 < param_1[3]) {
      param_1 = (void **)*param_1;
    }
    *(undefined2 *)((longlong)param_1 + (longlong)pvVar1 * 2) = param_2;
    *(undefined2 *)((longlong)param_1 + (longlong)pvVar1 * 2 + 2) = 0;
    return (void **)0x0;
  }
  pvVar1 = param_1[2];
  if (pvVar1 == (void *)0x7ffffffffffffffe) {
    std::_Xlength_error("string too long");
    pcVar3 = (code *)swi(3);
    ppvVar4 = (void **)(*pcVar3)();
    return ppvVar4;
  }
  pvVar2 = param_1[3];
  pvVar5 = (void *)FUN_180008b88((void *)((longlong)pvVar1 + 1),pvVar2);
  uVar6 = (longlong)pvVar5 + 1;
  if (pvVar5 == (void *)0xffffffffffffffff) {
    uVar6 = 0xffffffffffffffff;
  }
  if (0x7fffffffffffffff < uVar6) {
                    // WARNING: Subroutine does not return
    FUN_18001642c();
  }
  _Dst = (void *)FUN_180008bb4(uVar6 * 2);
  _Size = (longlong)pvVar1 * 2;
  param_1[2] = (void *)((longlong)pvVar1 + 1);
  param_1[3] = pvVar5;
  if (pvVar2 < (void *)0x8) {
    memcpy(_Dst,param_1,_Size);
    *(undefined2 *)(_Size + (longlong)_Dst) = param_2;
    *(undefined2 *)(_Size + 2 + (longlong)_Dst) = 0;
  }
  else {
    pvVar1 = *param_1;
    memcpy(_Dst,pvVar1,_Size);
    *(undefined2 *)(_Size + (longlong)_Dst) = param_2;
    *(undefined2 *)(_Size + 2 + (longlong)_Dst) = 0;
    FUN_180003f84(pvVar1,(longlong)pvVar2 * 2 + 2);
  }
  *param_1 = _Dst;
  return param_1;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_180001364(longlong param_1,undefined8 *param_2)

{
  ulonglong *puVar1;
  undefined8 *puVar2;
  undefined8 uVar3;
  undefined auStack248 [32];
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined4 uStack192;
  undefined4 uStack188;
  undefined8 local_b8;
  undefined8 uStack176;
  longlong local_a8;
  undefined local_a0 [32];
  undefined local_80 [32];
  undefined local_60 [32];
  undefined8 *local_40;
  ulonglong local_38;
  
  local_38 = DAT_180418010 ^ (ulonglong)auStack248;
  local_d8 = (undefined8 *)((ulonglong)local_d8 & 0xffffffff00000000);
  *(undefined *)(param_1 + 1) = 0;
  *(undefined *)(param_1 + 3) = 0;
  *(undefined *)(param_1 + 5) = 0;
  *(undefined *)(param_1 + 7) = 0;
  *(undefined *)(param_1 + 9) = 0;
  *(undefined *)(param_1 + 0xb) = 0;
  *(undefined *)(param_1 + 0x10) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
  *(undefined *)(param_1 + 0x1d) = 0;
  *(undefined *)(param_1 + 0x24) = 0;
  *(undefined *)(param_1 + 0x2c) = 0;
  *(undefined *)(param_1 + 0x34) = 0;
  *(undefined *)(param_1 + 0x3c) = 0;
  *(undefined *)(param_1 + 0x44) = 0;
  *(undefined *)(param_1 + 0x49) = 0;
  *(undefined *)(param_1 + 0x4b) = 0;
  local_a8 = param_1;
  local_40 = param_2;
  FUN_180001f84(param_1 + 0x50);
  puVar2 = (undefined8 *)(param_1 + 0xa0);
  *puVar2 = 0;
  *(undefined8 *)(param_1 + 0xb0) = 0;
  *(undefined8 *)(param_1 + 0xb8) = 7;
  *(undefined2 *)puVar2 = 0;
  local_d0 = param_2[2];
  puVar1 = param_2 + 3;
  local_d8 = param_2;
  if (0xf < *puVar1) {
    local_d8 = (undefined8 *)*param_2;
  }
  FUN_1800016a8(local_a0,&local_d8);
  local_d8._0_4_ = 1;
  uVar3 = FUN_180001930(local_60);
  uVar3 = FUN_180001b70(uVar3,local_80);
  FUN_180001a98(&local_c8,uVar3);
  local_d8 = (undefined8 *)CONCAT44(local_d8._4_4_,3);
  FUN_180001cb4(&local_c8,local_a0);
  if (puVar2 != &local_c8) {
    FUN_180008a34(puVar2);
    *(uint *)puVar2 = (uint)local_c8;
    *(undefined4 *)(param_1 + 0xa4) = local_c8._4_4_;
    *(undefined4 *)(param_1 + 0xa8) = uStack192;
    *(undefined4 *)(param_1 + 0xac) = uStack188;
    *(undefined4 *)(param_1 + 0xb0) = (undefined4)local_b8;
    *(undefined4 *)(param_1 + 0xb4) = local_b8._4_4_;
    *(undefined4 *)(param_1 + 0xb8) = (undefined4)uStack176;
    *(undefined4 *)(param_1 + 0xbc) = uStack176._4_4_;
    local_b8 = 0;
    uStack176 = 7;
    local_c8._0_4_ = (uint)local_c8 & 0xffff0000;
  }
  FUN_180008a34(&local_c8);
  FUN_180008a34(local_80);
  FUN_180008a34(local_60);
  FUN_180008a34(local_a0);
  FUN_180001518(param_1);
  if (0xf < *puVar1) {
    FUN_180003f84(*param_2,*puVar1 + 1);
  }
  param_2[2] = 0;
  *(undefined *)param_2 = 0;
  *puVar1 = 0xf;
  FUN_18000e8c0(local_38 ^ (ulonglong)auStack248);
  return;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_180001518(undefined2 *param_1)

{
  short *psVar1;
  short *psVar2;
  int iVar3;
  undefined4 uVar4;
  undefined8 *puVar5;
  undefined8 uVar6;
  short *psVar7;
  undefined8 uVar8;
  undefined2 *puVar9;
  undefined8 *puVar10;
  short *psVar11;
  short *psVar12;
  undefined auStack184 [32];
  undefined8 ***local_98;
  undefined8 uStack144;
  undefined8 ****local_88;
  undefined8 ****local_80 [3];
  ulonglong local_68;
  undefined8 **local_60 [4];
  FILE *local_40;
  undefined8 **local_38 [2];
  undefined8 local_28;
  undefined8 local_20;
  ulonglong local_18;
  
  local_18 = DAT_180418010 ^ (ulonglong)auStack184;
  puVar10 = (undefined8 *)(param_1 + 0x50);
  if (7 < *(ulonglong *)(param_1 + 0x5c)) {
    puVar10 = (undefined8 *)*puVar10;
  }
  local_40 = (FILE *)0x0;
  _wfopen_s(&local_40,(wchar_t *)puVar10,L"rb");
  if (local_40 != (FILE *)0x0) {
    iVar3 = FUN_180015b4c(param_1 + 0x28);
    fclose(local_40);
    if (iVar3 == 0) {
      local_88 = local_80;
      uVar6 = FUN_180007c64(local_80,"DepthInverted");
      uVar8 = FUN_180007c64(local_60,"Depth");
      puVar9 = (undefined2 *)FUN_1800166fc(param_1,&local_40,uVar8,uVar6);
      *param_1 = *puVar9;
      local_98 = local_60;
      uVar6 = FUN_180007c64(local_60,"AutoExposure");
      uVar8 = FUN_180007c64(local_80,"Color");
      puVar9 = (undefined2 *)FUN_1800166fc(param_1,&local_40,uVar8,uVar6);
      param_1[1] = *puVar9;
      local_98 = local_60;
      uVar6 = FUN_180007c64(local_60,&DAT_1800ac5d0);
      uVar8 = FUN_180007c64(local_80,"Color");
      puVar9 = (undefined2 *)FUN_1800166fc(param_1,&local_40,uVar8,uVar6);
      param_1[2] = *puVar9;
      local_98 = local_60;
      uVar6 = FUN_180007c64(local_60,"JitterCancellation");
      uVar8 = FUN_180007c64(local_80,"MotionVectors");
      puVar9 = (undefined2 *)FUN_1800166fc(param_1,&local_40,uVar8,uVar6);
      param_1[3] = *puVar9;
      local_98 = local_60;
      uVar6 = FUN_180007c64(local_60,"DisplayResolution");
      uVar8 = FUN_180007c64(local_80,"MotionVectors");
      puVar9 = (undefined2 *)FUN_1800166fc(param_1,&local_40,uVar8,uVar6);
      param_1[4] = *puVar9;
      local_98 = local_60;
      uVar6 = FUN_180007c64(local_60,"EnableSharpening");
      uVar8 = FUN_180007c64(local_80,"Sharpening");
      puVar9 = (undefined2 *)FUN_1800166fc(param_1,&local_40,uVar8,uVar6);
      param_1[5] = *puVar9;
      local_98 = local_60;
      uVar6 = FUN_180007c64(local_60,"Sharpness");
      uVar8 = FUN_180007c64(local_80,"Sharpening");
      puVar10 = (undefined8 *)FUN_1800168b0(param_1,&local_40,uVar8,uVar6);
      *(undefined8 *)(param_1 + 6) = *puVar10;
      local_98 = local_60;
      uVar6 = FUN_180007c64(local_60,"SharpnessRange");
      uVar8 = FUN_180007c64(local_80,"Sharpening");
      puVar10 = (undefined8 *)FUN_180016b50(param_1,&local_40,uVar8,uVar6);
      *(undefined8 *)(param_1 + 10) = *puVar10;
      local_98 = local_60;
      uVar6 = FUN_180007c64(local_60,"UpscaleRatioOverrideEnabled");
      uVar8 = FUN_180007c64(local_80,"UpscaleRatio");
      puVar9 = (undefined2 *)FUN_1800166fc(param_1,&local_40,uVar8,uVar6);
      param_1[0xe] = *puVar9;
      local_98 = local_60;
      uVar6 = FUN_180007c64(local_60,"UpscaleRatioOverrideValue");
      uVar8 = FUN_180007c64(local_80,"UpscaleRatio");
      puVar10 = (undefined8 *)FUN_1800168b0(param_1,&local_40,uVar8,uVar6);
      *(undefined8 *)(param_1 + 0x10) = *puVar10;
      local_98 = local_60;
      uVar6 = FUN_180007c64(local_60,"Method");
      uVar8 = FUN_180007c64(local_80,&DAT_1800ac694);
      puVar10 = (undefined8 *)FUN_180016f70(param_1,&local_40,uVar8,uVar6);
      *(undefined8 *)(param_1 + 0x14) = *puVar10;
      local_98 = local_60;
      uVar6 = FUN_180007c64(local_60,"VerticalFOV");
      uVar8 = FUN_180007c64(local_80,&DAT_1800ac694);
      puVar10 = (undefined8 *)FUN_1800168b0(param_1,&local_40,uVar8,uVar6);
      *(undefined8 *)(param_1 + 0x18) = *puVar10;
      local_98 = local_60;
      uVar6 = FUN_180007c64(local_60,"NearPlane");
      uVar8 = FUN_180007c64(local_80,&DAT_1800ac694);
      puVar10 = (undefined8 *)FUN_1800168b0(param_1,&local_40,uVar8,uVar6);
      *(undefined8 *)(param_1 + 0x1c) = *puVar10;
      local_98 = local_60;
      uVar6 = FUN_180007c64(local_60,"FarPlane");
      uVar8 = FUN_180007c64(local_80,&DAT_1800ac694);
      puVar10 = (undefined8 *)FUN_1800168b0(param_1,&local_40,uVar8,uVar6);
      *(undefined8 *)(param_1 + 0x20) = *puVar10;
      local_98 = local_60;
      uVar6 = FUN_180007c64(local_60,"InfiniteFarPlane");
      uVar8 = FUN_180007c64(local_80,&DAT_1800ac694);
      puVar9 = (undefined2 *)FUN_1800166fc(param_1,&local_40,uVar8,uVar6);
      param_1[0x24] = *puVar9;
      local_98 = local_60;
      uVar6 = FUN_180007c64(local_60,"DisableReactiveMask");
      uVar8 = FUN_180007c64(local_80,"Hotfix");
      puVar9 = (undefined2 *)FUN_1800166fc(param_1,&local_40,uVar8,uVar6);
      param_1[0x25] = *puVar9;
    }
  }
  puVar5 = (undefined8 *)FUN_1800017cc(local_60);
  puVar10 = puVar5;
  if (7 < (ulonglong)puVar5[3]) {
    puVar10 = (undefined8 *)*puVar5;
  }
  psVar11 = (short *)((longlong)puVar10 + puVar5[2] * 2);
  psVar12 = psVar11;
  uVar6 = FUN_180001dec();
  psVar7 = (short *)FUN_180001e34(uVar6);
  psVar2 = psVar11;
  do {
    psVar1 = psVar12;
    if ((psVar7 == psVar2) || (psVar2 = psVar1 + -1, *psVar2 == 0x5c)) break;
    psVar12 = psVar2;
  } while (*psVar2 != 0x2f);
  local_98 = local_38;
  local_38[0] = (undefined8 **)0x0;
  local_28 = 0;
  local_20 = 0;
  FUN_180001c10(local_38,psVar1,(longlong)psVar11 - (longlong)psVar1 >> 1);
  FUN_180008a34(local_60);
  local_98 = (undefined8 ***)0x18001d538;
  uStack144 = 0x11;
  FUN_1800016a8(local_80,&local_98);
  local_98 = local_80;
  if (7 < local_68) {
    local_98 = local_80[0];
  }
  iVar3 = FUN_180001e54(local_38,&local_98);
  FUN_180008a34(local_80);
  if (iVar3 == 0) {
    if (*(char *)(param_1 + 0x16) == '\0') {
      uVar4 = 1;
    }
    else {
LAB_1800016a2:
      uVar4 = *(undefined4 *)(param_1 + 0x14);
    }
  }
  else {
    local_98 = (undefined8 ***)0x18001e470;
    uStack144 = 0x1b;
    FUN_1800016a8(local_80,&local_98);
    local_98 = local_80;
    if (7 < local_68) {
      local_98 = local_80[0];
    }
    iVar3 = FUN_180001e54(local_38,&local_98);
    FUN_180008a34(local_80);
    if (iVar3 == 0) {
      if (*(char *)(param_1 + 0xc) == '\0') {
        uVar4 = 1;
      }
      else {
        uVar4 = *(undefined4 *)(param_1 + 10);
      }
      local_40._0_5_ = CONCAT14(1,uVar4);
      local_40 = (FILE *)((ulonglong)local_40 & 0xffffff0000000000 | (ulonglong)(uint5)local_40);
      *(FILE **)(param_1 + 10) = local_40;
      goto LAB_180001674;
    }
    local_98 = (undefined8 ***)0x18001e490;
    uStack144 = 8;
    FUN_1800016a8(local_80,&local_98);
    local_98 = local_80;
    if (7 < local_68) {
      local_98 = local_80[0];
    }
    iVar3 = FUN_180001e54(local_38,&local_98);
    FUN_180008a34(local_80);
    if (iVar3 != 0) goto LAB_180001674;
    if (*(char *)(param_1 + 0x16) != '\0') goto LAB_1800016a2;
    uVar4 = 2;
  }
  local_40._0_5_ = CONCAT14(1,uVar4);
  local_40 = (FILE *)((ulonglong)local_40 & 0xffffff0000000000 | (ulonglong)(uint5)local_40);
  *(FILE **)(param_1 + 0x14) = local_40;
LAB_180001674:
  FUN_180008a34(local_38);
  FUN_18000e8c0(local_18 ^ (ulonglong)auStack184);
  return;
}



undefined8 FUN_1800016a8(undefined8 param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined local_28 [16];
  
  uVar2 = *param_2;
  uVar3 = param_2[1];
  uVar4 = param_2[2];
  uVar5 = param_2[3];
  uVar1 = FUN_18000e798();
  local_28 = CONCAT412(uVar5,CONCAT48(uVar4,CONCAT44(uVar3,uVar2)));
  FUN_1800016e4(param_1,uVar1,local_28);
  return param_1;
}



undefined8 * FUN_1800016e4(undefined8 *param_1,undefined4 param_2,undefined8 *param_3)

{
  undefined4 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  int extraout_var;
  undefined8 *puVar4;
  ulonglong uVar5;
  int local_68 [2];
  undefined **ppuStack96;
  undefined local_58 [48];
  
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 7;
  *(undefined2 *)param_1 = 0;
  if (param_3[1] != 0) {
    if (0x7fffffff < (ulonglong)param_3[1]) {
      local_68[0] = 0x16;
      ppuStack96 = &PTR_vftable_180419a30;
      FUN_180014fc8(local_58,local_68);
                    // WARNING: Subroutine does not return
      _CxxThrowException(local_58,(ThrowInfo *)&DAT_1804160f0);
    }
    uVar1 = *(undefined4 *)(param_3 + 1);
    uVar2 = *param_3;
    uVar3 = __std_fs_convert_narrow_to_wide(param_2,uVar2,uVar1,0,0);
    local_68[0] = (int)((ulonglong)uVar3 >> 0x20);
    if (local_68[0] != 0) {
      ppuStack96 = &PTR_vftable_180419a40;
      FUN_180014fc8(local_58,local_68);
                    // WARNING: Subroutine does not return
      _CxxThrowException(local_58,(ThrowInfo *)&DAT_1804160f0);
    }
    uVar5 = (ulonglong)(int)uVar3;
    if (uVar5 < (ulonglong)param_1[2] || uVar5 == param_1[2]) {
      puVar4 = param_1;
      if (7 < (ulonglong)param_1[3]) {
        puVar4 = (undefined8 *)*param_1;
      }
      param_1[2] = uVar5;
      *(undefined2 *)((longlong)puVar4 + uVar5 * 2) = 0;
    }
    else {
      FUN_18000876c(param_1,uVar5 - param_1[2]);
    }
    puVar4 = param_1;
    if (7 < (ulonglong)param_1[3]) {
      puVar4 = (undefined8 *)*param_1;
    }
    __std_fs_convert_narrow_to_wide(param_2,uVar2,uVar1,puVar4,(int)uVar3);
    if (extraout_var != 0) {
      ppuStack96 = &PTR_vftable_180419a40;
      local_68[0] = extraout_var;
      FUN_180014fc8(local_58,local_68);
                    // WARNING: Subroutine does not return
      _CxxThrowException(local_58,(ThrowInfo *)&DAT_1804160f0);
    }
  }
  return param_1;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1800017cc(undefined8 *param_1)

{
  longlong lVar1;
  longlong in_GS_OFFSET;
  undefined auStack632 [32];
  undefined8 local_258;
  undefined4 uStack592;
  undefined4 uStack588;
  undefined8 local_248;
  undefined8 uStack576;
  undefined8 *local_230;
  WCHAR local_228 [264];
  ulonglong local_18;
  
  local_18 = DAT_180418010 ^ (ulonglong)auStack632;
  lVar1 = -1;
  local_230 = param_1;
  if (*(int *)(*(longlong *)(*(longlong *)(in_GS_OFFSET + 0x58) + (ulonglong)DAT_18041eb54 * 8) + 4)
      < _DAT_18041eca4) {
    _Init_thread_header(&DAT_18041eca4);
    if (_DAT_18041eca4 == -1) {
      atexit(&LAB_1800105b0);
      FUN_18000ea80(&DAT_18041eca4);
    }
  }
  if (CONCAT44(uRam0000000180418394,_DAT_180418390) == 0) {
    GetModuleFileNameW((HMODULE)0x0,local_228,0x104);
    local_230 = &local_258;
    do {
      lVar1 = lVar1 + 1;
    } while (local_228[lVar1] != L'\0');
    local_258 = 0;
    local_248 = 0;
    uStack576 = 0;
    FUN_180001c10(&local_258,local_228,lVar1);
    FUN_180008a34(&DAT_180418380);
    _DAT_180418380 = (undefined4)local_258;
    uRam0000000180418384 = local_258._4_4_;
    uRam0000000180418388 = uStack592;
    uRam000000018041838c = uStack588;
    _DAT_180418390 = (undefined4)local_248;
    uRam0000000180418394 = local_248._4_4_;
    uRam0000000180418398 = (undefined4)uStack576;
    uRam000000018041839c = uStack576._4_4_;
    local_248 = 0;
    uStack576 = 7;
    local_258 = local_258 & 0xffffffffffff0000;
    FUN_180008a34(0,&local_258);
  }
  FUN_180001a98(param_1,&DAT_180418380);
  FUN_18000e8c0(local_18 ^ (ulonglong)auStack632);
  return;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180001930(undefined8 *param_1)

{
  longlong lVar1;
  longlong in_GS_OFFSET;
  undefined auStack632 [32];
  undefined8 local_258;
  undefined4 uStack592;
  undefined4 uStack588;
  undefined8 local_248;
  undefined8 uStack576;
  undefined8 *local_230;
  WCHAR local_228 [264];
  ulonglong local_18;
  
  local_18 = DAT_180418010 ^ (ulonglong)auStack632;
  lVar1 = -1;
  local_230 = param_1;
  if (*(int *)(*(longlong *)(*(longlong *)(in_GS_OFFSET + 0x58) + (ulonglong)DAT_18041eb54 * 8) + 4)
      < _DAT_18041eca0) {
    _Init_thread_header(&DAT_18041eca0);
    if (_DAT_18041eca0 == -1) {
      atexit(&LAB_1800105a0);
      FUN_18000ea80(&DAT_18041eca0);
    }
  }
  if (CONCAT44(uRam0000000180418374,_DAT_180418370) == 0) {
    GetModuleFileNameW(DAT_18041ebb0,local_228,0x104);
    local_230 = &local_258;
    do {
      lVar1 = lVar1 + 1;
    } while (local_228[lVar1] != L'\0');
    local_258 = 0;
    local_248 = 0;
    uStack576 = 0;
    FUN_180001c10(&local_258,local_228,lVar1);
    FUN_180008a34(&DAT_180418360);
    _DAT_180418360 = (undefined4)local_258;
    uRam0000000180418364 = local_258._4_4_;
    uRam0000000180418368 = uStack592;
    uRam000000018041836c = uStack588;
    _DAT_180418370 = (undefined4)local_248;
    uRam0000000180418374 = local_248._4_4_;
    uRam0000000180418378 = (undefined4)uStack576;
    uRam000000018041837c = uStack576._4_4_;
    local_248 = 0;
    uStack576 = 7;
    local_258 = local_258 & 0xffffffffffff0000;
    FUN_180008a34(0,&local_258);
  }
  FUN_180001a98(param_1,&DAT_180418360);
  FUN_18000e8c0(local_18 ^ (ulonglong)auStack632);
  return;
}



undefined8 * FUN_180001a98(undefined8 *param_1,undefined8 *param_2)

{
  undefined8 *puVar1;
  
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  puVar1 = param_2 + 2;
  if (7 < (ulonglong)param_2[3]) {
    param_2 = (undefined8 *)*param_2;
  }
  FUN_180001ad0(param_1,param_2,*puVar1);
  return param_1;
}



void FUN_180001ad0(void **param_1,void *param_2,void *param_3)

{
  code *pcVar1;
  void *pvVar2;
  void *_Dst;
  ulonglong uVar3;
  longlong lVar4;
  
  if ((void *)0x7ffffffffffffffe < param_3) {
    std::_Xlength_error("string too long");
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  lVar4 = 7;
  param_1[3] = (void *)0x7;
  if (param_3 < (void *)0x8) {
    param_1[2] = param_3;
    memmove(param_1,param_2,0x10);
  }
  else {
    pvVar2 = (void *)FUN_180008b88(param_3);
    uVar3 = (longlong)pvVar2 + 1;
    if (pvVar2 == (void *)0xffffffffffffffff) {
      uVar3 = lVar4 - 8;
    }
    if (0x7fffffffffffffff < uVar3) {
                    // WARNING: Subroutine does not return
      FUN_18001642c();
    }
    _Dst = (void *)FUN_180008bb4(uVar3 * 2);
    *param_1 = _Dst;
    param_1[2] = param_3;
    param_1[3] = pvVar2;
    memcpy(_Dst,param_2,(longlong)param_3 * 2 + 2);
  }
  return;
}



undefined8 * FUN_180001b70(undefined8 *param_1,undefined8 *param_2)

{
  short *psVar1;
  short *psVar2;
  undefined8 uVar3;
  short *psVar4;
  short *psVar5;
  undefined8 *puVar6;
  
  puVar6 = param_1;
  if (7 < (ulonglong)param_1[3]) {
    puVar6 = (undefined8 *)*param_1;
  }
  psVar5 = (short *)((longlong)puVar6 + param_1[2] * 2);
  uVar3 = FUN_180001dec(puVar6);
  psVar4 = (short *)FUN_180001e34(uVar3);
  if (psVar4 != psVar5) {
    do {
      psVar1 = psVar5 + -1;
      psVar2 = psVar5;
      if ((*psVar1 == 0x5c) || (*psVar1 == 0x2f)) break;
      psVar5 = psVar1;
      psVar2 = psVar1;
    } while (psVar4 != psVar1);
    do {
      psVar5 = psVar2;
      if (psVar4 == psVar5) break;
      psVar2 = psVar5 + -1;
    } while ((*psVar2 == 0x5c) || (*psVar2 == 0x2f));
  }
  *param_2 = 0;
  param_2[2] = 0;
  param_2[3] = 0;
  FUN_180001c10(param_2,puVar6,(longlong)psVar5 - (longlong)puVar6 >> 1);
  return param_2;
}



void FUN_180001c10(void **param_1,void *param_2,void *param_3)

{
  code *pcVar1;
  void *pvVar2;
  void *_Dst;
  ulonglong uVar3;
  longlong lVar4;
  
  if ((void *)0x7ffffffffffffffe < param_3) {
    std::_Xlength_error("string too long");
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  lVar4 = 7;
  param_1[3] = (void *)0x7;
  if (param_3 < (void *)0x8) {
    param_1[2] = param_3;
    memmove(param_1,param_2,(longlong)param_3 * 2);
    *(undefined2 *)((longlong)param_3 * 2 + (longlong)param_1) = 0;
  }
  else {
    pvVar2 = (void *)FUN_180008b88(param_3);
    uVar3 = (longlong)pvVar2 + 1;
    if (pvVar2 == (void *)0xffffffffffffffff) {
      uVar3 = lVar4 - 8;
    }
    if (0x7fffffffffffffff < uVar3) {
                    // WARNING: Subroutine does not return
      FUN_18001642c();
    }
    _Dst = (void *)FUN_180008bb4(uVar3 * 2);
    param_1[2] = param_3;
    *param_1 = _Dst;
    param_1[3] = pvVar2;
    memcpy(_Dst,param_2,(longlong)param_3 * 2);
    *(undefined2 *)((longlong)param_3 * 2 + (longlong)_Dst) = 0;
  }
  return;
}



short ** FUN_180001cb4(short **param_1,short **param_2)

{
  short **ppsVar1;
  short *psVar2;
  code *pcVar3;
  short **ppsVar4;
  short *psVar5;
  short **ppsVar6;
  short **ppsVar7;
  ulonglong uVar8;
  short *psVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  longlong lVar12;
  
  psVar9 = param_2[3];
  ppsVar7 = param_2;
  if ((short *)0x7 < psVar9) {
    ppsVar7 = (short **)*param_2;
  }
  psVar2 = param_2[2];
  lVar12 = (longlong)psVar2 * 2;
  if ((lVar12 >> 1 < 2) || (0x19 < (*(uint *)ppsVar7 & 0xffffffdf) - 0x3a0041)) {
    ppsVar4 = (short **)FUN_180001dec(ppsVar7,(short *)(lVar12 + (longlong)ppsVar7));
    if (ppsVar7 != ppsVar4) goto LAB_180010d66;
  }
  else if ((2 < lVar12 >> 1) &&
          ((*(short *)((longlong)ppsVar7 + 4) == 0x5c || (*(short *)((longlong)ppsVar7 + 4) == 0x2f)
           ))) goto LAB_180010d66;
  ppsVar7 = param_1;
  if ((short *)0x7 < param_1[3]) {
    ppsVar7 = (short **)*param_1;
  }
  ppsVar4 = param_2;
  if ((short *)0x7 < psVar9) {
    ppsVar4 = (short **)*param_2;
  }
  ppsVar1 = (short **)(lVar12 + (longlong)ppsVar4);
  psVar5 = (short *)FUN_180001dec(ppsVar7,(short *)((longlong)ppsVar7 + (longlong)param_1[2] * 2));
  ppsVar6 = (short **)FUN_180001dec(ppsVar4,ppsVar1);
  if (ppsVar4 != ppsVar6) {
    uVar11 = (longlong)psVar5 - (longlong)ppsVar7 >> 1;
    uVar8 = (longlong)ppsVar6 - (longlong)ppsVar4 >> 1;
    uVar10 = uVar8;
    if (uVar11 <= uVar8) {
      uVar10 = uVar11;
    }
    if (uVar10 != 0) {
      lVar12 = (longlong)ppsVar7 - (longlong)ppsVar4;
      do {
        if (*(short *)(lVar12 + (longlong)ppsVar4) != *(short *)ppsVar4) goto LAB_180010d66;
        ppsVar4 = (short **)((longlong)ppsVar4 + 2);
        uVar10 = uVar10 - 1;
      } while (uVar10 != 0);
    }
    if ((uVar11 < uVar8) || (uVar8 < uVar11)) {
LAB_180010d66:
      if (param_1 != param_2) {
        if ((short *)0x7 < psVar9) {
          param_2 = (short **)*param_2;
        }
        FUN_180016504(param_1,param_2,psVar2);
      }
      return param_1;
    }
  }
  if ((ppsVar6 == ppsVar1) || ((*(short *)ppsVar6 != 0x5c && (*(short *)ppsVar6 != 0x2f)))) {
    psVar9 = (short *)((longlong)ppsVar7 + (longlong)param_1[2] * 2);
    if (psVar5 == psVar9) {
      if ((longlong)((longlong)psVar5 - (longlong)ppsVar7 & 0xfffffffffffffffeU) < 6)
      goto LAB_180001dbe;
    }
    else if ((psVar9[-1] == 0x5c) || (psVar9[-1] == 0x2f)) goto LAB_180001dbe;
    FUN_180001334(param_1,0x5c);
  }
  else {
    psVar9 = (short *)((longlong)psVar5 - (longlong)ppsVar7 >> 1);
    if (param_1[2] < psVar9) {
      std::_Xout_of_range("invalid string position");
      pcVar3 = (code *)swi(3);
      ppsVar7 = (short **)(*pcVar3)();
      return ppsVar7;
    }
    ppsVar7 = param_1;
    if ((short *)0x7 < param_1[3]) {
      ppsVar7 = (short **)*param_1;
    }
    param_1[2] = psVar9;
    *(short *)((longlong)ppsVar7 + (longlong)psVar9 * 2) = 0;
  }
LAB_180001dbe:
  FUN_1800089c0(param_1,ppsVar6,(longlong)ppsVar1 - (longlong)ppsVar6 >> 1);
  return param_1;
}



uint * FUN_180001dec(uint *param_1,uint *param_2)

{
  uint *puVar1;
  longlong lVar2;
  
  lVar2 = (longlong)param_2 - (longlong)param_1 >> 1;
  if (1 < lVar2) {
    if ((*param_1 & 0xffffffdf) - 0x3a0041 < 0x1a) {
      return param_1 + 1;
    }
    if ((*(short *)param_1 == 0x5c) || (*(short *)param_1 == 0x2f)) {
      if (lVar2 < 4) {
        if (lVar2 < 3) {
          return param_1;
        }
      }
      else {
        puVar1 = (uint *)((longlong)param_1 + 6);
        if (((*(short *)puVar1 == 0x5c) || (*(short *)puVar1 == 0x2f)) &&
           ((lVar2 == 4 || ((*(short *)(param_1 + 2) != 0x5c && (*(short *)(param_1 + 2) != 0x2f))))
           )) {
          if ((*(short *)((longlong)param_1 + 2) == 0x5c) ||
             (*(short *)((longlong)param_1 + 2) == 0x2f)) {
            if (*(short *)(param_1 + 1) == 0x3f) {
              return puVar1;
            }
            if (*(short *)(param_1 + 1) == 0x2e) {
              return puVar1;
            }
          }
          if ((*(short *)((longlong)param_1 + 2) == 0x3f) && (*(short *)(param_1 + 1) == 0x3f)) {
            return puVar1;
          }
        }
      }
      if ((((*(short *)((longlong)param_1 + 2) == 0x5c) ||
           (*(short *)((longlong)param_1 + 2) == 0x2f)) && (*(short *)(param_1 + 1) != 0x5c)) &&
         (*(short *)(param_1 + 1) != 0x2f)) {
        param_1 = (uint *)((longlong)param_1 + 6);
        while( true ) {
          if (param_1 == param_2) {
            return param_1;
          }
          if ((*(short *)param_1 == 0x5c) || (*(short *)param_1 == 0x2f)) break;
          param_1 = (uint *)((longlong)param_1 + 2);
        }
      }
    }
  }
  return param_1;
}



short * FUN_180001e34(short *param_1,short *param_2)

{
  for (; (param_1 != param_2 && ((*param_1 == 0x5c || (*param_1 == 0x2f)))); param_1 = param_1 + 1)
  {
  }
  return param_1;
}



int FUN_180001e54(undefined8 *param_1,ushort **param_2)

{
  ushort *puVar1;
  ushort *puVar2;
  ushort uVar3;
  int iVar4;
  ushort *puVar5;
  ushort *puVar6;
  ushort *puVar7;
  ushort *puVar8;
  int iVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  undefined8 *puVar13;
  longlong lVar14;
  
  puVar13 = param_1;
  if (7 < (ulonglong)param_1[3]) {
    puVar13 = (undefined8 *)*param_1;
  }
  puVar1 = (ushort *)((longlong)puVar13 + param_1[2] * 2);
  puVar5 = (ushort *)FUN_180001dec(puVar13,puVar1);
  puVar7 = *param_2;
  puVar2 = puVar7 + (longlong)param_2[1];
  puVar6 = (ushort *)FUN_180001dec(puVar7,puVar2);
  uVar11 = (longlong)puVar6 - (longlong)puVar7 >> 1;
  uVar12 = (longlong)puVar5 - (longlong)puVar13 >> 1;
  uVar10 = uVar11;
  if (uVar12 <= uVar11) {
    uVar10 = uVar12;
  }
  if (uVar10 != 0) {
    lVar14 = (longlong)puVar13 - (longlong)puVar7;
    do {
      uVar3 = *(ushort *)(lVar14 + (longlong)puVar7);
      if (uVar3 != *puVar7) {
        return (-(uint)(uVar3 < *puVar7) & 0xfffffffe) + 1;
      }
      puVar7 = puVar7 + 1;
      uVar10 = uVar10 - 1;
    } while (uVar10 != 0);
  }
  if (uVar12 < uVar11) {
    iVar4 = -1;
  }
  else if (uVar11 < uVar12) {
    iVar4 = 1;
  }
  else {
    puVar7 = (ushort *)FUN_180001e34(puVar5,puVar1);
    puVar8 = (ushort *)FUN_180001e34();
    iVar4 = (uint)(puVar5 != puVar7) - (uint)(puVar6 != puVar8);
    if (iVar4 == 0) {
      while ((iVar4 = (uint)(puVar8 == puVar2) - (uint)(puVar7 == puVar1), puVar7 != puVar1 &&
             (iVar4 == 0))) {
        if ((*puVar7 == 0x5c) || (*puVar7 == 0x2f)) {
          iVar4 = 1;
        }
        else {
          iVar4 = 0;
        }
        if ((*puVar8 == 0x5c) || (*puVar8 == 0x2f)) {
          iVar9 = 1;
        }
        else {
          iVar9 = 0;
        }
        if (iVar9 - iVar4 != 0) {
          return iVar9 - iVar4;
        }
        if ((char)iVar4 == '\0') {
          if ((uint)*puVar7 - (uint)*puVar8 != 0) {
            return (uint)*puVar7 - (uint)*puVar8;
          }
          puVar7 = puVar7 + 1;
          puVar8 = puVar8 + 1;
        }
        else {
          puVar7 = (ushort *)FUN_180001e34(puVar7 + 1,puVar1);
          puVar8 = (ushort *)FUN_180001e34();
        }
      }
    }
  }
  return iVar4;
}



undefined8 * FUN_180001f84(undefined8 *param_1)

{
  void *pvVar1;
  
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  *(undefined *)(param_1 + 3) = 0;
  param_1[4] = (void *)0x0;
  param_1[5] = 0;
  pvVar1 = operator_new(0x48);
  *(void **)pvVar1 = pvVar1;
  *(void **)((longlong)pvVar1 + 8) = pvVar1;
  *(void **)((longlong)pvVar1 + 0x10) = pvVar1;
  *(undefined2 *)((longlong)pvVar1 + 0x18) = 0x101;
  param_1[4] = pvVar1;
  param_1[6] = 0;
  param_1[7] = 0;
  pvVar1 = operator_new(0x28);
  *(void **)pvVar1 = pvVar1;
  *(void **)((longlong)pvVar1 + 8) = pvVar1;
  param_1[6] = pvVar1;
  *(undefined4 *)(param_1 + 8) = 0x1000000;
  *(undefined2 *)((longlong)param_1 + 0x44) = 0;
  *(undefined4 *)(param_1 + 9) = 0;
  return param_1;
}



void FUN_180002014(undefined8 param_1)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  longlong **pplVar6;
  code *pcVar7;
  undefined8 *puVar8;
  char cVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  longlong lVar12;
  longlong *plVar13;
  undefined8 *puVar14;
  
  uVar11 = FUN_180002294(param_1,DAT_18041ec70 + 1);
  puVar8 = DAT_18041ec68;
  for (lVar12 = 0x3f; 0xfffffffffffffffU >> lVar12 == 0; lVar12 = lVar12 + -1) {
  }
  if ((ulonglong)(1 << ((byte)lVar12 & 0x3f)) < uVar11) {
    std::_Xlength_error("invalid hash bucket count");
    pcVar7 = (code *)swi(3);
    (*pcVar7)();
    return;
  }
  uVar11 = uVar11 - 1 | 1;
  lVar12 = 0x3f;
  if (uVar11 != 0) {
    for (; uVar11 >> lVar12 == 0; lVar12 = lVar12 + -1) {
    }
  }
  lVar12 = 1 << ((char)lVar12 + 1U & 0x3f);
  FUN_180002464(&DAT_18041ec78,lVar12 * 2,DAT_18041ec68);
  DAT_18041ec90 = lVar12 - 1;
  puVar14 = (undefined8 *)*DAT_18041ec68;
  DAT_18041ec98 = lVar12;
LAB_1800012c6:
  do {
    if (puVar14 == puVar8) {
      return;
    }
    puVar1 = (undefined8 *)*puVar14;
    uVar11 = DAT_18041ec90;
    uVar10 = FUN_18000d1d8();
    lVar12 = DAT_18041ec78;
    uVar10 = uVar10 & uVar11;
    if (*(undefined8 **)(DAT_18041ec78 + uVar10 * 0x10) == puVar8) {
      *(undefined8 **)(DAT_18041ec78 + uVar10 * 0x10) = puVar14;
    }
    else {
      plVar13 = *(longlong **)(DAT_18041ec78 + 8 + uVar10 * 0x10);
      cVar9 = FUN_180007044();
      if (cVar9 != '\0') {
        do {
          if (*(longlong **)(lVar12 + uVar10 * 0x10) == plVar13) {
            puVar2 = (undefined8 *)puVar14[1];
            *puVar2 = puVar1;
            pplVar6 = (longlong **)puVar1[1];
            *pplVar6 = plVar13;
            puVar3 = (undefined8 *)plVar13[1];
            *puVar3 = puVar14;
            plVar13[1] = (longlong)pplVar6;
            puVar1[1] = puVar2;
            puVar14[1] = puVar3;
            *(undefined8 **)(lVar12 + uVar10 * 0x10) = puVar14;
            puVar14 = puVar1;
            goto LAB_1800012c6;
          }
          plVar13 = (longlong *)plVar13[1];
          cVar9 = FUN_180007044();
        } while (cVar9 != '\0');
        lVar12 = *plVar13;
        puVar2 = (undefined8 *)puVar14[1];
        *puVar2 = puVar1;
        plVar13 = (longlong *)puVar1[1];
        *plVar13 = lVar12;
        puVar3 = *(undefined8 **)(lVar12 + 8);
        *puVar3 = puVar14;
        *(longlong **)(lVar12 + 8) = plVar13;
        puVar1[1] = puVar2;
        puVar14[1] = puVar3;
        puVar14 = puVar1;
        goto LAB_1800012c6;
      }
      puVar2 = (undefined8 *)*plVar13;
      if (puVar2 != puVar14) {
        puVar3 = (undefined8 *)puVar14[1];
        *puVar3 = puVar1;
        puVar4 = (undefined8 *)puVar1[1];
        *puVar4 = puVar2;
        puVar5 = (undefined8 *)puVar2[1];
        *puVar5 = puVar14;
        puVar2[1] = puVar4;
        puVar1[1] = puVar3;
        puVar14[1] = puVar5;
      }
    }
    *(undefined8 **)(lVar12 + 8 + uVar10 * 0x10) = puVar14;
    puVar14 = puVar1;
  } while( true );
}



void FUN_180002034(ulonglong *param_1,ulonglong param_2,undefined8 param_3)

{
  undefined8 *puVar1;
  ulonglong uVar2;
  undefined8 uVar3;
  undefined8 *puVar4;
  ulonglong uVar5;
  
  uVar2 = param_1[1];
  uVar5 = (longlong)(uVar2 - *param_1) >> 3;
  if (uVar5 < param_2) {
    uVar3 = FUN_1800024f4(param_2);
    puVar4 = (undefined8 *)FUN_180008bb4(uVar3);
    if (uVar5 != 0) {
      FUN_180003f84(*param_1,uVar5 * 8);
    }
    puVar1 = puVar4 + param_2;
    *param_1 = (ulonglong)puVar4;
    param_1[1] = (ulonglong)puVar1;
    param_1[2] = (ulonglong)puVar1;
    for (; puVar4 != puVar1; puVar4 = puVar4 + 1) {
      *puVar4 = param_3;
    }
  }
  else {
    uVar5 = (uVar2 - *param_1) + 7 >> 3;
    if (uVar2 <= *param_1 && *param_1 != uVar2) {
      uVar5 = 0;
    }
    if (uVar5 != 0) {
      puVar4 = (undefined8 *)*param_1;
      for (; uVar5 != 0; uVar5 = uVar5 - 1) {
        *puVar4 = param_3;
        puVar4 = puVar4 + 1;
      }
    }
  }
  return;
}



longlong FUN_1800020b8(longlong *param_1,undefined8 *param_2,undefined8 *param_3,undefined8 param_4)

{
  longlong lVar1;
  undefined8 uVar2;
  char *pcVar3;
  ulonglong uVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;
  longlong lVar7;
  undefined8 *puVar8;
  undefined8 *unaff_RDI;
  ulonglong unaff_R13;
  ulonglong uVar9;
  longlong local_68;
  
  lVar7 = (longlong)param_2 - *param_1 >> 3;
  lVar1 = param_1[1] - *param_1 >> 3;
  uVar9 = 0x1fffffffffffffff;
  if (lVar1 != 0x1fffffffffffffff) {
    unaff_R13 = lVar1 + 1;
    uVar4 = param_1[2] - *param_1 >> 3;
    if ((uVar4 <= 0x1fffffffffffffff - (uVar4 >> 1)) &&
       (uVar9 = (uVar4 >> 1) + uVar4, uVar9 < unaff_R13)) {
      uVar9 = unaff_R13;
    }
    uVar2 = FUN_1800024f4(uVar9);
    pcVar3 = (char *)FUN_180008bb4(uVar2);
    local_68 = lVar7 * 8;
    puVar8 = (undefined8 *)((longlong)pcVar3 + lVar7 * 8) + 1;
    uVar2 = *param_3;
    param_4 = 0;
    *param_3 = 0;
    *(undefined8 *)((longlong)pcVar3 + lVar7 * 8) = uVar2;
    param_3 = (undefined8 *)param_1[1];
    puVar6 = (undefined8 *)*param_1;
    puVar5 = (undefined8 *)pcVar3;
    unaff_RDI = (undefined8 *)pcVar3;
    if (param_2 == param_3) {
      while (param_2 = puVar6, puVar6 != param_3) {
LAB_180010f2a:
        uVar2 = *param_2;
        *param_2 = param_4;
        *(undefined8 *)pcVar3 = uVar2;
        pcVar3 = (char *)((longlong)pcVar3 + 8);
        puVar6 = param_2 + 1;
      }
      FUN_18000e450(pcVar3,pcVar3);
      pcVar3 = (char *)unaff_RDI;
    }
    else {
      for (; puVar6 != param_2; puVar6 = puVar6 + 1) {
        uVar2 = *puVar6;
        *puVar6 = 0;
        *puVar5 = uVar2;
        puVar5 = puVar5 + 1;
      }
      FUN_18000e450(puVar5,puVar5);
      puVar6 = (undefined8 *)param_1[1];
      if (param_2 != puVar6) {
        param_2 = (undefined8 *)
                  ((longlong)puVar8 + (lVar7 * -8 - (longlong)pcVar3) + -8 + (longlong)param_2);
        do {
          uVar2 = *param_2;
          *param_2 = 0;
          *puVar8 = uVar2;
          puVar8 = puVar8 + 1;
          param_2 = param_2 + 1;
        } while (param_2 != puVar6);
      }
      FUN_18000e450(puVar8,puVar8);
    }
    if (*param_1 != 0) {
      FUN_18000e450(*param_1,param_1[1]);
      FUN_180003f84(*param_1,param_1[2] - *param_1 & 0xfffffffffffffff8);
    }
    *param_1 = (longlong)pcVar3;
    param_1[1] = (longlong)((longlong)pcVar3 + unaff_R13 * 8);
    param_1[2] = (longlong)((longlong)pcVar3 + uVar9 * 8);
    return local_68 + (longlong)pcVar3;
  }
  pcVar3 = s_vector_too_long_1800ac8e0;
  std::_Xlength_error(s_vector_too_long_1800ac8e0);
  goto LAB_180010f2a;
}



ulonglong FUN_1800021cc(undefined8 param_1,ulonglong param_2)

{
  uint uVar1;
  ulonglong in_RAX;
  longlong lVar2;
  int iVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  float fVar6;
  undefined auVar7 [16];
  
  if ((longlong)param_2 < 0) {
    in_RAX = param_2 >> 1 | (ulonglong)((uint)param_2 & 1);
    fVar6 = (float)in_RAX + (float)in_RAX;
  }
  else {
    fVar6 = (float)param_2;
  }
  fVar6 = fVar6 / DAT_18041ebc0;
  auVar7 = CONCAT124(ZEXT412(0),fVar6);
  iVar3 = (int)fVar6;
  if ((iVar3 != -0x80000000) && ((float)iVar3 != fVar6)) {
    uVar1 = movmskps((int)in_RAX,
                     ZEXT816(SUB168(auVar7,0) | SUB168(auVar7,0) << 0x20) &
                     (undefined  [16])0xffffffffffffffff);
    auVar7 = ZEXT416((uint)(float)(iVar3 + (uVar1 & 1 ^ 1)));
  }
  lVar2 = 0;
  if ((9.223372e+18 <= SUB164(auVar7,0)) &&
     (fVar6 = SUB164(auVar7,0) - 9.223372e+18, auVar7 = CONCAT124(SUB1612(auVar7 >> 0x20,0),fVar6),
     fVar6 < 9.223372e+18)) {
    lVar2 = -0x8000000000000000;
  }
  uVar4 = (longlong)SUB164(auVar7,0) + lVar2;
  uVar5 = 8;
  if (8 < uVar4) {
    uVar5 = uVar4;
  }
  if (DAT_18041ebf8 < uVar5) {
    if ((DAT_18041ebf8 < 0x200) && (uVar5 <= DAT_18041ebf8 * 8)) {
      uVar5 = DAT_18041ebf8 * 8;
    }
    return uVar5;
  }
  return DAT_18041ebf8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ulonglong FUN_180002294(undefined8 param_1,ulonglong param_2)

{
  uint uVar1;
  ulonglong in_RAX;
  ulonglong uVar2;
  int iVar3;
  longlong lVar4;
  ulonglong uVar5;
  float fVar6;
  undefined auVar7 [16];
  
  if ((longlong)param_2 < 0) {
    in_RAX = param_2 >> 1 | (ulonglong)((uint)param_2 & 1);
    fVar6 = (float)in_RAX + (float)in_RAX;
  }
  else {
    fVar6 = (float)param_2;
  }
  fVar6 = fVar6 / _DAT_18041ec60;
  auVar7 = CONCAT124(ZEXT412(0),fVar6);
  iVar3 = (int)fVar6;
  if ((iVar3 != -0x80000000) && ((float)iVar3 != fVar6)) {
    uVar1 = movmskps((int)in_RAX,
                     ZEXT816(SUB168(auVar7,0) | SUB168(auVar7,0) << 0x20) &
                     (undefined  [16])0xffffffffffffffff);
    auVar7 = ZEXT416((uint)(float)(iVar3 + (uVar1 & 1 ^ 1)));
  }
  lVar4 = 0;
  if ((9.223372e+18 <= SUB164(auVar7,0)) &&
     (fVar6 = SUB164(auVar7,0) - 9.223372e+18, auVar7 = CONCAT124(SUB1612(auVar7 >> 0x20,0),fVar6),
     fVar6 < 9.223372e+18)) {
    lVar4 = -0x8000000000000000;
  }
  uVar2 = (longlong)SUB164(auVar7,0) + lVar4;
  uVar5 = 8;
  if (8 < uVar2) {
    uVar5 = uVar2;
  }
  uVar2 = DAT_18041ec98;
  if (((DAT_18041ec98 < uVar5) && (uVar2 = uVar5, DAT_18041ec98 < 0x200)) &&
     (uVar5 <= DAT_18041ec98 << 3)) {
    uVar2 = DAT_18041ec98 << 3;
  }
  return uVar2;
}



void FUN_180002350(undefined8 param_1,ulonglong param_2)

{
  longlong **pplVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  longlong **pplVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;
  undefined8 *puVar7;
  code *pcVar8;
  undefined8 *puVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  longlong *plVar12;
  longlong *plVar13;
  longlong lVar14;
  undefined8 *puVar15;
  
  puVar9 = DAT_18041ebc8;
  for (lVar14 = 0x3f; 0xfffffffffffffffU >> lVar14 == 0; lVar14 = lVar14 + -1) {
  }
  if ((ulonglong)(1 << ((byte)lVar14 & 0x3f)) < param_2) {
    std::_Xlength_error("invalid hash bucket count");
    pcVar8 = (code *)swi(3);
    (*pcVar8)();
    return;
  }
  uVar10 = param_2 - 1 | 1;
  lVar14 = 0x3f;
  if (uVar10 != 0) {
    for (; uVar10 >> lVar14 == 0; lVar14 = lVar14 + -1) {
    }
  }
  lVar14 = 1 << ((char)lVar14 + 1U & 0x3f);
  FUN_180002464(&DAT_18041ebd8,lVar14 * 2,DAT_18041ebc8);
  DAT_18041ebf0 = lVar14 - 1;
  puVar15 = (undefined8 *)*DAT_18041ebc8;
  DAT_18041ebf8 = lVar14;
LAB_1800023c9:
  do {
    uVar10 = DAT_18041ebf0;
    if (puVar15 == puVar9) {
      return;
    }
    puVar2 = (undefined8 *)*puVar15;
    plVar13 = puVar15 + 2;
    uVar11 = FUN_18000d1d8();
    lVar14 = DAT_18041ebd8;
    uVar11 = uVar11 & uVar10;
    if (*(undefined8 **)(DAT_18041ebd8 + uVar11 * 0x10) == puVar9) {
      *(undefined8 **)(DAT_18041ebd8 + uVar11 * 0x10) = puVar15;
LAB_1800023fe:
      *(undefined8 **)(lVar14 + 8 + uVar11 * 0x10) = puVar15;
      puVar15 = puVar2;
      goto LAB_1800023c9;
    }
    plVar12 = *(longlong **)(DAT_18041ebd8 + 8 + uVar11 * 0x10);
    if (*plVar13 == plVar12[2]) {
      puVar3 = (undefined8 *)*plVar12;
      if (puVar3 != puVar15) {
        puVar7 = (undefined8 *)puVar15[1];
        *puVar7 = puVar2;
        puVar5 = (undefined8 *)puVar2[1];
        *puVar5 = puVar3;
        puVar6 = (undefined8 *)puVar3[1];
        *puVar6 = puVar15;
        puVar3[1] = puVar5;
        puVar2[1] = puVar7;
        puVar15[1] = puVar6;
      }
      goto LAB_1800023fe;
    }
    do {
      pplVar1 = (longlong **)(plVar12 + 1);
      if (*(longlong **)(DAT_18041ebd8 + uVar11 * 0x10) == plVar12) {
        puVar3 = (undefined8 *)puVar15[1];
        *puVar3 = puVar2;
        pplVar4 = (longlong **)puVar2[1];
        *pplVar4 = plVar12;
        plVar13 = *pplVar1;
        *plVar13 = (longlong)puVar15;
        *pplVar1 = (longlong *)pplVar4;
        puVar2[1] = puVar3;
        puVar15[1] = plVar13;
        *(undefined8 **)(lVar14 + uVar11 * 0x10) = puVar15;
        puVar15 = puVar2;
        goto LAB_1800023c9;
      }
      plVar12 = *pplVar1;
    } while (*plVar13 != plVar12[2]);
    lVar14 = *plVar12;
    puVar3 = (undefined8 *)puVar15[1];
    *puVar3 = puVar2;
    plVar13 = (longlong *)puVar2[1];
    *plVar13 = lVar14;
    puVar7 = *(undefined8 **)(lVar14 + 8);
    *puVar7 = puVar15;
    *(longlong **)(lVar14 + 8) = plVar13;
    puVar2[1] = puVar3;
    puVar15[1] = puVar7;
    puVar15 = puVar2;
  } while( true );
}



void FUN_180002464(ulonglong *param_1,ulonglong param_2,undefined8 param_3)

{
  undefined8 *puVar1;
  ulonglong uVar2;
  undefined8 uVar3;
  undefined8 *puVar4;
  ulonglong uVar5;
  
  uVar2 = param_1[1];
  uVar5 = (longlong)(uVar2 - *param_1) >> 3;
  if (uVar5 < param_2) {
    uVar3 = FUN_1800024f4(param_2);
    puVar4 = (undefined8 *)FUN_180008bb4(uVar3);
    if (uVar5 != 0) {
      FUN_180003f84(*param_1,uVar5 * 8);
    }
    puVar1 = puVar4 + param_2;
    *param_1 = (ulonglong)puVar4;
    param_1[1] = (ulonglong)puVar1;
    param_1[2] = (ulonglong)puVar1;
    for (; puVar4 != puVar1; puVar4 = puVar4 + 1) {
      *puVar4 = param_3;
    }
  }
  else {
    uVar5 = (uVar2 - *param_1) + 7 >> 3;
    if (uVar2 <= *param_1 && *param_1 != uVar2) {
      uVar5 = 0;
    }
    if (uVar5 != 0) {
      puVar4 = (undefined8 *)*param_1;
      for (; uVar5 != 0; uVar5 = uVar5 - 1) {
        *puVar4 = param_3;
        puVar4 = puVar4 + 1;
      }
    }
  }
  return;
}



longlong FUN_1800024f4(ulonglong param_1)

{
  if (param_1 < 0x2000000000000000) {
    return param_1 * 8;
  }
                    // WARNING: Subroutine does not return
  FUN_18001642c();
}



undefined8 NVSDK_NGX_D3D12_GetParameters(undefined8 *param_1)

{
  undefined8 *puVar1;
  undefined8 uVar2;
  undefined local_18 [8];
  longlong local_10;
  
                    // 0x251c  6  NVSDK_NGX_D3D12_GetParameters
                    // 0x251c  21  NVSDK_NGX_VULKAN_GetParameters
  puVar1 = (undefined8 *)FUN_18000328c(local_18);
  uVar2 = FUN_180002554(*puVar1);
  *param_1 = uVar2;
  if (local_10 != 0) {
    FUN_1800030d8();
  }
  return 1;
}



undefined8 FUN_180002554(longlong param_1)

{
  void **ppvVar1;
  void *pvVar2;
  void *local_18 [2];
  
  pvVar2 = operator_new(0x90);
  memset(pvVar2,0,0x90);
  local_18[0] = (void *)FUN_1800025e0();
  ppvVar1 = *(void ***)(param_1 + 0x30);
  if (ppvVar1 == *(void ***)(param_1 + 0x38)) {
    FUN_1800020b8(param_1 + 0x28,ppvVar1,local_18);
    pvVar2 = local_18[0];
  }
  else {
    pvVar2 = (void *)0x0;
    *ppvVar1 = local_18[0];
    *(longlong *)(param_1 + 0x30) = *(longlong *)(param_1 + 0x30) + 8;
  }
  if (pvVar2 != (void *)0x0) {
    free(pvVar2);
  }
  return *(undefined8 *)(*(longlong *)(param_1 + 0x30) + -8);
}



undefined8 * FUN_1800025e0(undefined8 *param_1)

{
  *(undefined4 *)(param_1 + 3) = 1;
  *param_1 = NvParameter::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  *(undefined2 *)((longlong)param_1 + 0x1c) = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  *(undefined *)((longlong)param_1 + 0x34) = 0;
  *(undefined4 *)((longlong)param_1 + 0x44) = 0;
  param_1[9] = 0;
  *(undefined4 *)(param_1 + 10) = 0;
  *(undefined2 *)((longlong)param_1 + 0x54) = 0;
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  param_1[0xd] = 0;
  param_1[0xe] = 0;
  param_1[0xf] = 0;
  param_1[0x10] = 0;
  param_1[0x11] = 0;
  *(undefined4 *)(param_1 + 6) = 0x3f800000;
  *(undefined4 *)(param_1 + 7) = 0x3f800000;
  *(undefined8 *)((longlong)param_1 + 0x3c) = 0x3f800000;
  return param_1;
}



undefined8 * FUN_180002654(undefined8 *param_1)

{
  undefined8 *puVar1;
  void *pvVar2;
  undefined8 uVar3;
  undefined8 *local_18;
  undefined8 *local_10;
  
  *param_1 = 0;
  param_1[1] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  puVar1 = param_1 + 8;
  *(undefined4 *)puVar1 = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  local_18 = puVar1;
  local_10 = param_1;
  pvVar2 = operator_new(0x20);
  *(void **)pvVar2 = pvVar2;
  *(void **)((longlong)pvVar2 + 8) = pvVar2;
  param_1[9] = pvVar2;
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  param_1[0xd] = 0;
  param_1[0xe] = 7;
  param_1[0xf] = 8;
  *(undefined4 *)puVar1 = 0x3f800000;
  FUN_180002034(param_1 + 0xb,0x10,param_1[9]);
  uVar3 = FUN_180002714(&local_18);
  FUN_180002778(param_1,uVar3);
  puVar1 = local_18;
  if (local_18 != (undefined8 *)0x0) {
    FUN_180008a34(local_18 + 0x14);
    FUN_1800029b4(puVar1 + 10);
    free(puVar1);
  }
  return param_1;
}



undefined8 * FUN_180002714(undefined8 *param_1)

{
  void *_Dst;
  undefined8 uVar1;
  undefined local_30 [40];
  
  _Dst = operator_new(0xc0);
  memset(_Dst,0,0xc0);
  uVar1 = FUN_180007c64(local_30,"nvngx.ini");
  uVar1 = FUN_180001364(_Dst,uVar1);
  *param_1 = uVar1;
  return param_1;
}



longlong * FUN_180002778(longlong *param_1,longlong *param_2)

{
  longlong lVar1;
  longlong local_18;
  undefined (*pauStack16) [16];
  
  local_18 = *param_2;
  pauStack16 = (undefined (*) [16])0x0;
  if (local_18 == 0) {
    local_18 = 0;
  }
  else {
    pauStack16 = (undefined (*) [16])operator_new(0x18);
    *pauStack16 = ZEXT816(0);
    *(undefined4 *)(*pauStack16 + 8) = 1;
    *(undefined4 *)(*pauStack16 + 0xc) = 1;
    *(undefined ***)*pauStack16 =
         std::_Ref_count_resource<class_Config*___ptr64,struct_std::default_delete<class_Config>_>::
         vftable;
    *(longlong *)pauStack16[1] = local_18;
    *param_2 = 0;
  }
  lVar1 = param_1[1];
  *param_1 = local_18;
  param_1[1] = (longlong)pauStack16;
  if (lVar1 != 0) {
    FUN_1800030d8();
  }
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 * FUN_180002800(undefined8 param_1,undefined8 param_2)

{
  undefined (*pauVar1) [16];
  
  _DAT_18041eb88 = ZEXT816(0);
  pauVar1 = (undefined (*) [16])operator_new(0x18);
  *pauVar1 = ZEXT816(0);
  *(undefined4 *)(*pauVar1 + 8) = 1;
  *(undefined4 *)(*pauVar1 + 0xc) = 1;
  *(undefined ***)*pauVar1 = std::_Ref_count<class_CyberFsrContext>::vftable;
  *(undefined8 *)pauVar1[1] = param_2;
  _DAT_18041eb88 = CONCAT88(pauVar1,param_2);
  return &DAT_18041eb88;
}



void FUN_180002868(longlong *param_1)

{
  longlong lVar1;
  undefined auStack72 [32];
  undefined local_28 [16];
  DWORD local_18 [2];
  ulonglong local_10;
  
  local_10 = DAT_180418010 ^ (ulonglong)auStack72;
  if (DAT_18041eba8 == 0) {
    lVar1 = *param_1;
    DAT_18041eba8 = *(longlong *)(lVar1 + 0xe8);
    if (DAT_18041eba0 == (HANDLE)0x0) {
      DAT_18041eba0 = HeapCreate(0,0,0);
    }
    FUN_18000d030(local_28);
    VirtualProtect((LPVOID)(lVar1 + 0xe8),8,4,local_18);
    *(code **)(lVar1 + 0xe8) = FUN_1800092f0;
    VirtualProtect((LPVOID)(lVar1 + 0xe8),8,local_18[0],(PDWORD)0x0);
    FUN_18000daa0(local_28);
  }
  FUN_18000e8c0(local_10 ^ (ulonglong)auStack72);
  return;
}



void FUN_180002924(longlong param_1)

{
  undefined8 uVar1;
  undefined8 uVar2;
  longlong lVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  
  if ((*(int *)(param_1 + 0x70) != 0) && (*(int *)(param_1 + 0x74) != 0)) {
    uVar1 = *(undefined8 *)(param_1 + 0x98);
    uVar2 = *(undefined8 *)(param_1 + 0x90);
    lVar3 = *(longlong *)(param_1 + 0xb8);
    uVar4 = *(undefined8 *)(param_1 + 0xb0);
    uVar5 = *(undefined8 *)(param_1 + 0xa0);
    uVar6 = *(undefined8 *)(param_1 + 0xa8);
    uVar7 = *(undefined8 *)(param_1 + 0x88);
    *(undefined8 *)(lVar3 + 0x28) = *(undefined8 *)(param_1 + 0x80);
    *(undefined8 *)(lVar3 + 0x30) = uVar7;
    *(undefined8 *)(lVar3 + 0x38) = uVar2;
    *(undefined8 *)(lVar3 + 0x40) = uVar1;
    *(undefined8 *)(lVar3 + 0x48) = uVar6;
    *(undefined8 *)(lVar3 + 0x50) = uVar5;
    *(undefined8 *)(lVar3 + 0x58) = uVar4;
    (**(code **)(**(longlong **)(param_1 + 0xb8) + 0x18))
              (*(longlong **)(param_1 + 0xb8),*(undefined4 *)(param_1 + 0x70),
               *(undefined4 *)(param_1 + 0x74));
  }
  return;
}



void FUN_1800029b4(void **param_1)

{
  void **ppvVar1;
  undefined8 *puVar2;
  void **ppvVar3;
  undefined8 *puVar4;
  void **ppvVar5;
  longlong lVar6;
  void **ppvVar7;
  undefined auStack72 [32];
  void **local_28;
  ulonglong local_20;
  
  local_20 = DAT_180418010 ^ (ulonglong)auStack72;
  free(*param_1);
  *param_1 = (void *)0x0;
  param_1[1] = (void *)0x0;
  param_1[2] = (void *)0x0;
  if (param_1[5] != (void *)0x0) {
    ppvVar1 = param_1 + 4;
    ppvVar5 = (void **)*ppvVar1;
    local_28 = (void **)*ppvVar5;
    if (*(char *)((longlong)ppvVar5 + 0x19) == '\0') {
      while (local_28 != ppvVar5) {
        ppvVar7 = local_28;
        FUN_18001523c(&local_28);
        FUN_180015e1c(ppvVar1,ppvVar7);
      }
    }
    else {
      FUN_18000e5e4(ppvVar1,ppvVar1,ppvVar5[1]);
      ppvVar5[1] = ppvVar5;
      *ppvVar5 = ppvVar5;
      ppvVar5[2] = ppvVar5;
      param_1[5] = (void *)0x0;
    }
  }
  ppvVar1 = param_1 + 6;
  if (param_1[7] != (void *)0x0) {
    ppvVar5 = (void **)*ppvVar1;
    while( true ) {
      ppvVar5 = (void **)*ppvVar5;
      ppvVar7 = (void **)*ppvVar1;
      if (ppvVar5 == ppvVar7) break;
      free(ppvVar5[2]);
    }
    ppvVar5 = (void **)*ppvVar7;
    if (ppvVar5 != ppvVar7) {
      puVar2 = (undefined8 *)ppvVar5[1];
      lVar6 = 0;
      *puVar2 = ppvVar7;
      ppvVar7[1] = puVar2;
      do {
        ppvVar3 = (void **)*ppvVar5;
        FUN_180003f84(ppvVar5,0x28);
        lVar6 = lVar6 + 1;
        ppvVar5 = ppvVar3;
      } while (ppvVar3 != ppvVar7);
      param_1[7] = (void *)((longlong)param_1[7] - lVar6);
    }
  }
  puVar2 = (undefined8 *)*ppvVar1;
  *(undefined8 *)puVar2[1] = 0;
  puVar2 = (undefined8 *)*puVar2;
  while (puVar2 != (undefined8 *)0x0) {
    puVar4 = (undefined8 *)*puVar2;
    FUN_180003f84(puVar2,0x28);
    puVar2 = puVar4;
  }
  FUN_180003f84(*ppvVar1,0x28);
  param_1 = param_1 + 4;
  FUN_18000e5e4(param_1,param_1,*(undefined8 *)((longlong)*param_1 + 8));
  FUN_180003f84(*param_1,0x48);
  FUN_18000e8c0(local_20 ^ (ulonglong)auStack72);
  return;
}



void FUN_180002a84(longlong param_1)

{
  longlong *plVar1;
  void *pvVar2;
  
  plVar1 = *(longlong **)(param_1 + 0x80);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x18))(plVar1,1);
  }
  pvVar2 = *(void **)(param_1 + 0x78);
  if (pvVar2 != (void *)0x0) {
    FUN_18000e0d4((longlong)pvVar2 + 8);
    free(pvVar2);
  }
  pvVar2 = *(void **)(param_1 + 0x70);
  if (pvVar2 != (void *)0x0) {
    FUN_18000e0d4((longlong)pvVar2 + 8);
    free(pvVar2);
  }
  pvVar2 = *(void **)(param_1 + 0x68);
  if (pvVar2 != (void *)0x0) {
    FUN_18000e0d4((longlong)pvVar2 + 8);
    free(pvVar2);
  }
  pvVar2 = *(void **)(param_1 + 0x60);
  if (pvVar2 != (void *)0x0) {
    FUN_18000e0d4((longlong)pvVar2 + 8);
    free(pvVar2);
  }
  FUN_18000e0d4(param_1 + 0x18);
  FUN_18000e0d4(param_1 + 0x10);
  return;
}



void FUN_180002b48(longlong param_1)

{
  void *pvVar1;
  
  pvVar1 = *(void **)(param_1 + 0xb8);
  if (pvVar1 != (void *)0x0) {
    FUN_180002a84(pvVar1);
    free(pvVar1);
  }
  pvVar1 = *(void **)(param_1 + 0xb0);
  if (pvVar1 != (void *)0x0) {
    FUN_18000e0d4((longlong)pvVar1 + 8);
    free(pvVar1);
  }
  pvVar1 = *(void **)(param_1 + 0xa8);
  if (pvVar1 != (void *)0x0) {
    FUN_18000e0d4((longlong)pvVar1 + 8);
    free(pvVar1);
  }
  pvVar1 = *(void **)(param_1 + 0xa0);
  if (pvVar1 != (void *)0x0) {
    FUN_18000e0d4((longlong)pvVar1 + 8);
    free(pvVar1);
  }
  pvVar1 = *(void **)(param_1 + 0x98);
  if (pvVar1 != (void *)0x0) {
    FUN_18000e0d4((longlong)pvVar1 + 8);
    free(pvVar1);
  }
  pvVar1 = *(void **)(param_1 + 0x90);
  if (pvVar1 != (void *)0x0) {
    FUN_18000e0d4((longlong)pvVar1 + 8);
    free(pvVar1);
  }
  pvVar1 = *(void **)(param_1 + 0x88);
  if (pvVar1 != (void *)0x0) {
    FUN_18000e0d4((longlong)pvVar1 + 8);
    free(pvVar1);
  }
  pvVar1 = *(void **)(param_1 + 0x80);
  if (pvVar1 != (void *)0x0) {
    FUN_18000e0d4((longlong)pvVar1 + 8);
    free(pvVar1);
  }
  FUN_180003e80(param_1 + 0x10);
  return;
}



void * FUN_180002c58(void *param_1,ulonglong param_2)

{
  longlong *plVar1;
  
  FUN_18000e0d4((longlong)param_1 + 0x58);
  plVar1 = *(longlong **)((longlong)param_1 + 0x10);
  if (plVar1 != (longlong *)0x0) {
    *(undefined8 *)((longlong)param_1 + 0x10) = 0;
    (**(code **)(*plVar1 + 0x10))();
  }
  FUN_18000e0d4((longlong)param_1 + 8);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined8 NVSDK_NGX_D3D12_Shutdown(void)

{
  longlong *plVar1;
  undefined local_18 [8];
  longlong local_10;
  
                    // 0x2cb0  13  NVSDK_NGX_D3D12_Shutdown
                    // 0x2cb0  14  NVSDK_NGX_D3D12_Shutdown1
  plVar1 = (longlong *)FUN_18000328c(local_18);
  FUN_18000e428(*plVar1 + 0x28);
  if (local_10 != 0) {
    FUN_1800030d8();
  }
  plVar1 = (longlong *)FUN_18000328c(local_18);
  FUN_18000e610(*plVar1 + 0x40);
  if (local_10 != 0) {
    FUN_1800030d8();
  }
  return 1;
}



// WARNING: Could not reconcile some variable overlaps

void NVSDK_NGX_D3D12_CreateFeature
               (longlong *param_1,undefined8 param_2,undefined8 param_3,longlong *param_4)

{
  longlong *plVar1;
  longlong lVar2;
  undefined8 *puVar3;
  longlong lVar4;
  void *_Dst;
  undefined8 uVar5;
  char cVar6;
  undefined auStack344 [32];
  undefined4 local_138;
  void *local_128;
  void *local_120;
  longlong local_118;
  longlong local_110;
  undefined local_108 [8];
  longlong local_100;
  uint local_f8;
  undefined4 uStack244;
  undefined4 uStack240;
  undefined4 uStack236;
  undefined4 local_e8;
  undefined4 uStack228;
  undefined4 uStack224;
  undefined4 uStack220;
  undefined4 local_d8;
  undefined4 uStack212;
  undefined4 uStack208;
  undefined4 uStack204;
  undefined4 local_c8;
  undefined4 uStack196;
  undefined4 uStack192;
  undefined4 uStack188;
  undefined4 local_b8;
  undefined4 uStack180;
  undefined4 uStack176;
  undefined4 uStack172;
  undefined4 local_a8;
  undefined4 uStack164;
  undefined4 uStack160;
  undefined4 uStack156;
  undefined4 local_98;
  undefined4 uStack148;
  undefined4 uStack144;
  undefined4 uStack140;
  undefined4 uStack136;
  undefined4 uStack132;
  undefined4 uStack128;
  undefined4 uStack124;
  undefined4 uStack120;
  undefined4 uStack116;
  undefined8 local_70;
  undefined8 local_68;
  undefined local_60 [16];
  undefined local_50 [16];
  ulonglong local_40;
  
                    // 0x2d1c  2  NVSDK_NGX_D3D12_CreateFeature
  local_40 = DAT_180418010 ^ (ulonglong)auStack344;
  local_138 = 0;
  lVar2 = __RTDynamicCast(param_3,0,&struct_NVSDK_NGX_Parameter_RTTI_Type_Descriptor,
                          &struct_NvParameter_RTTI_Type_Descriptor);
  (**(code **)(*param_1 + 0x38))(param_1,&DAT_18001dbd8);
  local_50 = ZEXT816(0);
  FUN_18000328c(local_50);
  local_60 = ZEXT816(0);
  shared_ptr__(local_60,local_50._0_8_);
  puVar3 = (undefined8 *)FUN_18000328c(local_108);
  lVar4 = FUN_180003754(*puVar3);
  if (local_100 != 0) {
    FUN_1800030d8();
  }
  FUN_1800034c0(&local_128,local_60._0_8_);
  FUN_180003444(lVar4);
  if (local_128 != (void *)0x0) {
    free(local_128);
  }
  _Dst = operator_new(0xc0);
  memset(_Dst,0,0xc0);
  uVar5 = FUN_180003520(_Dst,local_68);
  plVar1 = *(longlong **)(lVar4 + 0x10);
  *(undefined8 *)(lVar4 + 0x10) = uVar5;
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x18))(plVar1,1);
  }
  *param_4 = lVar4 + 8;
  local_f8 = *(uint *)(lVar4 + 0x10278);
  uStack244 = *(undefined4 *)(lVar4 + 0x1027c);
  uStack240 = *(undefined4 *)(lVar4 + 0x10280);
  uStack236 = *(undefined4 *)(lVar4 + 0x10284);
  local_e8 = *(undefined4 *)(lVar4 + 0x10288);
  uStack228 = *(undefined4 *)(lVar4 + 0x1028c);
  uStack224 = *(undefined4 *)(lVar4 + 0x10290);
  uStack220 = *(undefined4 *)(lVar4 + 0x10294);
  local_d8 = *(undefined4 *)(lVar4 + 0x10298);
  uStack212 = *(undefined4 *)(lVar4 + 0x1029c);
  uStack208 = *(undefined4 *)(lVar4 + 0x102a0);
  uStack204 = *(undefined4 *)(lVar4 + 0x102a4);
  local_c8 = *(undefined4 *)(lVar4 + 0x102a8);
  uStack196 = *(undefined4 *)(lVar4 + 0x102ac);
  uStack192 = *(undefined4 *)(lVar4 + 0x102b0);
  uStack188 = *(undefined4 *)(lVar4 + 0x102b4);
  local_b8 = *(undefined4 *)(lVar4 + 0x102b8);
  uStack180 = *(undefined4 *)(lVar4 + 0x102bc);
  uStack176 = *(undefined4 *)(lVar4 + 0x102c0);
  uStack172 = *(undefined4 *)(lVar4 + 0x102c4);
  local_a8 = *(undefined4 *)(lVar4 + 0x102c8);
  uStack164 = *(undefined4 *)(lVar4 + 0x102cc);
  uStack160 = *(undefined4 *)(lVar4 + 0x102d0);
  uStack156 = *(undefined4 *)(lVar4 + 0x102d4);
  local_98 = *(undefined4 *)(lVar4 + 0x102d8);
  uStack148 = *(undefined4 *)(lVar4 + 0x102dc);
  uStack144 = *(undefined4 *)(lVar4 + 0x102e0);
  uStack140 = *(undefined4 *)(lVar4 + 0x102e4);
  uStack120 = *(undefined4 *)(lVar4 + 0x102f8);
  uStack116 = *(undefined4 *)(lVar4 + 0x102fc);
  local_70 = *(undefined8 *)(lVar4 + 0x10300);
  uStack136 = *(undefined4 *)(lVar4 + 0x102e8);
  uStack132 = *(undefined4 *)(lVar4 + 0x102ec);
  uStack128 = *(undefined4 *)(lVar4 + 0x102f0);
  uStack124 = *(undefined4 *)(lVar4 + 0x102f4);
  local_120 = (void *)FUN_180008bb4(0x3c250);
  local_118 = (longlong)local_120 + 0x3c250;
  local_110 = local_118;
  memset(local_120,0,0x3c250);
  FUN_180003474((undefined8 *)(lVar4 + 0x10308),&local_120);
  if (local_120 != (void *)0x0) {
    FUN_180003f84(local_120,local_110 - (longlong)local_120);
  }
  ffxFsr2GetInterfaceDX12(&uStack224,local_68,*(undefined8 *)(lVar4 + 0x10308),0x3c250);
  local_70 = local_68;
  uStack244 = *(undefined4 *)(lVar2 + 8);
  uStack240 = *(undefined4 *)(lVar2 + 0xc);
  uStack236 = *(undefined4 *)(lVar2 + 0x10);
  local_e8 = *(undefined4 *)(lVar2 + 0x14);
  if (local_60._0_8_[1] == '\0') {
    cVar6 = *(char *)(lVar2 + 0x50);
  }
  else {
    cVar6 = *local_60._0_8_;
  }
  local_f8 = 0;
  if (cVar6 != '\0') {
    local_f8 = 8;
  }
  if (local_60._0_8_[3] == '\0') {
    cVar6 = *(char *)(lVar2 + 0x51);
  }
  else {
    cVar6 = local_60._0_8_[2];
  }
  if (cVar6 != '\0') {
    local_f8 = local_f8 | 0x20;
  }
  if (local_60._0_8_[5] == '\0') {
    cVar6 = *(char *)(lVar2 + 0x52);
  }
  else {
    cVar6 = local_60._0_8_[4];
  }
  if (cVar6 != '\0') {
    local_f8 = local_f8 | 1;
  }
  if (local_60._0_8_[7] == '\0') {
    cVar6 = *(char *)(lVar2 + 0x54);
  }
  else {
    cVar6 = local_60._0_8_[6];
  }
  if (cVar6 != '\0') {
    local_f8 = local_f8 | 4;
  }
  cVar6 = *(char *)(lVar2 + 0x55) == '\0';
  if (local_60._0_8_[9] != '\0') {
    cVar6 = local_60._0_8_[8];
  }
  if (cVar6 != '\0') {
    local_f8 = local_f8 | 2;
  }
  if ((local_60._0_8_[0x49] != '\0') && (local_60._0_8_[0x48] != '\0')) {
    local_f8 = local_f8 | 0x10;
  }
  ffxFsr2ContextCreate(lVar4 + 0x18,&local_f8);
  (**(code **)(**(longlong **)(lVar4 + 0x10) + 0x58))
            (*(longlong **)(lVar4 + 0x10),*(undefined4 *)(lVar2 + 0x10),
             *(undefined4 *)(lVar2 + 0x14));
  FUN_180002868(param_1);
  if (local_60._8_8_ != 0) {
    FUN_1800030d8();
  }
  if (local_50._8_8_ != 0) {
    FUN_1800030d8();
  }
  FUN_18000e8c0(local_40 ^ (ulonglong)auStack344);
  return;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_18000302c(longlong param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 *puVar3;
  undefined4 uVar4;
  float fVar5;
  undefined auStack104 [32];
  undefined4 local_48;
  undefined local_38 [8];
  longlong local_30;
  undefined local_28 [16];
  ulonglong local_18;
  
  local_18 = DAT_180418010 ^ (ulonglong)auStack104;
  uVar4 = 0;
  local_28 = ZEXT816(0);
  puVar3 = (undefined8 *)FUN_18000328c(local_38);
  shared_ptr__(local_28,*puVar3);
  if (local_30 != 0) {
    FUN_1800030d8();
  }
  if ((*(char *)(local_28._0_8_ + 0x1d) == '\0') || (*(char *)(local_28._0_8_ + 0x24) == '\0')) {
    iVar1 = *(int *)(param_1 + 0x18);
    if (iVar1 == 0) {
      uVar4 = 3;
    }
    else if (iVar1 == 1) {
      uVar4 = 2;
    }
    else if (iVar1 == 2) {
      uVar4 = 1;
    }
    else if (iVar1 == 3) {
      uVar4 = 4;
    }
    else if (iVar1 == 4) {
      uVar4 = *(undefined4 *)(param_1 + 8);
      uVar2 = *(undefined4 *)(param_1 + 0xc);
      goto LAB_18001128f;
    }
    local_48 = uVar4;
    ffxFsr2GetRenderResolutionFromQualityMode
              (param_1 + 0x10,param_1 + 0x14,*(undefined4 *)(param_1 + 8),
               *(undefined4 *)(param_1 + 0xc));
  }
  else {
    fVar5 = 1.0 / *(float *)(local_28._0_8_ + 0x20);
    uVar4 = (undefined4)(longlong)((float)(ulonglong)*(uint *)(param_1 + 8) * fVar5);
    uVar2 = (undefined4)(longlong)((float)(ulonglong)*(uint *)(param_1 + 0xc) * fVar5);
LAB_18001128f:
    *(undefined4 *)(param_1 + 0x14) = uVar2;
    *(undefined4 *)(param_1 + 0x10) = uVar4;
  }
  if (local_28._8_8_ != 0) {
    FUN_1800030d8();
  }
  FUN_18000e8c0(local_18 ^ (ulonglong)auStack104);
  return;
}



void FUN_1800030d8(longlong *param_1)

{
  longlong *plVar1;
  int *piVar2;
  int iVar3;
  
  LOCK();
  plVar1 = param_1 + 1;
  iVar3 = *(int *)plVar1;
  *(int *)plVar1 = *(int *)plVar1 + -1;
  if (iVar3 == 1) {
    (**(code **)*param_1)();
    LOCK();
    piVar2 = (int *)((longlong)param_1 + 0xc);
    iVar3 = *piVar2;
    *piVar2 = *piVar2 + -1;
    if (iVar3 == 1) {
                    // WARNING: Could not recover jumptable at 0x000180003111. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*param_1 + 8))(param_1);
      return;
    }
  }
  return;
}



void NVSDK_NGX_D3D12_ReleaseFeature(undefined4 *param_1)

{
  undefined4 uVar1;
  longlong lVar2;
  char cVar3;
  longlong *plVar4;
  undefined8 uVar5;
  void *pvVar6;
  undefined4 *puVar7;
  longlong lVar8;
  undefined8 *puVar9;
  longlong lVar10;
  undefined auStack136 [32];
  undefined local_68 [8];
  longlong local_60;
  undefined local_58 [16];
  undefined4 local_48;
  undefined4 uStack68;
  undefined4 uStack64;
  undefined4 uStack60;
  longlong local_38;
  undefined8 local_30;
  ulonglong local_28;
  
                    // 0x3118  12  NVSDK_NGX_D3D12_ReleaseFeature
  local_28 = DAT_180418010 ^ (ulonglong)auStack136;
  plVar4 = (longlong *)FUN_18000328c(local_68);
  lVar2 = *plVar4;
  lVar10 = lVar2 + 0x40;
  uVar5 = FUN_18000d1d8();
  FUN_180003954(lVar10,&local_48,param_1,uVar5);
  lVar8 = CONCAT44(uStack60,uStack64);
  if (lVar8 == 0) {
    FUN_180003ce8();
    local_38 = lVar2 + 0x48;
    pvVar6 = operator_new(0x20);
    uVar1 = *param_1;
    *(undefined8 *)((longlong)pvVar6 + 0x18) = 0;
    *(undefined4 *)((longlong)pvVar6 + 0x10) = uVar1;
    cVar3 = FUN_180003ff0(lVar10);
    if (cVar3 != '\0') {
      FUN_18001763c(lVar10);
      puVar7 = (undefined4 *)FUN_180003954(lVar10,local_58,(longlong)pvVar6 + 0x10,uVar5);
      local_48 = *puVar7;
      uStack68 = puVar7[1];
      uStack64 = puVar7[2];
      uStack60 = puVar7[3];
    }
    local_30 = 0;
    lVar8 = FUN_18000399c(lVar10,uVar5,CONCAT44(uStack68,local_48),pvVar6);
    FUN_180003fbc(&local_38);
  }
  lVar2 = *(longlong *)(lVar8 + 0x18);
  if (local_60 != 0) {
    FUN_1800030d8();
  }
  plVar4 = *(longlong **)(lVar2 + 0x10);
  *(undefined8 *)(lVar2 + 0x10) = 0;
  if (plVar4 != (longlong *)0x0) {
    (**(code **)(*plVar4 + 0x18))(plVar4,1);
  }
  if (lVar2 != -0x18) {
    FUN_180003b00();
  }
  puVar9 = (undefined8 *)FUN_18000328c(local_68);
  FUN_180003db0(*puVar9,param_1);
  if (local_60 != 0) {
    FUN_1800030d8();
  }
  FUN_180017930(&DAT_18041ebc0);
  FUN_18000e8c0(local_28 ^ (ulonglong)auStack136);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 * FUN_18000328c(undefined8 *param_1)

{
  void *_Dst;
  longlong in_GS_OFFSET;
  
  if (*(int *)(*(longlong *)(*(longlong *)(in_GS_OFFSET + 0x58) + (ulonglong)DAT_18041eb54 * 8) + 4)
      < _DAT_18041eb98) {
    _Init_thread_header(&DAT_18041eb98);
    if (_DAT_18041eb98 == -1) {
      _DAT_18041eb88 = ZEXT816(0);
      _Dst = operator_new(0x80);
      memset(_Dst,0,0x80);
      FUN_180002654(_Dst);
      FUN_180002800();
      atexit(&LAB_180010550);
      FUN_18000ea80(&DAT_18041eb98);
    }
  }
  *param_1 = 0;
  param_1[1] = 0;
  if (DAT_18041eb90 != 0) {
    LOCK();
    *(int *)(DAT_18041eb90 + 8) = *(int *)(DAT_18041eb90 + 8) + 1;
  }
  *param_1 = DAT_18041eb88;
  param_1[1] = DAT_18041eb90;
  return param_1;
}



// Library Function - Multiple Matches With Same Base Name
//  public: __cdecl std::shared_ptr<struct _EXCEPTION_RECORD const >::shared_ptr<struct
// _EXCEPTION_RECORD const >(class std::shared_ptr<struct _EXCEPTION_RECORD const > const & __ptr64)
// __ptr64
//  public: __cdecl std::shared_ptr<class __ExceptionPtr>::shared_ptr<class __ExceptionPtr>(class
// std::shared_ptr<class __ExceptionPtr> const & __ptr64) __ptr64
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 * shared_ptr__(undefined8 *param_1,undefined8 *param_2)

{
  int *piVar1;
  
  *param_1 = 0;
  param_1[1] = 0;
  if (param_2[1] != 0) {
    LOCK();
    piVar1 = (int *)(param_2[1] + 8);
    *piVar1 = *piVar1 + 1;
  }
  *param_1 = *param_2;
  param_1[1] = param_2[1];
  return param_1;
}



undefined8
ffxFsr2GetRenderResolutionFromQualityMode
          (undefined4 *param_1,undefined4 *param_2,uint param_3,uint param_4,int param_5)

{
  undefined8 uVar1;
  float fVar2;
  
                    // 0x3398  37  ffxFsr2GetRenderResolutionFromQualityMode
  if ((param_1 == (undefined4 *)0x0) || (param_2 == (undefined4 *)0x0)) {
    uVar1 = 0x80000000;
  }
  else if (param_5 - 1U < 4) {
    fVar2 = (float)ffxFsr2GetUpscaleRatioFromQualityMode();
    *param_1 = (int)(longlong)((float)(ulonglong)param_3 / fVar2);
    *param_2 = (int)(longlong)((float)(ulonglong)param_4 / fVar2);
    uVar1 = 0;
  }
  else {
    uVar1 = 0x80000009;
  }
  return uVar1;
}



undefined8 ffxFsr2GetUpscaleRatioFromQualityMode(int param_1)

{
                    // 0x3420  40  ffxFsr2GetUpscaleRatioFromQualityMode
  if (param_1 == 1) {
    return 0x3fc00000;
  }
  if (param_1 == 2) {
    return 0x3fd9999a;
  }
  if (param_1 == 3) {
    return 0x40000000;
  }
  if (param_1 != 4) {
    return 0;
  }
  return 0x40400000;
}



void ** FUN_180003444(void **param_1,void **param_2)

{
  void *pvVar1;
  void *_Memory;
  
  if (param_1 != param_2) {
    pvVar1 = *param_2;
    *param_2 = (void *)0x0;
    _Memory = *param_1;
    *param_1 = pvVar1;
    if (_Memory != (void *)0x0) {
      free(_Memory);
    }
  }
  return param_1;
}



undefined8 * FUN_180003474(undefined8 *param_1,undefined8 *param_2)

{
  if (param_1 != param_2) {
    FUN_180003eb4();
    *param_1 = *param_2;
    param_1[1] = param_2[1];
    param_1[2] = param_2[2];
    *param_2 = 0;
    param_2[1] = 0;
    param_2[2] = 0;
  }
  return param_1;
}



undefined8 * FUN_1800034c0(undefined8 *param_1,longlong param_2)

{
  int iVar1;
  undefined8 uVar2;
  undefined8 *puVar3;
  undefined4 local_res10;
  undefined4 uStackX20;
  undefined4 local_res18 [2];
  undefined4 local_res20 [2];
  void *local_10;
  
  if ((*(char *)(param_2 + 0x2c) == '\0') || (iVar1 = *(int *)(param_2 + 0x28), iVar1 == 0)) {
LAB_18001130a:
    if (*(char *)(param_2 + 0x3c) == '\0') {
      local_res10 = 0;
    }
    else {
      local_res10 = *(undefined4 *)(param_2 + 0x38);
    }
    if (*(char *)(param_2 + 0x44) == '\0') {
      local_res18[0] = 0x7f800000;
    }
    else {
      local_res18[0] = *(undefined4 *)(param_2 + 0x40);
    }
    if (*(char *)(param_2 + 0x34) == '\0') {
      local_res20[0] = 0x42700000;
    }
    else {
      local_res20[0] = *(undefined4 *)(param_2 + 0x30);
    }
    puVar3 = (undefined8 *)FUN_180018e98(&local_10,local_res20,local_res18,&local_res10);
    uVar2 = *puVar3;
    *puVar3 = 0;
    *param_1 = uVar2;
  }
  else {
    if (iVar1 == 1) {
      puVar3 = (undefined8 *)FUN_18000357c(&local_res10);
    }
    else {
      if (iVar1 != 2) goto LAB_18001130a;
      puVar3 = (undefined8 *)FUN_180018f10(&local_res10);
    }
    uVar2 = *puVar3;
    *puVar3 = 0;
    *param_1 = uVar2;
    local_10 = (void *)CONCAT44(uStackX20,local_res10);
  }
  if (local_10 != (void *)0x0) {
    free(local_10);
  }
  return param_1;
}



undefined8 * FUN_180003520(undefined8 *param_1)

{
  FUN_1800035e4();
  *param_1 = CyberPipeline::vftable;
  param_1[0x10] = 0;
  param_1[0x11] = 0;
  param_1[0x12] = 0;
  param_1[0x13] = 0;
  param_1[0x14] = 0;
  param_1[0x15] = 0;
  param_1[0x16] = 0;
  param_1[0x17] = 0;
  return param_1;
}



undefined (**) [16] FUN_18000357c(undefined (**param_1) [16])

{
  undefined (*pauVar1) [16];
  HMODULE pHVar2;
  
  pauVar1 = (undefined (*) [16])operator_new(0x10);
  *pauVar1 = ZEXT816(0);
  *(undefined8 *)(*pauVar1 + 8) = 0;
  *(undefined ***)*pauVar1 = ViewMatrixHook::Cyberpunk2077::vftable;
  pHVar2 = GetModuleHandleW(L"Cyberpunk2077.exe");
  *(longlong *)(*pauVar1 + 8) = *(longlong *)(pHVar2 + 0x130e430) + 0x60;
  *param_1 = pauVar1;
  return param_1;
}



undefined8 * FUN_1800035e4(undefined8 *param_1,undefined8 param_2)

{
  *param_1 = Pipeline::vftable;
  param_1[1] = 0;
  memset((void *)((longlong)param_1 + 0x14),0,0x5c);
  param_1[2] = 0;
  *(undefined4 *)(param_1 + 3) = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  *(undefined4 *)(param_1 + 6) = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  *(undefined4 *)(param_1 + 9) = 0;
  param_1[10] = 0;
  param_1[0xb] = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  param_1[0xd] = 0;
  param_1[0xe] = 0;
  FUN_18000366c(param_1,param_2);
  return param_1;
}



void FUN_18000366c(longlong param_1,undefined8 param_2)

{
  undefined8 local_70;
  undefined4 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined4 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined4 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined4 local_20;
  undefined8 local_18;
  
  memset(&local_70,0,0x60);
  local_70 = 0;
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  *(undefined8 *)(param_1 + 8) = param_2;
  FUN_18000e154(param_1 + 0x10,&local_70);
  FUN_180003e80(&local_70);
  FUN_180004bdc(param_1 + 0x58,param_2,0,0x180);
  FUN_180004bdc(param_1 + 0x10,param_2,3);
  FUN_180004bdc(param_1 + 0x28,param_2,2);
  FUN_180004bdc(param_1 + 0x40,param_2,1);
  return;
}



undefined8 FUN_180003754(longlong param_1)

{
  undefined8 *_Memory;
  int iVar1;
  undefined8 *_Memory_00;
  longlong *plVar2;
  undefined8 **ppuVar3;
  int local_38 [2];
  undefined8 *local_30;
  undefined local_28 [16];
  
  iVar1 = rand();
  _Memory_00 = (undefined8 *)operator_new(0x10320);
  _Memory_00[1] = 0;
  *(undefined (*) [16])(_Memory_00 + 0x2062) = ZEXT816(0);
  *_Memory_00 = 0;
  _Memory_00[2] = 0;
  memset(_Memory_00 + 3,0,0x102f0);
  _Memory_00[0x2061] = 0;
  _Memory_00[0x2062] = 0;
  _Memory_00[0x2063] = 0;
  param_1 = param_1 + 0x40;
  local_38[0] = iVar1;
  local_30 = _Memory_00;
  plVar2 = (longlong *)FUN_18000386c(param_1,local_28,local_38);
  ppuVar3 = (undefined8 **)(*plVar2 + 0x18);
  if (ppuVar3 != &local_30) {
    _Memory = *ppuVar3;
    *ppuVar3 = _Memory_00;
    _Memory_00 = (undefined8 *)0x0;
    if (_Memory != (undefined8 *)0x0) {
      FUN_18000e118(_Memory);
      free(_Memory);
    }
  }
  if (_Memory_00 != (undefined8 *)0x0) {
    FUN_18000e118(_Memory_00);
    free(_Memory_00);
  }
  local_38[0] = iVar1;
  plVar2 = (longlong *)FUN_18000386c(param_1,local_28,local_38);
  *(int *)(*(longlong *)(*plVar2 + 0x18) + 8) = iVar1;
  local_38[0] = iVar1;
  plVar2 = (longlong *)FUN_18000386c(param_1,local_28,local_38);
  return *(undefined8 *)(*plVar2 + 0x18);
}



void FUN_18000386c(longlong param_1,longlong *param_2,undefined4 *param_3)

{
  char cVar1;
  undefined8 uVar2;
  void *pvVar3;
  longlong lVar4;
  undefined4 *puVar5;
  undefined auStack120 [32];
  longlong local_58;
  void *local_50;
  undefined4 local_48;
  undefined4 uStack68;
  undefined4 uStack64;
  undefined4 uStack60;
  ulonglong local_38;
  
  local_38 = DAT_180418010 ^ (ulonglong)auStack120;
  uVar2 = FUN_18000d1d8(param_1,param_3,4);
  FUN_180003954(param_1,&local_48,param_3,uVar2);
  if (CONCAT44(uStack60,uStack64) == 0) {
    FUN_180003ce8(param_1);
    local_58 = param_1 + 8;
    local_50 = (void *)0x0;
    pvVar3 = operator_new(0x20);
    *(undefined4 *)((longlong)pvVar3 + 0x10) = *param_3;
    *(undefined8 *)((longlong)pvVar3 + 0x18) = 0;
    local_50 = pvVar3;
    cVar1 = FUN_180003ff0(param_1);
    if (cVar1 != '\0') {
      FUN_18001763c(param_1);
      puVar5 = (undefined4 *)FUN_180003954(param_1,&local_48,(longlong)pvVar3 + 0x10,uVar2);
      local_48 = *puVar5;
      uStack68 = puVar5[1];
      uStack64 = puVar5[2];
      uStack60 = puVar5[3];
    }
    local_50 = (void *)0x0;
    lVar4 = FUN_18000399c(param_1,uVar2,CONCAT44(uStack68,local_48),pvVar3);
    *param_2 = lVar4;
    *(undefined *)(param_2 + 1) = 1;
    FUN_180003fbc(&local_58);
  }
  else {
    *param_2 = CONCAT44(uStack60,uStack64);
    *(undefined *)(param_2 + 1) = 0;
  }
  FUN_18000e8c0(local_38 ^ (ulonglong)auStack120);
  return;
}



longlong ** FUN_180003954(longlong param_1,longlong **param_2,int *param_3,ulonglong param_4)

{
  longlong **pplVar1;
  
  param_4 = *(ulonglong *)(param_1 + 0x30) & param_4;
  pplVar1 = *(longlong ***)(*(longlong *)(param_1 + 0x18) + 8 + param_4 * 0x10);
  if (pplVar1 == *(longlong ***)(param_1 + 8)) {
    *param_2 = (longlong *)*(longlong ***)(param_1 + 8);
LAB_180003992:
    param_2[1] = (longlong *)0x0;
  }
  else {
    for (; *param_3 != *(int *)(pplVar1 + 2); pplVar1 = (longlong **)pplVar1[1]) {
      if (pplVar1 == *(longlong ***)(*(longlong *)(param_1 + 0x18) + param_4 * 0x10)) {
        *param_2 = (longlong *)pplVar1;
        goto LAB_180003992;
      }
    }
    *param_2 = *pplVar1;
    param_2[1] = (longlong *)pplVar1;
  }
  return param_2;
}



longlong * FUN_18000399c(longlong param_1,ulonglong param_2,longlong param_3,longlong *param_4)

{
  longlong **pplVar1;
  longlong lVar2;
  longlong lVar3;
  
  pplVar1 = *(longlong ***)(param_3 + 8);
  *(longlong *)(param_1 + 0x10) = *(longlong *)(param_1 + 0x10) + 1;
  *param_4 = param_3;
  param_4[1] = (longlong)pplVar1;
  *pplVar1 = param_4;
  *(longlong **)(param_3 + 8) = param_4;
  lVar2 = *(longlong *)(param_1 + 0x18);
  param_2 = *(ulonglong *)(param_1 + 0x30) & param_2;
  lVar3 = *(longlong *)(lVar2 + param_2 * 0x10);
  if (lVar3 == *(longlong *)(param_1 + 8)) {
    *(longlong **)(lVar2 + param_2 * 0x10) = param_4;
  }
  else {
    if (lVar3 == param_3) {
      *(longlong **)(lVar2 + param_2 * 0x10) = param_4;
      return param_4;
    }
    if (*(longlong ***)(lVar2 + 8 + param_2 * 0x10) != pplVar1) {
      return param_4;
    }
  }
  *(longlong **)(lVar2 + 8 + param_2 * 0x10) = param_4;
  return param_4;
}



undefined8 ffxFsr2ContextCreate(void *param_1,longlong param_2)

{
  undefined8 uVar1;
  
                    // 0x39e0  29  ffxFsr2ContextCreate
  memset(param_1,0,0x10260);
  if ((param_1 == (void *)0x0) || (param_2 == 0)) {
    uVar1 = 0x80000000;
  }
  else if ((((*(longlong *)(param_2 + 0x20) == 0) || (*(longlong *)(param_2 + 0x18) == 0)) ||
           (*(longlong *)(param_2 + 0x28) == 0)) ||
          ((*(longlong *)(param_2 + 0x78) != 0 && (*(longlong *)(param_2 + 0x80) == 0)))) {
    uVar1 = 0x80000008;
  }
  else {
    uVar1 = FUN_18000582c(param_1,param_2);
  }
  return uVar1;
}



undefined8
ffxFsr2GetInterfaceDX12(undefined8 *param_1,undefined8 param_2,longlong param_3,ulonglong param_4)

{
                    // 0x3a50  33  ffxFsr2GetInterfaceDX12
  if ((param_1 != (undefined8 *)0x0) && (param_3 != 0)) {
    if (0x3c24f < param_4) {
      param_1[0xc] = param_3;
      param_1[1] = FUN_1800043e8;
      *param_1 = &LAB_180004c88;
      param_1[2] = FUN_180003d08;
      param_1[3] = &DAT_180006138;
      param_1[4] = &DAT_18000c9a0;
      param_1[5] = &LAB_1800095a8;
      param_1[6] = &LAB_18000ae80;
      param_1[7] = &LAB_180003c0c;
      param_1[8] = &DAT_180008118;
      param_1[9] = FUN_180003c4c;
      param_1[10] = FUN_18000c8d0;
      param_1[0xb] = FUN_180006960;
      param_1[0xd] = param_4;
      return 0;
    }
    return 0x8000000e;
  }
  return 0x80000000;
}



undefined8 FUN_180003b00(longlong param_1)

{
  longlong lVar1;
  longlong lVar2;
  undefined4 *puVar3;
  
  lVar1 = param_1 + 0x18;
  (**(code **)(param_1 + 0x60))(lVar1,param_1 + 0x138);
  (**(code **)(param_1 + 0x60))(lVar1,param_1 + 0xf28);
  (**(code **)(param_1 + 0x60))(lVar1,param_1 + 0x1d18);
  (**(code **)(param_1 + 0x60))(lVar1,param_1 + 0x2b08);
  (**(code **)(param_1 + 0x60))(lVar1,param_1 + 0x38f8);
  (**(code **)(param_1 + 0x60))(lVar1,param_1 + 0x46e8);
  (**(code **)(param_1 + 0x60))(lVar1,param_1 + 0x54d8);
  (**(code **)(param_1 + 0x60))(lVar1,param_1 + 0x62c8);
  (**(code **)(param_1 + 0x60))(lVar1,param_1 + 0x70b8);
  puVar3 = (undefined4 *)(param_1 + 0x7ea8);
  *(undefined8 *)(param_1 + 0x7eac) = 0;
  *(undefined8 *)(param_1 + 0x7eb4) = 0;
  *(undefined8 *)(param_1 + 0x7ebc) = 0;
  lVar2 = 0x2b;
  *(undefined8 *)(param_1 + 0x7ed0) = 0;
  *(undefined8 *)(param_1 + 0x7ef0) = 0;
  do {
    (**(code **)(param_1 + 0x50))(lVar1,*puVar3);
    puVar3 = puVar3 + 1;
    lVar2 = lVar2 + -1;
  } while (lVar2 != 0);
  if (*(longlong *)(param_1 + 0x120) != 0) {
    (**(code **)(param_1 + 0x28))(lVar1);
    *(undefined8 *)(param_1 + 0x120) = 0;
  }
  return 0;
}



undefined8 FUN_180003c4c(undefined8 param_1,longlong **param_2)

{
  if (param_2 != (longlong **)0x0) {
    if (*param_2 != (longlong *)0x0) {
      (**(code **)(**param_2 + 0x10))();
    }
    *param_2 = (longlong *)0x0;
    if (param_2[1] != (longlong *)0x0) {
      (**(code **)(*param_2[1] + 0x10))();
    }
    param_2[1] = (longlong *)0x0;
  }
  return 0;
}



void FUN_180003c88(longlong param_1,undefined4 param_2,undefined4 param_3)

{
  *(undefined4 *)(param_1 + 0x78) = param_2;
  *(undefined4 *)(param_1 + 0x7c) = param_3;
  FUN_180003c94();
  return;
}



void FUN_180003c94(longlong *param_1)

{
  (**(code **)*param_1)();
                    // WARNING: Could not recover jumptable at 0x000180003cad. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 8))(param_1);
  return;
}



void * FUN_180003cb4(void *param_1,ulonglong param_2)

{
  FUN_180002b48();
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_180003ce8(longlong param_1)

{
  code *pcVar1;
  
  if (*(longlong *)(param_1 + 0x10) != 0x7ffffffffffffff) {
    return;
  }
  std::_Xlength_error("unordered_map/set too long");
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



undefined8 FUN_180003d08(longlong param_1)

{
  longlong **pplVar1;
  uint uVar2;
  
  pplVar1 = *(longlong ***)(param_1 + 0x60);
  (**(code **)(*pplVar1[0x7803] + 0x10))();
  (**(code **)(*pplVar1[0x7805] + 0x10))();
  (**(code **)(*pplVar1[0x7806] + 0x10))();
  (**(code **)(*pplVar1[0x7808] + 0x10))();
  uVar2 = 0;
  if (*(int *)((longlong)pplVar1 + 0x3b20c) != 0) {
    do {
      if (pplVar1[((ulonglong)uVar2 + 0x10e5) * 7] != (longlong *)0x0) {
        (**(code **)(*pplVar1[((ulonglong)uVar2 + 0x10e5) * 7] + 0x10))();
        pplVar1[((ulonglong)uVar2 + 0x10e5) * 7] = (longlong *)0x0;
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < *(uint *)((longlong)pplVar1 + 0x3b20c));
  }
  *(undefined4 *)((longlong)pplVar1 + 0x3b20c) = 0;
  if (*pplVar1 != (longlong *)0x0) {
    (**(code **)(**pplVar1 + 0x10))();
    *pplVar1 = (longlong *)0x0;
  }
  return 0;
}



longlong * FUN_180003db0(longlong param_1,int *param_2)

{
  longlong lVar1;
  longlong *_Memory;
  ulonglong uVar2;
  longlong *plVar3;
  longlong **pplVar4;
  
  for (pplVar4 = (longlong **)**(longlong ***)(param_1 + 0x48);
      (pplVar4 != *(longlong ***)(param_1 + 0x48) && (*(int *)(pplVar4 + 2) != *param_2));
      pplVar4 = (longlong **)*pplVar4) {
  }
  param_1 = param_1 + 0x40;
  uVar2 = FUN_18000d1d8(param_1,pplVar4 + 2,4);
  lVar1 = *(longlong *)(param_1 + 0x18);
  uVar2 = uVar2 & *(ulonglong *)(param_1 + 0x30);
  if (*(longlong ***)(lVar1 + 8 + uVar2 * 0x10) == pplVar4) {
    if (*(longlong ***)(lVar1 + uVar2 * 0x10) == pplVar4) {
      plVar3 = *(longlong **)(param_1 + 8);
      *(longlong **)(lVar1 + uVar2 * 0x10) = plVar3;
    }
    else {
      plVar3 = pplVar4[1];
    }
    *(longlong **)(lVar1 + 8 + uVar2 * 0x10) = plVar3;
  }
  else if (*(longlong ***)(lVar1 + uVar2 * 0x10) == pplVar4) {
    *(longlong **)(lVar1 + uVar2 * 0x10) = *pplVar4;
  }
  plVar3 = *pplVar4;
  *(longlong *)(param_1 + 0x10) = *(longlong *)(param_1 + 0x10) + -1;
  *pplVar4[1] = (longlong)plVar3;
  plVar3[1] = (longlong)pplVar4[1];
  _Memory = pplVar4[3];
  if (_Memory != (longlong *)0x0) {
    FUN_18000e118(_Memory);
    free(_Memory);
  }
  FUN_180003f84(pplVar4,0x20);
  return plVar3;
}



void FUN_180003e80(longlong param_1)

{
  FUN_18000e0f4(param_1 + 0x58);
  FUN_18000e0f4(param_1 + 0x40);
  FUN_18000e0f4(param_1 + 0x28);
  FUN_18000e0f4(param_1 + 0x10);
  return;
}



void FUN_180003eb4(longlong *param_1)

{
  longlong lVar1;
  
  lVar1 = *param_1;
  if (lVar1 != 0) {
    FUN_180003f84(lVar1,param_1[2] - lVar1);
    *param_1 = 0;
    param_1[1] = 0;
    param_1[2] = 0;
  }
  return;
}



void FUN_180003ee8(undefined8 param_1,undefined8 *param_2)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  
  *(undefined8 *)param_2[1] = 0;
  puVar2 = (undefined8 *)*param_2;
  while (puVar2 != (undefined8 *)0x0) {
    puVar1 = (undefined8 *)*puVar2;
    if (0xf < (ulonglong)puVar2[5]) {
      FUN_180003f84(puVar2[2],puVar2[5] + 1);
    }
    puVar2[4] = 0;
    *(undefined *)(puVar2 + 2) = 0;
    puVar2[5] = 0xf;
    FUN_180003f84(puVar2,0x38);
    puVar2 = puVar1;
  }
  return;
}



void FUN_180003f50(undefined8 param_1,undefined8 *param_2)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  
  *(undefined8 *)param_2[1] = 0;
  puVar2 = (undefined8 *)*param_2;
  while (puVar2 != (undefined8 *)0x0) {
    puVar1 = (undefined8 *)*puVar2;
    FUN_180003f84(puVar2,0x20);
    puVar2 = puVar1;
  }
  return;
}



void FUN_180003f84(void *param_1,ulonglong param_2)

{
  void *_Memory;
  
  _Memory = param_1;
  if ((0xfff < param_2) &&
     (_Memory = *(void **)((longlong)param_1 + -8),
     0x1f < (ulonglong)((longlong)param_1 + (-8 - (longlong)_Memory)))) {
                    // WARNING: Subroutine does not return
    _invalid_parameter_noinfo_noreturn();
  }
  free(_Memory);
  return;
}



void FUN_180003fbc(longlong param_1)

{
  void *_Memory;
  
  if ((*(longlong *)(param_1 + 8) != 0) &&
     (_Memory = *(void **)(*(longlong *)(param_1 + 8) + 0x18), _Memory != (void *)0x0)) {
    FUN_18000e118(_Memory);
    free(_Memory);
  }
  if (*(longlong *)(param_1 + 8) != 0) {
    FUN_180003f84(*(longlong *)(param_1 + 8),0x20);
  }
  return;
}



ulonglong FUN_180003ff0(float *param_1)

{
  ulonglong in_RAX;
  ulonglong uVar1;
  float fVar2;
  float fVar3;
  
  uVar1 = *(longlong *)(param_1 + 4) + 1;
  if ((longlong)uVar1 < 0) {
    in_RAX = uVar1 >> 1 | (ulonglong)((uint)uVar1 & 1);
    fVar2 = (float)in_RAX + (float)in_RAX;
  }
  else {
    fVar2 = (float)uVar1;
  }
  uVar1 = *(ulonglong *)(param_1 + 0xe);
  if ((longlong)uVar1 < 0) {
    in_RAX = uVar1 >> 1 | (ulonglong)((uint)uVar1 & 1);
    fVar3 = (float)in_RAX + (float)in_RAX;
  }
  else {
    fVar3 = (float)uVar1;
  }
  return in_RAX & 0xffffffffffffff00 |
         (ulonglong)(*param_1 <= fVar2 / fVar3 && fVar2 / fVar3 != *param_1);
}



undefined8 FUN_180004050(undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined8 uVar2;
  undefined4 local_res8;
  undefined4 local_resc;
  undefined4 local_res10;
  undefined4 local_res14;
  undefined4 local_68 [2];
  undefined4 *local_60;
  undefined8 local_58;
  undefined4 *local_50;
  undefined4 local_48;
  
  local_68[0] = *param_1;
  puVar1 = param_1 + 6;
  local_res8 = 0;
  local_60 = &local_res8;
  local_resc = 1;
  local_50 = &local_res10;
  local_res10 = 0x24;
  local_58 = 2;
  local_res14 = 6;
  local_48 = 2;
  uVar2 = (**(code **)(param_1 + 0x16))(puVar1,7,local_68,param_1 + 0x18b2);
  if ((int)uVar2 == 0) {
    uVar2 = (**(code **)(param_1 + 0x16))(puVar1,6,local_68,param_1 + 0x1536);
    if ((int)uVar2 == 0) {
      local_48 = 1;
      uVar2 = (**(code **)(param_1 + 0x16))(puVar1,0,local_68,param_1 + 0x4e);
      if ((int)uVar2 == 0) {
        uVar2 = (**(code **)(param_1 + 0x16))(puVar1,1,local_68,param_1 + 0x3ca);
        if ((int)uVar2 == 0) {
          uVar2 = (**(code **)(param_1 + 0x16))(puVar1,2,local_68,param_1 + 0x746);
          if ((int)uVar2 == 0) {
            uVar2 = (**(code **)(param_1 + 0x16))(puVar1,3,local_68,param_1 + 0xac2);
            if ((int)uVar2 == 0) {
              uVar2 = (**(code **)(param_1 + 0x16))(puVar1,4,local_68,param_1 + 0xe3e);
              if ((int)uVar2 == 0) {
                uVar2 = (**(code **)(param_1 + 0x16))(puVar1,5,local_68,param_1 + 0x11ba);
                if ((int)uVar2 == 0) {
                  uVar2 = (**(code **)(param_1 + 0x16))(puVar1,8,local_68,param_1 + 0x1c2e);
                  if ((int)uVar2 == 0) {
                    FUN_180004220(param_1 + 0x4e);
                    FUN_180004220(param_1 + 0x3ca);
                    FUN_180004220(param_1 + 0x746);
                    FUN_180004220(param_1 + 0xac2);
                    FUN_180004220(param_1 + 0xe3e);
                    FUN_180004220(param_1 + 0x18b2);
                    FUN_180004220(param_1 + 0x11ba);
                    FUN_180004220(param_1 + 0x1536);
                    FUN_180004220(param_1 + 0x1c2e);
                    uVar2 = 0;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return uVar2;
}



undefined8 FUN_180004220(longlong param_1)

{
  wchar_t wVar1;
  wchar_t wVar2;
  short sVar3;
  short sVar4;
  ulonglong uVar5;
  uint uVar6;
  longlong lVar7;
  wchar_t *pwVar8;
  short *psVar9;
  uint uVar10;
  longlong lVar11;
  
  uVar10 = 0;
  if (*(int *)(param_1 + 0x14) != 0) {
    do {
      uVar6 = 0;
      uVar5 = (ulonglong)uVar10;
      lVar11 = 0;
      do {
        pwVar8 = L"r_input_color_jittered" + (longlong)(int)uVar6 * 0x42;
        lVar7 = (param_1 + 0x464 + uVar5 * 0x88) - (longlong)pwVar8;
        do {
          wVar1 = *pwVar8;
          wVar2 = *(wchar_t *)((longlong)pwVar8 + lVar7);
          if (wVar1 != wVar2) break;
          pwVar8 = pwVar8 + 1;
        } while (wVar2 != L'\0');
        if (wVar1 == wVar2) break;
        uVar6 = uVar6 + 1;
        lVar11 = lVar11 + 1;
      } while (uVar6 < 0x15);
      if (uVar6 == 0x15) {
        return 0x8000000a;
      }
      uVar10 = uVar10 + 1;
      *(undefined4 *)(uVar5 * 0x88 + 0x460 + param_1) =
           *(undefined4 *)(&UNK_180020e70 + lVar11 * 0x84);
    } while (uVar10 < *(uint *)(param_1 + 0x14));
  }
  uVar10 = 0;
  if (*(int *)(param_1 + 0x10) != 0) {
    do {
      uVar6 = 0;
      uVar5 = (ulonglong)uVar10;
      lVar11 = 0;
      do {
        pwVar8 = L"rw_reconstructed_previous_nearest_depth" + (longlong)(int)uVar6 * 0x42;
        lVar7 = (param_1 + 0x24 + uVar5 * 0x88) - (longlong)pwVar8;
        do {
          wVar1 = *pwVar8;
          wVar2 = *(wchar_t *)((longlong)pwVar8 + lVar7);
          if (wVar1 != wVar2) break;
          pwVar8 = pwVar8 + 1;
        } while (wVar2 != L'\0');
        if (wVar1 == wVar2) break;
        uVar6 = uVar6 + 1;
        lVar11 = lVar11 + 1;
      } while (uVar6 < 0xe);
      if (uVar6 == 0xe) {
        return 0x8000000a;
      }
      uVar10 = uVar10 + 1;
      *(undefined4 *)(uVar5 * 0x88 + 0x20 + param_1) =
           *(undefined4 *)(&UNK_180020730 + lVar11 * 0x84);
    } while (uVar10 < *(uint *)(param_1 + 0x10));
  }
  uVar10 = 0;
  if (*(int *)(param_1 + 0x18) != 0) {
    do {
      uVar6 = 0;
      uVar5 = (ulonglong)uVar10;
      lVar11 = 0;
      do {
        psVar9 = &DAT_1800205a4 + (longlong)(int)uVar6 * 0x42;
        lVar7 = (param_1 + 0xce4 + uVar5 * 0x88) - (longlong)psVar9;
        do {
          sVar3 = *psVar9;
          sVar4 = *(short *)((longlong)psVar9 + lVar7);
          if (sVar3 != sVar4) break;
          psVar9 = psVar9 + 1;
        } while (sVar4 != 0);
        if (sVar3 == sVar4) break;
        uVar6 = uVar6 + 1;
        lVar11 = lVar11 + 1;
      } while (uVar6 < 3);
      if (uVar6 == 3) {
        return 0x8000000a;
      }
      uVar10 = uVar10 + 1;
      *(undefined4 *)(uVar5 * 0x88 + 0xce0 + param_1) = (&DAT_1800205a0)[lVar11 * 0x21];
    } while (uVar10 < *(uint *)(param_1 + 0x18));
  }
  return 0;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_1800043e8(undefined8 param_1,undefined4 *param_2,longlong *param_3)

{
  int iVar1;
  undefined auStack168 [32];
  int local_88 [2];
  undefined8 local_80;
  int local_78;
  undefined local_70 [8];
  undefined4 uStack104;
  undefined8 local_60;
  undefined local_58 [16];
  undefined local_48 [16];
  undefined local_38 [16];
  undefined8 local_28;
  undefined4 local_20;
  ulonglong local_18;
  
  local_18 = DAT_180418010 ^ (ulonglong)auStack168;
  local_88[0] = 0x66;
  iVar1 = (**(code **)(*param_3 + 0x68))(param_3,7,local_88);
  if ((iVar1 < 0) || (local_88[0] == 0x51)) {
    *param_2 = 0;
  }
  else if (local_88[0] == 0x60) {
    *param_2 = 1;
  }
  else if (local_88[0] == 0x61) {
    *param_2 = 2;
  }
  else if (local_88[0] == 0x62) {
    *param_2 = 3;
  }
  else if (local_88[0] == 99) {
    *param_2 = 4;
  }
  else if (local_88[0] == 100) {
    *param_2 = 5;
  }
  else if (local_88[0] == 0x65) {
    *param_2 = 6;
  }
  else {
    *param_2 = 7;
  }
  local_60 = 0;
  _local_70 = ZEXT816(0);
  iVar1 = (**(code **)(*param_3 + 0x68))(param_3,8,local_70);
  if (-1 < iVar1) {
    param_2[1] = local_70._4_4_;
    param_2[2] = uStack104;
  }
  local_28 = 0;
  local_20 = 0;
  local_58 = ZEXT816(0);
  local_48 = ZEXT816(0);
  local_38 = ZEXT816(0);
  iVar1 = (**(code **)(*param_3 + 0x68))(param_3,0,local_58,0x3c);
  if (-1 < iVar1) {
    *(byte *)(param_2 + 3) = (byte)(local_58._8_4_ >> 1) & 1;
  }
  local_80 = 0;
  local_78 = 0;
  iVar1 = (**(code **)(*param_3 + 0x68))(param_3,0x1b,&local_80);
  if (-1 < iVar1) {
    *(bool *)((longlong)param_2 + 0xd) = local_78 != 0;
  }
  FUN_18000e8c0(local_18 ^ (ulonglong)auStack168);
  return;
}



undefined8 FUN_180004550(void)

{
  return 10;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_180004558(longlong param_1)

{
  longlong lVar1;
  longlong *plVar2;
  code *pcVar3;
  undefined4 uVar4;
  int iVar5;
  void *_Dst;
  longlong *plVar6;
  longlong *plVar7;
  undefined8 *puVar8;
  longlong **pplVar9;
  longlong *plVar10;
  undefined auStack168 [32];
  undefined **local_88;
  undefined local_80 [16];
  longlong local_68;
  undefined *local_60;
  undefined8 local_58;
  undefined local_50 [16];
  undefined local_40 [16];
  undefined8 local_30 [2];
  undefined local_20 [16];
  ulonglong local_10;
  
  local_40._0_8_ = 0x18000456f;
  _Dst = operator_new(0x68);
  local_20 = CONCAT88(_Dst,local_20._0_8_);
  local_40._0_8_ = 0x180004585;
  memset(_Dst,0,0x68);
  local_40._0_8_ = 0x180004591;
  plVar6 = (longlong *)FUN_1800048b4(_Dst,*(undefined8 *)(param_1 + 8));
  pplVar9 = (longlong **)(param_1 + 0x80);
  if (pplVar9 == (longlong **)(local_20 + 8)) {
    if (plVar6 != (longlong *)0x0) {
      local_40._0_8_ = 0x1800114fd;
      (**(code **)(*plVar6 + 0x18))(plVar6,1);
    }
  }
  else {
    plVar10 = *pplVar9;
    *pplVar9 = plVar6;
    if (plVar10 != (longlong *)0x0) {
      local_40._0_8_ = 0x1800114df;
      (**(code **)(*plVar10 + 0x18))(plVar10,1);
    }
  }
  plVar6 = *pplVar9;
  local_10 = DAT_180418010 ^ (ulonglong)auStack168;
  local_30[0] = 0;
  local_20 = ZEXT816(0);
  FUN_180001c10(local_30,L"Reactive Mask",0xd);
  lVar1 = plVar6[10];
  uVar4 = (**(code **)(*plVar6 + 0x10))(plVar6);
  FUN_18000e278(lVar1 + 0x50,uVar4,plVar6 + 4);
  plVar7 = (longlong *)(**(code **)*plVar6)(plVar6);
  plVar10 = (longlong *)plVar6[2];
  if ((longlong *)plVar6[2] != plVar7) {
    if (plVar7 != (longlong *)0x0) {
      (**(code **)(*plVar7 + 8))(plVar7);
    }
    plVar2 = (longlong *)plVar6[2];
    plVar6[2] = (longlong)plVar7;
    plVar10 = plVar7;
    if (plVar2 != (longlong *)0x0) {
      (**(code **)(*plVar2 + 0x10))();
      plVar10 = (longlong *)plVar6[2];
    }
  }
  pcVar3 = *(code **)(*plVar10 + 0x30);
  puVar8 = (undefined8 *)FUN_180004fb0(&local_88,local_30,L" Signature");
  if (7 < (ulonglong)puVar8[3]) {
    puVar8 = (undefined8 *)*puVar8;
  }
  (*pcVar3)(plVar10,puVar8);
  FUN_180008a34(&local_88);
  local_50 = ZEXT816(0);
  local_40 = ZEXT816(0);
  local_68 = plVar6[2];
  local_60 = &DAT_18001e700;
  local_58 = 0x1e98;
  plVar10 = *(longlong **)plVar6[10];
  pcVar3 = *(code **)(*plVar10 + 0x58);
  FUN_18000e0d4(plVar6 + 1);
  iVar5 = (*pcVar3)(plVar10,&local_68,&DAT_18001db48,plVar6 + 1);
  if (-1 < iVar5) {
    plVar6 = (longlong *)plVar6[1];
    pcVar3 = *(code **)(*plVar6 + 0x30);
    puVar8 = (undefined8 *)FUN_180004fb0(&local_88,local_30,L" PSO");
    if (7 < (ulonglong)puVar8[3]) {
      puVar8 = (undefined8 *)*puVar8;
    }
    (*pcVar3)(plVar6,puVar8);
    FUN_180008a34(&local_88);
    FUN_180008a34(local_30);
    FUN_18000e8c0(local_10 ^ (ulonglong)auStack168);
    return;
  }
  local_88 = std::exception::vftable;
  local_80 = ZEXT816(0);
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_88,(ThrowInfo *)&DAT_180416238);
}



void FUN_1800045c8(longlong *param_1)

{
  longlong *plVar1;
  undefined8 uVar2;
  longlong *_Dst;
  longlong **pplVar3;
  longlong *local_18 [2];
  
  uVar2 = (**(code **)(*param_1 + 0x50))();
  _Dst = (longlong *)operator_new(0x88);
  local_18[0] = _Dst;
  memset(_Dst,0,0x88);
  FUN_180004680(_Dst,uVar2);
  *_Dst = (longlong)CyberReactiveMaskPass::vftable;
  _Dst[0xc] = 0;
  _Dst[0xd] = 0;
  _Dst[0xe] = 0;
  _Dst[0xf] = 0;
  _Dst[0x10] = 0;
  pplVar3 = (longlong **)(param_1 + 0x17);
  if (pplVar3 == local_18) {
    if (_Dst == (longlong *)0x0) goto LAB_180004661;
    FUN_180002a84(_Dst);
  }
  else {
    plVar1 = *pplVar3;
    *pplVar3 = _Dst;
    if (plVar1 == (longlong *)0x0) goto LAB_180004661;
    FUN_180002a84(plVar1);
    _Dst = plVar1;
  }
  free(_Dst);
LAB_180004661:
                    // WARNING: Could not recover jumptable at 0x00018000467c. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**pplVar3 + 0x10))();
  return;
}



undefined8 * FUN_180004680(undefined8 *param_1,longlong **param_2)

{
  undefined8 *puVar1;
  longlong **pplVar2;
  longlong *plVar3;
  code *pcVar4;
  longlong *plVar5;
  int iVar6;
  undefined **local_38;
  undefined local_30 [16];
  
  *param_1 = PostProcessPass::vftable;
  param_1[1] = param_2;
  puVar1 = param_1 + 2;
  *puVar1 = 0;
  pplVar2 = (longlong **)(param_1 + 3);
  *pplVar2 = (longlong *)0x0;
  *(undefined *)(param_1 + 4) = 1;
  iVar6 = (**(code **)(**param_2 + 0x48))(*param_2,1,&DAT_18001d738,puVar1);
  if (iVar6 < 0) {
    local_38 = std::exception::vftable;
    local_30 = ZEXT816(0);
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_38,(ThrowInfo *)&DAT_180416238);
  }
  plVar3 = *(longlong **)param_1[1];
  pcVar4 = *(code **)(*plVar3 + 0x60);
  plVar5 = *pplVar2;
  if (plVar5 != (longlong *)0x0) {
    *pplVar2 = (longlong *)0x0;
    (**(code **)(*plVar5 + 0x10))();
  }
  iVar6 = (*pcVar4)(plVar3,0,1,*puVar1,0,&DAT_18001d748,pplVar2);
  if (-1 < iVar6) {
    (**(code **)(**pplVar2 + 0x48))();
    return param_1;
  }
  local_38 = std::exception::vftable;
  local_30 = ZEXT816(0);
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_38,(ThrowInfo *)&DAT_180416238);
}



void FUN_18000474c(undefined8 *param_1,undefined8 param_2,undefined8 param_3,longlong param_4,
                  undefined4 param_5)

{
  longlong **pplVar1;
  longlong *plVar2;
  code *pcVar3;
  int iVar4;
  undefined auStack184 [32];
  undefined4 local_98;
  undefined8 local_90;
  undefined *local_88;
  longlong **local_80;
  undefined8 *local_78;
  undefined **local_70;
  undefined local_68 [16];
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  ulonglong local_40;
  
  local_40 = DAT_180418010 ^ (ulonglong)auStack184;
  *param_1 = param_2;
  pplVar1 = (longlong **)(param_1 + 1);
  *pplVar1 = (longlong *)0x0;
  *(undefined4 *)(param_1 + 2) = 0;
  *(undefined4 *)((longlong)param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 3) = 0;
  *(undefined4 *)((longlong)param_1 + 0x1c) = param_5;
  *(undefined4 *)(param_1 + 4) = 0xffffffff;
  *(undefined4 *)((longlong)param_1 + 0x24) = 0xffffffff;
  *(undefined4 *)(param_1 + 5) = 0xffffffff;
  *(undefined4 *)((longlong)param_1 + 0x2c) = 1;
  param_1[6] = 0;
  *(undefined (*) [16])(param_1 + 7) = ZEXT816(0);
  *(undefined (*) [16])(param_1 + 9) = ZEXT816(0);
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  *(undefined (*) [16])(param_1 + 0xd) = ZEXT816(0);
  *(undefined (*) [16])(param_1 + 0xf) = ZEXT816(0);
  param_1[0x11] = 0;
  param_1[0x12] = 0;
  *(undefined (*) [16])(param_1 + 0x13) = ZEXT816(0);
  param_1[0x15] = 0;
  param_1[0x16] = 0;
  *(undefined (*) [16])(param_1 + 0x17) = ZEXT816(0);
  param_1[0x19] = 0;
  local_58 = 1;
  local_54 = 0;
  local_50 = 0;
  local_4c = 1;
  local_48 = 1;
  *(undefined4 *)((longlong)param_1 + 0x1c) = param_5;
  *(undefined4 *)(param_1 + 2) = *(undefined4 *)(param_4 + 0x10);
  *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(param_4 + 0x18);
  *(undefined4 *)(param_1 + 3) = *(undefined4 *)(param_4 + 0x20);
  plVar2 = *(longlong **)*param_1;
  pcVar3 = *(code **)(*plVar2 + 0xd8);
  local_78 = param_1;
  FUN_18000e0d4(pplVar1);
  local_88 = &DAT_18001db68;
  local_90 = 0;
  local_98 = param_5;
  local_80 = pplVar1;
  iVar4 = (*pcVar3)(plVar2,&local_58,0,param_4);
  if (-1 < iVar4) {
    (**(code **)(**pplVar1 + 0x30))(*pplVar1,param_3);
    FUN_18000e8c0(local_40 ^ (ulonglong)auStack184);
    return;
  }
  local_70 = std::exception::vftable;
  local_68 = ZEXT816(0);
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_70,(ThrowInfo *)&DAT_180416238);
}



void FUN_1800048b4(undefined8 *param_1,longlong **param_2)

{
  longlong **pplVar1;
  longlong *plVar2;
  code *pcVar3;
  int iVar4;
  undefined auStack296 [32];
  undefined4 local_108;
  undefined8 local_100;
  undefined *local_f8;
  longlong **local_f0;
  undefined4 local_e8;
  undefined8 uStack224;
  undefined8 local_d8;
  undefined4 uStack208;
  undefined8 uStack204;
  undefined8 uStack196;
  undefined4 uStack188;
  undefined4 uStack184;
  uint uStack180;
  undefined **local_b0;
  undefined local_a8 [16];
  undefined8 *local_98;
  undefined8 local_90;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined4 local_68 [2];
  undefined4 uStack96;
  undefined4 uStack92;
  undefined4 local_58;
  undefined4 uStack84;
  undefined4 uStack80;
  undefined4 uStack76;
  undefined4 local_48;
  undefined4 uStack68;
  undefined4 uStack64;
  undefined4 uStack60;
  longlong local_38;
  ulonglong local_30;
  
  local_30 = DAT_180418010 ^ (ulonglong)auStack296;
  param_1[1] = 0;
  param_1[2] = 0;
  *(undefined4 *)(param_1 + 3) = 0x10;
  *(undefined8 *)((longlong)param_1 + 0x1c) = 0x10;
  *(undefined4 *)((longlong)param_1 + 0x24) = 0;
  *(undefined (*) [16])(param_1 + 5) = ZEXT816(0);
  param_1[7] = 0;
  *(undefined (*) [16])(param_1 + 8) = ZEXT816(0);
  param_1[10] = param_2;
  *param_1 = CyberReactiveMaskShader::vftable;
  pplVar1 = (longlong **)(param_1 + 0xb);
  *pplVar1 = (longlong *)0x0;
  local_90 = 2;
  local_88 = 0;
  local_84 = 1;
  local_80 = 1;
  local_e8 = 1;
  uStack224 = 0;
  local_d8 = 0x100;
  uStack208 = 1;
  uStack204 = 0x10001;
  uStack196 = 1;
  uStack188 = 1;
  uStack184 = 0;
  local_68[0] = 1;
  uStack96 = 0;
  uStack92 = 0;
  local_58 = 0x100;
  uStack84 = 0;
  uStack80 = 1;
  uStack76 = 0x10001;
  local_48 = 0;
  uStack68 = 1;
  uStack64 = 0;
  uStack60 = 1;
  local_38 = (ulonglong)uStack180 << 0x20;
  plVar2 = *param_2;
  pcVar3 = *(code **)(*plVar2 + 0xd8);
  local_98 = param_1;
  FUN_18000e0d4(pplVar1);
  local_f8 = &DAT_18001db68;
  local_100 = 0;
  local_108 = 0xac3;
  local_f0 = pplVar1;
  iVar4 = (*pcVar3)(plVar2,&local_90,0,local_68);
  if (iVar4 < 0) {
    local_b0 = std::exception::vftable;
    local_a8 = ZEXT816(0);
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_b0,(ThrowInfo *)&DAT_180416238);
  }
  local_78 = 0;
  local_70 = 0;
  iVar4 = (**(code **)(**pplVar1 + 0x40))(*pplVar1,0,&local_78,param_1 + 0xc);
  if (-1 < iVar4) {
    FUN_18000e8c0(local_30 ^ (ulonglong)auStack296);
    return;
  }
  local_b0 = std::exception::vftable;
  local_a8 = ZEXT816(0);
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_b0,(ThrowInfo *)&DAT_180416238);
}



void FUN_180004a10(longlong param_1)

{
  longlong *plVar1;
  code *pcVar2;
  int iVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined extraout_XMM0 [16];
  undefined extraout_XMM0_00 [16];
  undefined auStack392 [32];
  undefined *local_168;
  undefined *local_160;
  undefined **local_158;
  undefined local_150 [16];
  longlong *local_140;
  longlong *local_138;
  undefined local_130 [8];
  undefined4 local_128 [2];
  undefined4 local_120;
  undefined4 *local_118;
  undefined4 local_110;
  undefined4 local_108 [2];
  undefined4 *local_100;
  undefined4 local_f8;
  undefined8 *local_f0;
  undefined4 local_e8;
  undefined4 local_e0;
  undefined8 local_dc;
  undefined4 local_d4;
  undefined4 local_d0;
  undefined4 local_cc;
  undefined8 local_c8;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined8 local_b4;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined8 local_98;
  undefined8 uStack144;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined8 local_74;
  undefined8 local_6c;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined8 local_38;
  ulonglong local_28;
  
  local_28 = DAT_180418010 ^ (ulonglong)auStack392;
  local_dc = 6;
  local_88 = 0;
  local_78 = 0;
  local_54 = 0;
  local_44 = 0;
  local_d0 = 0xffffffff;
  local_bc = 0xffffffff;
  local_a8 = 0xffffffff;
  local_118 = &local_e0;
  local_c8 = 3;
  local_80 = 4;
  local_4c = 4;
  local_100 = local_128;
  local_f0 = &local_98;
  local_b8 = 2;
  local_120 = 3;
  local_84 = 0x10;
  local_7c = 2;
  local_60 = 3;
  local_5c = 3;
  local_50 = 0x10;
  local_48 = 2;
  local_f8 = 2;
  local_e0 = 0;
  local_d4 = 0;
  local_cc = 1;
  local_c0 = 0;
  local_b4 = 1;
  local_ac = 0;
  local_128[0] = 0;
  local_110 = 0;
  local_74 = 0x7f7fffff;
  local_98 = 0x300000000;
  uStack144 = 0x100000003;
  local_6c = 0;
  local_3c = 1;
  local_64 = 0x15;
  local_58 = 1;
  local_40 = 0x7f7fffff;
  local_38 = 0;
  local_108[0] = 1;
  local_e8 = 0;
  local_140 = (longlong *)0x0;
  local_138 = (longlong *)0x0;
  iVar3 = D3D12SerializeRootSignature(0x300000000,local_108,1,&local_140,&local_138);
  if (iVar3 < 0) {
    local_150 = extraout_XMM0 & (undefined  [16])0x0;
    local_158 = std::exception::vftable;
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_158,(ThrowInfo *)&DAT_180416238);
  }
  plVar1 = **(longlong ***)(param_1 + 0x50);
  pcVar2 = *(code **)(*plVar1 + 0x80);
  uVar4 = (**(code **)(*local_140 + 0x20))();
  uVar5 = (**(code **)(*local_140 + 0x18))();
  local_160 = local_130;
  local_168 = &DAT_18001db78;
  iVar3 = (*pcVar2)(plVar1,0,uVar5,uVar4);
  if (-1 < iVar3) {
    (**(code **)(*local_140 + 0x10))();
    if (local_138 != (longlong *)0x0) {
      (**(code **)(*local_138 + 0x10))();
    }
    FUN_18000e8c0(local_28 ^ (ulonglong)auStack392);
    return;
  }
  local_150 = extraout_XMM0_00 & (undefined  [16])0x0;
  local_158 = std::exception::vftable;
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_158,(ThrowInfo *)&DAT_180416238);
}



void FUN_180004bdc(undefined4 *param_1,longlong *param_2,int param_3,undefined4 param_4)

{
  code *pcVar1;
  undefined4 uVar2;
  int iVar3;
  undefined auStack120 [32];
  undefined **local_58;
  undefined local_50 [16];
  int local_40;
  undefined4 local_3c;
  uint local_38;
  undefined4 local_34;
  ulonglong local_30;
  
  local_30 = DAT_180418010 ^ (ulonglong)auStack120;
  *param_1 = 0;
  param_1[1] = param_4;
  uVar2 = (**(code **)(*param_2 + 0x78))(param_2);
  param_1[2] = uVar2;
  local_34 = 0;
  local_38 = (uint)(1 < param_3 - 2U);
  pcVar1 = *(code **)(*param_2 + 0x70);
  local_40 = param_3;
  local_3c = param_4;
  FUN_18000e0f4(param_1 + 4);
  iVar3 = (*pcVar1)(param_2,&local_40,&DAT_18001d710,param_1 + 4);
  if (-1 < iVar3) {
    (**(code **)(**(longlong **)(param_1 + 4) + 0x30))(*(longlong **)(param_1 + 4),L"DX12 Heap");
    FUN_18000e8c0(local_30 ^ (ulonglong)auStack120);
    return;
  }
  local_58 = std::exception::vftable;
  local_50 = ZEXT816(0);
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_58,(ThrowInfo *)&DAT_180416238);
}



void FUN_180004dd8(undefined8 *param_1,longlong param_2,int param_3)

{
  undefined auStack168 [32];
  longlong local_88;
  int local_78;
  undefined4 uStack116;
  undefined4 uStack112;
  undefined auStack108 [16];
  undefined4 uStack92;
  undefined4 uStack88;
  undefined4 local_54;
  int local_30;
  ulonglong local_18;
  
  local_18 = DAT_180418010 ^ (ulonglong)auStack168;
  (**(code **)(*(longlong *)param_1[1] + 0x50))();
  uStack92 = 0;
  uStack88 = 0;
  local_54 = 0;
  auStack108 = ZEXT816(0);
  if ((local_30 == 0x27) || (local_30 == 0x28)) {
    local_78 = 0x2a;
  }
  else if (local_30 == 0x35) {
    local_78 = 0x39;
  }
  else {
    local_78 = local_30;
  }
  *(int *)((longlong)param_1 + 0x24) = param_3;
  param_1[0xc] = param_2;
  uStack116 = 4;
  uStack112 = 0;
  *(int *)(param_1 + 0xd) = local_78;
  *(undefined4 *)((longlong)param_1 + 0x6c) = 4;
  *(undefined4 *)(param_1 + 0xe) = 0;
  *(undefined4 *)((longlong)param_1 + 0x74) = 0;
  *(undefined4 *)(param_1 + 0xf) = 0;
  *(undefined4 *)((longlong)param_1 + 0x7c) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)((longlong)param_1 + 0x84) = 0;
  param_1[0x11] = 0;
  local_88 = (longlong)*(int *)(param_2 + 4) * (longlong)param_3 + *(longlong *)(param_2 + 8);
  (**(code **)(**(longlong **)*param_1 + 0x98))(*(longlong **)*param_1,param_1[1],0,&local_78);
  FUN_18000e8c0(local_18 ^ (ulonglong)auStack168);
  return;
}



undefined8 *
FUN_180004ecc(undefined8 *param_1,undefined8 param_2,undefined8 param_3,void *param_4,
             longlong param_5,void *param_6,longlong param_7)

{
  ulonglong uVar1;
  longlong lVar2;
  undefined8 *_Dst;
  ulonglong uVar3;
  longlong lVar4;
  
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  uVar1 = param_5 + param_7;
  lVar4 = 7;
  lVar2 = lVar4;
  _Dst = param_1;
  if (7 < uVar1) {
    lVar2 = FUN_180008b88(uVar1,7,0x7ffffffffffffffe,param_4,param_1);
    uVar3 = lVar2 + 1;
    if (lVar2 == -1) {
      uVar3 = lVar4 - 8;
    }
    if (0x7fffffffffffffff < uVar3) {
                    // WARNING: Subroutine does not return
      FUN_18001642c();
    }
    _Dst = (undefined8 *)FUN_180008bb4(uVar3 * 2);
    *param_1 = _Dst;
  }
  param_1[2] = uVar1;
  param_1[3] = lVar2;
  memcpy(_Dst,param_4,param_5 * 2);
  memcpy((void *)(param_5 * 2 + (longlong)_Dst),param_6,param_7 * 2);
  *(undefined2 *)((longlong)_Dst + uVar1 * 2) = 0;
  return param_1;
}



undefined8 FUN_180004fb0(undefined8 param_1,undefined8 *param_2,longlong param_3)

{
  longlong *plVar1;
  code *pcVar2;
  undefined8 uVar3;
  ulonglong uVar4;
  
  plVar1 = param_2 + 2;
  uVar4 = 0xffffffffffffffff;
  do {
    uVar4 = uVar4 + 1;
  } while (*(short *)(param_3 + uVar4 * 2) != 0);
  if (uVar4 <= 0x7ffffffffffffffeU - *plVar1) {
    if (7 < (ulonglong)param_2[3]) {
      param_2 = (undefined8 *)*param_2;
    }
    FUN_180004ecc(param_1,param_2,param_3,param_2,*plVar1,param_3,uVar4);
    return param_1;
  }
  std::_Xlength_error("string too long");
  pcVar2 = (code *)swi(3);
  uVar3 = (*pcVar2)();
  return uVar3;
}



void FUN_180005010(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                  undefined8 param_5,longlong param_6,undefined8 param_7,undefined8 param_8,
                  undefined8 param_9,undefined8 param_10)

{
  longlong lVar1;
  undefined auStack184 [64];
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined4 local_60;
  ulonglong local_58;
  
  local_58 = DAT_180418010 ^ (ulonglong)auStack184;
  lVar1 = param_1 + 0x20;
  local_78 = param_8;
  local_70 = param_10;
  FUN_180005324(param_9,lVar1,0,0);
  FUN_180005324(param_2,lVar1,1);
  FUN_180005324(param_3,lVar1,2,1);
  FUN_180005324(param_4,lVar1,3);
  if (param_6 != 0) {
    FUN_180005324(param_6,lVar1,4);
  }
  FUN_180005324(param_5,lVar1,5,1);
  FUN_180004dd8(param_7,lVar1,6);
  FUN_180004dd8(local_78,lVar1,7);
  FUN_180004dd8(local_70,lVar1,8);
  local_68 = (**(code **)(**(longlong **)(param_1 + 0x58) + 0x58))();
  local_60 = 0x100;
  (**(code **)(***(longlong ***)(param_1 + 0x50) + 0x88))
            (**(longlong ***)(param_1 + 0x50),&local_68,
             (longlong)*(int *)(param_1 + 0x24) * 9 + *(longlong *)(param_1 + 0x28));
  FUN_18000e8c0(local_58 ^ (ulonglong)auStack184);
  return;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_180005324(undefined8 *param_1,longlong param_2,int param_3,char param_4)

{
  longlong *plVar1;
  longlong lVar2;
  undefined auStack216 [32];
  undefined local_b8 [56];
  undefined4 local_80;
  undefined4 uStack124;
  undefined4 uStack120;
  undefined auStack116 [8];
  undefined8 uStack108;
  uint uStack100;
  undefined4 uStack96;
  undefined4 local_5c;
  int local_58 [7];
  ushort local_3c;
  int local_38;
  int local_34;
  ulonglong local_20;
  
  local_20 = DAT_180418010 ^ (ulonglong)auStack216;
  (**(code **)(*(longlong *)param_1[1] + 0x50))((longlong *)param_1[1],local_58);
  uStack100 = 0;
  uStack96 = 0;
  local_5c = 0;
  _auStack116 = ZEXT816(0);
  if (local_58[0] == 1) {
    local_80 = *(undefined4 *)(param_1 + 3);
    _auStack116 = CONCAT412(*(undefined4 *)(param_1 + 2),_auStack116);
    uStack124 = 1;
  }
  else {
    if (local_38 == 0x13) {
      local_80 = 0x15;
      if (param_4 != '\0') {
        local_80 = 0x16;
        _auStack116 = CONCAT412(1,_auStack116);
      }
    }
    else if ((local_38 == 0x27) || (local_38 == 0x28)) {
      local_80 = 0x29;
    }
    else if (local_38 == 0x2c) {
      local_80 = 0x2e;
    }
    else if (local_38 == 0x35) {
      local_80 = 0x36;
    }
    else if (local_38 == 0x37) {
      local_80 = 0x38;
    }
    else if (local_38 == 0x3d) {
      local_80 = 0x3d;
    }
    else {
      lVar2 = (**(code **)(*(longlong *)param_1[1] + 0x50))((longlong *)param_1[1],local_b8);
      local_80 = *(undefined4 *)(lVar2 + 0x20);
    }
    if (local_34 == 1) {
      auStack116 = (ulonglong)auStack116._0_4_;
      plVar1 = (longlong *)param_1[1];
      if (local_3c == 1) {
        uStack124 = 4;
        lVar2 = (**(code **)(*plVar1 + 0x50))();
        _auStack116 = ZEXT1012(CONCAT28(*(undefined2 *)(lVar2 + 0x1e),auStack116));
      }
      else {
        uStack124 = 5;
        lVar2 = (**(code **)(*plVar1 + 0x50))(plVar1,local_b8);
        _auStack116 = _auStack116 & (undefined  [16])0xffffffffffffffff;
        uStack100 = (uint)local_3c;
        _auStack116 = ZEXT1012(CONCAT28(*(undefined2 *)(lVar2 + 0x1e),auStack116));
      }
    }
    else if (local_3c == 1) {
      uStack124 = 6;
    }
    else {
      auStack116 = (ulonglong)auStack116._0_4_;
      _auStack116 = ZEXT1012(CONCAT28(local_3c,auStack116));
      uStack124 = 7;
    }
  }
  *(int *)(param_1 + 4) = param_3;
  param_1[6] = param_2;
  uStack120 = 0x1688;
  *(undefined4 *)(param_1 + 7) = local_80;
  *(undefined4 *)((longlong)param_1 + 0x3c) = uStack124;
  *(undefined4 *)(param_1 + 8) = 0x1688;
  *(uint *)((longlong)param_1 + 0x44) = auStack116._0_4_;
  *(undefined4 *)(param_1 + 9) = auStack116._4_4_;
  *(undefined4 *)((longlong)param_1 + 0x4c) = (undefined4)uStack108;
  *(undefined4 *)(param_1 + 10) = uStack108._4_4_;
  *(uint *)((longlong)param_1 + 0x54) = uStack100;
  param_1[0xb] = CONCAT44(local_5c,uStack96);
  (**(code **)(**(longlong **)*param_1 + 0x90))
            (*(longlong **)*param_1,param_1[1],&local_80,
             (longlong)*(int *)(param_2 + 4) * (longlong)param_3 + *(longlong *)(param_2 + 8));
  FUN_18000e8c0(local_20 ^ (ulonglong)auStack216);
  return;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_1800054b8(longlong param_1,longlong param_2,longlong *param_3,longlong *param_4)

{
  longlong *plVar1;
  undefined auStack376 [32];
  ulonglong local_158;
  undefined8 *local_150;
  undefined *local_148;
  undefined *local_140;
  undefined *local_138;
  undefined local_128 [8];
  undefined local_120 [16];
  undefined local_110 [16];
  undefined local_100 [16];
  undefined local_f0 [8];
  undefined local_e8 [8];
  undefined8 local_e0;
  undefined8 local_d8;
  undefined4 local_d0;
  undefined4 uStack204;
  undefined4 uStack200;
  undefined4 uStack196;
  undefined4 local_c0;
  undefined4 uStack188;
  undefined4 uStack184;
  undefined4 uStack180;
  undefined local_b0 [8];
  undefined4 uStack168;
  undefined4 uStack164;
  undefined local_a0 [8];
  undefined4 uStack152;
  undefined4 uStack148;
  undefined local_90 [56];
  ulonglong local_58;
  
  local_58 = DAT_180418010 ^ (ulonglong)auStack376;
  local_e0 = *(undefined8 *)(((longlong)*(int *)(param_2 + 8) + 0x10e5) * 0x38 + param_1);
  plVar1 = *(longlong **)(((longlong)*(int *)(param_2 + 0xc) + 0x10e5) * 0x38 + param_1);
  (**(code **)(*plVar1 + 0x50))(plVar1,local_90);
  local_138 = local_f0;
  local_140 = local_e8;
  local_148 = local_128;
  local_150 = (undefined8 *)local_b0;
  local_158 = 0;
  _local_b0 = ZEXT816(0);
  _local_a0 = ZEXT816(0);
  (**(code **)(*param_3 + 0x130))(param_3,local_90,0,1);
  local_d8 = 1;
  local_d0 = local_b0._0_4_;
  uStack204 = local_b0._4_4_;
  uStack200 = uStack168;
  uStack196 = uStack164;
  local_110 = ZEXT816(0) & (undefined  [16])0xffffffff00000000;
  local_120 = ZEXT816(plVar1);
  local_c0 = local_a0._0_4_;
  uStack188 = local_a0._4_4_;
  uStack184 = uStack152;
  uStack180 = uStack148;
  local_100 = ZEXT816(0);
  FUN_18000578c(param_1,(int *)(param_2 + 8),4);
  FUN_18000578c(param_1,(int *)(param_2 + 0xc),8);
  FUN_180005620(param_1,param_4);
  local_150 = &local_e0;
  local_148 = (undefined *)0x0;
  local_158 = local_158 & 0xffffffff00000000;
  (**(code **)(*param_4 + 0x80))(param_4,local_120,0,0);
  FUN_18000e8c0(local_58 ^ (ulonglong)auStack376);
  return;
}



void FUN_180005620(longlong param_1,longlong *param_2)

{
  if (*(int *)(param_1 + 0x3c248) != 0) {
    (**(code **)(*param_2 + 0xd0))(param_2,*(int *)(param_1 + 0x3c248),param_1 + 0x3c048);
    *(undefined4 *)(param_1 + 0x3c248) = 0;
  }
  return;
}



undefined8 FUN_180005658(longlong param_1,longlong param_2,longlong *param_3,longlong *param_4)

{
  undefined (*pauVar1) [16];
  longlong *plVar2;
  int iVar3;
  undefined auVar4 [16];
  undefined8 uVar5;
  int iVar6;
  longlong lVar7;
  longlong local_res8;
  longlong local_res10;
  
  lVar7 = ((ulonglong)*(uint *)(param_2 + 0x18) + 0x10e5) * 0x38;
  uVar5 = *(undefined8 *)(lVar7 + param_1);
  pauVar1 = (undefined (*) [16])(lVar7 + 0x20 + param_1);
  iVar3 = *(int *)(*pauVar1 + 0xc);
  auVar4 = *pauVar1;
  (**(code **)(**(longlong **)(param_1 + 0x3c028) + 0x48))
            (*(longlong **)(param_1 + 0x3c028),&local_res8);
  iVar6 = (**(code **)(*param_3 + 0x78))(param_3,0);
  plVar2 = *(longlong **)(param_1 + 0x3c030);
  local_res8 = local_res8 + (ulonglong)(uint)(iVar6 * iVar3);
  (**(code **)(*plVar2 + 0x50))(SUB168(auVar4 >> 0x60,0),plVar2,&local_res10);
  iVar6 = (**(code **)(*param_3 + 0x78))(param_3,0);
  local_res10 = local_res10 + (ulonglong)(uint)(iVar6 * iVar3);
  (**(code **)(*param_4 + 0xe0))(param_4,1,(longlong **)(param_1 + 0x3c030));
  FUN_18000578c(param_1,param_2 + 0x18,1);
  FUN_180005620(param_1,param_4);
  (**(code **)(*param_4 + 400))(param_4,local_res10,local_res8,uVar5,param_2 + 8,0,0);
  return 0;
}



void FUN_18000578c(longlong param_1,int *param_2,uint param_3)

{
  undefined4 *puVar1;
  undefined8 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  longlong lVar5;
  longlong lVar6;
  undefined4 uStack32;
  undefined4 uStack28;
  
  lVar6 = (longlong)*param_2 * 0x38;
  uVar2 = *(undefined8 *)(((longlong)*param_2 + 0x10e5) * 0x38 + param_1);
  lVar5 = (ulonglong)*(uint *)(param_1 + 0x3c248) * 0x20;
  uStack32 = (undefined4)uVar2;
  uStack28 = (undefined4)((ulonglong)uVar2 >> 0x20);
  if ((*(uint *)(lVar6 + 0x3b23c + param_1) & param_3) == param_3) {
    if (param_3 != 1) {
      return;
    }
    puVar1 = (undefined4 *)(lVar5 + 0x3c048 + param_1);
    *puVar1 = 2;
    puVar1[1] = 0;
    puVar1[2] = uStack32;
    puVar1[3] = uStack28;
    *(undefined (*) [16])(lVar5 + 0x3c058 + param_1) = ZEXT816(0);
  }
  else {
    uVar3 = FUN_180007004();
    uVar4 = FUN_180007004(param_3);
    puVar1 = (undefined4 *)(lVar5 + 0x3c048 + param_1);
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = uStack32;
    puVar1[3] = uStack28;
    puVar1 = (undefined4 *)(lVar5 + 0x3c058 + param_1);
    *puVar1 = 0xffffffff;
    puVar1[1] = uVar3;
    puVar1[2] = uVar4;
    puVar1[3] = 0;
    *(uint *)(lVar6 + 0x3b23c + param_1) = param_3;
  }
  *(int *)(param_1 + 0x3c248) = *(int *)(param_1 + 0x3c248) + 1;
  return;
}



// WARNING: Removing unreachable block (ram,0x0001800072f6)
// WARNING: Removing unreachable block (ram,0x000180007324)
// WARNING: Removing unreachable block (ram,0x000180011972)
// WARNING: Removing unreachable block (ram,0x0001800072c8)
// WARNING: Removing unreachable block (ram,0x00018000721a)
// WARNING: Removing unreachable block (ram,0x000180011987)
// WARNING: Removing unreachable block (ram,0x000180007221)

void FUN_18000580c(longlong param_1,undefined8 param_2,uint param_3)

{
  undefined4 uVar1;
  ulonglong in_stack_ffffffffffffffe8;
  ulonglong uVar2;
  
  uVar2 = in_stack_ffffffffffffffe8 & 0xffffffff00000000 | (ulonglong)param_3;
  uVar1 = FUN_180007480();
  switch(uVar1) {
  case 7:
  case 0xe:
    *(uint *)(param_1 + 8) = param_3;
    return;
  case 8:
  case 0xf:
    *(uint *)(param_1 + 0xc) = param_3;
    return;
  case 9:
    *(uint *)(param_1 + 0x18) = param_3;
    return;
  case 10:
    *(bool *)(param_1 + 0x1c) = param_3 != 0;
    return;
  case 0xb:
    *(bool *)(param_1 + 0x1d) = param_3 != 0;
    break;
  case 0xc:
    *(uint *)(param_1 + 0x10) = param_3;
    return;
  case 0xd:
    *(uint *)(param_1 + 0x14) = param_3;
    return;
  case 0x14:
    *(uint *)(param_1 + 0x30) = param_3;
    return;
  case 0x17:
    *(uint *)(param_1 + 0x20) = param_3;
    return;
  case 0x18:
    *(uint *)(param_1 + 0x24) = param_3;
    return;
  case 0x19:
    *(byte *)(param_1 + 0x52) = (byte)param_3 & 1;
    *(byte *)(param_1 + 0x53) = (byte)(param_3 >> 5) & 1;
    *(bool *)(param_1 + 0x50) = (param_3 & 8) != 0;
    *(bool *)(param_1 + 0x54) = (param_3 & 4) != 0;
    *(bool *)(param_1 + 0x55) = (param_3 & 2) != 0;
    return;
  case 0x1b:
    *(ulonglong *)(param_1 + 0x60) = uVar2;
    break;
  case 0x1c:
    *(ulonglong *)(param_1 + 0x70) = uVar2;
    break;
  case 0x1d:
    *(ulonglong *)(param_1 + 0x68) = uVar2;
    break;
  case 0x1e:
    *(ulonglong *)(param_1 + 0x78) = uVar2;
    break;
  case 0x1f:
    *(ulonglong *)(param_1 + 0x80) = uVar2;
    break;
  case 0x20:
    *(ulonglong *)(param_1 + 0x88) = uVar2;
    break;
  case 0x21:
    *(ulonglong *)(param_1 + 0x58) = uVar2;
    break;
  case 0x24:
    *(bool *)(param_1 + 0x34) = param_3 != 0;
    return;
  case 0x25:
    *(uint *)(param_1 + 0x38) = param_3;
    return;
  case 0x26:
    *(uint *)(param_1 + 0x3c) = param_3;
    return;
  case 0x27:
    *(uint *)(param_1 + 0x40) = param_3;
    return;
  case 0x28:
    *(uint *)(param_1 + 0x44) = param_3;
    return;
  }
  return;
}



void FUN_18000582c(uint *param_1,uint *param_2)

{
  code **ppcVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  ulonglong uVar6;
  undefined2 *puVar7;
  undefined4 *puVar8;
  longlong lVar9;
  float *pfVar10;
  float fVar11;
  float fVar12;
  undefined auStack2008 [32];
  undefined local_7b8 [4];
  undefined4 local_7b4;
  undefined4 local_7b0;
  undefined4 local_7ac;
  int local_7a8;
  undefined4 uStack1956;
  undefined4 uStack1952;
  uint uStack1948;
  undefined4 local_798;
  undefined4 uStack1940;
  undefined4 local_788;
  int local_784;
  undefined4 uStack1920;
  undefined4 uStack1916;
  uint uStack1912;
  undefined8 local_774;
  undefined4 local_76c;
  int local_768;
  undefined4 local_764;
  undefined8 local_760;
  undefined8 local_758;
  int local_750;
  uint local_74c;
  undefined4 local_748;
  wchar_t *local_740;
  undefined4 local_738;
  undefined4 local_734;
  uint local_730;
  uint local_72c;
  undefined4 local_728;
  undefined4 local_724;
  undefined local_720 [16];
  undefined4 local_710;
  wchar_t *local_708;
  undefined4 local_700;
  undefined4 local_6fc;
  uint local_6f8;
  uint local_6f4;
  undefined4 local_6f0;
  undefined4 local_6ec;
  undefined local_6e8 [16];
  undefined4 local_6d8;
  wchar_t *local_6d0;
  undefined4 local_6c8;
  undefined4 local_6c4;
  uint local_6c0;
  uint local_6bc;
  undefined4 local_6b8;
  undefined4 local_6b4;
  undefined local_6b0 [16];
  undefined4 local_6a0;
  wchar_t *local_698;
  undefined4 local_690;
  undefined4 local_68c;
  uint local_688;
  uint local_684;
  undefined4 local_680;
  undefined4 local_67c;
  undefined local_678 [16];
  undefined4 local_668;
  wchar_t *local_660;
  undefined4 local_658;
  undefined4 local_654;
  uint local_650;
  uint local_64c;
  undefined4 local_648;
  undefined4 local_644;
  undefined local_640 [16];
  undefined4 local_630;
  wchar_t *local_628;
  undefined4 local_620;
  undefined4 local_61c;
  uint local_618;
  uint local_614;
  undefined4 local_610;
  undefined local_60c [16];
  undefined4 local_5fc;
  undefined4 local_5f8;
  wchar_t *local_5f0;
  undefined4 local_5e8;
  undefined4 local_5e4;
  uint local_5e0;
  uint local_5dc;
  undefined4 local_5d8;
  undefined local_5d4 [16];
  undefined4 local_5c4;
  undefined4 local_5c0;
  wchar_t *local_5b8;
  undefined4 local_5b0;
  undefined4 local_5ac;
  uint local_5a8;
  uint local_5a4;
  undefined4 local_5a0;
  undefined local_59c [16];
  undefined4 local_58c;
  undefined4 local_588;
  wchar_t *local_580;
  undefined4 local_578;
  undefined4 local_574;
  uint local_570;
  uint local_56c;
  undefined4 local_568;
  undefined local_564 [16];
  undefined4 local_554;
  undefined4 local_550;
  wchar_t *local_548;
  undefined4 local_540;
  undefined4 local_53c;
  uint local_538;
  uint local_534;
  undefined4 local_530;
  undefined4 local_52c;
  undefined local_528 [16];
  undefined4 local_518;
  wchar_t *local_510;
  undefined4 local_508;
  undefined4 local_504;
  uint local_500;
  uint local_4fc;
  undefined4 local_4f8;
  undefined local_4f4 [16];
  undefined4 local_4e4;
  undefined4 local_4e0;
  wchar_t *local_4d8;
  undefined4 local_4d0;
  undefined4 local_4cc;
  undefined4 local_4c8;
  undefined4 local_4c4;
  undefined4 local_4c0;
  undefined4 local_4bc;
  undefined4 local_4b8;
  undefined4 *local_4b0;
  undefined4 local_4a8;
  wchar_t *local_4a0;
  undefined4 local_498;
  undefined4 local_494;
  uint local_490;
  uint local_48c;
  undefined4 local_488;
  undefined4 local_484;
  undefined local_480 [16];
  undefined4 local_470;
  wchar_t *local_468;
  undefined4 local_460;
  undefined4 local_45c;
  undefined4 local_458;
  undefined4 local_454;
  undefined8 local_450;
  undefined4 local_448;
  undefined2 *local_440;
  undefined4 local_438;
  wchar_t *local_430;
  undefined4 local_428;
  undefined4 local_424;
  undefined4 local_420;
  undefined4 local_41c;
  undefined8 local_418;
  undefined4 local_410;
  undefined *local_408;
  undefined4 local_400;
  wchar_t *local_3f8;
  undefined4 local_3f0;
  undefined4 local_3ec;
  undefined4 local_3e8;
  undefined4 local_3e4;
  undefined8 local_3e0;
  undefined4 local_3d8;
  undefined2 *local_3d0;
  undefined4 local_3c8;
  wchar_t *local_3c0;
  undefined4 local_3b8;
  undefined4 local_3b4;
  undefined4 local_3b0;
  undefined4 local_3ac;
  undefined8 local_3a8;
  undefined4 local_3a0;
  undefined4 *local_398;
  undefined4 local_390;
  wchar_t *local_388;
  undefined4 local_380;
  undefined4 local_37c;
  undefined4 local_378;
  undefined4 local_374;
  undefined4 local_370;
  undefined local_36c [16];
  undefined4 local_35c;
  undefined2 local_358 [128];
  undefined2 local_258 [256];
  ulonglong local_58;
  
  local_58 = DAT_180418010 ^ (ulonglong)auStack2008;
  memset(param_1,0,0x8018);
  ppcVar1 = (code **)(param_1 + 6);
  *(undefined8 *)(param_1 + 0x48) = *(undefined8 *)(param_2 + 0x22);
  uVar5 = param_2[1];
  uVar2 = param_2[2];
  uVar3 = param_2[3];
  *param_1 = *param_2;
  param_1[1] = uVar5;
  param_1[2] = uVar2;
  param_1[3] = uVar3;
  uVar5 = param_2[5];
  uVar2 = param_2[6];
  uVar3 = param_2[7];
  param_1[4] = param_2[4];
  param_1[5] = uVar5;
  param_1[6] = uVar2;
  param_1[7] = uVar3;
  uVar5 = param_2[9];
  uVar2 = param_2[10];
  uVar3 = param_2[0xb];
  param_1[8] = param_2[8];
  param_1[9] = uVar5;
  param_1[10] = uVar2;
  param_1[0xb] = uVar3;
  uVar5 = param_2[0xd];
  uVar2 = param_2[0xe];
  uVar3 = param_2[0xf];
  param_1[0xc] = param_2[0xc];
  param_1[0xd] = uVar5;
  param_1[0xe] = uVar2;
  param_1[0xf] = uVar3;
  uVar5 = param_2[0x11];
  uVar2 = param_2[0x12];
  uVar3 = param_2[0x13];
  param_1[0x10] = param_2[0x10];
  param_1[0x11] = uVar5;
  param_1[0x12] = uVar2;
  param_1[0x13] = uVar3;
  uVar5 = param_2[0x15];
  uVar2 = param_2[0x16];
  uVar3 = param_2[0x17];
  param_1[0x14] = param_2[0x14];
  param_1[0x15] = uVar5;
  param_1[0x16] = uVar2;
  param_1[0x17] = uVar3;
  uVar5 = param_2[0x19];
  uVar2 = param_2[0x1a];
  uVar3 = param_2[0x1b];
  param_1[0x18] = param_2[0x18];
  param_1[0x19] = uVar5;
  param_1[0x1a] = uVar2;
  param_1[0x1b] = uVar3;
  uVar5 = param_2[0x1d];
  uVar2 = param_2[0x1e];
  uVar3 = param_2[0x1f];
  param_1[0x1c] = param_2[0x1c];
  param_1[0x1d] = uVar5;
  param_1[0x1e] = uVar2;
  param_1[0x1f] = uVar3;
  uVar5 = param_2[0x21];
  uVar2 = param_2[0x22];
  uVar3 = param_2[0x23];
  param_1[0x20] = param_2[0x20];
  param_1[0x21] = uVar5;
  param_1[0x22] = uVar2;
  param_1[0x23] = uVar3;
  iVar4 = (**ppcVar1)(ppcVar1);
  if (iVar4 == 0) {
    iVar4 = (**(code **)(param_1 + 8))(ppcVar1,param_1 + 0x4a,*(undefined8 *)(param_1 + 0x48));
    if (iVar4 == 0) {
      *(undefined *)(param_1 + 0x2000) = 1;
      param_1[0x2001] = 0;
      param_1[0x26] = param_2[3];
      param_1[0x27] = param_2[4];
      param_1[0x2c] = (uint)(1.0 / (float)(ulonglong)param_2[3]);
      param_1[0x2d] = (uint)(1.0 / (float)(ulonglong)param_2[4]);
      memset(local_358,0,0x100);
      fVar12 = 32767.0;
      puVar7 = local_358;
      uVar6 = 0;
      do {
        fVar11 = (float)FUN_1800060b0(((float)uVar6 + (float)uVar6) / 127.0);
        fVar11 = (float)roundf(fVar11 * fVar12);
        uVar5 = (int)uVar6 + 1;
        uVar6 = (ulonglong)uVar5;
        *puVar7 = (short)(int)fVar11;
        puVar7 = puVar7 + 1;
      } while (uVar5 < 0x80);
      puVar7 = local_258;
      lVar9 = 0x100;
      pfVar10 = (float *)&DAT_180022f30;
      do {
        fVar11 = (float)roundf(*pfVar10 * 0.5 * fVar12);
        pfVar10 = pfVar10 + 1;
        *puVar7 = (short)(int)fVar11;
        puVar7 = puVar7 + 1;
        lVar9 = lVar9 + -1;
      } while (lVar9 != 0);
      local_730 = param_2[1];
      local_72c = param_2[2];
      local_7b0 = 0;
      local_7ac = 0;
      uVar5 = *param_1;
      local_7b8[0] = 0;
      local_7b4 = 0;
      local_6d8 = 8;
      local_61c = 8;
      local_618 = param_2[3];
      local_740 = L"FSR2_PreparedInputColor";
      local_728 = 1;
      local_708 = L"FSR2_ReconstructedPrevNearestDepth";
      local_724 = 1;
      local_6d0 = L"FSR2_DilatedVelocity";
      local_6c4 = 9;
      local_6a0 = 9;
      local_698 = L"FSR2_DilatedDepth";
      local_660 = L"FSR2_DepthClip";
      local_628 = L"FSR2_LockStatus1";
      local_614 = param_2[4];
      local_6f0 = 1;
      local_6ec = 1;
      local_6b8 = 1;
      local_6b4 = 1;
      local_680 = 1;
      local_67c = 1;
      local_648 = 1;
      local_644 = 1;
      local_610 = 1;
      local_748 = 0xd;
      local_738 = 2;
      local_734 = 3;
      local_720 = ZEXT816(0);
      local_710 = 7;
      local_700 = 2;
      local_6fc = 5;
      local_6e8 = ZEXT816(0);
      local_6c8 = 2;
      local_6b0 = ZEXT816(0);
      local_690 = 2;
      local_68c = 0xb;
      local_678 = ZEXT816(0);
      local_668 = 0xc;
      local_658 = 2;
      local_654 = 0xf;
      local_640 = ZEXT816(0);
      local_630 = 0x14;
      local_620 = 3;
      local_60c = ZEXT816(0);
      local_530 = 0;
      local_554 = 0;
      local_548 = L"FSR2_ExposureMips";
      local_538 = local_730 >> 1;
      local_5fc = 0;
      local_534 = local_72c >> 1;
      local_5f0 = L"FSR2_LockStatus2";
      local_5c4 = 0;
      local_510 = L"FSR2_LumaHistory";
      local_5b8 = L"FSR2_InternalUpscaled1";
      local_58c = 0;
      local_4e4 = 0;
      local_5e8 = 3;
      local_4d8 = L"FSR2_SpdAtomicCounter";
      local_4b0 = &local_7b4;
      local_5ac = 3;
      local_580 = L"FSR2_InternalUpscaled2";
      local_574 = 3;
      local_4a0 = L"FSR2_DilatedReactiveMasks";
      local_5f8 = 0x15;
      local_5e4 = 8;
      local_5d8 = 1;
      local_5d4 = ZEXT816(0);
      local_5c0 = 0x16;
      local_5b0 = 2;
      local_5a0 = 1;
      local_59c = ZEXT816(0);
      local_588 = 0x17;
      local_578 = 2;
      local_568 = 1;
      local_564 = ZEXT816(0);
      local_550 = 0x1c;
      local_540 = 2;
      local_53c = 0xb;
      local_52c = 1;
      local_528 = ZEXT816(0);
      local_518 = 0xe;
      local_508 = 2;
      local_504 = 7;
      local_4f8 = 1;
      local_4f4 = ZEXT816(0);
      local_4e0 = 0x11;
      local_4d0 = 2;
      local_4cc = 5;
      local_4c8 = 1;
      local_4c4 = 1;
      local_4c0 = 1;
      local_4bc = 1;
      local_4b8 = 4;
      local_4a8 = 0x1b;
      local_498 = 2;
      local_494 = 0x10;
      local_470 = 0x10;
      local_468 = L"FSR2_LanczosLutData";
      local_440 = local_358;
      local_3e8 = 0x10;
      local_3e4 = 0x10;
      local_430 = L"FSR2_DefaultReactiviyMask";
      local_408 = local_7b8;
      local_3f8 = L"FSR2_MaximumUpsampleBias";
      local_3d0 = local_258;
      local_3c0 = L"FSR2_DefaultExposure";
      local_398 = &local_7b0;
      local_388 = L"FSR2_Exposure";
      local_3a0 = 8;
      local_35c = 0;
      local_488 = 1;
      local_484 = 1;
      local_480 = ZEXT816(0);
      local_460 = 0;
      local_45c = 0xe;
      local_458 = 0x80;
      local_454 = 1;
      local_450 = 1;
      local_448 = 0x100;
      local_438 = 0x18;
      local_428 = 0;
      local_424 = 0xf;
      local_420 = 1;
      local_41c = 1;
      local_418 = 1;
      local_410 = 1;
      local_400 = 0x1a;
      local_3f0 = 0;
      local_3ec = 0xe;
      local_3e0 = 1;
      local_3d8 = 0x200;
      local_3c8 = 0x29;
      local_3b8 = 2;
      local_3b4 = 4;
      local_3b0 = 1;
      local_3ac = 1;
      local_3a8 = 1;
      local_390 = 0x2a;
      local_380 = 2;
      local_37c = 4;
      local_378 = 1;
      local_374 = 1;
      local_370 = 1;
      local_36c = ZEXT816(0);
      local_6f8 = local_730;
      local_6f4 = local_72c;
      local_6c0 = local_730;
      local_6bc = local_72c;
      local_688 = local_730;
      local_684 = local_72c;
      local_650 = local_730;
      local_64c = local_72c;
      local_5e0 = local_618;
      local_5dc = local_614;
      local_5a8 = local_618;
      local_5a4 = local_614;
      local_570 = local_618;
      local_56c = local_614;
      local_500 = local_730;
      local_4fc = local_72c;
      local_490 = local_730;
      local_48c = local_72c;
      memset(param_1 + 0x1faa,0,0xac);
      lVar9 = 0;
      puVar8 = &local_734;
      do {
        uStack1948 = puVar8[2];
        local_750 = puVar8[-1];
        local_7a8 = 2 - (uint)((uVar5 & 0x80) != 0);
        if (1 < uStack1948) {
          local_7a8 = 2;
        }
        uStack1956 = *puVar8;
        uStack1952 = puVar8[1];
        uStack1940 = puVar8[3];
        local_76c = 0;
        local_798 = 1;
        local_764 = puVar8[5];
        local_774 = CONCAT44(uStack1940,1);
        local_768 = 2 - (uint)(local_750 != 0);
        local_760 = *(undefined8 *)(puVar8 + 7);
        local_758 = *(undefined8 *)(puVar8 + -3);
        local_74c = puVar8[-5];
        local_788 = 0;
        local_784 = local_7a8;
        uStack1920 = uStack1956;
        uStack1916 = uStack1952;
        uStack1912 = uStack1948;
        iVar4 = (**(code **)(param_1 + 0xc))
                          (param_1 + 6,&local_788,param_1 + (ulonglong)local_74c + 0x1faa);
        if (iVar4 != 0) goto LAB_18000607f;
        lVar9 = lVar9 + 1;
        puVar8 = puVar8 + 0xe;
      } while (lVar9 < 0x12);
      *(undefined *)((longlong)param_1 + 0x8001) = 0;
      param_1[0x1fd5] = param_1[0x1faa];
      param_1[0x1fd6] = param_1[0x1fab];
      param_1[0x1fd7] = param_1[0x1fac];
      param_1[0x1fd8] = param_1[0x1fad];
      param_1[0x1fd9] = param_1[0x1fae];
      param_1[0x1fda] = param_1[0x1faf];
      param_1[0x1fdb] = param_1[0x1fb0];
      param_1[0x1fdc] = param_1[0x1fb1];
      param_1[0x1fdd] = param_1[0x1fb2];
      param_1[0x1fde] = param_1[0x1fb3];
      param_1[0x1fdf] = param_1[0x1fb4];
      param_1[0x1fe0] = param_1[0x1fb5];
      param_1[0x1fe1] = param_1[0x1fb6];
      param_1[0x1fe2] = param_1[0x1fb7];
      param_1[0x1fe3] = param_1[0x1fb8];
      param_1[0x1fe4] = param_1[0x1fb9];
      param_1[0x1fe5] = param_1[0x1fba];
      param_1[0x1fe6] = param_1[0x1fbb];
      param_1[0x1fe7] = param_1[0x1fbc];
      param_1[0x1fe8] = param_1[0x1fbd];
      param_1[0x1fe9] = param_1[0x1fbe];
      param_1[0x1fea] = param_1[0x1fbf];
      param_1[0x1feb] = param_1[0x1fc0];
      param_1[0x1fec] = param_1[0x1fc1];
      param_1[0x1fed] = param_1[0x1fc2];
      param_1[0x1fee] = param_1[0x1fc3];
      param_1[0x1fef] = param_1[0x1fc4];
      param_1[0x1ff0] = param_1[0x1fc5];
      param_1[0x1ff1] = param_1[0x1fc6];
      param_1[0x1ff2] = param_1[0x1fc7];
      param_1[0x1ff3] = param_1[0x1fc8];
      param_1[0x1ff4] = param_1[0x1fc9];
      param_1[0x1ff5] = param_1[0x1fca];
      param_1[0x1ff6] = param_1[0x1fcb];
      param_1[0x1ff7] = param_1[0x1fcc];
      param_1[0x1ff8] = param_1[0x1fcd];
      param_1[0x1ff9] = param_1[0x1fce];
      param_1[0x1ffa] = param_1[0x1fcf];
      param_1[0x1ffb] = param_1[0x1fd0];
      param_1[0x1ffc] = param_1[0x1fd1];
      *(undefined8 *)(param_1 + 0x1ffd) = *(undefined8 *)(param_1 + 0x1fd2);
      param_1[0x1fff] = param_1[0x1fd4];
      FUN_180004050(param_1);
    }
  }
LAB_18000607f:
  FUN_18000e8c0(local_58 ^ (ulonglong)auStack2008);
  return;
}



undefined8 FUN_1800060b0(float param_1)

{
  float fVar1;
  undefined4 extraout_XMM0_Db;
  undefined4 uVar2;
  float fVar3;
  
  if ((float)((uint)param_1 & 0x7fffffff) < 1e-06) {
    fVar1 = 1.0;
    uVar2 = 0;
  }
  else {
    fVar3 = param_1 * 1.570796;
    param_1 = param_1 * 3.141593;
    fVar1 = sinf(fVar3);
    fVar1 = fVar1 / fVar3;
    uVar2 = extraout_XMM0_Db;
    fVar3 = sinf(param_1);
    fVar1 = fVar1 * (fVar3 / param_1);
  }
  return CONCAT44(uVar2,fVar1);
}



int FUN_1800067ec(int param_1)

{
  if (0x28 < param_1) {
    if (((param_1 == 0x2c) || (param_1 == 0x2d)) || (param_1 == 0x2f)) {
      return 0x2e;
    }
    if (param_1 == 0x30) {
      return 0x31;
    }
    if (param_1 == 0x35) {
      return 0x36;
    }
    if (param_1 == 0x37) {
      return 0x38;
    }
    if (param_1 == 0x3c) {
      return 0x3d;
    }
    if (param_1 == 0x5a) {
      return 0x57;
    }
    if (param_1 != 0x5c) {
      return param_1;
    }
    return 0x5d;
  }
  if (param_1 != 0x28) {
    if (param_1 < 0x15) {
      if (param_1 != 0x14) {
        if (param_1 == 1) {
          return 2;
        }
        if (param_1 == 5) {
          return 6;
        }
        if (param_1 == 9) {
          return 10;
        }
        if (param_1 == 0xf) {
          return 0x10;
        }
        if (param_1 != 0x13) {
          return param_1;
        }
      }
      return 0x15;
    }
    if (param_1 == 0x17) {
      return 0x18;
    }
    if (param_1 == 0x1b) {
      return 0x1c;
    }
    if (param_1 == 0x21) {
      return 0x22;
    }
    if (param_1 != 0x27) {
      return param_1;
    }
  }
  return 0x29;
}



void FUN_1800068b8(DWORD param_1)

{
  undefined auStackY872 [32];
  undefined4 local_328 [2];
  size_t local_320;
  WCHAR local_318 [256];
  char local_118 [256];
  ulonglong local_18;
  
  if (-1 < (int)param_1) {
    return;
  }
  local_18 = DAT_180418010 ^ (ulonglong)auStackY872;
  memset(local_318,0,0x100);
  FormatMessageW(0x1000,(LPCVOID)0x0,param_1,0x400,local_318,0xff,(va_list *)0x0);
  wcstombs_s(&local_320,local_118,0xff,local_318,0xff);
  local_328[0] = 1;
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_328,(ThrowInfo *)&DAT_1804162e8);
}



undefined8 FUN_180006960(longlong param_1)

{
  int iVar1;
  undefined8 *puVar2;
  int iVar3;
  uint uVar4;
  
  puVar2 = *(undefined8 **)(param_1 + 0x60);
  iVar3 = 0;
  uVar4 = 0;
  if (*(int *)(puVar2 + 0x7641) != 0) {
    do {
      iVar1 = *(int *)(puVar2 + (ulonglong)uVar4 * 0x3b2 + 1);
      if (iVar1 == 2) {
        iVar3 = FUN_180006a10();
      }
      else if (iVar1 == 0) {
        iVar3 = FUN_180005658();
      }
      else if (iVar1 == 1) {
        iVar3 = FUN_1800054b8(puVar2,puVar2 + (ulonglong)uVar4 * 0x3b2 + 1,*puVar2);
      }
      uVar4 = uVar4 + 1;
    } while (uVar4 < *(uint *)(puVar2 + 0x7641));
    if (iVar3 != 0) {
      return 0x8000000d;
    }
  }
  *(undefined4 *)(puVar2 + 0x7641) = 0;
  return 0;
}



// WARNING: Could not reconcile some variable overlaps

undefined8 FUN_180006a10(longlong param_1,longlong param_2,longlong *param_3,longlong *param_4)

{
  undefined4 *puVar1;
  undefined8 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint *puVar6;
  ulonglong uVar7;
  longlong lVar8;
  undefined4 uVar9;
  longlong lVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  longlong local_res8;
  longlong *local_res10;
  longlong local_res18;
  longlong *local_res20;
  longlong local_98;
  undefined8 local_90;
  undefined8 uStack136;
  undefined4 local_80;
  undefined4 uStack124;
  undefined8 uStack120;
  undefined8 local_70;
  undefined8 uStack104;
  
  local_res10 = *(longlong **)(param_1 + 0x3c040);
  local_res20 = param_4;
  if (*(code **)(*param_4 + 0xe8) == FUN_1800092f0) {
    FUN_1800092f0();
  }
  else {
    (**(code **)(*param_4 + 0xe8))(param_4,*(undefined8 *)(param_2 + 8));
  }
  (**(code **)(*param_4 + 0xe0))(param_4,1,&local_res10);
  uVar12 = 0;
  if (*(uint *)(param_2 + 0x18) != 0) {
    puVar6 = (uint *)(param_2 + 0x24);
    uVar7 = (ulonglong)*(uint *)(param_2 + 0x18);
    do {
      uVar11 = *puVar6;
      puVar6 = puVar6 + 0x22;
      if (uVar11 <= uVar12) {
        uVar11 = uVar12;
      }
      uVar12 = uVar11;
      uVar7 = uVar7 - 1;
    } while (uVar7 != 0);
  }
  if (0x900 < *(int *)(param_1 + 0x3c03c) + 1 + uVar12) {
    *(undefined4 *)(param_1 + 0x3c03c) = 0;
  }
  (**(code **)(*local_res10 + 0x50))();
  iVar3 = (**(code **)(*param_3 + 0x78))();
  uVar7 = 0;
  local_98 = local_98 + (ulonglong)(uint)(iVar3 * *(int *)(param_1 + 0x3c03c));
  if (*(int *)(param_2 + 0x18) != 0) {
    do {
      uVar9 = 0;
      lVar8 = (longlong)*(int *)(param_2 + 0x1644 + uVar7 * 4);
      lVar10 = lVar8 * 0x38;
      uVar11 = *(uint *)(lVar10 + 0x3b23c + param_1);
      uVar2 = *(undefined8 *)((lVar8 + 0x10e5) * 0x38 + param_1);
      lVar8 = (ulonglong)*(uint *)(param_1 + 0x3c248) * 0x20 + param_1;
      uStack136._0_4_ = (undefined4)uVar2;
      uStack136._4_4_ = (undefined4)((ulonglong)uVar2 >> 0x20);
      if ((uVar11 & 1) == 0) {
        if (uVar11 == 2) {
          uVar9 = 0x40;
        }
        else if (uVar11 == 1) {
          uVar9 = 8;
        }
        else if (uVar11 == 4) {
          uVar9 = 0x800;
        }
        else if (uVar11 == 6) {
          uVar9 = 0xac3;
        }
        else if (uVar11 == 8) {
          uVar9 = 0x400;
        }
        local_90 = 0;
        uStack120 = 8;
        *(undefined4 *)(lVar8 + 0x3c048) = 0;
        *(undefined4 *)(lVar8 + 0x3c04c) = 0;
        *(undefined4 *)(lVar8 + 0x3c050) = (undefined4)uStack136;
        *(undefined4 *)(lVar8 + 0x3c054) = uStack136._4_4_;
        local_80 = 0xffffffff;
        *(undefined4 *)(lVar8 + 0x3c058) = 0xffffffff;
        *(undefined4 *)(lVar8 + 0x3c05c) = uVar9;
        *(undefined4 *)(lVar8 + 0x3c060) = 8;
        *(undefined4 *)(lVar8 + 0x3c064) = 0;
        *(undefined4 *)(lVar10 + 0x3b23c + param_1) = 1;
        uStack136 = uVar2;
        uStack124 = uVar9;
      }
      else {
        local_70 = 2;
        *(undefined4 *)(lVar8 + 0x3c048) = 2;
        *(undefined4 *)(lVar8 + 0x3c04c) = 0;
        *(undefined4 *)(lVar8 + 0x3c050) = (undefined4)uStack136;
        *(undefined4 *)(lVar8 + 0x3c054) = uStack136._4_4_;
        *(undefined (*) [16])(lVar8 + 0x3c058) = ZEXT816(0);
        uStack104 = uVar2;
      }
      *(int *)(param_1 + 0x3c248) = *(int *)(param_1 + 0x3c248) + 1;
      iVar3 = *(int *)(param_2 + 0x1664 + uVar7 * 4);
      iVar5 = *(int *)((ulonglong)*(uint *)(param_2 + 0x1644 + uVar7 * 4) * 0x38 + 0x3b244 + param_1
                      );
      (**(code **)(**(longlong **)(param_1 + 0x3c028) + 0x48))
                (*(longlong **)(param_1 + 0x3c028),&local_res18);
      iVar4 = (**(code **)(*param_3 + 0x78))(param_3,0);
      local_res18 = local_res18 + (ulonglong)(uint)(iVar4 * (iVar3 + iVar5));
      iVar3 = *(int *)(uVar7 * 0x88 + 0x24 + param_2);
      (**(code **)(*local_res10 + 0x48))();
      iVar5 = (**(code **)(*param_3 + 0x78))(param_3);
      local_res8 = local_res8 + (ulonglong)(uint)(iVar5 * *(int *)(param_1 + 0x3c03c));
      iVar5 = (**(code **)(*param_3 + 0x78))();
      local_res8 = local_res8 + (ulonglong)(uint)(iVar5 * iVar3);
      (**(code **)(*param_3 + 0xc0))(param_3,1,local_res8,local_res18,0);
      uVar11 = (int)uVar7 + 1;
      uVar7 = (ulonglong)uVar11;
    } while (uVar11 < *(uint *)(param_2 + 0x18));
  }
  uVar11 = 0;
  *(int *)(param_1 + 0x3c03c) = *(int *)(param_1 + 0x3c03c) + uVar12 + 1;
  (**(code **)(*param_4 + 0xf8))(param_4,0,local_98);
  uVar12 = uVar11;
  if (*(uint *)(param_2 + 0x1c) != 0) {
    puVar6 = (uint *)(param_2 + 0x464);
    uVar7 = (ulonglong)*(uint *)(param_2 + 0x1c);
    uVar13 = 0;
    do {
      uVar12 = *puVar6;
      puVar6 = puVar6 + 0x22;
      if (uVar12 <= uVar13) {
        uVar12 = uVar13;
      }
      uVar7 = uVar7 - 1;
      uVar13 = uVar12;
    } while (uVar7 != 0);
  }
  if (0x900 < *(int *)(param_1 + 0x3c03c) + 1 + uVar12) {
    *(undefined4 *)(param_1 + 0x3c03c) = 0;
  }
  (**(code **)(*local_res10 + 0x50))(local_res10,&local_98);
  iVar3 = (**(code **)(*param_3 + 0x78))(param_3,0);
  local_98 = local_98 + (ulonglong)(uint)(iVar3 * *(int *)(param_1 + 0x3c03c));
  if (*(int *)(param_2 + 0x1c) != 0) {
    do {
      uVar9 = 0;
      uVar7 = (ulonglong)uVar11;
      lVar10 = (ulonglong)*(uint *)(param_1 + 0x3c248) * 0x20;
      lVar8 = (longlong)*(int *)(param_2 + 0xe04 + uVar7 * 4);
      uVar2 = *(undefined8 *)((lVar8 + 0x10e5) * 0x38 + param_1);
      lVar8 = lVar8 * 0x38;
      uVar13 = *(uint *)(lVar8 + 0x3b23c + param_1);
      if ((uVar13 & 2) == 0) {
        if (uVar13 == 1) {
          uVar9 = 8;
        }
        else if (uVar13 == 8) {
          uVar9 = 0x400;
        }
        else if (uVar13 == 2) {
          uVar9 = 0x40;
        }
        else if (uVar13 == 4) {
          uVar9 = 0x800;
        }
        else if (uVar13 == 6) {
          uVar9 = 0xac3;
        }
        local_90 = 0;
        uStack136._0_4_ = (undefined4)uVar2;
        uStack136._4_4_ = (undefined4)((ulonglong)uVar2 >> 0x20);
        uStack120 = 0x40;
        puVar1 = (undefined4 *)(lVar10 + 0x3c048 + param_1);
        *puVar1 = 0;
        puVar1[1] = 0;
        puVar1[2] = (undefined4)uStack136;
        puVar1[3] = uStack136._4_4_;
        local_80 = 0xffffffff;
        puVar1 = (undefined4 *)(lVar10 + 0x3c058 + param_1);
        *puVar1 = 0xffffffff;
        puVar1[1] = uVar9;
        puVar1[2] = 0x40;
        puVar1[3] = 0;
        *(undefined4 *)(lVar8 + 0x3b23c + param_1) = 2;
        *(int *)(param_1 + 0x3c248) = *(int *)(param_1 + 0x3c248) + 1;
        uStack136 = uVar2;
        uStack124 = uVar9;
      }
      iVar3 = *(int *)(param_2 + 0xe04 + uVar7 * 4);
      (**(code **)(**(longlong **)(param_1 + 0x3c018) + 0x48))
                (*(longlong **)(param_1 + 0x3c018),&local_res18);
      iVar5 = (**(code **)(*param_3 + 0x78))(param_3,0);
      local_res18 = local_res18 + (ulonglong)(uint)(iVar5 * iVar3);
      iVar3 = *(int *)(uVar7 * 0x88 + 0x464 + param_2);
      (**(code **)(*local_res10 + 0x48))(local_res10,&local_res8);
      iVar5 = (**(code **)(*param_3 + 0x78))(param_3,0);
      local_res8 = local_res8 + (ulonglong)(uint)(iVar5 * *(int *)(param_1 + 0x3c03c));
      iVar5 = (**(code **)(*param_3 + 0x78))(param_3,0);
      local_res8 = local_res8 + (ulonglong)(uint)(iVar5 * iVar3);
      (**(code **)(*param_3 + 0xc0))(param_3,1,local_res8,local_res18,0);
      uVar11 = uVar11 + 1;
      param_4 = local_res20;
    } while (uVar11 < *(uint *)(param_2 + 0x1c));
  }
  uVar11 = 0;
  *(int *)(param_1 + 0x3c03c) = *(int *)(param_1 + 0x3c03c) + uVar12 + 1;
  (**(code **)(*param_4 + 0xf8))(param_4,1,local_98);
  if (*(int *)(param_1 + 0x3c248) != 0) {
    (**(code **)(*param_4 + 0xd0))(param_4,*(int *)(param_1 + 0x3c248),param_1 + 0x3c048);
    *(undefined4 *)(param_1 + 0x3c248) = 0;
  }
  (**(code **)(*param_4 + 200))(param_4,*(undefined8 *)(param_2 + 0x10));
  if (*(int *)(param_2 + 0x20) != 0) {
    do {
      (**(code **)(*param_4 + 0x118))
                (param_4,uVar11 + 2,*(undefined4 *)((ulonglong)uVar11 * 0x104 + 0x1a84 + param_2),
                 param_2 + 0x1a88 + (ulonglong)uVar11 * 0x104,0);
      uVar11 = uVar11 + 1;
    } while (uVar11 < *(uint *)(param_2 + 0x20));
  }
  (**(code **)(*param_4 + 0x70))
            (param_4,*(undefined4 *)(param_2 + 0xdf8),*(undefined4 *)(param_2 + 0xdfc),
             *(undefined4 *)(param_2 + 0xe00));
  return 0;
}



undefined4 FUN_180006f58(int param_1)

{
  if (param_1 < 10) {
    if (param_1 == 9) {
      return 0x22;
    }
    if (param_1 == 1) {
      return 1;
    }
    if (param_1 == 2) {
      return 2;
    }
    if (param_1 == 3) {
      return 10;
    }
    if (param_1 == 4) {
      return 0x10;
    }
    if (param_1 == 5) {
      return 0x2a;
    }
    if (param_1 == 6) {
      return 0x1b;
    }
    if (param_1 == 7) {
      return 0x1c;
    }
    if (param_1 == 8) {
      return 0x1a;
    }
  }
  else {
    if (param_1 == 10) {
      return 0x24;
    }
    if (param_1 == 0xb) {
      return 0x36;
    }
    if (param_1 == 0xc) {
      return 0x39;
    }
    if (param_1 == 0xd) {
      return 0x38;
    }
    if (param_1 == 0xe) {
      return 0x3a;
    }
    if (param_1 == 0xf) {
      return 0x3d;
    }
    if (param_1 == 0x10) {
      return 0x31;
    }
    if (param_1 == 0x11) {
      return 0x29;
    }
  }
  return 0;
}



undefined4 FUN_180007004(int param_1)

{
  if (param_1 == 1) {
    return 8;
  }
  if (param_1 == 2) {
    return 0x40;
  }
  if (param_1 == 4) {
    return 0x800;
  }
  if (param_1 != 6) {
    if (param_1 == 8) {
      return 0x400;
    }
    return 0;
  }
  return 0xac3;
}



undefined8 thunk_FUN_180007080(longlong param_1,undefined8 param_2,code **param_3)

{
  int iVar1;
  undefined4 uVar2;
  code *pcVar3;
  
  iVar1 = FUN_180007480();
  if (iVar1 < 0x11) {
    if (iVar1 != 0x10) {
      if (iVar1 == 2) {
LAB_1800070ac:
        *(undefined4 *)param_3 = 1;
        return 1;
      }
      if ((iVar1 == 3) || (iVar1 == 4)) {
LAB_18000712a:
        *(undefined4 *)param_3 = 0;
        return 1;
      }
      if (iVar1 == 5) goto LAB_1800070ac;
      if (iVar1 == 6) goto LAB_18000712a;
      if (iVar1 == 0xc) goto LAB_1800070ca;
      if (iVar1 == 0xd) goto LAB_1800070ff;
      if (iVar1 != 0xe) {
        if (iVar1 != 0xf) {
          return 0xbad00000;
        }
        uVar2 = *(undefined4 *)(param_1 + 0xc);
        goto LAB_1800070cd;
      }
    }
    uVar2 = *(undefined4 *)(param_1 + 8);
  }
  else {
    if (iVar1 == 0x11) {
      *(undefined4 *)param_3 = *(undefined4 *)(param_1 + 0xc);
      return 1;
    }
    if (iVar1 != 0x12) {
      if (iVar1 != 0x13) {
        if (iVar1 != 0x14) {
          if (iVar1 == 0x15) {
            pcVar3 = NVSDK_NGX_D3D12_Init;
          }
          else {
            if (iVar1 != 0x16) {
              if (iVar1 == 0x29) {
                *param_3 = (code *)0x1337;
                return 1;
              }
              if ((iVar1 != 0x2a) && (iVar1 != 0x2b)) {
                return 0xbad00000;
              }
              goto LAB_18000712a;
            }
            pcVar3 = (code *)&LAB_180002d08;
          }
          *param_3 = pcVar3;
          return 1;
        }
        uVar2 = *(undefined4 *)(param_1 + 0x30);
        goto LAB_1800070cd;
      }
LAB_1800070ff:
      uVar2 = *(undefined4 *)(param_1 + 0x14);
      goto LAB_1800070cd;
    }
LAB_1800070ca:
    uVar2 = *(undefined4 *)(param_1 + 0x10);
  }
LAB_1800070cd:
  *(undefined4 *)param_3 = uVar2;
  return 1;
}



ulonglong FUN_180007044(undefined8 param_1,undefined8 *param_2,undefined8 *param_3)

{
  size_t *psVar1;
  size_t *psVar2;
  int iVar3;
  undefined4 extraout_var;
  byte bVar4;
  
  psVar1 = param_3 + 2;
  if (0xf < (ulonglong)param_3[3]) {
    param_3 = (undefined8 *)*param_3;
  }
  psVar2 = param_2 + 2;
  if (0xf < (ulonglong)param_2[3]) {
    param_2 = (undefined8 *)*param_2;
  }
  if (*psVar2 == *psVar1) {
    iVar3 = memcmp(param_2,param_3,*psVar2);
    param_2 = (undefined8 *)CONCAT44(extraout_var,iVar3);
    bVar4 = 0;
    if (iVar3 == 0) goto LAB_180007072;
  }
  bVar4 = 1;
LAB_180007072:
  return (ulonglong)param_2 & 0xffffffffffffff00 | (ulonglong)bVar4;
}



undefined8 FUN_180007080(longlong param_1,undefined8 param_2,code **param_3)

{
  int iVar1;
  undefined4 uVar2;
  code *pcVar3;
  
  iVar1 = FUN_180007480();
  if (iVar1 < 0x11) {
    if (iVar1 != 0x10) {
      if (iVar1 == 2) {
LAB_1800070ac:
        *(undefined4 *)param_3 = 1;
        return 1;
      }
      if ((iVar1 == 3) || (iVar1 == 4)) {
LAB_18000712a:
        *(undefined4 *)param_3 = 0;
        return 1;
      }
      if (iVar1 == 5) goto LAB_1800070ac;
      if (iVar1 == 6) goto LAB_18000712a;
      if (iVar1 == 0xc) goto LAB_1800070ca;
      if (iVar1 == 0xd) goto LAB_1800070ff;
      if (iVar1 != 0xe) {
        if (iVar1 != 0xf) {
          return 0xbad00000;
        }
        uVar2 = *(undefined4 *)(param_1 + 0xc);
        goto LAB_1800070cd;
      }
    }
    uVar2 = *(undefined4 *)(param_1 + 8);
  }
  else {
    if (iVar1 == 0x11) {
      *(undefined4 *)param_3 = *(undefined4 *)(param_1 + 0xc);
      return 1;
    }
    if (iVar1 != 0x12) {
      if (iVar1 != 0x13) {
        if (iVar1 != 0x14) {
          if (iVar1 == 0x15) {
            pcVar3 = NVSDK_NGX_D3D12_Init;
          }
          else {
            if (iVar1 != 0x16) {
              if (iVar1 == 0x29) {
                *param_3 = (code *)0x1337;
                return 1;
              }
              if ((iVar1 != 0x2a) && (iVar1 != 0x2b)) {
                return 0xbad00000;
              }
              goto LAB_18000712a;
            }
            pcVar3 = (code *)&LAB_180002d08;
          }
          *param_3 = pcVar3;
          return 1;
        }
        uVar2 = *(undefined4 *)(param_1 + 0x30);
        goto LAB_1800070cd;
      }
LAB_1800070ff:
      uVar2 = *(undefined4 *)(param_1 + 0x14);
      goto LAB_1800070cd;
    }
LAB_1800070ca:
    uVar2 = *(undefined4 *)(param_1 + 0x10);
  }
LAB_1800070cd:
  *(undefined4 *)param_3 = uVar2;
  return 1;
}



// WARNING: Removing unreachable block (ram,0x0001800072f6)
// WARNING: Removing unreachable block (ram,0x000180007324)
// WARNING: Removing unreachable block (ram,0x000180011972)
// WARNING: Removing unreachable block (ram,0x0001800072c8)
// WARNING: Removing unreachable block (ram,0x00018000721a)
// WARNING: Removing unreachable block (ram,0x000180011987)
// WARNING: Removing unreachable block (ram,0x000180007221)

void FUN_180007170(longlong param_1,undefined8 param_2,uint param_3)

{
  undefined4 uVar1;
  ulonglong in_stack_ffffffffffffffe8;
  ulonglong uVar2;
  
  uVar2 = in_stack_ffffffffffffffe8 & 0xffffffff00000000 | (ulonglong)param_3;
  uVar1 = FUN_180007480();
  switch(uVar1) {
  case 7:
  case 0xe:
    *(uint *)(param_1 + 8) = param_3;
    return;
  case 8:
  case 0xf:
    *(uint *)(param_1 + 0xc) = param_3;
    return;
  case 9:
    *(uint *)(param_1 + 0x18) = param_3;
    return;
  case 10:
    *(bool *)(param_1 + 0x1c) = param_3 != 0;
    return;
  case 0xb:
    *(bool *)(param_1 + 0x1d) = param_3 != 0;
    break;
  case 0xc:
    *(uint *)(param_1 + 0x10) = param_3;
    return;
  case 0xd:
    *(uint *)(param_1 + 0x14) = param_3;
    return;
  case 0x14:
    *(uint *)(param_1 + 0x30) = param_3;
    return;
  case 0x17:
    *(uint *)(param_1 + 0x20) = param_3;
    return;
  case 0x18:
    *(uint *)(param_1 + 0x24) = param_3;
    return;
  case 0x19:
    *(byte *)(param_1 + 0x52) = (byte)param_3 & 1;
    *(byte *)(param_1 + 0x53) = (byte)(param_3 >> 5) & 1;
    *(bool *)(param_1 + 0x50) = (param_3 & 8) != 0;
    *(bool *)(param_1 + 0x54) = (param_3 & 4) != 0;
    *(bool *)(param_1 + 0x55) = (param_3 & 2) != 0;
    return;
  case 0x1b:
    *(ulonglong *)(param_1 + 0x60) = uVar2;
    break;
  case 0x1c:
    *(ulonglong *)(param_1 + 0x70) = uVar2;
    break;
  case 0x1d:
    *(ulonglong *)(param_1 + 0x68) = uVar2;
    break;
  case 0x1e:
    *(ulonglong *)(param_1 + 0x78) = uVar2;
    break;
  case 0x1f:
    *(ulonglong *)(param_1 + 0x80) = uVar2;
    break;
  case 0x20:
    *(ulonglong *)(param_1 + 0x88) = uVar2;
    break;
  case 0x21:
    *(ulonglong *)(param_1 + 0x58) = uVar2;
    break;
  case 0x24:
    *(bool *)(param_1 + 0x34) = param_3 != 0;
    return;
  case 0x25:
    *(uint *)(param_1 + 0x38) = param_3;
    return;
  case 0x26:
    *(uint *)(param_1 + 0x3c) = param_3;
    return;
  case 0x27:
    *(uint *)(param_1 + 0x40) = param_3;
    return;
  case 0x28:
    *(uint *)(param_1 + 0x44) = param_3;
    return;
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x0001800072f6)
// WARNING: Removing unreachable block (ram,0x000180007324)
// WARNING: Removing unreachable block (ram,0x000180011972)
// WARNING: Removing unreachable block (ram,0x0001800072c8)
// WARNING: Removing unreachable block (ram,0x00018000721a)
// WARNING: Removing unreachable block (ram,0x000180011987)
// WARNING: Removing unreachable block (ram,0x000180007221)

void FUN_180007190(undefined8 param_1,undefined8 param_2,uint param_3,longlong param_4)

{
  undefined4 uVar1;
  ulonglong in_stack_ffffffffffffffe8;
  ulonglong uVar2;
  
  uVar2 = in_stack_ffffffffffffffe8 & 0xffffffff00000000 | (ulonglong)param_3;
  uVar1 = FUN_180007480();
  switch(uVar1) {
  case 7:
  case 0xe:
    *(uint *)(param_4 + 8) = param_3;
    return;
  case 8:
  case 0xf:
    *(uint *)(param_4 + 0xc) = param_3;
    return;
  case 9:
    *(uint *)(param_4 + 0x18) = param_3;
    return;
  case 10:
    *(bool *)(param_4 + 0x1c) = param_3 != 0;
    return;
  case 0xb:
    *(bool *)(param_4 + 0x1d) = param_3 != 0;
    break;
  case 0xc:
    *(uint *)(param_4 + 0x10) = param_3;
    return;
  case 0xd:
    *(uint *)(param_4 + 0x14) = param_3;
    return;
  case 0x14:
    *(uint *)(param_4 + 0x30) = param_3;
    return;
  case 0x17:
    *(uint *)(param_4 + 0x20) = param_3;
    return;
  case 0x18:
    *(uint *)(param_4 + 0x24) = param_3;
    return;
  case 0x19:
    *(byte *)(param_4 + 0x52) = (byte)param_3 & 1;
    *(byte *)(param_4 + 0x53) = (byte)(param_3 >> 5) & 1;
    *(bool *)(param_4 + 0x50) = (param_3 & 8) != 0;
    *(bool *)(param_4 + 0x54) = (param_3 & 4) != 0;
    *(bool *)(param_4 + 0x55) = (param_3 & 2) != 0;
    return;
  case 0x1b:
    *(ulonglong *)(param_4 + 0x60) = uVar2;
    break;
  case 0x1c:
    *(ulonglong *)(param_4 + 0x70) = uVar2;
    break;
  case 0x1d:
    *(ulonglong *)(param_4 + 0x68) = uVar2;
    break;
  case 0x1e:
    *(ulonglong *)(param_4 + 0x78) = uVar2;
    break;
  case 0x1f:
    *(ulonglong *)(param_4 + 0x80) = uVar2;
    break;
  case 0x20:
    *(ulonglong *)(param_4 + 0x88) = uVar2;
    break;
  case 0x21:
    *(ulonglong *)(param_4 + 0x58) = uVar2;
    break;
  case 0x24:
    *(bool *)(param_4 + 0x34) = param_3 != 0;
    return;
  case 0x25:
    *(uint *)(param_4 + 0x38) = param_3;
    return;
  case 0x26:
    *(uint *)(param_4 + 0x3c) = param_3;
    return;
  case 0x27:
    *(uint *)(param_4 + 0x40) = param_3;
    return;
  case 0x28:
    *(uint *)(param_4 + 0x44) = param_3;
    return;
  }
  return;
}



void FUN_1800071b0(longlong param_1,undefined8 param_2,longlong *param_3)

{
  undefined4 uVar1;
  wchar_t *pwVar2;
  int iVar3;
  
  uVar1 = FUN_180007480();
  iVar3 = (int)param_3;
  switch(uVar1) {
  case 7:
  case 0xe:
    *(int *)(param_1 + 8) = iVar3;
    return;
  case 8:
  case 0xf:
    *(int *)(param_1 + 0xc) = iVar3;
    return;
  case 9:
    *(int *)(param_1 + 0x18) = iVar3;
    return;
  case 10:
    *(bool *)(param_1 + 0x1c) = iVar3 != 0;
    return;
  case 0xb:
    *(bool *)(param_1 + 0x1d) = iVar3 != 0;
    break;
  case 0xc:
    *(int *)(param_1 + 0x10) = iVar3;
    return;
  case 0xd:
    *(int *)(param_1 + 0x14) = iVar3;
    return;
  case 0x14:
    *(int *)(param_1 + 0x30) = iVar3;
    return;
  case 0x17:
    *(int *)(param_1 + 0x20) = iVar3;
    return;
  case 0x18:
    *(int *)(param_1 + 0x24) = iVar3;
    return;
  case 0x19:
    *(byte *)(param_1 + 0x52) = (byte)param_3 & 1;
    *(byte *)(param_1 + 0x53) = (byte)(((ulonglong)param_3 & 0xffffffff) >> 5) & 1;
    *(bool *)(param_1 + 0x50) = ((ulonglong)param_3 & 8) != 0;
    *(bool *)(param_1 + 0x54) = ((ulonglong)param_3 & 4) != 0;
    *(bool *)(param_1 + 0x55) = ((ulonglong)param_3 & 2) != 0;
    return;
  case 0x1b:
    *(longlong **)(param_1 + 0x60) = param_3;
    goto LAB_180007210;
  case 0x1c:
    *(longlong **)(param_1 + 0x70) = param_3;
    if (param_3 != (longlong *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00018000730a. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*param_3 + 0x30))(param_3,L"MotionVectors");
      return;
    }
    break;
  case 0x1d:
    *(longlong **)(param_1 + 0x68) = param_3;
    if (param_3 != (longlong *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0001800072dc. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*param_3 + 0x30))(param_3,L"Depth");
      return;
    }
    break;
  case 0x1e:
    *(longlong **)(param_1 + 0x78) = param_3;
    if (param_3 != (longlong *)0x0) {
                    // WARNING: Could not recover jumptable at 0x000180007338. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*param_3 + 0x30))(param_3,L"Output");
      return;
    }
    break;
  case 0x1f:
    *(longlong **)(param_1 + 0x80) = param_3;
    if (param_3 == (longlong *)0x0) {
      return;
    }
    pwVar2 = L"TransparencyMask";
    goto LAB_180007221;
  case 0x20:
    *(longlong **)(param_1 + 0x88) = param_3;
    if (param_3 != (longlong *)0x0) {
      pwVar2 = L"ExposureTexture";
      goto LAB_180007221;
    }
    break;
  case 0x21:
    *(longlong **)(param_1 + 0x58) = param_3;
LAB_180007210:
    if (param_3 != (longlong *)0x0) {
      pwVar2 = L"Color";
LAB_180007221:
                    // WARNING: Could not recover jumptable at 0x00018000722e. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*param_3 + 0x30))(param_3,pwVar2);
      return;
    }
    break;
  case 0x24:
    *(bool *)(param_1 + 0x34) = iVar3 != 0;
    return;
  case 0x25:
    *(int *)(param_1 + 0x38) = iVar3;
    return;
  case 0x26:
    *(int *)(param_1 + 0x3c) = iVar3;
    return;
  case 0x27:
    *(int *)(param_1 + 0x40) = iVar3;
    return;
  case 0x28:
    *(int *)(param_1 + 0x44) = iVar3;
    return;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180007480(void *param_1)

{
  longlong lVar1;
  code *pcVar2;
  undefined **ppuVar3;
  char cVar4;
  int iVar5;
  undefined8 *puVar6;
  void *pvVar7;
  longlong *plVar8;
  undefined8 *puVar9;
  undefined8 *puVar10;
  undefined8 *puVar11;
  ulonglong uVar12;
  longlong lVar13;
  ulonglong uVar14;
  longlong in_GS_OFFSET;
  undefined auStack2024 [48];
  undefined8 local_7b8;
  undefined8 *local_7a8;
  ulonglong local_7a0;
  undefined local_788 [32];
  undefined4 local_768;
  undefined local_760 [32];
  undefined4 local_740;
  undefined local_738 [32];
  undefined4 local_718;
  undefined local_710 [32];
  undefined4 local_6f0;
  undefined local_6e8 [32];
  undefined4 local_6c8;
  undefined local_6c0 [32];
  undefined4 local_6a0;
  undefined local_698 [32];
  undefined4 local_678;
  undefined local_670 [32];
  undefined4 local_650;
  undefined local_648 [32];
  undefined4 local_628;
  undefined local_620 [32];
  undefined4 local_600;
  undefined local_5f8 [32];
  undefined4 local_5d8;
  undefined local_5d0 [32];
  undefined4 local_5b0;
  undefined local_5a8 [32];
  undefined4 local_588;
  undefined local_580 [32];
  undefined4 local_560;
  undefined local_558 [32];
  undefined4 local_538;
  undefined local_530 [32];
  undefined4 local_510;
  undefined local_508 [32];
  undefined4 local_4e8;
  undefined local_4e0 [32];
  undefined4 local_4c0;
  undefined local_4b8 [32];
  undefined4 local_498;
  undefined local_490 [32];
  undefined4 local_470;
  undefined local_468 [32];
  undefined4 local_448;
  undefined local_440 [32];
  undefined4 local_420;
  undefined local_418 [32];
  undefined4 local_3f8;
  undefined local_3f0 [32];
  undefined4 local_3d0;
  undefined local_3c8 [32];
  undefined4 local_3a8;
  undefined local_3a0 [32];
  undefined4 local_380;
  undefined local_378 [32];
  undefined4 local_358;
  undefined local_350 [32];
  undefined4 local_330;
  undefined local_328 [32];
  undefined4 local_308;
  undefined local_300 [32];
  undefined4 local_2e0;
  undefined local_2d8 [32];
  undefined4 local_2b8;
  undefined local_2b0 [32];
  undefined4 local_290;
  undefined local_288 [32];
  undefined4 local_268;
  undefined local_260 [32];
  undefined4 local_240;
  undefined local_238 [32];
  undefined4 local_218;
  undefined local_210 [32];
  undefined4 local_1f0;
  undefined local_1e8 [32];
  undefined4 local_1c8;
  undefined local_1c0 [32];
  undefined4 local_1a0;
  undefined local_198 [32];
  undefined4 local_178;
  undefined local_170 [32];
  undefined4 local_150;
  undefined local_148 [32];
  undefined4 local_128;
  undefined local_120 [32];
  undefined4 local_100;
  undefined local_f8 [32];
  undefined4 local_d8;
  undefined local_d0 [32];
  undefined4 local_b0;
  undefined local_a8 [32];
  undefined4 local_88;
  undefined local_80 [32];
  undefined4 local_60;
  undefined *local_58;
  undefined **local_50;
  undefined8 *local_48;
  undefined4 uStack64;
  undefined4 uStack60;
  ulonglong local_38;
  
  local_38 = DAT_180418010 ^ (ulonglong)auStack2024;
  if ((*(int *)(*(longlong *)(*(longlong *)(in_GS_OFFSET + 0x58) + (ulonglong)DAT_18041eb54 * 8) + 4
               ) < _DAT_18041ecb8) && (_Init_thread_header(&DAT_18041ecb8), _DAT_18041ecb8 == -1)) {
    FUN_180007c64(local_788,"SuperSampling.ScaleFactor");
    local_768 = 1;
    FUN_180007c64(local_760,"SuperSampling.Available");
    local_740 = 2;
    FUN_180007c64(local_738,"SuperSampling.MinDriverVersionMajor");
    local_718 = 3;
    FUN_180007c64(local_710,"SuperSampling.MinDriverVersionMinor");
    local_6f0 = 4;
    FUN_180007c64(local_6e8,"SuperSampling.FeatureInitResult");
    local_6c8 = 5;
    FUN_180007c64(local_6c0,"SuperSampling.NeedsUpdatedDriver");
    local_6a0 = 6;
    FUN_180007c64(local_698,&DAT_18001e1fc);
    local_678 = 2;
    FUN_180007c64(local_670,"Width");
    local_650 = 7;
    FUN_180007c64(local_648,"Height");
    local_628 = 8;
    FUN_180007c64(local_620,"PerfQualityValue");
    local_600 = 9;
    FUN_180007c64(local_5f8,"RTXValue");
    local_5d8 = 10;
    FUN_180007c64(local_5d0,"NVSDK_NGX_Parameter_FreeMemOnReleaseFeature");
    local_5b0 = 0xb;
    FUN_180007c64(local_5a8,"OutWidth");
    local_588 = 0xc;
    FUN_180007c64(local_580,"OutHeight");
    local_560 = 0xd;
    FUN_180007c64(local_558,"DLSS.Render.Subrect.Dimensions.Width");
    local_538 = 0xe;
    FUN_180007c64(local_530,"DLSS.Render.Subrect.Dimensions.Height");
    local_510 = 0xf;
    FUN_180007c64(local_508,"DLSS.Get.Dynamic.Max.Render.Width");
    local_4e8 = 0x10;
    FUN_180007c64(local_4e0,"DLSS.Get.Dynamic.Max.Render.Height");
    local_4c0 = 0x11;
    FUN_180007c64(local_4b8,"DLSS.Get.Dynamic.Min.Render.Width");
    local_498 = 0x12;
    FUN_180007c64(local_490,"DLSS.Get.Dynamic.Min.Render.Height");
    local_470 = 0x13;
    FUN_180007c64(local_468,"Sharpness");
    local_448 = 0x14;
    FUN_180007c64(local_440,"DLSSOptimalSettingsCallback");
    local_420 = 0x16;
    FUN_180007c64(local_418,"DLSSGetStatsCallback");
    local_3f8 = 0x15;
    FUN_180007c64(local_3f0,"CreationNodeMask");
    local_3d0 = 0x17;
    FUN_180007c64(local_3c8,"VisibilityNodeMask");
    local_3a8 = 0x18;
    FUN_180007c64(local_3a0,"DLSS.Feature.Create.Flags");
    local_380 = 0x19;
    FUN_180007c64(local_378,"DLSS.Enable.Output.Subrects");
    local_358 = 0x1a;
    FUN_180007c64(local_350,"Color");
    local_330 = 0x1b;
    FUN_180007c64(local_328,"MotionVectors");
    local_308 = 0x1c;
    FUN_180007c64(local_300,"Depth");
    local_2e0 = 0x1d;
    FUN_180007c64(local_2d8,"Output");
    local_2b8 = 0x1e;
    FUN_180007c64(local_2b0,"TransparencyMask");
    local_290 = 0x1f;
    FUN_180007c64(local_288,"ExposureTexture");
    local_268 = 0x20;
    FUN_180007c64(local_260,"DLSS.Input.Bias.Current.Color.Mask");
    local_240 = 0x21;
    FUN_180007c64(local_238,"DLSS.Pre.Exposure");
    local_218 = 0x22;
    FUN_180007c64(local_210,"DLSS.Exposure.Scale");
    local_1f0 = 0x23;
    FUN_180007c64(local_1e8,"Reset");
    local_1c8 = 0x24;
    FUN_180007c64(local_1c0,"MV.Scale.X");
    local_1a0 = 0x25;
    FUN_180007c64(local_198,"MV.Scale.Y");
    local_178 = 0x26;
    FUN_180007c64(local_170,"Jitter.Offset.X");
    local_150 = 0x27;
    FUN_180007c64(local_148,"Jitter.Offset.Y");
    local_128 = 0x28;
    FUN_180007c64(local_120,"SizeInBytes");
    local_100 = 0x29;
    FUN_180007c64(local_f8,"Snippet.OptLevel");
    local_d8 = 0x2a;
    FUN_180007c64(local_d0,&DAT_18001e1f8);
    local_b0 = 0x2a;
    FUN_180007c64(local_a8,"Snippet.IsDevBranch");
    local_88 = 0x2b;
    FUN_180007c64(local_80,&DAT_18001e1f4);
    local_60 = 0x2b;
    local_58 = local_788;
    local_50 = &local_58;
    FUN_180001124();
    _eh_vector_destructor_iterator_(local_788,0x28,0x2e,(FuncDef3 *)&LAB_180007138);
    atexit(&DAT_180010590);
    FUN_18000ea80(&DAT_18041ecb8);
  }
  puVar9 = (undefined8 *)0x0;
  local_7b8 = (undefined8 *)0x0;
  local_7a8 = (undefined8 *)0x0;
  local_7a0 = 0;
  puVar11 = (undefined8 *)0xffffffffffffffff;
  do {
    puVar11 = (undefined8 *)((longlong)puVar11 + 1);
  } while (*(char *)((longlong)param_1 + (longlong)puVar11) != '\0');
  if ((undefined8 *)0x7fffffffffffffff < puVar11) {
    std::_Xlength_error("string too long");
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
  local_7a0 = 0xf;
  if (puVar11 < (undefined8 *)0x10) {
    local_7a8 = puVar11;
    memcpy(&local_7b8,param_1,(size_t)puVar11);
    *(undefined *)((longlong)&local_7b8 + (longlong)puVar11) = 0;
  }
  else {
    uVar12 = (ulonglong)puVar11 | 0xf;
    uVar14 = 0x7fffffffffffffff;
    if ((uVar12 < 0x8000000000000000) && (uVar14 = uVar12, uVar12 < 0x16)) {
      uVar14 = 0x16;
    }
    uVar12 = uVar14 + 1;
    if (uVar14 == 0xffffffffffffffff) {
      uVar12 = 0xffffffffffffffff;
    }
    if (uVar12 < 0x1000) {
      puVar6 = puVar9;
      if (uVar12 != 0) {
        puVar6 = (undefined8 *)operator_new(uVar12);
      }
    }
    else {
      if (uVar12 + 0x27 <= uVar12) {
                    // WARNING: Subroutine does not return
        FUN_18001642c();
      }
      pvVar7 = operator_new(uVar12 + 0x27);
      if (pvVar7 == (void *)0x0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      puVar6 = (undefined8 *)((longlong)pvVar7 + 0x27U & 0xffffffffffffffe0);
      puVar6[-1] = pvVar7;
    }
    local_7b8 = puVar6;
    local_7a8 = puVar11;
    local_7a0 = uVar14;
    memcpy(puVar6,param_1,(size_t)puVar11);
    *(undefined *)((longlong)puVar6 + (longlong)puVar11) = 0;
  }
  uVar14 = local_7a0;
  puVar6 = local_7a8;
  puVar11 = local_7b8;
  puVar10 = &local_7b8;
  if (0xf < local_7a0) {
    puVar10 = local_7b8;
  }
  uVar12 = 0xcbf29ce484222325;
  if (local_7a8 != (undefined8 *)0x0) {
    do {
      uVar12 = (uVar12 ^ *(byte *)((longlong)puVar9 + (longlong)puVar10)) * 0x100000001b3;
      puVar9 = (undefined8 *)((longlong)puVar9 + 1);
    } while (puVar9 < local_7a8);
  }
  lVar13 = *(longlong *)(DAT_18041ec78 + 8 + (uVar12 & DAT_18041ec90) * 0x10);
  if (lVar13 != DAT_18041ec68) {
    lVar1 = *(longlong *)(DAT_18041ec78 + (uVar12 & DAT_18041ec90) * 0x10);
    while( true ) {
      puVar9 = (undefined8 *)(lVar13 + 0x10);
      if (0xf < *(ulonglong *)(lVar13 + 0x28)) {
        puVar9 = (undefined8 *)*puVar9;
      }
      puVar10 = &local_7b8;
      if (0xf < uVar14) {
        puVar10 = puVar11;
      }
      if ((puVar6 == *(undefined8 **)(lVar13 + 0x20)) &&
         (iVar5 = memcmp(puVar10,puVar9,(size_t)puVar6), iVar5 == 0)) goto LAB_18000760d;
      if (lVar13 == lVar1) break;
      lVar13 = *(longlong *)(lVar13 + 8);
    }
  }
  if (DAT_18041ec70 == 0x492492492492492) {
    std::_Xlength_error("unordered_map/set too long");
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
  local_48 = &local_7b8;
  FUN_180018ca8(&local_58,&DAT_18041ec68);
  cVar4 = FUN_180007d6c();
  if (cVar4 != '\0') {
    FUN_180002014();
    plVar8 = (longlong *)FUN_18000802c();
    local_48 = (undefined8 *)*plVar8;
    uStack64 = *(undefined4 *)(plVar8 + 1);
    uStack60 = *(undefined4 *)((longlong)plVar8 + 0xc);
  }
  local_50 = (undefined **)0x0;
  FUN_180007ed8();
  ppuVar3 = local_50;
  puVar11 = local_7b8;
  uVar14 = local_7a0;
  if (local_50 != (undefined **)0x0) {
    if ((undefined *)0xf < local_50[5]) {
      FUN_180003f84(local_50[2],local_50[5] + 1);
    }
    ppuVar3[4] = (undefined *)0x0;
    *(undefined *)(ppuVar3 + 2) = 0;
    ppuVar3[5] = (undefined *)0xf;
    puVar11 = local_7b8;
    uVar14 = local_7a0;
    if (local_50 != (undefined **)0x0) {
      FUN_180003f84(local_50,0x38);
      puVar11 = local_7b8;
      uVar14 = local_7a0;
    }
  }
LAB_18000760d:
  if (0xf < uVar14) {
    puVar9 = puVar11;
    if ((0xfff < uVar14 + 1) &&
       (puVar9 = (undefined8 *)puVar11[-1],
       0x1f < (ulonglong)((longlong)puVar11 + (-8 - (longlong)puVar9)))) {
                    // WARNING: Subroutine does not return
      _invalid_parameter_noinfo_noreturn();
    }
    free(puVar9);
  }
  FUN_18000e8c0(local_38 ^ (ulonglong)auStack2024);
  return;
}



void _guard_check_icall(void)

{
  return;
}



undefined8 * FUN_180007c64(undefined8 *param_1,longlong param_2)

{
  longlong lVar1;
  
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  lVar1 = -1;
  do {
    lVar1 = lVar1 + 1;
  } while (*(char *)(param_2 + lVar1) != '\0');
  FUN_180007c9c();
  return param_1;
}



void FUN_180007c9c(void **param_1,void *param_2,void *param_3)

{
  code *pcVar1;
  void *pvVar2;
  void *_Dst;
  longlong lVar3;
  
  if (param_3 < (void *)0x8000000000000000) {
    param_1[3] = (void *)0xf;
    if (param_3 < (void *)0x10) {
      param_1[2] = param_3;
      memmove(param_1,param_2,(size_t)param_3);
      *(undefined *)((longlong)param_3 + (longlong)param_1) = 0;
    }
    else {
      pvVar2 = (void *)FUN_180007d30(param_1,param_3);
      lVar3 = (longlong)pvVar2 + 1;
      if (pvVar2 == (void *)0xffffffffffffffff) {
        lVar3 = -1;
      }
      _Dst = (void *)FUN_180008bb4(lVar3);
      *param_1 = _Dst;
      param_1[2] = param_3;
      param_1[3] = pvVar2;
      memcpy(_Dst,param_2,(size_t)param_3);
      *(undefined *)((longlong)param_3 + (longlong)_Dst) = 0;
    }
    return;
  }
  std::_Xlength_error("string too long");
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



ulonglong FUN_180007d30(longlong param_1,ulonglong param_2)

{
  ulonglong uVar1;
  ulonglong uVar2;
  
  uVar1 = *(ulonglong *)(param_1 + 0x18);
  param_2 = param_2 | 0xf;
  uVar2 = 0x7fffffffffffffff;
  if (((param_2 < 0x8000000000000000) && (uVar1 <= 0x7fffffffffffffff - (uVar1 >> 1))) &&
     (uVar2 = (uVar1 >> 1) + uVar1, uVar2 <= param_2)) {
    uVar2 = param_2;
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ulonglong FUN_180007d6c(void)

{
  ulonglong in_RAX;
  ulonglong uVar1;
  float fVar2;
  float fVar3;
  
  uVar1 = DAT_18041ec70 + 1;
  if ((longlong)uVar1 < 0) {
    in_RAX = uVar1 >> 1 | (ulonglong)((uint)uVar1 & 1);
    fVar2 = (float)in_RAX + (float)in_RAX;
  }
  else {
    fVar2 = (float)uVar1;
  }
  if ((longlong)DAT_18041ec98 < 0) {
    in_RAX = DAT_18041ec98 >> 1 | (ulonglong)((uint)DAT_18041ec98 & 1);
    fVar3 = (float)in_RAX + (float)in_RAX;
  }
  else {
    fVar3 = (float)DAT_18041ec98;
  }
  return in_RAX & 0xffffffffffffff00 | (ulonglong)(_DAT_18041ec60 < fVar2 / fVar3);
}



void FUN_180007e08(void)

{
  code *pcVar1;
  
  if (DAT_18041ec70 != 0x492492492492492) {
    return;
  }
  std::_Xlength_error("unordered_map/set too long");
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void ** FUN_180007e28(void **param_1,undefined8 *param_2,undefined8 param_3,undefined8 param_4)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  void *_Dst;
  void **ppvVar4;
  longlong lVar5;
  
  *param_1 = (void *)0x0;
  param_1[2] = (void *)0x0;
  param_1[3] = (void *)0x0;
  pvVar1 = (void *)param_2[2];
  if (0xf < (ulonglong)param_2[3]) {
    param_2 = (undefined8 *)*param_2;
  }
  if (pvVar1 < (void *)0x8000000000000000) {
    param_1[3] = (void *)0xf;
    if (pvVar1 < (void *)0x10) {
      param_1[2] = pvVar1;
      memmove(param_1,param_2,0x10);
    }
    else {
      pvVar3 = (void *)FUN_180007d30(param_1,pvVar1,0x10,param_4,param_1);
      lVar5 = (longlong)pvVar3 + 1;
      if (pvVar3 == (void *)0xffffffffffffffff) {
        lVar5 = -1;
      }
      _Dst = (void *)FUN_180008bb4(lVar5);
      *param_1 = _Dst;
      param_1[2] = pvVar1;
      param_1[3] = pvVar3;
      memcpy(_Dst,param_2,(longlong)pvVar1 + 1);
    }
    return param_1;
  }
  std::_Xlength_error("string too long");
  pcVar2 = (code *)swi(3);
  ppvVar4 = (void **)(*pcVar2)();
  return ppvVar4;
}



longlong * FUN_180007ed8(undefined8 param_1,ulonglong param_2,longlong param_3,longlong *param_4)

{
  longlong **pplVar1;
  longlong lVar2;
  longlong lVar3;
  
  pplVar1 = *(longlong ***)(param_3 + 8);
  DAT_18041ec70 = DAT_18041ec70 + 1;
  *param_4 = param_3;
  param_4[1] = (longlong)pplVar1;
  *pplVar1 = param_4;
  *(longlong **)(param_3 + 8) = param_4;
  lVar3 = DAT_18041ec78;
  param_2 = DAT_18041ec90 & param_2;
  lVar2 = *(longlong *)(DAT_18041ec78 + param_2 * 0x10);
  if (lVar2 == DAT_18041ec68) {
    *(longlong **)(DAT_18041ec78 + param_2 * 0x10) = param_4;
  }
  else {
    if (lVar2 == param_3) {
      *(longlong **)(DAT_18041ec78 + param_2 * 0x10) = param_4;
      return param_4;
    }
    if (*(longlong ***)(DAT_18041ec78 + 8 + param_2 * 0x10) != pplVar1) {
      return param_4;
    }
  }
  *(longlong **)(lVar3 + 8 + param_2 * 0x10) = param_4;
  return param_4;
}



void FUN_180007f34(undefined8 param_1,longlong *param_2,undefined8 *param_3)

{
  longlong lVar1;
  char cVar2;
  longlong lVar3;
  undefined4 *puVar4;
  undefined8 *puVar5;
  undefined auStack88 [32];
  undefined4 local_38;
  undefined4 uStack52;
  undefined4 uStack48;
  undefined4 uStack44;
  undefined local_28 [8];
  longlong local_20;
  ulonglong local_18;
  
  local_18 = DAT_180418010 ^ (ulonglong)auStack88;
  puVar5 = param_3;
  if (0xf < (ulonglong)param_3[3]) {
    puVar5 = (undefined8 *)*param_3;
  }
  FUN_18000d1d8(param_1,puVar5,param_3[2]);
  FUN_18000802c();
  if (CONCAT44(uStack44,uStack48) == 0) {
    FUN_180007e08();
    FUN_1800080b8(local_28,&DAT_18041ec68,param_3);
    cVar2 = FUN_180007d6c();
    if (cVar2 != '\0') {
      FUN_180002014();
      puVar4 = (undefined4 *)FUN_18000802c();
      local_38 = *puVar4;
      uStack52 = puVar4[1];
      uStack48 = puVar4[2];
      uStack44 = puVar4[3];
    }
    local_20 = 0;
    lVar3 = FUN_180007ed8();
    lVar1 = local_20;
    *param_2 = lVar3;
    *(undefined *)(param_2 + 1) = 1;
    if (local_20 != 0) {
      if (0xf < *(ulonglong *)(local_20 + 0x28)) {
        FUN_180003f84(*(undefined8 *)(local_20 + 0x10),*(ulonglong *)(local_20 + 0x28) + 1);
      }
      *(undefined8 *)(lVar1 + 0x20) = 0;
      *(undefined *)(lVar1 + 0x10) = 0;
      *(undefined8 *)(lVar1 + 0x28) = 0xf;
      if (local_20 != 0) {
        FUN_180003f84(local_20,0x38);
      }
    }
  }
  else {
    *param_2 = CONCAT44(uStack44,uStack48);
    *(undefined *)(param_2 + 1) = 0;
  }
  FUN_18000e8c0(local_18 ^ (ulonglong)auStack88);
  return;
}



undefined8 *
FUN_18000802c(undefined8 param_1,undefined8 *param_2,undefined8 param_3,ulonglong param_4)

{
  undefined8 *puVar1;
  char cVar2;
  undefined8 *puVar3;
  
  puVar1 = DAT_18041ec68;
  puVar3 = *(undefined8 **)(DAT_18041ec78 + 8 + (DAT_18041ec90 & param_4) * 0x10);
  if (puVar3 == DAT_18041ec68) {
    param_2[1] = 0;
    *param_2 = puVar1;
  }
  else {
    puVar1 = *(undefined8 **)(DAT_18041ec78 + (DAT_18041ec90 & param_4) * 0x10);
    while (cVar2 = FUN_180007044(), cVar2 != '\0') {
      if (puVar3 == puVar1) {
        param_2[1] = 0;
        *param_2 = puVar3;
        return param_2;
      }
      puVar3 = (undefined8 *)puVar3[1];
    }
    *param_2 = *puVar3;
    param_2[1] = puVar3;
  }
  return param_2;
}



undefined8 * FUN_1800080b8(undefined8 *param_1,undefined8 param_2,longlong param_3)

{
  void *pvVar1;
  
  *param_1 = param_2;
  param_1[1] = 0;
  param_1[1] = 0;
  pvVar1 = operator_new(0x38);
  param_1[1] = pvVar1;
  FUN_180007e28((longlong)pvVar1 + 0x10,param_3);
  *(undefined4 *)((longlong)pvVar1 + 0x30) = *(undefined4 *)(param_3 + 0x20);
  return param_1;
}



undefined8 FUN_1800086ec(undefined8 param_1,undefined8 param_2,longlong param_3)

{
  longlong lVar1;
  
  lVar1 = -1;
  do {
    lVar1 = lVar1 + 1;
  } while (*(char *)(param_3 + lVar1) != '\0');
  FUN_180008854();
  return param_2;
}



void FUN_180008714(undefined8 param_1,void *param_2,void *param_3,longlong param_4,longlong param_5)

{
  longlong lVar1;
  undefined2 *puVar2;
  
  memcpy(param_2,param_3,param_4 * 2);
  puVar2 = (undefined2 *)(param_4 * 2 + (longlong)param_2);
  lVar1 = param_5;
  if (param_5 != 0) {
    for (; lVar1 != 0; lVar1 = lVar1 + -1) {
      *puVar2 = 0;
      puVar2 = puVar2 + 1;
    }
  }
  *(undefined2 *)((longlong)param_2 + (param_5 + param_4) * 2) = 0;
  return;
}



undefined8 * FUN_18000876c(undefined8 *param_1,ulonglong param_2,ulonglong param_3)

{
  longlong lVar1;
  longlong lVar2;
  undefined2 *puVar3;
  undefined8 *puVar4;
  byte local_18;
  
  lVar2 = param_1[2];
  if ((ulonglong)(param_1[3] - lVar2) < param_2) {
    param_1 = (undefined8 *)
              FUN_1800087a0(param_1,param_2,param_3 & 0xffffffffffffff00 | (ulonglong)local_18,
                            param_2);
  }
  else {
    lVar1 = param_2 + lVar2;
    param_1[2] = lVar1;
    puVar4 = param_1;
    if (7 < (ulonglong)param_1[3]) {
      puVar4 = (undefined8 *)*param_1;
    }
    puVar3 = (undefined2 *)((longlong)puVar4 + lVar2 * 2);
    if (param_2 != 0) {
      for (; param_2 != 0; param_2 = param_2 - 1) {
        *puVar3 = 0;
        puVar3 = puVar3 + 1;
      }
    }
    *(undefined2 *)((longlong)puVar4 + lVar1 * 2) = 0;
  }
  return param_1;
}



undefined8 * FUN_1800087a0(undefined8 *param_1,ulonglong param_2)

{
  longlong lVar1;
  ulonglong uVar2;
  undefined8 uVar3;
  code *pcVar4;
  longlong lVar5;
  undefined8 uVar6;
  undefined8 *puVar7;
  ulonglong uVar8;
  
  if (0x7ffffffffffffffe - param_1[2] < param_2) {
    std::_Xlength_error("string too long");
    pcVar4 = (code *)swi(3);
    puVar7 = (undefined8 *)(*pcVar4)();
    return puVar7;
  }
  uVar2 = param_1[3];
  lVar1 = param_2 + param_1[2];
  lVar5 = FUN_180008b88(lVar1,uVar2);
  uVar8 = lVar5 + 1;
  if (lVar5 == -1) {
    uVar8 = 0xffffffffffffffff;
  }
  if (uVar8 < 0x8000000000000000) {
    uVar6 = FUN_180008bb4(uVar8 * 2);
    param_1[2] = lVar1;
    param_1[3] = lVar5;
    if (uVar2 < 8) {
      FUN_180008714();
    }
    else {
      uVar3 = *param_1;
      FUN_180008714();
      FUN_180003f84(uVar3,uVar2 * 2 + 2);
    }
    *param_1 = uVar6;
    return param_1;
  }
                    // WARNING: Subroutine does not return
  FUN_18001642c();
}



// WARNING: Could not reconcile some variable overlaps

void FUN_180008854(longlong param_1,undefined8 ****param_2,char *param_3,char *param_4)

{
  code *pcVar1;
  int iVar2;
  undefined8 ****ppppuVar3;
  undefined auStackY232 [32];
  char *local_a8;
  undefined8 ****local_a0 [2];
  undefined8 ****local_90 [2];
  ulonglong local_80;
  ulonglong local_78;
  undefined8 local_70;
  undefined4 uStack104;
  undefined4 uStack100;
  undefined8 local_60;
  undefined8 uStack88;
  ulonglong local_50;
  
  local_50 = DAT_180418010 ^ (ulonglong)auStackY232;
  local_80 = 0;
  local_78 = 7;
  local_90[0] = (undefined8 ****)0x0;
  local_60 = 0;
  uStack88 = 7;
  local_70 = 0;
  if (*(char *)(param_1 + 0x68) == '\0') {
    *(undefined8 *)(param_1 + 0x60) = 0;
  }
  local_a8 = param_3;
  local_a0[0] = param_2;
  FUN_18000876c(0,local_90,8);
  *(undefined8 *)(param_1 + 0x70) = 0;
  do {
    if (local_a8 == param_4) {
      *(undefined4 *)param_2 = (undefined4)local_70;
      *(undefined4 *)((longlong)param_2 + 4) = local_70._4_4_;
      *(undefined4 *)(param_2 + 1) = uStack104;
      *(undefined4 *)((longlong)param_2 + 0xc) = uStack100;
      *(undefined4 *)(param_2 + 2) = (undefined4)local_60;
      *(undefined4 *)((longlong)param_2 + 0x14) = local_60._4_4_;
      *(undefined4 *)(param_2 + 3) = (undefined4)uStack88;
      *(undefined4 *)((longlong)param_2 + 0x1c) = uStack88._4_4_;
      local_60 = 0;
      uStack88 = 7;
      local_70 = local_70 & 0xffffffffffff0000;
LAB_180008989:
      FUN_180008a34(&local_70);
      FUN_180008a34(local_90);
      FUN_18000e8c0(local_50 ^ (ulonglong)auStackY232);
      return;
    }
    ppppuVar3 = local_90;
    if (7 < local_78) {
      ppppuVar3 = local_90[0];
    }
    iVar2 = std::codecvt<wchar_t,char,struct__Mbstatet>::in
                      (*(codecvt_wchar_t_char_struct__Mbstatet_ **)(param_1 + 8),
                       (_Mbstatet *)(param_1 + 0x60),local_a8,param_4,&local_a8,(wchar_t *)ppppuVar3
                       ,(wchar_t *)((longlong)ppppuVar3 + local_80 * 2),(wchar_t **)local_a0);
    if ((iVar2 == 0) || (iVar2 == 1)) {
      if (ppppuVar3 < local_a0[0]) {
        FUN_1800089c0(&local_70,ppppuVar3,(longlong)local_a0[0] - (longlong)ppppuVar3 >> 1);
      }
      else {
        if (0xf < local_80) {
          if (*(char *)(param_1 + 0x6a) == '\0') {
            FUN_1800194d8();
            pcVar1 = (code *)swi(3);
            (*pcVar1)();
            return;
          }
          goto LAB_180011cbc;
        }
        FUN_18000876c(local_90,8);
      }
    }
    else {
      if (iVar2 != 3) {
        if (*(char *)(param_1 + 0x6a) == '\0') {
          FUN_1800194d8();
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
LAB_180011cbc:
        FUN_180001a98(param_2,param_1 + 0x40);
        goto LAB_180008989;
      }
      for (; local_a8 != param_4; local_a8 = local_a8 + 1) {
        FUN_180001334(&local_70,*local_a8);
      }
    }
    *(longlong *)(param_1 + 0x70) = (longlong)local_a8 - (longlong)param_3;
  } while( true );
}



undefined8 * FUN_1800089c0(undefined8 *param_1,void *param_2,ulonglong param_3)

{
  longlong lVar1;
  undefined8 *puVar2;
  
  lVar1 = param_1[2];
  if ((ulonglong)(param_1[3] - lVar1) < param_3) {
    param_1 = (undefined8 *)FUN_180008a70(param_1,param_3,param_3,param_2,param_3);
  }
  else {
    param_1[2] = lVar1 + param_3;
    puVar2 = param_1;
    if (7 < (ulonglong)param_1[3]) {
      puVar2 = (undefined8 *)*param_1;
    }
    memmove((void *)((longlong)puVar2 + lVar1 * 2),param_2,param_3 * 2);
    *(undefined2 *)((longlong)puVar2 + (lVar1 + param_3) * 2) = 0;
  }
  return param_1;
}



void FUN_180008a34(undefined8 *param_1)

{
  if (7 < (ulonglong)param_1[3]) {
    FUN_180003f84(*param_1,param_1[3] * 2 + 2);
  }
  param_1[2] = 0;
  *(undefined2 *)param_1 = 0;
  param_1[3] = 7;
  return;
}



void ** FUN_180008a70(void **param_1,ulonglong param_2,undefined8 param_3,void *param_4,
                     longlong param_5)

{
  void *pvVar1;
  void *pvVar2;
  code *pcVar3;
  size_t _Size;
  void *pvVar4;
  void *_Dst;
  void **ppvVar5;
  ulonglong uVar6;
  
  pvVar1 = param_1[2];
  if (0x7ffffffffffffffeU - (longlong)pvVar1 < param_2) {
    std::_Xlength_error("string too long");
    pcVar3 = (code *)swi(3);
    ppvVar5 = (void **)(*pcVar3)();
    return ppvVar5;
  }
  pvVar2 = param_1[3];
  pvVar4 = (void *)FUN_180008b88((void *)(param_2 + (longlong)pvVar1),pvVar2);
  uVar6 = (longlong)pvVar4 + 1;
  if (pvVar4 == (void *)0xffffffffffffffff) {
    uVar6 = 0xffffffffffffffff;
  }
  if (uVar6 < 0x8000000000000000) {
    _Dst = (void *)FUN_180008bb4(uVar6 * 2);
    param_1[2] = (void *)(param_2 + (longlong)pvVar1);
    _Size = (longlong)pvVar1 * 2;
    param_1[3] = pvVar4;
    if (pvVar2 < (void *)0x8) {
      memcpy(_Dst,param_1,_Size);
      memcpy((void *)((longlong)_Dst + _Size),param_4,param_5 * 2);
      *(undefined2 *)((longlong)_Dst + (param_5 + (longlong)pvVar1) * 2) = 0;
    }
    else {
      pvVar4 = *param_1;
      memcpy(_Dst,pvVar4,_Size);
      memcpy((void *)((longlong)_Dst + _Size),param_4,param_5 * 2);
      *(undefined2 *)((longlong)_Dst + (param_5 + (longlong)pvVar1) * 2) = 0;
      FUN_180003f84(pvVar4,(longlong)pvVar2 * 2 + 2);
    }
    *param_1 = _Dst;
    return param_1;
  }
                    // WARNING: Subroutine does not return
  FUN_18001642c();
}



ulonglong FUN_180008b88(ulonglong param_1,ulonglong param_2,ulonglong param_3)

{
  param_1 = param_1 | 7;
  if ((param_1 <= param_3) && (param_2 <= param_3 - (param_2 >> 1))) {
    param_2 = (param_2 >> 1) + param_2;
    if (param_2 <= param_1) {
      param_2 = param_1;
    }
    return param_2;
  }
  return param_3;
}



void * FUN_180008bb4(ulonglong param_1)

{
  void *pvVar1;
  void *pvVar2;
  
  if (param_1 < 0x1000) {
    if (param_1 != 0) {
      pvVar1 = operator_new(param_1);
      return pvVar1;
    }
    return (void *)0x0;
  }
  if (param_1 + 0x27 <= param_1) {
                    // WARNING: Subroutine does not return
    FUN_18001642c();
  }
  pvVar1 = operator_new(param_1 + 0x27);
  if (pvVar1 != (void *)0x0) {
    pvVar2 = (void *)((longlong)pvVar1 + 0x27U & 0xffffffffffffffe0);
    *(void **)((longlong)pvVar2 - 8) = pvVar1;
    return pvVar2;
  }
                    // WARNING: Subroutine does not return
  _invalid_parameter_noinfo_noreturn();
}



longlong * FUN_180008c10(undefined8 param_1,ulonglong param_2,longlong param_3,longlong *param_4)

{
  longlong **pplVar1;
  longlong lVar2;
  longlong lVar3;
  
  pplVar1 = *(longlong ***)(param_3 + 8);
  DAT_18041ebd0 = DAT_18041ebd0 + 1;
  *param_4 = param_3;
  param_4[1] = (longlong)pplVar1;
  *pplVar1 = param_4;
  *(longlong **)(param_3 + 8) = param_4;
  lVar3 = DAT_18041ebd8;
  param_2 = DAT_18041ebf0 & param_2;
  lVar2 = *(longlong *)(DAT_18041ebd8 + param_2 * 0x10);
  if (lVar2 == DAT_18041ebc8) {
    *(longlong **)(DAT_18041ebd8 + param_2 * 0x10) = param_4;
  }
  else {
    if (lVar2 == param_3) {
      *(longlong **)(DAT_18041ebd8 + param_2 * 0x10) = param_4;
      return param_4;
    }
    if (*(longlong ***)(DAT_18041ebd8 + 8 + param_2 * 0x10) != pplVar1) {
      return param_4;
    }
  }
  *(longlong **)(lVar3 + 8 + param_2 * 0x10) = param_4;
  return param_4;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_180008c70(longlong param_1,longlong *param_2)

{
  longlong lVar1;
  longlong *plVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined auStack424 [32];
  int local_188;
  undefined4 local_184;
  int local_180;
  int local_17c;
  int local_178;
  int local_170;
  int local_16c;
  int local_168;
  int local_164;
  undefined4 local_160;
  undefined4 local_15c;
  int local_158;
  int local_154;
  int local_150;
  undefined8 local_148;
  undefined8 uStack320;
  undefined4 local_138;
  undefined4 uStack308;
  undefined4 uStack304;
  undefined4 uStack300;
  undefined8 local_128;
  undefined8 uStack288;
  undefined4 local_118;
  int iStack276;
  int iStack272;
  undefined4 uStack268;
  undefined local_108 [16];
  longlong local_f8;
  int local_f0;
  int local_e8;
  undefined local_d0 [16];
  longlong local_c0;
  int local_b8;
  int local_b0;
  longlong *local_98 [2];
  undefined4 local_88;
  undefined4 uStack132;
  undefined4 uStack128;
  undefined4 uStack124;
  undefined4 local_78;
  undefined4 uStack116;
  undefined4 uStack112;
  undefined4 uStack108;
  undefined4 local_68;
  undefined4 uStack100;
  undefined4 uStack96;
  undefined4 uStack92;
  undefined4 local_58;
  int iStack84;
  int iStack80;
  undefined4 uStack76;
  ulonglong local_48;
  
  local_48 = DAT_180418010 ^ (ulonglong)auStack424;
  lVar1 = *(longlong *)(param_1 + 0x28);
  if (*(int *)(lVar1 + 0x1c) != 0x40) {
    uStack288 = *(longlong **)(lVar1 + 8);
    local_128 = 0;
    iStack272 = 0x40;
    local_118 = 0xffffffff;
    iStack276 = *(int *)(lVar1 + 0x1c);
    (**(code **)(*param_2 + 0xd0))(param_2,1,&local_128);
    local_170 = *(int *)(lVar1 + 0x1c);
    *(undefined4 *)(lVar1 + 0x1c) = 0x40;
  }
  lVar1 = *(longlong *)(param_1 + 0x30);
  local_188 = local_170;
  if (*(int *)(lVar1 + 0x1c) != 0x40) {
    uStack288 = *(longlong **)(lVar1 + 8);
    local_128 = 0;
    iStack272 = 0x40;
    local_118 = 0xffffffff;
    iStack276 = *(int *)(lVar1 + 0x1c);
    (**(code **)(*param_2 + 0xd0))(param_2,1,&local_128);
    local_16c = *(int *)(lVar1 + 0x1c);
    *(undefined4 *)(lVar1 + 0x1c) = 0x40;
  }
  iVar5 = local_16c;
  lVar1 = *(longlong *)(param_1 + 0x40);
  if (*(int *)(lVar1 + 0x1c) != 0x40) {
    uStack288 = *(longlong **)(lVar1 + 8);
    local_128 = 0;
    iStack272 = 0x40;
    local_118 = 0xffffffff;
    iStack276 = *(int *)(lVar1 + 0x1c);
    (**(code **)(*param_2 + 0xd0))(param_2,1,&local_128);
    local_168 = *(int *)(lVar1 + 0x1c);
    *(undefined4 *)(lVar1 + 0x1c) = 0x40;
  }
  iVar6 = local_168;
  lVar1 = *(longlong *)(param_1 + 0x48);
  if ((lVar1 != 0) && (*(int *)(lVar1 + 0x1c) != 0x40)) {
    uStack288 = *(longlong **)(lVar1 + 8);
    local_128 = 0;
    iStack272 = 0x40;
    local_118 = 0xffffffff;
    iStack276 = *(int *)(lVar1 + 0x1c);
    (**(code **)(*param_2 + 0xd0))(param_2,1,&local_128);
    local_164 = *(int *)(lVar1 + 0x1c);
    *(undefined4 *)(lVar1 + 0x1c) = 0x40;
  }
  if (*(longlong *)(param_1 + 0x50) != 0) {
    FUN_180018b10(*(longlong *)(param_1 + 0x50),param_2,0x40,&local_160);
    local_188 = local_170;
    iVar5 = local_16c;
    iVar6 = local_168;
  }
  if (*(longlong *)(param_1 + 0x58) != 0) {
    FUN_180018b10(*(longlong *)(param_1 + 0x58),param_2,0x40,&local_15c);
    local_188 = local_170;
    iVar5 = local_16c;
    iVar6 = local_168;
  }
  iVar4 = local_164;
  lVar1 = *(longlong *)(param_1 + 0x60);
  if (*(int *)(lVar1 + 0x1c) != 8) {
    uStack288 = *(longlong **)(lVar1 + 8);
    local_128 = 0;
    iStack272 = 8;
    local_118 = 0xffffffff;
    iStack276 = *(int *)(lVar1 + 0x1c);
    (**(code **)(*param_2 + 0xd0))(param_2,1,&local_128);
    local_158 = *(int *)(lVar1 + 0x1c);
    *(undefined4 *)(lVar1 + 0x1c) = 8;
  }
  lVar1 = *(longlong *)(param_1 + 0x68);
  local_17c = local_158;
  if (*(int *)(lVar1 + 0x1c) != 8) {
    uStack288 = *(longlong **)(lVar1 + 8);
    local_128 = 0;
    iStack272 = 8;
    local_118 = 0xffffffff;
    iStack276 = *(int *)(lVar1 + 0x1c);
    (**(code **)(*param_2 + 0xd0))(param_2,1,&local_128);
    local_154 = *(int *)(lVar1 + 0x1c);
    *(undefined4 *)(lVar1 + 0x1c) = 8;
  }
  lVar1 = *(longlong *)(param_1 + 0x78);
  local_178 = local_154;
  if (*(int *)(lVar1 + 0x1c) != 8) {
    uStack288 = *(longlong **)(lVar1 + 8);
    local_128 = 0;
    iStack272 = 8;
    local_118 = 0xffffffff;
    iStack276 = *(int *)(lVar1 + 0x1c);
    (**(code **)(*param_2 + 0xd0))(param_2,1,&local_128);
    local_150 = *(int *)(lVar1 + 0x1c);
    *(undefined4 *)(lVar1 + 0x1c) = 8;
  }
  plVar2 = *(longlong **)(param_1 + 0x80);
  (**(code **)(*plVar2 + 8))(plVar2);
  local_98[0] = *(longlong **)(plVar2[10] + 0x60);
  (**(code **)(*param_2 + 0xe0))(param_2,1,local_98);
  (**(code **)(*param_2 + 0xe8))(param_2,plVar2[2]);
  (**(code **)(*param_2 + 0xf8))(param_2,0,plVar2[6]);
  (**(code **)(*param_2 + 200))(param_2);
  (**(code **)(*param_2 + 0x70))
            (param_2,*(undefined4 *)(plVar2 + 3),*(undefined4 *)((longlong)plVar2 + 0x1c),1);
  local_180 = *(int *)(*(longlong *)(param_1 + 0x70) + 0x1c);
  plVar2 = *(longlong **)(*(longlong *)(param_1 + 0x70) + 8);
  local_184 = *(undefined4 *)(*(longlong *)(param_1 + 0x30) + 0x1c);
  local_98[0] = *(longlong **)(*(longlong *)(param_1 + 0x30) + 8);
  (**(code **)(*local_98[0] + 0x50))(local_98[0],local_d0);
  (**(code **)(*plVar2 + 0x50))(plVar2,local_108);
  if ((local_b8 == local_f0) && (local_c0 == local_f8)) {
    if (local_b0 != local_e8) {
      FUN_180018a88(&local_148,"Wrong format");
                    // WARNING: Subroutine does not return
      _CxxThrowException(&local_148,(ThrowInfo *)&DAT_1804162c8);
    }
    uStack320 = local_98[0];
    uStack308 = local_184;
    local_148 = 0;
    uStack320._0_4_ = SUB84(local_98[0],0);
    uStack320._4_4_ = (undefined4)((ulonglong)local_98[0] >> 0x20);
    local_128 = 0;
    iStack276 = local_180;
    local_88 = 0;
    uStack132 = 0;
    uStack128 = (undefined4)uStack320;
    uStack124 = uStack320._4_4_;
    local_138 = 0xffffffff;
    uStack304 = 0x800;
    uStack288._0_4_ = SUB84(plVar2,0);
    uStack288._4_4_ = (undefined4)((ulonglong)plVar2 >> 0x20);
    local_118 = 0xffffffff;
    local_78 = 0xffffffff;
    uStack116 = local_184;
    uStack112 = 0x800;
    uStack108 = uStack300;
    iStack272 = 0x400;
    local_68 = 0;
    uStack100 = 0;
    uStack96 = (undefined4)uStack288;
    uStack92 = uStack288._4_4_;
    local_58 = 0xffffffff;
    iStack84 = local_180;
    iStack80 = 0x400;
    uStack76 = uStack268;
    uStack288 = plVar2;
    (**(code **)(*param_2 + 0xd0))(param_2,2,&local_88);
    (**(code **)(*param_2 + 0x88))(param_2,plVar2,local_98[0]);
    uStack112 = local_184;
    iStack80 = local_180;
    uStack116 = 0x800;
    iStack84 = 0x400;
    (**(code **)(*param_2 + 0xd0))(param_2,2,&local_88);
    iVar3 = local_188;
    local_98[0] = *(longlong **)(param_1 + 0x28);
    if (*(int *)((longlong)local_98[0] + 0x1c) != local_188) {
      uStack288 = (longlong *)local_98[0][1];
      local_128 = 0;
      iStack272 = local_188;
      local_118 = 0xffffffff;
      iStack276 = *(int *)((longlong)local_98[0] + 0x1c);
      (**(code **)(*param_2 + 0xd0))(param_2,1,&local_128);
      *(int *)((longlong)local_98[0] + 0x1c) = iVar3;
    }
    lVar1 = *(longlong *)(param_1 + 0x30);
    if (*(int *)(lVar1 + 0x1c) != iVar5) {
      uStack288 = *(longlong **)(lVar1 + 8);
      local_128 = 0;
      local_118 = 0xffffffff;
      iStack276 = *(int *)(lVar1 + 0x1c);
      iStack272 = iVar5;
      (**(code **)(*param_2 + 0xd0))(param_2,1,&local_128);
      *(int *)(lVar1 + 0x1c) = iVar5;
    }
    lVar1 = *(longlong *)(param_1 + 0x40);
    if (*(int *)(lVar1 + 0x1c) != iVar6) {
      uStack288 = *(longlong **)(lVar1 + 8);
      local_128 = 0;
      local_118 = 0xffffffff;
      iStack276 = *(int *)(lVar1 + 0x1c);
      iStack272 = iVar6;
      (**(code **)(*param_2 + 0xd0))(param_2,1,&local_128);
      *(int *)(lVar1 + 0x1c) = iVar6;
    }
    lVar1 = *(longlong *)(param_1 + 0x48);
    if ((lVar1 != 0) && (*(int *)(lVar1 + 0x1c) != iVar4)) {
      uStack288 = *(longlong **)(lVar1 + 8);
      local_128 = 0;
      local_118 = 0xffffffff;
      iStack276 = *(int *)(lVar1 + 0x1c);
      iStack272 = iVar4;
      (**(code **)(*param_2 + 0xd0))(param_2,1,&local_128);
      *(int *)(lVar1 + 0x1c) = iVar4;
    }
    if (*(longlong *)(param_1 + 0x50) != 0) {
      FUN_180018b10(*(longlong *)(param_1 + 0x50),param_2,local_160,0);
    }
    if (*(longlong *)(param_1 + 0x58) != 0) {
      FUN_180018b10(*(longlong *)(param_1 + 0x58),param_2,local_15c,0);
    }
    iVar5 = local_17c;
    lVar1 = *(longlong *)(param_1 + 0x60);
    if (*(int *)(lVar1 + 0x1c) != local_17c) {
      uStack288 = *(longlong **)(lVar1 + 8);
      local_128 = 0;
      iStack272 = local_17c;
      local_118 = 0xffffffff;
      iStack276 = *(int *)(lVar1 + 0x1c);
      (**(code **)(*param_2 + 0xd0))(param_2,1,&local_128);
      *(int *)(lVar1 + 0x1c) = iVar5;
    }
    iVar5 = local_178;
    lVar1 = *(longlong *)(param_1 + 0x68);
    if (*(int *)(lVar1 + 0x1c) != local_178) {
      uStack288 = *(longlong **)(lVar1 + 8);
      local_128 = 0;
      iStack272 = local_178;
      local_118 = 0xffffffff;
      iStack276 = *(int *)(lVar1 + 0x1c);
      (**(code **)(*param_2 + 0xd0))(param_2,1,&local_128);
      *(int *)(lVar1 + 0x1c) = iVar5;
    }
    lVar1 = *(longlong *)(param_1 + 0x78);
    if (*(int *)(lVar1 + 0x1c) != local_150) {
      uStack288 = *(longlong **)(lVar1 + 8);
      local_128 = 0;
      local_118 = 0xffffffff;
      iStack276 = *(int *)(lVar1 + 0x1c);
      iStack272 = local_150;
      (**(code **)(*param_2 + 0xd0))(param_2,1,&local_128);
      *(int *)(lVar1 + 0x1c) = local_150;
    }
    FUN_18000e8c0(local_48 ^ (ulonglong)auStack424);
    return;
  }
  FUN_180018a88(&local_148,"Wrong size");
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_148,(ThrowInfo *)&DAT_1804162c8);
}



void FUN_1800092f0(ulonglong param_1,undefined8 param_2)

{
  code *pcVar1;
  int iVar2;
  longlong lVar3;
  undefined8 *puVar4;
  ulonglong uVar5;
  float fVar6;
  float fVar7;
  undefined auStack136 [32];
  ulonglong local_68;
  undefined8 *local_58;
  void *pvStack80;
  ulonglong local_40;
  
  local_40 = DAT_180418010 ^ (ulonglong)auStack136;
  local_58 = (undefined8 *)(param_1 >> 0x10);
  local_68 = param_1 >> 8;
  iVar2 = _Mtx_lock(&DAT_18041ec00);
  if (iVar2 != 0) {
    std::_Throw_C_error(iVar2);
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  uVar5 = ((((((((param_1 & 0xff ^ 0xcbf29ce484222325) * 0x100000001b3 ^ local_68 & 0xff) *
                0x100000001b3 ^ (ulonglong)local_58 & 0xff) * 0x100000001b3 ^ param_1 >> 0x18 & 0xff
              ) * 0x100000001b3 ^ param_1 >> 0x20 & 0xff) * 0x100000001b3 ^ param_1 >> 0x28 & 0xff)
            * 0x100000001b3 ^ param_1 >> 0x30 & 0xff) * 0x100000001b3 ^ param_1 >> 0x38) *
          0x100000001b3 & DAT_18041ebf0;
  lVar3 = *(longlong *)(DAT_18041ebd8 + 8 + uVar5 * 0x10);
  if (lVar3 == DAT_18041ebc8) {
LAB_180009451:
    if (DAT_18041ebd0 == 0x7ffffffffffffff) {
      std::_Xlength_error("unordered_map/set too long");
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    local_58 = &DAT_18041ebc8;
    pvStack80 = (void *)0x0;
    pvStack80 = operator_new(0x20);
    *(ulonglong *)((longlong)pvStack80 + 0x10) = param_1;
    *(undefined8 *)((longlong)pvStack80 + 0x18) = 0;
    uVar5 = DAT_18041ebd0 + 1;
    if ((longlong)uVar5 < 0) {
      fVar7 = (float)(uVar5 >> 1 | (ulonglong)((uint)uVar5 & 1));
      fVar7 = fVar7 + fVar7;
    }
    else {
      fVar7 = (float)uVar5;
    }
    if ((longlong)DAT_18041ebf8 < 0) {
      fVar6 = (float)(DAT_18041ebf8 >> 1 | (ulonglong)((uint)DAT_18041ebf8 & 1));
      fVar6 = fVar6 + fVar6;
    }
    else {
      fVar6 = (float)DAT_18041ebf8;
    }
    if (DAT_18041ebc0 < fVar7 / fVar6) {
      FUN_1800021cc();
      FUN_180002350();
      puVar4 = (undefined8 *)FUN_18000e4c4();
      local_58 = (undefined8 *)*puVar4;
      pvStack80 = (void *)puVar4[1];
    }
    lVar3 = FUN_180008c10();
  }
  else {
    for (; param_1 != *(ulonglong *)(lVar3 + 0x10); lVar3 = *(longlong *)(lVar3 + 8)) {
      if (lVar3 == *(longlong *)(DAT_18041ebd8 + uVar5 * 0x10)) goto LAB_180009451;
    }
  }
  *(undefined8 *)(lVar3 + 0x18) = param_2;
  _Mtx_unlock(&DAT_18041ec00);
  (*DAT_18041eba8)(param_1,param_2);
  FUN_18000e8c0(local_40 ^ (ulonglong)auStack136);
  return;
}



void FUN_180009544(longlong *param_1,int param_2,int param_3)

{
  if ((param_2 != *(int *)(param_1 + 0xe)) || (param_3 != *(int *)((longlong)param_1 + 0x74))) {
    (**(code **)(*param_1 + 0x10))();
    *(int *)(param_1 + 0xe) = param_2;
    *(int *)((longlong)param_1 + 0x74) = param_3;
    (**(code **)(*param_1 + 8))(param_1);
  }
  return;
}



void FUN_180009590(longlong param_1)

{
                    // WARNING: Could not recover jumptable at 0x00018000959a. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)(param_1 + 0xb8) + 0x20))();
  return;
}



void FUN_1800095a0(longlong *param_1)

{
                    // WARNING: Could not recover jumptable at 0x0001800095a3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x38))();
  return;
}



undefined4 FUN_1800095c0(longlong param_1)

{
  return *(undefined4 *)(*(longlong *)(param_1 + 8) + 0x20);
}



// WARNING: Function: __chkstk replaced with injection: alloca_probe
// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void NVSDK_NGX_D3D12_EvaluateFeature(longlong *param_1,int *param_2,longlong *param_3)

{
  longlong *plVar1;
  undefined8 *puVar2;
  code *pcVar3;
  double dVar4;
  char cVar5;
  int iVar6;
  longlong lVar7;
  int *piVar8;
  longlong *plVar9;
  ulonglong *puVar10;
  void *pvVar11;
  longlong **pplVar12;
  undefined8 uVar13;
  ULONGLONG UVar14;
  ulonglong uVar15;
  ulonglong uVar16;
  ulonglong uVar17;
  ulonglong uVar18;
  longlong lVar19;
  longlong *plVar20;
  ulonglong uVar21;
  longlong in_GS_OFFSET;
  undefined4 uVar22;
  undefined4 uVar23;
  float fVar24;
  undefined4 uVar25;
  float fVar26;
  undefined4 in_XMM6_Dc;
  undefined4 in_XMM6_Dd;
  undefined auStack6944 [32];
  longlong **local_1b00;
  longlong *local_1af0;
  longlong *local_1ae8;
  ulonglong local_1ae0;
  longlong local_1ad8;
  longlong *local_1ad0;
  void *local_1ac8;
  longlong *local_1ac0;
  longlong **local_1ab8;
  void *local_1ab0;
  void *local_1aa8 [2];
  undefined8 local_1a98;
  undefined8 local_1a90;
  undefined8 local_1a88;
  undefined8 local_1a80;
  void *local_1a78;
  undefined8 local_1a70;
  void *local_1a68;
  void *local_1a60;
  void *local_1a58;
  undefined8 local_1a50;
  undefined4 uStack6728;
  undefined4 uStack6724;
  undefined4 local_1a40;
  undefined4 uStack6716;
  undefined4 uStack6712;
  undefined4 uStack6708;
  undefined4 local_1a30;
  undefined4 uStack6700;
  undefined4 uStack6696;
  undefined4 uStack6692;
  undefined4 local_1a20;
  undefined4 uStack6684;
  undefined4 uStack6680;
  undefined4 uStack6676;
  undefined4 local_1a10;
  undefined4 uStack6668;
  undefined4 uStack6664;
  undefined4 uStack6660;
  undefined4 local_1a00;
  undefined4 uStack6652;
  undefined4 uStack6648;
  undefined4 uStack6644;
  undefined4 local_19f0;
  undefined4 uStack6636;
  undefined4 uStack6632;
  undefined4 uStack6628;
  undefined4 local_19e0;
  undefined4 uStack6620;
  undefined4 uStack6616;
  undefined4 uStack6612;
  undefined4 local_19d0;
  undefined4 uStack6604;
  undefined4 uStack6600;
  undefined4 uStack6596;
  undefined4 local_19c0;
  undefined4 uStack6588;
  uint uStack6584;
  uint uStack6580;
  undefined4 local_19b0;
  undefined4 uStack6572;
  undefined8 uStack6568;
  undefined8 local_19a0;
  undefined8 local_1998;
  undefined4 uStack6544;
  undefined4 uStack6540;
  undefined4 local_1988;
  undefined4 uStack6532;
  undefined4 uStack6528;
  undefined4 uStack6524;
  undefined4 local_1978;
  undefined4 uStack6516;
  undefined4 uStack6512;
  undefined4 uStack6508;
  undefined4 local_1968;
  undefined4 uStack6500;
  undefined4 uStack6496;
  undefined4 uStack6492;
  undefined4 local_1958;
  undefined4 uStack6484;
  undefined4 uStack6480;
  undefined4 uStack6476;
  undefined4 local_1948;
  undefined4 uStack6468;
  undefined4 uStack6464;
  undefined4 uStack6460;
  undefined4 local_1938;
  undefined4 uStack6452;
  undefined4 uStack6448;
  undefined4 uStack6444;
  undefined4 local_1928;
  undefined4 uStack6436;
  undefined4 uStack6432;
  undefined4 uStack6428;
  undefined4 local_1918;
  undefined4 uStack6420;
  undefined4 uStack6416;
  undefined4 uStack6412;
  undefined4 local_1908;
  undefined4 uStack6404;
  uint uStack6400;
  uint uStack6396;
  undefined4 local_18f8;
  undefined4 uStack6388;
  undefined8 uStack6384;
  undefined8 local_18e8;
  undefined8 local_18e0;
  undefined4 uStack6360;
  undefined4 uStack6356;
  undefined4 local_18d0;
  undefined4 uStack6348;
  undefined4 uStack6344;
  undefined4 uStack6340;
  undefined4 local_18c0;
  undefined4 uStack6332;
  undefined4 uStack6328;
  undefined4 uStack6324;
  undefined4 local_18b0;
  undefined4 uStack6316;
  undefined4 uStack6312;
  undefined4 uStack6308;
  undefined4 local_18a0;
  undefined4 uStack6300;
  undefined4 uStack6296;
  undefined4 uStack6292;
  undefined4 local_1890;
  undefined4 uStack6284;
  undefined4 uStack6280;
  undefined4 uStack6276;
  undefined4 local_1880;
  undefined4 uStack6268;
  undefined4 uStack6264;
  undefined4 uStack6260;
  undefined4 local_1870;
  undefined4 uStack6252;
  undefined4 uStack6248;
  undefined4 uStack6244;
  undefined4 local_1860;
  undefined4 uStack6236;
  undefined4 uStack6232;
  undefined4 uStack6228;
  undefined4 local_1850;
  undefined4 uStack6220;
  uint uStack6216;
  uint uStack6212;
  undefined4 local_1840;
  undefined4 uStack6204;
  undefined8 uStack6200;
  undefined8 local_1830;
  undefined8 local_1828;
  undefined4 uStack6176;
  undefined4 uStack6172;
  undefined4 local_1818;
  undefined4 uStack6164;
  undefined4 uStack6160;
  undefined4 uStack6156;
  undefined4 local_1808;
  undefined4 uStack6148;
  undefined4 uStack6144;
  undefined4 uStack6140;
  undefined4 local_17f8;
  undefined4 uStack6132;
  undefined4 uStack6128;
  undefined4 uStack6124;
  undefined4 local_17e8;
  undefined4 uStack6116;
  undefined4 uStack6112;
  undefined4 uStack6108;
  undefined4 local_17d8;
  undefined4 uStack6100;
  undefined4 uStack6096;
  undefined4 uStack6092;
  undefined4 local_17c8;
  undefined4 uStack6084;
  undefined4 uStack6080;
  undefined4 uStack6076;
  undefined4 local_17b8;
  undefined4 uStack6068;
  undefined4 uStack6064;
  undefined4 uStack6060;
  undefined4 local_17a8;
  undefined4 uStack6052;
  undefined4 uStack6048;
  undefined4 uStack6044;
  undefined4 local_1798;
  undefined4 uStack6036;
  uint uStack6032;
  uint uStack6028;
  undefined4 local_1788;
  undefined4 uStack6020;
  undefined8 uStack6016;
  undefined8 local_1778;
  undefined8 local_1770;
  undefined4 uStack5992;
  undefined4 uStack5988;
  undefined4 local_1760;
  undefined4 uStack5980;
  undefined4 uStack5976;
  undefined4 uStack5972;
  undefined4 local_1750;
  undefined4 uStack5964;
  undefined4 uStack5960;
  undefined4 uStack5956;
  undefined4 local_1740;
  undefined4 uStack5948;
  undefined4 uStack5944;
  undefined4 uStack5940;
  undefined4 local_1730;
  undefined4 uStack5932;
  undefined4 uStack5928;
  undefined4 uStack5924;
  undefined4 local_1720;
  undefined4 uStack5916;
  undefined4 uStack5912;
  undefined4 uStack5908;
  undefined4 local_1710;
  undefined4 uStack5900;
  undefined4 uStack5896;
  undefined4 uStack5892;
  undefined4 local_1700;
  undefined4 uStack5884;
  undefined4 uStack5880;
  undefined4 uStack5876;
  undefined4 local_16f0;
  undefined4 uStack5868;
  undefined4 uStack5864;
  undefined4 uStack5860;
  undefined4 local_16e0;
  undefined4 uStack5852;
  uint uStack5848;
  uint uStack5844;
  undefined4 local_16d0;
  undefined4 uStack5836;
  undefined8 uStack5832;
  undefined8 local_16c0;
  undefined8 local_16b8;
  undefined4 uStack5808;
  undefined4 uStack5804;
  undefined4 local_16a8;
  undefined4 uStack5796;
  undefined4 uStack5792;
  undefined4 uStack5788;
  undefined4 local_1698;
  undefined4 uStack5780;
  undefined4 uStack5776;
  undefined4 uStack5772;
  undefined4 local_1688;
  undefined4 uStack5764;
  undefined4 uStack5760;
  undefined4 uStack5756;
  undefined4 local_1678;
  undefined4 uStack5748;
  undefined4 uStack5744;
  undefined4 uStack5740;
  undefined4 local_1668;
  undefined4 uStack5732;
  undefined4 uStack5728;
  undefined4 uStack5724;
  undefined4 local_1658;
  undefined4 uStack5716;
  undefined4 uStack5712;
  undefined4 uStack5708;
  undefined4 local_1648;
  undefined4 uStack5700;
  undefined4 uStack5696;
  undefined4 uStack5692;
  undefined4 local_1638;
  undefined4 uStack5684;
  undefined4 uStack5680;
  undefined4 uStack5676;
  undefined4 local_1628;
  undefined4 uStack5668;
  uint uStack5664;
  uint uStack5660;
  undefined4 local_1618;
  undefined4 uStack5652;
  undefined8 uStack5648;
  undefined8 local_1608;
  undefined8 local_1600;
  undefined4 uStack5624;
  undefined4 uStack5620;
  undefined4 local_15f0;
  undefined4 uStack5612;
  undefined4 uStack5608;
  undefined4 uStack5604;
  undefined4 local_15e0;
  undefined4 uStack5596;
  undefined4 uStack5592;
  undefined4 uStack5588;
  undefined4 local_15d0;
  undefined4 uStack5580;
  undefined4 uStack5576;
  undefined4 uStack5572;
  undefined4 local_15c0;
  undefined4 uStack5564;
  undefined4 uStack5560;
  undefined4 uStack5556;
  undefined4 local_15b0;
  undefined4 uStack5548;
  undefined4 uStack5544;
  undefined4 uStack5540;
  undefined4 local_15a0;
  undefined4 uStack5532;
  undefined4 uStack5528;
  undefined4 uStack5524;
  undefined4 local_1590;
  undefined4 uStack5516;
  undefined4 uStack5512;
  undefined4 uStack5508;
  undefined4 local_1580;
  undefined4 uStack5500;
  undefined4 uStack5496;
  undefined4 uStack5492;
  undefined4 local_1570;
  undefined4 uStack5484;
  uint uStack5480;
  uint uStack5476;
  undefined4 local_1560;
  undefined4 uStack5468;
  undefined8 uStack5464;
  undefined8 local_1550;
  undefined local_1538 [24];
  undefined local_1520 [160];
  undefined8 local_1480;
  undefined local_1468 [160];
  undefined8 local_13c8;
  undefined8 local_13b8;
  longlong local_13b0;
  undefined8 local_13a8;
  longlong *local_13a0;
  wchar_t *local_1398;
  undefined8 local_1390;
  longlong *local_1388;
  wchar_t *local_1380;
  undefined8 local_1378;
  wchar_t *local_1370;
  ulonglong local_1368;
  undefined4 uStack4960;
  undefined4 uStack4956;
  longlong *local_1358;
  undefined4 uStack4944;
  undefined4 uStack4940;
  wchar_t *local_1348;
  longlong *local_1340;
  undefined8 local_1338;
  wchar_t *local_1330;
  longlong *local_1328;
  wchar_t *local_1320;
  undefined8 local_1318;
  longlong *local_1310;
  wchar_t *local_1308;
  undefined8 local_1300;
  longlong *local_12f8;
  longlong **local_12f0;
  undefined8 local_12e8;
  undefined local_12d8 [16];
  longlong *local_12c8;
  undefined4 local_12c0;
  undefined4 uStack4796;
  undefined4 uStack4792;
  undefined4 uStack4788;
  undefined4 local_12b0;
  undefined4 uStack4780;
  undefined4 uStack4776;
  undefined4 uStack4772;
  undefined4 local_12a0;
  undefined4 uStack4764;
  undefined4 uStack4760;
  undefined4 uStack4756;
  undefined4 local_1290;
  undefined4 uStack4748;
  undefined4 uStack4744;
  undefined4 uStack4740;
  undefined4 local_1280;
  undefined4 uStack4732;
  undefined4 uStack4728;
  undefined4 uStack4724;
  undefined4 local_1270;
  undefined4 uStack4716;
  undefined4 uStack4712;
  undefined4 uStack4708;
  undefined4 local_1260;
  undefined4 uStack4700;
  undefined4 uStack4696;
  undefined4 uStack4692;
  undefined4 local_1250;
  undefined4 uStack4684;
  undefined4 uStack4680;
  undefined4 uStack4676;
  undefined4 local_1240;
  undefined4 uStack4668;
  undefined4 uStack4664;
  undefined4 uStack4660;
  undefined4 local_1230;
  undefined4 uStack4652;
  uint uStack4648;
  uint uStack4644;
  undefined4 local_1220;
  undefined4 uStack4636;
  undefined4 uStack4632;
  undefined4 uStack4628;
  undefined8 local_1210;
  undefined4 local_1208;
  undefined4 uStack4612;
  undefined4 uStack4608;
  undefined4 uStack4604;
  undefined4 local_11f8;
  undefined4 uStack4596;
  undefined4 uStack4592;
  undefined4 uStack4588;
  undefined4 local_11e8;
  undefined4 uStack4580;
  undefined4 uStack4576;
  undefined4 uStack4572;
  undefined4 local_11d8;
  undefined4 uStack4564;
  undefined4 uStack4560;
  undefined4 uStack4556;
  undefined4 local_11c8;
  undefined4 uStack4548;
  undefined4 uStack4544;
  undefined4 uStack4540;
  undefined4 local_11b8;
  undefined4 uStack4532;
  undefined4 uStack4528;
  undefined4 uStack4524;
  undefined4 local_11a8;
  undefined4 uStack4516;
  undefined4 uStack4512;
  undefined4 uStack4508;
  undefined4 local_1198;
  undefined4 uStack4500;
  undefined4 uStack4496;
  undefined4 uStack4492;
  undefined4 local_1188;
  undefined4 uStack4484;
  undefined4 uStack4480;
  undefined4 uStack4476;
  undefined4 local_1178;
  undefined4 uStack4468;
  uint uStack4464;
  uint uStack4460;
  undefined4 local_1168;
  undefined4 uStack4452;
  undefined4 uStack4448;
  undefined4 uStack4444;
  undefined8 local_1158;
  undefined4 local_1150;
  undefined4 uStack4428;
  undefined4 uStack4424;
  undefined4 uStack4420;
  undefined4 local_1140;
  undefined4 uStack4412;
  undefined4 uStack4408;
  undefined4 uStack4404;
  undefined4 local_1130;
  undefined4 uStack4396;
  undefined4 uStack4392;
  undefined4 uStack4388;
  undefined4 local_1120;
  undefined4 uStack4380;
  undefined4 uStack4376;
  undefined4 uStack4372;
  undefined4 local_1110;
  undefined4 uStack4364;
  undefined4 uStack4360;
  undefined4 uStack4356;
  undefined4 local_1100;
  undefined4 uStack4348;
  undefined4 uStack4344;
  undefined4 uStack4340;
  undefined4 local_10f0;
  undefined4 uStack4332;
  undefined4 uStack4328;
  undefined4 uStack4324;
  undefined4 local_10e0;
  undefined4 uStack4316;
  undefined4 uStack4312;
  undefined4 uStack4308;
  undefined4 local_10d0;
  undefined4 uStack4300;
  undefined4 uStack4296;
  undefined4 uStack4292;
  undefined4 local_10c0;
  undefined4 uStack4284;
  uint uStack4280;
  uint uStack4276;
  undefined4 local_10b0;
  undefined4 uStack4268;
  undefined4 uStack4264;
  undefined4 uStack4260;
  undefined8 local_10a0;
  undefined4 local_1098;
  undefined4 uStack4244;
  undefined4 uStack4240;
  undefined4 uStack4236;
  undefined4 local_1088;
  undefined4 uStack4228;
  undefined4 uStack4224;
  undefined4 uStack4220;
  undefined4 local_1078;
  undefined4 uStack4212;
  undefined4 uStack4208;
  undefined4 uStack4204;
  undefined4 local_1068;
  undefined4 uStack4196;
  undefined4 uStack4192;
  undefined4 uStack4188;
  undefined4 local_1058;
  undefined4 uStack4180;
  undefined4 uStack4176;
  undefined4 uStack4172;
  undefined4 local_1048;
  undefined4 uStack4164;
  undefined4 uStack4160;
  undefined4 uStack4156;
  undefined4 local_1038;
  undefined4 uStack4148;
  undefined4 uStack4144;
  undefined4 uStack4140;
  undefined4 local_1028;
  undefined4 uStack4132;
  undefined4 uStack4128;
  undefined4 uStack4124;
  undefined4 local_1018;
  undefined4 uStack4116;
  undefined4 uStack4112;
  undefined4 uStack4108;
  undefined4 local_1008;
  undefined4 uStack4100;
  uint uStack4096;
  uint uStack4092;
  undefined4 local_ff8;
  undefined4 uStack4084;
  undefined4 uStack4080;
  undefined4 uStack4076;
  undefined8 local_fe8;
  undefined4 local_fe0;
  undefined4 uStack4060;
  undefined4 uStack4056;
  undefined4 uStack4052;
  undefined4 local_fd0;
  undefined4 uStack4044;
  undefined4 uStack4040;
  undefined4 uStack4036;
  undefined4 local_fc0;
  undefined4 uStack4028;
  undefined4 uStack4024;
  undefined4 uStack4020;
  undefined4 local_fb0;
  undefined4 uStack4012;
  undefined4 uStack4008;
  undefined4 uStack4004;
  undefined4 local_fa0;
  undefined4 uStack3996;
  undefined4 uStack3992;
  undefined4 uStack3988;
  undefined4 local_f90;
  undefined4 uStack3980;
  undefined4 uStack3976;
  undefined4 uStack3972;
  undefined4 local_f80;
  undefined4 uStack3964;
  undefined4 uStack3960;
  undefined4 uStack3956;
  undefined4 local_f70;
  undefined4 uStack3948;
  undefined4 uStack3944;
  undefined4 uStack3940;
  undefined4 local_f60;
  undefined4 uStack3932;
  undefined4 uStack3928;
  undefined4 uStack3924;
  undefined4 local_f50;
  undefined4 uStack3916;
  uint uStack3912;
  uint uStack3908;
  undefined4 local_f40;
  undefined4 uStack3900;
  undefined4 uStack3896;
  undefined4 uStack3892;
  undefined8 local_f30;
  undefined4 local_f28;
  undefined4 uStack3876;
  undefined4 uStack3872;
  undefined4 uStack3868;
  undefined4 local_f18;
  undefined4 uStack3860;
  undefined4 uStack3856;
  undefined4 uStack3852;
  undefined4 local_f08;
  undefined4 uStack3844;
  undefined4 uStack3840;
  undefined4 uStack3836;
  undefined4 local_ef8;
  undefined4 uStack3828;
  undefined4 uStack3824;
  undefined4 uStack3820;
  undefined4 local_ee8;
  undefined4 uStack3812;
  undefined4 uStack3808;
  undefined4 uStack3804;
  undefined4 local_ed8;
  undefined4 uStack3796;
  undefined4 uStack3792;
  undefined4 uStack3788;
  undefined4 local_ec8;
  undefined4 uStack3780;
  undefined4 uStack3776;
  undefined4 uStack3772;
  undefined4 local_eb8;
  undefined4 uStack3764;
  undefined4 uStack3760;
  undefined4 uStack3756;
  undefined4 local_ea8;
  undefined4 uStack3748;
  undefined4 uStack3744;
  undefined4 uStack3740;
  undefined4 local_e98;
  undefined4 uStack3732;
  uint uStack3728;
  uint uStack3724;
  undefined4 local_e88;
  undefined4 uStack3716;
  undefined4 uStack3712;
  undefined4 uStack3708;
  undefined8 local_e78;
  undefined4 local_e70;
  undefined4 uStack3692;
  undefined4 uStack3688;
  undefined4 uStack3684;
  undefined4 local_e60;
  undefined4 uStack3676;
  undefined4 uStack3672;
  undefined4 uStack3668;
  undefined4 local_e50;
  undefined4 uStack3660;
  undefined4 uStack3656;
  undefined4 uStack3652;
  undefined4 local_e40;
  undefined4 uStack3644;
  undefined4 uStack3640;
  undefined4 uStack3636;
  undefined4 local_e30;
  undefined4 uStack3628;
  undefined4 uStack3624;
  undefined4 uStack3620;
  undefined4 local_e20;
  undefined4 uStack3612;
  undefined4 uStack3608;
  undefined4 uStack3604;
  undefined4 local_e10;
  undefined4 uStack3596;
  undefined4 uStack3592;
  undefined4 uStack3588;
  undefined4 local_e00;
  undefined4 uStack3580;
  undefined4 uStack3576;
  undefined4 uStack3572;
  undefined4 local_df0;
  undefined4 uStack3564;
  undefined4 uStack3560;
  undefined4 uStack3556;
  undefined4 local_de0;
  undefined4 uStack3548;
  uint uStack3544;
  uint uStack3540;
  undefined4 local_dd0;
  undefined4 uStack3532;
  undefined4 uStack3528;
  undefined4 uStack3524;
  undefined8 local_dc0;
  undefined4 local_db8;
  undefined4 local_db4;
  undefined4 local_db0;
  undefined4 local_dac;
  uint local_da8;
  uint local_da4;
  undefined local_da0;
  undefined2 local_d9f;
  undefined local_d9d;
  float local_d9c;
  float local_d98;
  undefined4 local_d94;
  undefined local_d90;
  undefined2 local_d8f;
  undefined local_d8d;
  undefined4 local_d8c;
  undefined4 local_d88;
  float local_d84;
  ulonglong local_d78;
  longlong *local_d70;
  longlong *local_d68;
  undefined4 local_d60;
  undefined4 local_d58;
  undefined4 local_d50;
  undefined4 local_d48;
  undefined4 local_d40;
  undefined local_d38 [16];
  undefined4 local_d28;
  undefined4 local_d20;
  undefined4 local_d18;
  undefined local_d00 [16];
  undefined4 local_cf0;
  undefined4 local_ce8;
  undefined4 local_ce0;
  undefined local_cc8 [16];
  undefined4 local_cb8;
  undefined4 local_cb0;
  undefined4 local_ca8;
  undefined local_c90 [16];
  undefined4 local_c80;
  undefined4 local_c78;
  undefined4 local_c70;
  undefined local_c58 [16];
  undefined4 local_c48;
  undefined4 local_c40;
  undefined4 local_c38;
  undefined local_c20 [112];
  undefined local_bb0 [56];
  undefined local_b78 [56];
  undefined local_b40 [56];
  undefined local_b08 [56];
  undefined local_ad0 [112];
  undefined local_a60 [56];
  undefined local_a28 [56];
  undefined local_9f0 [56];
  undefined local_9b8 [56];
  undefined local_980 [112];
  undefined local_910 [56];
  undefined local_8d8 [56];
  undefined local_8a0 [56];
  undefined local_868 [56];
  undefined local_830 [112];
  undefined local_7c0 [56];
  undefined local_788 [56];
  undefined local_750 [56];
  undefined local_718 [56];
  undefined local_6e0 [112];
  undefined local_670 [56];
  undefined local_638 [56];
  undefined local_600 [56];
  undefined local_5c8 [56];
  undefined local_590 [112];
  undefined local_520 [56];
  undefined local_4e8 [56];
  undefined local_4b0 [56];
  undefined local_478 [56];
  undefined local_440 [112];
  undefined local_3d0 [56];
  undefined local_398 [56];
  undefined local_360 [56];
  undefined local_328 [56];
  undefined local_2f0 [56];
  undefined local_2b8 [56];
  undefined local_280 [56];
  undefined local_248 [56];
  undefined local_210 [56];
  undefined local_1d8 [112];
  undefined local_168 [56];
  undefined local_130 [56];
  undefined local_f8 [56];
  undefined local_c0 [56];
  undefined local_88 [56];
  undefined local_50 [16];
  undefined8 uStack64;
  
                    // 0x95d0  4  NVSDK_NGX_D3D12_EvaluateFeature
  uStack64 = 0x1800095f2;
  local_50 = CONCAT88(CONCAT44(in_XMM6_Dd,in_XMM6_Dc),DAT_180418010 ^ (ulonglong)auStack6944);
  local_d70 = (longlong *)((ulonglong)param_1 >> 0x20);
  local_1af0 = (longlong *)((ulonglong)param_1 >> 0x18);
  local_d78 = (ulonglong)param_1 >> 0x10;
  local_1ae0 = (ulonglong)param_1 >> 8;
  uVar21 = 0;
  local_1ad8 = 0;
  local_d68 = param_3;
  iVar6 = _Mtx_lock(&DAT_18041ec00);
  if (iVar6 != 0) {
    std::_Throw_C_error(iVar6);
    pcVar3 = (code *)swi(3);
    (*pcVar3)();
    return;
  }
  uVar15 = (((((((((ulonglong)param_1 & 0xff ^ 0xcbf29ce484222325) * 0x100000001b3 ^
                 local_1ae0 & 0xff) * 0x100000001b3 ^ local_d78 & 0xff) * 0x100000001b3 ^
               (ulonglong)local_1af0 & 0xff) * 0x100000001b3 ^ (ulonglong)local_d70 & 0xff) *
              0x100000001b3 ^ (ulonglong)param_1 >> 0x28 & 0xff) * 0x100000001b3 ^
            (ulonglong)param_1 >> 0x30 & 0xff) * 0x100000001b3 ^ (ulonglong)param_1 >> 0x38) *
           0x100000001b3 & DAT_18041ebf0;
  uVar16 = *(ulonglong *)(DAT_18041ebd8 + 8 + uVar15 * 0x10);
  uVar17 = uVar21;
  if (uVar16 != DAT_18041ebc8) {
    for (uVar18 = uVar16;
        (uVar17 = uVar18, param_1 != *(longlong **)(uVar18 + 0x10) &&
        (uVar17 = uVar21, uVar18 != *(ulonglong *)(DAT_18041ebd8 + uVar15 * 0x10)));
        uVar18 = *(ulonglong *)(uVar18 + 8)) {
    }
  }
  if (uVar17 == 0) {
    FUN_18000e544("Cant find the RootSig\n");
  }
  else {
    if (uVar16 == DAT_18041ebc8) {
      local_1368 = DAT_18041ebc8;
      uVar16 = local_1368;
LAB_180011e2a:
      local_1368 = uVar16;
      if (DAT_18041ebd0 == 0x7ffffffffffffff) goto LAB_1800120b8;
      pvVar11 = operator_new(0x20);
      *(longlong **)((longlong)pvVar11 + 0x10) = param_1;
      *(undefined8 *)((longlong)pvVar11 + 0x18) = 0;
      uVar16 = DAT_18041ebd0 + 1;
      if ((longlong)uVar16 < 0) {
        fVar26 = (float)(uVar16 >> 1 | (ulonglong)((uint)uVar16 & 1));
        fVar26 = fVar26 + fVar26;
      }
      else {
        fVar26 = (float)uVar16;
      }
      if ((longlong)DAT_18041ebf8 < 0) {
        fVar24 = (float)(DAT_18041ebf8 >> 1 | (ulonglong)((uint)DAT_18041ebf8 & 1));
        fVar24 = fVar24 + fVar24;
      }
      else {
        fVar24 = (float)DAT_18041ebf8;
      }
      if (DAT_18041ebc0 < fVar26 / fVar24) {
        FUN_1800021cc();
        FUN_180002350();
        puVar10 = (ulonglong *)FUN_18000e4c4();
        local_1368 = *puVar10;
        uStack4960 = *(undefined4 *)(puVar10 + 1);
        uStack4956 = *(undefined4 *)((longlong)puVar10 + 0xc);
      }
      uVar16 = FUN_180008c10();
    }
    else {
      for (; param_1 != *(longlong **)(uVar16 + 0x10); uVar16 = *(ulonglong *)(uVar16 + 8)) {
        if (uVar16 == *(ulonglong *)(DAT_18041ebd8 + uVar15 * 0x10)) goto LAB_180011e2a;
      }
    }
    local_1ad8 = *(longlong *)(uVar16 + 0x18);
  }
  _Mtx_unlock(&DAT_18041ec00);
  (**(code **)(*param_1 + 0x38))(param_1,&DAT_18001dbd8,local_12d8);
  local_d78 = *(ulonglong *)(*(longlong *)(in_GS_OFFSET + 0x58) + (ulonglong)DAT_18041eb54 * 8);
  if ((*(int *)(local_d78 + 4) < _DAT_18041eb98) &&
     (_Init_thread_header(&DAT_18041eb98), _DAT_18041eb98 == -1)) {
    _DAT_18041eb88 = ZEXT816(0);
    pvVar11 = operator_new(0x80);
    memset(pvVar11,0,0x80);
    FUN_180002654(pvVar11);
    FUN_180002800();
    atexit(&LAB_180010550);
    FUN_18000ea80(&DAT_18041eb98);
  }
  local_1ac0 = DAT_18041eb90;
  if (DAT_18041eb90 != (longlong *)0x0) {
    LOCK();
    *(int *)(DAT_18041eb90 + 1) = *(int *)(DAT_18041eb90 + 1) + 1;
    local_1ac0 = DAT_18041eb90;
  }
  DAT_18041eb90 = local_1ac0;
  if (DAT_18041eb88[1] != 0) {
    LOCK();
    piVar8 = (int *)(DAT_18041eb88[1] + 8);
    *piVar8 = *piVar8 + 1;
  }
  local_1ae0 = *DAT_18041eb88;
  local_1af0 = (longlong *)DAT_18041eb88[1];
  if (*(int *)(local_d78 + 4) < _DAT_18041eb98) {
    _Init_thread_header(&DAT_18041eb98);
    if (_DAT_18041eb98 == -1) {
      _DAT_18041eb88 = ZEXT816(0);
      pvVar11 = operator_new(0x80);
      memset(pvVar11,0,0x80);
      FUN_180002654(pvVar11);
      FUN_180002800();
      atexit(&LAB_180010550);
      FUN_18000ea80(&DAT_18041eb98);
    }
  }
  if (DAT_18041eb90 != (longlong *)0x0) {
    LOCK();
    *(int *)(DAT_18041eb90 + 1) = *(int *)(DAT_18041eb90 + 1) + 1;
  }
  lVar19 = (longlong)DAT_18041eb88 + 0x40;
  uVar17 = (((((ulonglong)*(byte *)param_2 ^ 0xcbf29ce484222325) * 0x100000001b3 ^
             (ulonglong)*(byte *)((longlong)param_2 + 1)) * 0x100000001b3 ^
            (ulonglong)*(byte *)((longlong)param_2 + 2)) * 0x100000001b3 ^
           (ulonglong)*(byte *)((longlong)param_2 + 3)) * 0x100000001b3;
  uVar16 = *(ulonglong *)((longlong)DAT_18041eb88 + 0x70) & uVar17;
  plVar9 = *(longlong **)(*(longlong *)((longlong)DAT_18041eb88 + 0x58) + 8 + uVar16 * 0x10);
  local_1ae8 = *(longlong **)((longlong)DAT_18041eb88 + 0x48);
  plVar20 = local_1ae8;
  if (plVar9 == local_1ae8) {
LAB_18001200c:
    local_1358 = plVar20;
    if (*(longlong *)((longlong)DAT_18041eb88 + 0x50) == 0x7ffffffffffffff) {
LAB_1800120b8:
      std::_Xlength_error("unordered_map/set too long");
      pcVar3 = (code *)swi(3);
      (*pcVar3)();
      return;
    }
    local_12f0 = (longlong **)((longlong)DAT_18041eb88 + 0x48);
    local_1ad0 = (longlong *)operator_new(0x20);
    local_1ae8 = local_1ad0 + 2;
    *(int *)local_1ae8 = *param_2;
    local_1ad0[3] = 0;
    cVar5 = FUN_180003ff0(lVar19);
    if (cVar5 != '\0') {
      FUN_18001763c(lVar19);
      pplVar12 = (longlong **)FUN_180003954(lVar19,local_1538,local_1ae8,uVar17);
      plVar20 = *pplVar12;
      uStack4944 = *(undefined4 *)(pplVar12 + 1);
      uStack4940 = *(undefined4 *)((longlong)pplVar12 + 0xc);
      local_1358 = plVar20;
    }
    local_12e8 = 0;
    plVar9 = (longlong *)FUN_18000399c(lVar19,uVar17,plVar20,local_1ad0);
    FUN_180003fbc(&local_12f0);
  }
  else {
    for (; *param_2 != *(int *)(plVar9 + 2); plVar9 = (longlong *)plVar9[1]) {
      plVar20 = plVar9;
      if (plVar9 == *(longlong **)(*(longlong *)((longlong)DAT_18041eb88 + 0x58) + uVar16 * 0x10))
      goto LAB_18001200c;
    }
  }
  pplVar12 = (longlong **)plVar9[3];
  local_1ab8 = pplVar12;
  if (DAT_18041eb90 != (longlong *)0x0) {
    LOCK();
    plVar9 = DAT_18041eb90 + 1;
    iVar6 = *(int *)plVar9;
    *(int *)plVar9 = *(int *)plVar9 + -1;
    if (iVar6 == 1) {
      (**(code **)*DAT_18041eb90)(DAT_18041eb90);
      LOCK();
      piVar8 = (int *)((longlong)DAT_18041eb90 + 0xc);
      iVar6 = *piVar8;
      *piVar8 = *piVar8 + -1;
      if (iVar6 == 1) {
        (**(code **)(*DAT_18041eb90 + 8))(DAT_18041eb90);
      }
    }
  }
  if (local_1ad8 == 0) goto LAB_18000aafc;
  uVar22 = 0;
  local_1b00 = (longlong **)((ulonglong)local_1b00 & 0xffffffff00000000);
  lVar19 = __RTDynamicCast(local_d68,0,&struct_NVSDK_NGX_Parameter_RTTI_Type_Descriptor,
                           &struct_NvParameter_RTTI_Type_Descriptor);
  memset(&local_f28,0,0xb8);
  local_d9f = 0;
  local_d9d = 0;
  local_d8f = 0;
  local_d8d = 0;
  plVar9 = *(longlong **)(lVar19 + 0x60);
  local_12c8 = param_1;
  memset(&uStack6728,0,0x9c);
  uStack6568 = 0;
  uStack6572 = 2;
  local_19a0 = 0x1688;
  uVar25 = 0;
  local_1a50 = plVar9;
  if (plVar9 != (longlong *)0x0) {
    local_19b0 = 0;
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_718);
    local_19c0 = *(undefined4 *)(lVar7 + 0x10);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_280);
    uStack6588 = *(undefined4 *)(lVar7 + 0x18);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_248);
    uStack6584 = (uint)*(ushort *)(lVar7 + 0x1c);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_210);
    uStack6580 = (uint)*(ushort *)(lVar7 + 0x1e);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_1d8);
    if (*(int *)(lVar7 + 0x20) == 10) {
switchD_18001210f_caseD_a:
      uStack6596 = 3;
    }
    else {
      uStack6596 = uVar25;
      switch(*(int *)(lVar7 + 0x20)) {
      case 1:
        uStack6596 = 1;
        break;
      case 2:
        uStack6596 = 2;
        break;
      case 10:
        goto switchD_18001210f_caseD_a;
      case 0x10:
        uStack6596 = 4;
        break;
      case 0x1a:
        uStack6596 = 8;
        break;
      case 0x1b:
        uStack6596 = 6;
        break;
      case 0x1c:
        uStack6596 = 7;
        break;
      case 0x22:
        uStack6596 = 9;
        break;
      case 0x24:
        uStack6596 = 10;
        break;
      case 0x2a:
        uStack6596 = 5;
        break;
      case 0x36:
        uStack6596 = 0xb;
        break;
      case 0x38:
        uStack6596 = 0xd;
        break;
      case 0x39:
        uStack6596 = 0xc;
        break;
      case 0x3a:
        uStack6596 = 0xe;
        break;
      case 0x3d:
        uStack6596 = 0xf;
      }
    }
    piVar8 = (int *)(**(code **)(*plVar9 + 0x50))();
    iVar6 = *piVar8;
    if (iVar6 == 3) {
      uStack6600 = 2;
    }
    else if (iVar6 == 1) {
      uStack6600 = 0;
    }
    else if (iVar6 == 2) {
      uStack6600 = 1;
    }
    else if (iVar6 == 4) {
      uStack6600 = 3;
    }
  }
  local_12c0 = (undefined4)local_1a50;
  uStack4796 = local_1a50._4_4_;
  uStack4792 = uStack6728;
  uStack4788 = uStack6724;
  local_12b0 = local_1a40;
  uStack4780 = uStack6716;
  uStack4776 = uStack6712;
  uStack4772 = uStack6708;
  local_12a0 = local_1a30;
  uStack4764 = uStack6700;
  uStack4760 = uStack6696;
  uStack4756 = uStack6692;
  local_1290 = local_1a20;
  uStack4748 = uStack6684;
  uStack4744 = uStack6680;
  uStack4740 = uStack6676;
  local_1280 = local_1a10;
  uStack4732 = uStack6668;
  uStack4728 = uStack6664;
  uStack4724 = uStack6660;
  local_1270 = local_1a00;
  uStack4716 = uStack6652;
  uStack4712 = uStack6648;
  uStack4708 = uStack6644;
  local_1260 = local_19f0;
  uStack4700 = uStack6636;
  uStack4696 = uStack6632;
  uStack4692 = uStack6628;
  local_1250 = local_19e0;
  uStack4684 = uStack6620;
  uStack4680 = uStack6616;
  uStack4676 = uStack6612;
  local_1240 = local_19d0;
  uStack4668 = uStack6604;
  uStack4664 = uStack6600;
  uStack4660 = uStack6596;
  local_1230 = local_19c0;
  uStack4652 = uStack6588;
  uStack4648 = uStack6584;
  uStack4644 = uStack6580;
  local_1220 = local_19b0;
  uStack4636 = uStack6572;
  uStack4632 = (undefined4)uStack6568;
  uStack4628 = uStack6568._4_4_;
  local_1210 = local_19a0;
  plVar9 = *(longlong **)(lVar19 + 0x68);
  memset(&uStack6544,0,0x9c);
  uStack6384 = 0;
  uStack6388 = 2;
  local_18e8 = 0x1688;
  local_1998 = plVar9;
  if (plVar9 != (longlong *)0x0) {
    local_18f8 = 0;
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_168);
    local_1908 = *(undefined4 *)(lVar7 + 0x10);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_130);
    uStack6404 = *(undefined4 *)(lVar7 + 0x18);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_f8);
    uStack6400 = (uint)*(ushort *)(lVar7 + 0x1c);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_c0);
    uStack6396 = (uint)*(ushort *)(lVar7 + 0x1e);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_c20);
    iVar6 = *(int *)(lVar7 + 0x20);
    if ((iVar6 < 0x11) || (0x19 < iVar6)) {
      switch(iVar6) {
      case 1:
        uVar22 = 1;
        break;
      case 2:
        uVar22 = 2;
        break;
      case 10:
        uVar22 = 3;
        break;
      case 0x10:
        uVar22 = 4;
        break;
      case 0x1a:
        uVar22 = 8;
        break;
      case 0x1b:
        uVar22 = 6;
        break;
      case 0x1c:
        uVar22 = 7;
        break;
      case 0x22:
        uVar22 = 9;
        break;
      case 0x24:
        uVar22 = 10;
        break;
      case 0x2a:
        uVar22 = 5;
        break;
      case 0x36:
        uVar22 = 0xb;
        break;
      case 0x38:
        uVar22 = 0xd;
        break;
      case 0x39:
        uVar22 = 0xc;
        break;
      case 0x3a:
        uVar22 = 0xe;
        break;
      case 0x3d:
        uVar22 = 0xf;
      }
    }
    uStack6412 = uVar22;
    piVar8 = (int *)(**(code **)(*plVar9 + 0x50))();
    iVar6 = *piVar8;
    if (iVar6 == 3) {
      uStack6416 = 2;
    }
    else if (iVar6 == 1) {
      uStack6416 = 0;
    }
    else if (iVar6 == 2) {
      uStack6416 = 1;
    }
    else if (iVar6 == 4) {
      uStack6416 = 3;
    }
  }
  local_1208 = (undefined4)local_1998;
  uStack4612 = local_1998._4_4_;
  uStack4608 = uStack6544;
  uStack4604 = uStack6540;
  local_11f8 = local_1988;
  uStack4596 = uStack6532;
  uStack4592 = uStack6528;
  uStack4588 = uStack6524;
  local_11e8 = local_1978;
  uStack4580 = uStack6516;
  uStack4576 = uStack6512;
  uStack4572 = uStack6508;
  local_11d8 = local_1968;
  uStack4564 = uStack6500;
  uStack4560 = uStack6496;
  uStack4556 = uStack6492;
  local_11c8 = local_1958;
  uStack4548 = uStack6484;
  uStack4544 = uStack6480;
  uStack4540 = uStack6476;
  local_11b8 = local_1948;
  uStack4532 = uStack6468;
  uStack4528 = uStack6464;
  uStack4524 = uStack6460;
  local_11a8 = local_1938;
  uStack4516 = uStack6452;
  uStack4512 = uStack6448;
  uStack4508 = uStack6444;
  local_1198 = local_1928;
  uStack4500 = uStack6436;
  uStack4496 = uStack6432;
  uStack4492 = uStack6428;
  local_1188 = local_1918;
  uStack4484 = uStack6420;
  uStack4480 = uStack6416;
  uStack4476 = uStack6412;
  local_1178 = local_1908;
  uStack4468 = uStack6404;
  uStack4464 = uStack6400;
  uStack4460 = uStack6396;
  local_1168 = local_18f8;
  uStack4452 = uStack6388;
  uStack4448 = (undefined4)uStack6384;
  uStack4444 = uStack6384._4_4_;
  local_1158 = local_18e8;
  plVar9 = *(longlong **)(lVar19 + 0x70);
  memset(local_1520,0,0x80);
  local_1480 = 0;
  if (plVar9 != (longlong *)0x0) {
    (**(code **)(*plVar9 + 0x50))(plVar9,local_bb0);
    (**(code **)(*plVar9 + 0x50))(plVar9,local_b78);
    (**(code **)(*plVar9 + 0x50))(plVar9,local_b40);
    (**(code **)(*plVar9 + 0x50))(plVar9,local_b08);
    (**(code **)(*plVar9 + 0x50))(plVar9,local_ad0);
    (**(code **)(*plVar9 + 0x50))(plVar9);
  }
  plVar9 = *(longlong **)(lVar19 + 0x88);
  memset(&uStack6360,0,0x9c);
  uStack6200 = 0;
  uStack6204 = 2;
  local_1830 = 0x1688;
  local_18e0 = plVar9;
  if (plVar9 != (longlong *)0x0) {
    local_1840 = 0;
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_a60);
    local_1850 = *(undefined4 *)(lVar7 + 0x10);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_a28);
    uStack6220 = *(undefined4 *)(lVar7 + 0x18);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_9f0);
    uStack6216 = (uint)*(ushort *)(lVar7 + 0x1c);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_9b8);
    uStack6212 = (uint)*(ushort *)(lVar7 + 0x1e);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_980);
    uStack6228 = FUN_180019700(*(undefined4 *)(lVar7 + 0x20));
    piVar8 = (int *)(**(code **)(*plVar9 + 0x50))(plVar9);
    iVar6 = *piVar8;
    if (iVar6 == 1) {
      uStack6232 = 0;
    }
    else if (iVar6 == 2) {
      uStack6232 = 1;
    }
    else if (iVar6 == 3) {
      uStack6232 = 2;
    }
    else if (iVar6 == 4) {
      uStack6232 = 3;
    }
  }
  local_1098 = (undefined4)local_18e0;
  uStack4244 = local_18e0._4_4_;
  uStack4240 = uStack6360;
  uStack4236 = uStack6356;
  local_1088 = local_18d0;
  uStack4228 = uStack6348;
  uStack4224 = uStack6344;
  uStack4220 = uStack6340;
  local_1078 = local_18c0;
  uStack4212 = uStack6332;
  uStack4208 = uStack6328;
  uStack4204 = uStack6324;
  local_1068 = local_18b0;
  uStack4196 = uStack6316;
  uStack4192 = uStack6312;
  uStack4188 = uStack6308;
  local_1058 = local_18a0;
  uStack4180 = uStack6300;
  uStack4176 = uStack6296;
  uStack4172 = uStack6292;
  local_1048 = local_1890;
  uStack4164 = uStack6284;
  uStack4160 = uStack6280;
  uStack4156 = uStack6276;
  local_1038 = local_1880;
  uStack4148 = uStack6268;
  uStack4144 = uStack6264;
  uStack4140 = uStack6260;
  local_1028 = local_1870;
  uStack4132 = uStack6252;
  uStack4128 = uStack6248;
  uStack4124 = uStack6244;
  local_1018 = local_1860;
  uStack4116 = uStack6236;
  uStack4112 = uStack6232;
  uStack4108 = uStack6228;
  local_1008 = local_1850;
  uStack4100 = uStack6220;
  uStack4096 = uStack6216;
  uStack4092 = uStack6212;
  local_ff8 = local_1840;
  uStack4084 = uStack6204;
  uStack4080 = (undefined4)uStack6200;
  uStack4076 = uStack6200._4_4_;
  local_fe8 = local_1830;
  if ((*(char *)(local_1ae0 + 0x4b) == '\0') || (*(char *)(local_1ae0 + 0x4a) == '\0')) {
    plVar9 = *(longlong **)(lVar19 + 0x58);
    memset(local_1468,0,0x80);
    local_13c8 = 0;
    if (plVar9 != (longlong *)0x0) {
      (**(code **)(*plVar9 + 0x50))(plVar9,local_910);
      (**(code **)(*plVar9 + 0x50))(plVar9,local_8d8);
      (**(code **)(*plVar9 + 0x50))(plVar9,local_8a0);
      (**(code **)(*plVar9 + 0x50))(plVar9,local_868);
      (**(code **)(*plVar9 + 0x50))(plVar9,local_830);
      (**(code **)(*plVar9 + 0x50))(plVar9);
    }
    plVar9 = *(longlong **)(lVar19 + 0x80);
    memset(&uStack6176,0,0x9c);
    uStack6016 = 0;
    uStack6020 = 2;
    local_1778 = 0x1688;
    local_1828 = plVar9;
    if (plVar9 != (longlong *)0x0) {
      local_1788 = 0;
      lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_7c0);
      local_1798 = *(undefined4 *)(lVar7 + 0x10);
      lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_788);
      uStack6036 = *(undefined4 *)(lVar7 + 0x18);
      lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_750);
      uStack6032 = (uint)*(ushort *)(lVar7 + 0x1c);
      lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_3d0);
      uStack6028 = (uint)*(ushort *)(lVar7 + 0x1e);
      lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_6e0);
      uStack6044 = FUN_180019700(*(undefined4 *)(lVar7 + 0x20));
      piVar8 = (int *)(**(code **)(*plVar9 + 0x50))(plVar9);
      iVar6 = *piVar8;
      if (iVar6 == 1) {
        uStack6048 = 0;
      }
      else if (iVar6 == 2) {
        uStack6048 = 1;
      }
      else if (iVar6 == 3) {
        uStack6048 = 2;
      }
      else if (iVar6 == 4) {
        uStack6048 = 3;
      }
    }
    local_f28 = (undefined4)local_1828;
    uStack3876 = local_1828._4_4_;
    uStack3872 = uStack6176;
    uStack3868 = uStack6172;
    local_f18 = local_1818;
    uStack3860 = uStack6164;
    uStack3856 = uStack6160;
    uStack3852 = uStack6156;
    local_f08 = local_1808;
    uStack3844 = uStack6148;
    uStack3840 = uStack6144;
    uStack3836 = uStack6140;
    local_ef8 = local_17f8;
    uStack3828 = uStack6132;
    uStack3824 = uStack6128;
    uStack3820 = uStack6124;
    local_ee8 = local_17e8;
    uStack3812 = uStack6116;
    uStack3808 = uStack6112;
    uStack3804 = uStack6108;
    local_ed8 = local_17d8;
    uStack3796 = uStack6100;
    uStack3792 = uStack6096;
    uStack3788 = uStack6092;
    local_ec8 = local_17c8;
    uStack3780 = uStack6084;
    uStack3776 = uStack6080;
    uStack3772 = uStack6076;
    local_eb8 = local_17b8;
    uStack3764 = uStack6068;
    uStack3760 = uStack6064;
    uStack3756 = uStack6060;
    local_ea8 = local_17a8;
    uStack3748 = uStack6052;
    uStack3744 = uStack6048;
    uStack3740 = uStack6044;
    local_e98 = local_1798;
    uStack3732 = uStack6036;
    uStack3728 = uStack6032;
    uStack3724 = uStack6028;
    local_e88 = local_1788;
    uStack3716 = uStack6020;
    uStack3712 = (undefined4)uStack6016;
    uStack3708 = uStack6016._4_4_;
    local_e78 = local_1778;
  }
  plVar9 = pplVar12[2];
  local_13b0 = *(longlong *)(lVar19 + 0x80);
  local_d70 = *(longlong **)(lVar19 + 0x58);
  local_1ae8 = *(longlong **)(lVar19 + 0x88);
  local_1ad0 = *(longlong **)(lVar19 + 0x70);
  plVar20 = *(longlong **)(lVar19 + 0x68);
  plVar1 = *(longlong **)(lVar19 + 0x60);
  local_d40 = 0;
  local_1348 = L"ColorTex";
  local_1340 = plVar1;
  local_1390 = (**(code **)(*plVar9 + 0x50))(plVar9);
  if (plVar1 != (longlong *)0x0) {
    puVar2 = (undefined8 *)plVar9[0x10];
    if (puVar2 == (undefined8 *)0x0) {
      local_1b00 = (longlong **)&local_d40;
      uVar13 = FUN_18000db14(&local_1a78,&local_1390,&local_1348,&local_1340);
      FUN_18000e004(plVar9 + 0x10,uVar13);
      if (local_1a78 != (void *)0x0) {
        FUN_18000e0d4((longlong)local_1a78 + 8);
        free(local_1a78);
      }
    }
    else {
      (**(code **)(*plVar1 + 0x50))(plVar1,local_d38);
      *(undefined4 *)(puVar2 + 2) = local_d28;
      *(undefined4 *)((longlong)puVar2 + 0x14) = local_d20;
      *(undefined4 *)(puVar2 + 3) = local_d18;
      if ((longlong *)puVar2[1] != plVar1) {
        (**(code **)(*plVar1 + 8))(plVar1);
        local_1a98 = puVar2[1];
        puVar2[1] = plVar1;
        FUN_18000e0d4(&local_1a98);
      }
      if (*(int *)(puVar2 + 4) != -1) {
        (**(code **)(**(longlong **)*puVar2 + 0x90))
                  (*(longlong **)*puVar2,puVar2[1],puVar2 + 7,
                   (longlong)*(int *)(puVar2[6] + 4) * (longlong)*(int *)(puVar2 + 4) +
                   *(longlong *)(puVar2[6] + 8));
      }
      if (*(int *)((longlong)puVar2 + 0x24) != -1) {
        local_1b00 = (longlong **)
                     ((longlong)*(int *)(puVar2[0xc] + 4) *
                      (longlong)*(int *)((longlong)puVar2 + 0x24) + *(longlong *)(puVar2[0xc] + 8));
        (**(code **)(**(longlong **)*puVar2 + 0x98))(*(longlong **)*puVar2,puVar2[1],0,puVar2 + 0xd)
        ;
      }
      if (*(int *)(puVar2 + 5) != -1) {
        (**(code **)(**(longlong **)*puVar2 + 0xa0))
                  (*(longlong **)*puVar2,puVar2[1],puVar2 + 0x13,
                   (longlong)*(int *)(puVar2[0x12] + 4) * (longlong)*(int *)(puVar2 + 5) +
                   *(longlong *)(puVar2[0x12] + 8));
      }
    }
  }
  local_d48 = 0;
  local_1320 = L"DepthTex";
  local_1328 = plVar20;
  local_1318 = (**(code **)(*plVar9 + 0x50))(plVar9);
  if (plVar20 != (longlong *)0x0) {
    puVar2 = (undefined8 *)plVar9[0x11];
    if (puVar2 == (undefined8 *)0x0) {
      local_1b00 = (longlong **)&local_d48;
      uVar13 = FUN_18000db14(&local_1ac8,&local_1318,&local_1320,&local_1328);
      FUN_18000e004(plVar9 + 0x11,uVar13);
      if (local_1ac8 != (void *)0x0) {
        FUN_18000e0d4((longlong)local_1ac8 + 8);
        free(local_1ac8);
      }
    }
    else {
      (**(code **)(*plVar20 + 0x50))(plVar20,local_d00);
      *(undefined4 *)(puVar2 + 2) = local_cf0;
      *(undefined4 *)((longlong)puVar2 + 0x14) = local_ce8;
      *(undefined4 *)(puVar2 + 3) = local_ce0;
      if ((longlong *)puVar2[1] != plVar20) {
        (**(code **)(*plVar20 + 8))(plVar20);
        local_1a70 = puVar2[1];
        puVar2[1] = plVar20;
        FUN_18000e0d4(&local_1a70);
      }
      if (*(int *)(puVar2 + 4) != -1) {
        (**(code **)(**(longlong **)*puVar2 + 0x90))
                  (*(longlong **)*puVar2,puVar2[1],puVar2 + 7,
                   (longlong)*(int *)(puVar2[6] + 4) * (longlong)*(int *)(puVar2 + 4) +
                   *(longlong *)(puVar2[6] + 8));
      }
      if (*(int *)((longlong)puVar2 + 0x24) != -1) {
        local_1b00 = (longlong **)
                     ((longlong)*(int *)(puVar2[0xc] + 4) *
                      (longlong)*(int *)((longlong)puVar2 + 0x24) + *(longlong *)(puVar2[0xc] + 8));
        (**(code **)(**(longlong **)*puVar2 + 0x98))(*(longlong **)*puVar2,puVar2[1],0,puVar2 + 0xd)
        ;
      }
      if (*(int *)(puVar2 + 5) != -1) {
        (**(code **)(**(longlong **)*puVar2 + 0xa0))
                  (*(longlong **)*puVar2,puVar2[1],puVar2 + 0x13,
                   (longlong)*(int *)(puVar2[0x12] + 4) * (longlong)*(int *)(puVar2 + 5) +
                   *(longlong *)(puVar2[0x12] + 8));
      }
    }
  }
  local_d50 = 0;
  local_1308 = L"StencilTex";
  local_1310 = plVar20;
  local_1300 = (**(code **)(*plVar9 + 0x50))(plVar9);
  if (plVar20 != (longlong *)0x0) {
    puVar2 = (undefined8 *)plVar9[0x12];
    if (puVar2 == (undefined8 *)0x0) {
      local_1b00 = (longlong **)&local_d50;
      uVar13 = FUN_18000db14(&local_1a58,&local_1300,&local_1308,&local_1310);
      FUN_18000e004(plVar9 + 0x12,uVar13);
      if (local_1a58 != (void *)0x0) {
        FUN_18000e0d4((longlong)local_1a58 + 8);
        free(local_1a58);
      }
    }
    else {
      (**(code **)(*plVar20 + 0x50))(plVar20,local_cc8);
      *(undefined4 *)(puVar2 + 2) = local_cb8;
      *(undefined4 *)((longlong)puVar2 + 0x14) = local_cb0;
      *(undefined4 *)(puVar2 + 3) = local_ca8;
      if ((longlong *)puVar2[1] != plVar20) {
        (**(code **)(*plVar20 + 8))(plVar20);
        local_1a90 = puVar2[1];
        puVar2[1] = plVar20;
        FUN_18000e0d4(&local_1a90);
      }
      if (*(int *)(puVar2 + 4) != -1) {
        (**(code **)(**(longlong **)*puVar2 + 0x90))
                  (*(longlong **)*puVar2,puVar2[1],puVar2 + 7,
                   (longlong)*(int *)(puVar2[6] + 4) * (longlong)*(int *)(puVar2 + 4) +
                   *(longlong *)(puVar2[6] + 8));
      }
      if (*(int *)((longlong)puVar2 + 0x24) != -1) {
        local_1b00 = (longlong **)
                     ((longlong)*(int *)(puVar2[0xc] + 4) *
                      (longlong)*(int *)((longlong)puVar2 + 0x24) + *(longlong *)(puVar2[0xc] + 8));
        (**(code **)(**(longlong **)*puVar2 + 0x98))(*(longlong **)*puVar2,puVar2[1],0,puVar2 + 0xd)
        ;
      }
      if (*(int *)(puVar2 + 5) != -1) {
        (**(code **)(**(longlong **)*puVar2 + 0xa0))
                  (*(longlong **)*puVar2,puVar2[1],puVar2 + 0x13,
                   (longlong)*(int *)(puVar2[0x12] + 4) * (longlong)*(int *)(puVar2 + 5) +
                   *(longlong *)(puVar2[0x12] + 8));
      }
    }
  }
  plVar20 = local_1ad0;
  local_d58 = 0;
  local_12f8 = local_1ad0;
  local_1330 = L"MotionVectorTex";
  local_13a8 = (**(code **)(*plVar9 + 0x50))(plVar9);
  if (plVar20 != (longlong *)0x0) {
    puVar2 = (undefined8 *)plVar9[0x13];
    if (puVar2 == (undefined8 *)0x0) {
      local_1b00 = (longlong **)&local_d58;
      uVar13 = FUN_18000db14(&local_1a68,&local_13a8,&local_1330,&local_12f8);
      FUN_18000e004(plVar9 + 0x13,uVar13);
      if (local_1a68 != (void *)0x0) {
        FUN_18000e0d4((longlong)local_1a68 + 8);
        free(local_1a68);
      }
    }
    else {
      (**(code **)(*plVar20 + 0x50))(plVar20,local_c90);
      *(undefined4 *)(puVar2 + 2) = local_c80;
      *(undefined4 *)((longlong)puVar2 + 0x14) = local_c78;
      *(undefined4 *)(puVar2 + 3) = local_c70;
      if ((longlong *)puVar2[1] != plVar20) {
        (**(code **)(*plVar20 + 8))(plVar20);
        local_1a88 = puVar2[1];
        puVar2[1] = plVar20;
        FUN_18000e0d4(&local_1a88);
      }
      if (*(int *)(puVar2 + 4) != -1) {
        (**(code **)(**(longlong **)*puVar2 + 0x90))
                  (*(longlong **)*puVar2,puVar2[1],puVar2 + 7,
                   (longlong)*(int *)(puVar2[6] + 4) * (longlong)*(int *)(puVar2 + 4) +
                   *(longlong *)(puVar2[6] + 8));
      }
      if (*(int *)((longlong)puVar2 + 0x24) != -1) {
        local_1b00 = (longlong **)
                     ((longlong)*(int *)(puVar2[0xc] + 4) *
                      (longlong)*(int *)((longlong)puVar2 + 0x24) + *(longlong *)(puVar2[0xc] + 8));
        (**(code **)(**(longlong **)*puVar2 + 0x98))(*(longlong **)*puVar2,puVar2[1],0,puVar2 + 0xd)
        ;
      }
      if (*(int *)(puVar2 + 5) != -1) {
        (**(code **)(**(longlong **)*puVar2 + 0xa0))
                  (*(longlong **)*puVar2,puVar2[1],puVar2 + 0x13,
                   (longlong)*(int *)(puVar2[0x12] + 4) * (longlong)*(int *)(puVar2 + 5) +
                   *(longlong *)(puVar2[0x12] + 8));
      }
    }
  }
  plVar20 = local_1ae8;
  local_d60 = 0;
  local_13a0 = local_1ae8;
  local_1398 = L"ExposureTex";
  local_1338 = (**(code **)(*plVar9 + 0x50))(plVar9);
  if (plVar20 != (longlong *)0x0) {
    if (plVar9[0x14] == 0) {
      local_1b00 = (longlong **)&local_d60;
      uVar13 = FUN_18000db14(&local_1a60,&local_1338,&local_1398,&local_13a0);
      FUN_18000e004(plVar9 + 0x14,uVar13);
      if (local_1a60 != (void *)0x0) {
        FUN_18000e0d4((longlong)local_1a60 + 8);
        free(local_1a60);
      }
    }
    else {
      FUN_180018b94(plVar9[0x14],plVar20);
    }
  }
  plVar20 = local_d70;
  local_d68 = (longlong *)((ulonglong)local_d68 & 0xffffffff00000000);
  local_1388 = local_d70;
  local_1380 = L"ColorBiasTex";
  local_1378 = (**(code **)(*plVar9 + 0x50))(plVar9);
  if (plVar20 != (longlong *)0x0) {
    puVar2 = (undefined8 *)plVar9[0x15];
    if (puVar2 == (undefined8 *)0x0) {
      local_1b00 = &local_d68;
      uVar13 = FUN_18000db14(local_1aa8,&local_1378,&local_1380,&local_1388);
      FUN_18000e004(plVar9 + 0x15,uVar13);
      if (local_1aa8[0] != (void *)0x0) {
        FUN_18000e0d4((longlong)local_1aa8[0] + 8);
        free(local_1aa8[0]);
      }
    }
    else {
      (**(code **)(*plVar20 + 0x50))(plVar20,local_c58);
      *(undefined4 *)(puVar2 + 2) = local_c48;
      *(undefined4 *)((longlong)puVar2 + 0x14) = local_c40;
      *(undefined4 *)(puVar2 + 3) = local_c38;
      if ((longlong *)puVar2[1] != plVar20) {
        (**(code **)(*plVar20 + 8))(plVar20);
        local_1a80 = puVar2[1];
        puVar2[1] = plVar20;
        FUN_18000e0d4(&local_1a80);
      }
      if (*(int *)(puVar2 + 4) != -1) {
        (**(code **)(**(longlong **)*puVar2 + 0x90))
                  (*(longlong **)*puVar2,puVar2[1],puVar2 + 7,
                   (longlong)*(int *)(puVar2[6] + 4) * (longlong)*(int *)(puVar2 + 4) +
                   *(longlong *)(puVar2[6] + 8));
      }
      if (*(int *)((longlong)puVar2 + 0x24) != -1) {
        local_1b00 = (longlong **)
                     ((longlong)*(int *)(puVar2[0xc] + 4) *
                      (longlong)*(int *)((longlong)puVar2 + 0x24) + *(longlong *)(puVar2[0xc] + 8));
        (**(code **)(**(longlong **)*puVar2 + 0x98))(*(longlong **)*puVar2,puVar2[1],0,puVar2 + 0xd)
        ;
      }
      if (*(int *)(puVar2 + 5) != -1) {
        (**(code **)(**(longlong **)*puVar2 + 0xa0))
                  (*(longlong **)*puVar2,puVar2[1],puVar2 + 0x13,
                   (longlong)*(int *)(puVar2[0x12] + 4) * (longlong)*(int *)(puVar2 + 5) +
                   *(longlong *)(puVar2[0x12] + 8));
      }
    }
  }
  lVar7 = local_13b0;
  local_d70 = (longlong *)((ulonglong)local_d70 & 0xffffffff00000000);
  local_1370 = L"TransparencyTex";
  local_13b8 = (**(code **)(*plVar9 + 0x50))(plVar9);
  if (lVar7 != 0) {
    if (plVar9[0x16] == 0) {
      local_1b00 = &local_d70;
      uVar13 = FUN_18000db14(&local_1ab0,&local_13b8,&local_1370,&local_13b0);
      FUN_18000e004(plVar9 + 0x16,uVar13);
      if (local_1ab0 != (void *)0x0) {
        FUN_18000e0d4((longlong)local_1ab0 + 8);
        free(local_1ab0);
      }
    }
    else {
      FUN_180018b94(plVar9[0x16],lVar7);
    }
  }
  pplVar12 = local_1ab8;
  plVar9 = local_1ab8[2];
  uVar22 = (**(code **)(**local_1ab8 + 8))();
  uVar23 = (**(code **)(**pplVar12 + 0x10))();
  *(undefined4 *)(*(longlong *)(*(longlong *)(plVar9[0x17] + 0x80) + 0x60) + 0xc) = uVar23;
  *(undefined4 *)(*(longlong *)(*(longlong *)(plVar9[0x17] + 0x80) + 0x60) + 8) = uVar22;
  plVar9 = pplVar12[2];
  uVar22 = *(undefined4 *)(lVar19 + 0x44);
  *(undefined4 *)(*(longlong *)(*(longlong *)(plVar9[0x17] + 0x80) + 0x60) + 0x20) =
       *(undefined4 *)(lVar19 + 0x40);
  *(undefined4 *)(*(longlong *)(*(longlong *)(plVar9[0x17] + 0x80) + 0x60) + 0x24) = uVar22;
  plVar9 = pplVar12[2];
  uVar22 = *(undefined4 *)(lVar19 + 0x3c);
  **(undefined4 **)(*(longlong *)(plVar9[0x17] + 0x80) + 0x60) = *(undefined4 *)(lVar19 + 0x38);
  *(undefined4 *)(*(longlong *)(*(longlong *)(plVar9[0x17] + 0x80) + 0x60) + 4) = uVar22;
  local_1b00 = (longlong **)
               ((ulonglong)local_1b00 & 0xffffffff00000000 | (ulonglong)*(uint *)(lVar19 + 0x14));
  (**(code **)(*pplVar12[2] + 0x60))
            (pplVar12[2],*(undefined4 *)(lVar19 + 8),*(undefined4 *)(lVar19 + 0xc),
             *(undefined4 *)(lVar19 + 0x10));
  (**(code **)(*pplVar12[2] + 0x28))();
  plVar9 = (longlong *)(**(code **)(*pplVar12[2] + 0x30))();
  memset(&uStack5992,0,0x9c);
  uStack5832 = 0;
  uStack5836 = 2;
  local_16c0 = 0x1688;
  local_1770 = plVar9;
  if (plVar9 != (longlong *)0x0) {
    local_16d0 = 0;
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_670);
    local_16e0 = *(undefined4 *)(lVar7 + 0x10);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_638);
    uStack5852 = *(undefined4 *)(lVar7 + 0x18);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_600);
    uStack5848 = (uint)*(ushort *)(lVar7 + 0x1c);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_5c8);
    uStack5844 = (uint)*(ushort *)(lVar7 + 0x1e);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_590);
    uStack5860 = uVar25;
    switch(*(undefined4 *)(lVar7 + 0x20)) {
    case 1:
      uStack5860 = 1;
      break;
    case 2:
      uStack5860 = 2;
      break;
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 0xb:
    case 0xc:
    case 0xd:
    case 0xe:
    case 0xf:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x15:
    case 0x16:
    case 0x17:
    case 0x18:
    case 0x19:
    case 0x1d:
    case 0x1e:
    case 0x1f:
    case 0x20:
    case 0x21:
    case 0x23:
    case 0x25:
    case 0x26:
    case 0x27:
    case 0x28:
    case 0x29:
    case 0x2b:
    case 0x2c:
    case 0x2d:
    case 0x2e:
    case 0x2f:
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x37:
    case 0x3b:
    case 0x3c:
      break;
    case 10:
      uStack5860 = 3;
      break;
    case 0x10:
      uStack5860 = 4;
      break;
    case 0x1a:
      uStack5860 = 8;
      break;
    case 0x1b:
      uStack5860 = 6;
      break;
    case 0x1c:
      uStack5860 = 7;
      break;
    case 0x22:
      uStack5860 = 9;
      break;
    case 0x24:
      uStack5860 = 10;
      break;
    case 0x2a:
      uStack5860 = 5;
      break;
    case 0x36:
      uStack5860 = 0xb;
      break;
    case 0x38:
      uStack5860 = 0xd;
      break;
    case 0x39:
      uStack5860 = 0xc;
      break;
    case 0x3a:
      uStack5860 = 0xe;
      break;
    default:
      uStack5860 = 0xf;
    }
    piVar8 = (int *)(**(code **)(*plVar9 + 0x50))();
    iVar6 = *piVar8;
    if (iVar6 == 3) {
      uStack5864 = 2;
    }
    else if (iVar6 == 1) {
      uStack5864 = 0;
    }
    else if (iVar6 == 2) {
      uStack5864 = 1;
    }
    else if (iVar6 == 4) {
      uStack5864 = 3;
    }
  }
  local_fe0 = (undefined4)local_1770;
  uStack4060 = local_1770._4_4_;
  uStack4056 = uStack5992;
  uStack4052 = uStack5988;
  local_fd0 = local_1760;
  uStack4044 = uStack5980;
  uStack4040 = uStack5976;
  uStack4036 = uStack5972;
  local_fc0 = local_1750;
  uStack4028 = uStack5964;
  uStack4024 = uStack5960;
  uStack4020 = uStack5956;
  local_fb0 = local_1740;
  uStack4012 = uStack5948;
  uStack4008 = uStack5944;
  uStack4004 = uStack5940;
  local_fa0 = local_1730;
  uStack3996 = uStack5932;
  uStack3992 = uStack5928;
  uStack3988 = uStack5924;
  local_f90 = local_1720;
  uStack3980 = uStack5916;
  uStack3976 = uStack5912;
  uStack3972 = uStack5908;
  local_f80 = local_1710;
  uStack3964 = uStack5900;
  uStack3960 = uStack5896;
  uStack3956 = uStack5892;
  local_f70 = local_1700;
  uStack3948 = uStack5884;
  uStack3944 = uStack5880;
  uStack3940 = uStack5876;
  local_f60 = local_16f0;
  uStack3932 = uStack5868;
  uStack3928 = uStack5864;
  uStack3924 = uStack5860;
  local_f50 = local_16e0;
  uStack3916 = uStack5852;
  uStack3912 = uStack5848;
  uStack3908 = uStack5844;
  local_f40 = local_16d0;
  uStack3900 = uStack5836;
  uStack3896 = (undefined4)uStack5832;
  uStack3892 = uStack5832._4_4_;
  local_f30 = local_16c0;
  plVar9 = *(longlong **)(*(longlong *)(pplVar12[2][0x17] + 0x68) + 8);
  memset(&uStack5808,0,0x9c);
  uStack5648 = 0;
  uStack5652 = 2;
  local_1608 = 0x1688;
  local_16b8 = plVar9;
  if (plVar9 != (longlong *)0x0) {
    local_1618 = 0;
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_520);
    local_1628 = *(undefined4 *)(lVar7 + 0x10);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_4e8);
    uStack5668 = *(undefined4 *)(lVar7 + 0x18);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_4b0);
    uStack5664 = (uint)*(ushort *)(lVar7 + 0x1c);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_478);
    uStack5660 = (uint)*(ushort *)(lVar7 + 0x1e);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_440);
    if (*(int *)(lVar7 + 0x20) == 0x22) {
switchD_1800129bc_caseD_22:
      uStack5676 = 9;
    }
    else {
      uStack5676 = uVar25;
      switch(*(int *)(lVar7 + 0x20)) {
      case 1:
        uStack5676 = 1;
        break;
      case 2:
        uStack5676 = 2;
        break;
      case 10:
        uStack5676 = 3;
        break;
      case 0x10:
        uStack5676 = 4;
        break;
      case 0x1a:
        uStack5676 = 8;
        break;
      case 0x1b:
        uStack5676 = 6;
        break;
      case 0x1c:
        uStack5676 = 7;
        break;
      case 0x22:
        goto switchD_1800129bc_caseD_22;
      case 0x24:
        uStack5676 = 10;
        break;
      case 0x2a:
        uStack5676 = 5;
        break;
      case 0x36:
        uStack5676 = 0xb;
        break;
      case 0x38:
        uStack5676 = 0xd;
        break;
      case 0x39:
        uStack5676 = 0xc;
        break;
      case 0x3a:
        uStack5676 = 0xe;
        break;
      case 0x3d:
        uStack5676 = 0xf;
      }
    }
    piVar8 = (int *)(**(code **)(*plVar9 + 0x50))();
    iVar6 = *piVar8;
    if (iVar6 == 3) {
      uStack5680 = 2;
    }
    else if (iVar6 == 1) {
      uStack5680 = 0;
    }
    else if (iVar6 == 2) {
      uStack5680 = 1;
    }
    else if (iVar6 == 4) {
      uStack5680 = 3;
    }
  }
  local_1150 = (undefined4)local_16b8;
  uStack4428 = local_16b8._4_4_;
  uStack4424 = uStack5808;
  uStack4420 = uStack5804;
  local_1140 = local_16a8;
  uStack4412 = uStack5796;
  uStack4408 = uStack5792;
  uStack4404 = uStack5788;
  local_1130 = local_1698;
  uStack4396 = uStack5780;
  uStack4392 = uStack5776;
  uStack4388 = uStack5772;
  local_1120 = local_1688;
  uStack4380 = uStack5764;
  uStack4376 = uStack5760;
  uStack4372 = uStack5756;
  local_1110 = local_1678;
  uStack4364 = uStack5748;
  uStack4360 = uStack5744;
  uStack4356 = uStack5740;
  local_1100 = local_1668;
  uStack4348 = uStack5732;
  uStack4344 = uStack5728;
  uStack4340 = uStack5724;
  local_10f0 = local_1658;
  uStack4332 = uStack5716;
  uStack4328 = uStack5712;
  uStack4324 = uStack5708;
  local_10e0 = local_1648;
  uStack4316 = uStack5700;
  uStack4312 = uStack5696;
  uStack4308 = uStack5692;
  local_10d0 = local_1638;
  uStack4300 = uStack5684;
  uStack4296 = uStack5680;
  uStack4292 = uStack5676;
  local_10c0 = local_1628;
  uStack4284 = uStack5668;
  uStack4280 = uStack5664;
  uStack4276 = uStack5660;
  local_10b0 = local_1618;
  uStack4268 = uStack5652;
  uStack4264 = (undefined4)uStack5648;
  uStack4260 = uStack5648._4_4_;
  local_10a0 = local_1608;
  plVar9 = *(longlong **)(lVar19 + 0x78);
  memset(&uStack5624,0,0x9c);
  uStack5464 = 0;
  uStack5468 = 1;
  local_1550 = 0x1688;
  local_1600 = plVar9;
  if (plVar9 != (longlong *)0x0) {
    local_1560 = 0;
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_88);
    local_1570 = *(undefined4 *)(lVar7 + 0x10);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_398);
    uStack5484 = *(undefined4 *)(lVar7 + 0x18);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_360);
    uStack5480 = (uint)*(ushort *)(lVar7 + 0x1c);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_328);
    uStack5476 = (uint)*(ushort *)(lVar7 + 0x1e);
    lVar7 = (**(code **)(*plVar9 + 0x50))(plVar9,local_2f0);
    if (*(int *)(lVar7 + 0x20) == 10) {
switchD_180012aaf_caseD_a:
      uStack5492 = 3;
    }
    else {
      uStack5492 = 4;
      switch(*(int *)(lVar7 + 0x20)) {
      case 1:
        uStack5492 = 1;
        break;
      case 2:
        uStack5492 = 2;
        break;
      default:
        uStack5492 = uVar25;
        break;
      case 10:
        goto switchD_180012aaf_caseD_a;
      case 0x10:
        break;
      case 0x1a:
        uStack5492 = 8;
        break;
      case 0x1b:
        uStack5492 = 6;
        break;
      case 0x1c:
        uStack5492 = 7;
        break;
      case 0x22:
        uStack5492 = 9;
        break;
      case 0x24:
        uStack5492 = 10;
        break;
      case 0x2a:
        uStack5492 = 5;
        break;
      case 0x36:
        uStack5492 = 0xb;
        break;
      case 0x38:
        uStack5492 = 0xd;
        break;
      case 0x39:
        uStack5492 = 0xc;
        break;
      case 0x3a:
        uStack5492 = 0xe;
        break;
      case 0x3d:
        uStack5492 = 0xf;
      }
    }
    piVar8 = (int *)(**(code **)(*plVar9 + 0x50))(plVar9,local_2b8);
    iVar6 = *piVar8;
    if (iVar6 == 3) {
      uStack5496 = 2;
    }
    else if (iVar6 == 1) {
      uStack5496 = 0;
    }
    else if (iVar6 == 2) {
      uStack5496 = 1;
    }
    else if (iVar6 == 4) {
      uStack5496 = 3;
    }
  }
  local_e70 = (undefined4)local_1600;
  uStack3692 = local_1600._4_4_;
  uStack3688 = uStack5624;
  uStack3684 = uStack5620;
  local_e60 = local_15f0;
  uStack3676 = uStack5612;
  uStack3672 = uStack5608;
  uStack3668 = uStack5604;
  local_e50 = local_15e0;
  uStack3660 = uStack5596;
  uStack3656 = uStack5592;
  uStack3652 = uStack5588;
  local_e40 = local_15d0;
  uStack3644 = uStack5580;
  uStack3640 = uStack5576;
  uStack3636 = uStack5572;
  local_e30 = local_15c0;
  uStack3628 = uStack5564;
  uStack3624 = uStack5560;
  uStack3620 = uStack5556;
  local_e20 = local_15b0;
  uStack3612 = uStack5548;
  uStack3608 = uStack5544;
  uStack3604 = uStack5540;
  local_e10 = local_15a0;
  uStack3596 = uStack5532;
  uStack3592 = uStack5528;
  uStack3588 = uStack5524;
  local_e00 = local_1590;
  uStack3580 = uStack5516;
  uStack3576 = uStack5512;
  uStack3572 = uStack5508;
  local_df0 = local_1580;
  uStack3564 = uStack5500;
  uStack3560 = uStack5496;
  uStack3556 = uStack5492;
  local_de0 = local_1570;
  uStack3548 = uStack5484;
  uStack3544 = uStack5480;
  uStack3540 = uStack5476;
  local_dd0 = local_1560;
  uStack3532 = uStack5468;
  uStack3528 = (undefined4)uStack5464;
  uStack3524 = uStack5464._4_4_;
  local_dc0 = local_1550;
  local_db8 = *(undefined4 *)(lVar19 + 0x40);
  local_db4 = *(undefined4 *)(lVar19 + 0x44);
  local_db0 = *(undefined4 *)(lVar19 + 0x38);
  local_dac = *(undefined4 *)(lVar19 + 0x3c);
  local_d90 = *(undefined *)(lVar19 + 0x34);
  fVar26 = *(float *)(lVar19 + 0x30);
  if ((char)((ulonglong)*(undefined8 *)(local_1ae0 + 0x14) >> 0x20) != '\0') {
    uVar21 = (ulonglong)((int)*(undefined8 *)(local_1ae0 + 0x14) == 1);
  }
  local_d9c = fVar26;
  if (((char)uVar21 != '\0') && (local_d9c = 1.0, fVar26 < 1.0)) {
    if (-1.0 < fVar26) {
      local_d9c = fVar26 * 0.5 + 0.495;
    }
    else {
      local_d9c = 0.0;
    }
  }
  if (*(char *)(local_1ae0 + 0xb) == '\0') {
    local_da0 = *(undefined *)(lVar19 + 0x53);
  }
  else {
    local_da0 = *(undefined *)(local_1ae0 + 10);
  }
  if (*(char *)(local_1ae0 + 0x10) != '\0') {
    local_d9c = *(float *)(local_1ae0 + 0xc);
  }
  if ((*(int *)(local_d78 + 4) < _DAT_18041eca8) &&
     (_Init_thread_header(&DAT_18041eca8), _DAT_18041eca8 == -1)) {
    _DAT_18041ec58 = QueryPerformanceFrequency((LARGE_INTEGER *)&DAT_18041ecb0);
    FUN_18000ea80(&DAT_18041eca8);
  }
  if (_DAT_18041ec58 == 0) {
    UVar14 = GetTickCount64();
    if ((longlong)UVar14 < 0) {
      dVar4 = (double)(UVar14 >> 1 | (ulonglong)((uint)UVar14 & 1));
      dVar4 = dVar4 + dVar4;
      uVar25 = SUB84(dVar4,0);
      uVar22 = (undefined4)((ulonglong)dVar4 >> 0x20);
    }
    else {
      uVar25 = SUB84((double)UVar14,0);
      uVar22 = (undefined4)((ulonglong)(double)UVar14 >> 0x20);
    }
  }
  else {
    QueryPerformanceCounter(&local_d78);
    dVar4 = ((double)local_d78 * 1000.0) / (double)_DAT_18041ecb0;
    uVar25 = SUB84(dVar4,0);
    uVar22 = (undefined4)((ulonglong)dVar4 >> 0x20);
  }
  dVar4 = (double)CONCAT44(uVar22,uVar25) - _DAT_18041ec50;
  _DAT_18041ec50 = (double)CONCAT44(uVar22,uVar25);
  local_d98 = (float)dVar4;
  local_d94 = 0x3f800000;
  local_da8 = *(uint *)(lVar19 + 8);
  local_da4 = *(uint *)(lVar19 + 0xc);
  local_d88 = (**(code **)(**pplVar12 + 8))();
  local_d8c = (**(code **)(**pplVar12 + 0x10))();
  local_d84 = (float)(**(code **)**pplVar12)();
  local_d84 = local_d84 * 0.01745329;
  if ((((pplVar12 + 3 != (longlong **)0x0) && (local_da8 <= *(uint *)((longlong)pplVar12 + 0x1c)))
      && (local_da4 <= *(uint *)(pplVar12 + 4))) && (pplVar12[0x27] != (longlong *)0x0)) {
    FUN_18000aec0(pplVar12 + 3,&local_12c8);
  }
  (**(code **)(*param_1 + 0xe8))(param_1,local_1ad8);
LAB_18000aafc:
  if (local_1af0 != (longlong *)0x0) {
    LOCK();
    plVar9 = local_1af0 + 1;
    iVar6 = *(int *)plVar9;
    *(int *)plVar9 = *(int *)plVar9 + -1;
    if (iVar6 == 1) {
      (**(code **)*local_1af0)(local_1af0);
      LOCK();
      piVar8 = (int *)((longlong)local_1af0 + 0xc);
      iVar6 = *piVar8;
      *piVar8 = *piVar8 + -1;
      if (iVar6 == 1) {
        (**(code **)(*local_1af0 + 8))();
      }
    }
  }
  plVar9 = local_1ac0;
  if (local_1ac0 != (longlong *)0x0) {
    LOCK();
    plVar20 = local_1ac0 + 1;
    iVar6 = *(int *)plVar20;
    *(int *)plVar20 = *(int *)plVar20 + -1;
    if (iVar6 == 1) {
      (**(code **)*local_1ac0)(local_1ac0);
      LOCK();
      piVar8 = (int *)((longlong)plVar9 + 0xc);
      iVar6 = *piVar8;
      *piVar8 = *piVar8 + -1;
      if (iVar6 == 1) {
        (**(code **)(*plVar9 + 8))(plVar9);
      }
    }
  }
  FUN_18000e8c0(local_50._0_8_ ^ (ulonglong)auStack6944);
  return;
}



longlong FUN_18000ae20(longlong param_1)

{
  return param_1 + 8;
}



undefined4 FUN_18000ae30(longlong param_1)

{
  return *(undefined4 *)(*(longlong *)(param_1 + 8) + 0x44);
}



undefined4 FUN_18000ae40(longlong param_1)

{
  return *(undefined4 *)(*(longlong *)(param_1 + 8) + 0x40);
}



undefined8 FUN_18000ae4c(longlong param_1)

{
  longlong lVar1;
  
  lVar1 = (**(code **)(**(longlong **)(param_1 + 0xb8) + 8))();
  return *(undefined8 *)(lVar1 + 8);
}



undefined8 FUN_18000ae70(longlong param_1)

{
  return *(undefined8 *)(param_1 + 0x60);
}


/*
Unable to decompile 'FUN_18000aec0'
Cause: 
Low-level Error: Overlapping input varnodes
*/


undefined8 FUN_18000c8d0(longlong param_1,int *param_2)

{
  uint uVar1;
  longlong lVar2;
  longlong lVar3;
  void *_Dst;
  ulonglong uVar4;
  uint *puVar5;
  
  lVar2 = *(longlong *)(param_1 + 0x60);
  memcpy((void *)((ulonglong)*(uint *)(lVar2 + 0x3b208) * 0x1d90 + 8 + lVar2),param_2,0x1d90);
  if (*param_2 == 2) {
    lVar3 = (ulonglong)*(uint *)(lVar2 + 0x3b208) * 0x1d90 + 0x10 + lVar2;
    if (param_2[8] != 0) {
      _Dst = (void *)(lVar3 + 0x1a80);
      uVar4 = (ulonglong)(uint)param_2[8];
      puVar5 = (uint *)(lVar3 + 0x1a7c);
      do {
        uVar1 = *(uint *)((longlong)param_2 + (8 - lVar3) + (longlong)puVar5);
        *puVar5 = uVar1;
        memcpy(_Dst,(void *)((longlong)param_2 + (8 - lVar3) + (longlong)_Dst),(ulonglong)uVar1 << 2
              );
        _Dst = (void *)((longlong)_Dst + 0x104);
        puVar5 = puVar5 + 0x41;
        uVar4 = uVar4 - 1;
      } while (uVar4 != 0);
    }
  }
  *(int *)(lVar2 + 0x3b208) = *(int *)(lVar2 + 0x3b208) + 1;
  return 0;
}



bool FUN_18000cf20(undefined8 param_1,ushort *param_2,byte *param_3,byte *param_4,byte **param_5,
                  ushort *param_6,ushort *param_7,ushort **param_8)

{
  byte bVar1;
  byte *pbVar2;
  byte *pbVar3;
  uint uVar4;
  uint uVar5;
  ulonglong uVar6;
  uint uVar7;
  
  *param_5 = param_3;
  *param_8 = param_6;
  pbVar2 = *param_5;
  do {
    if ((pbVar2 == param_4) || (*param_8 == param_7)) {
      return param_3 == pbVar2;
    }
    bVar1 = *pbVar2;
    if (*param_2 < 2) {
      if (bVar1 < 0x80) {
        uVar6 = (ulonglong)(uint)bVar1;
        uVar7 = 0;
LAB_18000cfa4:
        uVar4 = 0;
        uVar5 = 0;
        if (uVar7 != 0) goto LAB_180013451;
        pbVar3 = pbVar2 + 1;
        *param_5 = pbVar3;
      }
      else {
        if (bVar1 < 0xc0) {
          *param_5 = pbVar2 + 1;
          return (bool)2;
        }
        uVar5 = (uint)bVar1;
        if (uVar5 < 0xe0) {
          uVar6 = (ulonglong)(uVar5 & 0x1f);
          uVar7 = 1;
          goto LAB_18000cfa4;
        }
        if (uVar5 < 0xf0) {
          uVar6 = (ulonglong)(uVar5 & 0xf);
          uVar7 = 2;
          goto LAB_18000cfa4;
        }
        if (uVar5 < 0xf8) {
          uVar5 = uVar5 & 7;
          uVar7 = 3;
        }
        else {
          uVar5 = uVar5 & 3;
          uVar7 = 5 - (bVar1 < 0xfc);
        }
        uVar6 = (ulonglong)uVar5;
        uVar5 = 1;
LAB_180013451:
        uVar4 = uVar5;
        if ((longlong)param_4 - (longlong)pbVar2 < (longlong)(int)((uVar7 - uVar4) + 1)) {
          return true;
        }
        pbVar3 = pbVar2 + 1;
        *param_5 = pbVar3;
        if (uVar4 < uVar7) {
          do {
            if (0x3f < *pbVar3 - 0x80) {
              return (bool)2;
            }
            uVar7 = uVar7 - 1;
            uVar6 = (ulonglong)(*pbVar3 & 0x3f | (int)uVar6 << 6);
            pbVar3 = pbVar3 + 1;
            *param_5 = pbVar3;
          } while ((int)uVar4 < (int)uVar7);
        }
        if (uVar4 != 0) {
          uVar6 = (ulonglong)(uint)((int)uVar6 << 6);
        }
      }
      uVar7 = (uint)uVar6;
      if (0x10ffff < uVar7) {
        return (bool)2;
      }
      param_3 = pbVar2;
      if (uVar7 < 0x10000) {
        if (uVar4 != 0) {
          if (pbVar3 == param_4) {
            *param_5 = pbVar2;
            return true;
          }
          bVar1 = *pbVar3;
          *param_5 = pbVar3 + 1;
          if (0x3f < bVar1 - 0x80) {
            return (bool)2;
          }
          uVar6 = (ulonglong)(uVar7 | bVar1 & 0x3f);
        }
        if (*param_2 == 0) {
          *param_2 = 1;
        }
        **param_8 = (ushort)uVar6;
        *param_8 = *param_8 + 1;
      }
      else {
        **param_8 = (short)(uVar6 >> 10) - 0x40U | 0xd800;
        *param_8 = *param_8 + 1;
        *param_2 = (ushort)uVar6 & 0x3ff | 0xdc00;
      }
    }
    else {
      if (0x3f < bVar1 - 0x80) {
        return (bool)2;
      }
      *param_5 = pbVar2 + 1;
      **param_8 = bVar1 & 0x3f | *param_2;
      *param_8 = *param_8 + 1;
      *param_2 = 1;
    }
    pbVar2 = *param_5;
  } while( true );
}



undefined8 FUN_18000d030(longlong *param_1)

{
  int iVar1;
  HANDLE hThread;
  undefined8 uVar2;
  uint uVar3;
  ulonglong uVar4;
  
  *param_1 = 0;
  *(undefined4 *)(param_1 + 1) = 0;
  *(undefined4 *)((longlong)param_1 + 0xc) = 0;
  iVar1 = FUN_18000d0b0();
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    if ((*param_1 != 0) && (uVar4 = 0, *(int *)((longlong)param_1 + 0xc) != 0)) {
      do {
        hThread = OpenThread(0x5a,0,*(DWORD *)(*param_1 + uVar4 * 4));
        if (hThread != (HANDLE)0x0) {
          SuspendThread(hThread);
          CloseHandle(hThread);
        }
        uVar3 = (int)uVar4 + 1;
        uVar4 = (ulonglong)uVar3;
      } while (uVar3 < *(uint *)((longlong)param_1 + 0xc));
    }
    uVar2 = 1;
  }
  return uVar2;
}



void FUN_18000d0b0(LPVOID *param_1)

{
  uint uVar1;
  HANDLE hHeap;
  int iVar2;
  DWORD DVar3;
  HANDLE hObject;
  LPVOID lpMem;
  uint *puVar4;
  undefined auStack88 [32];
  uint local_38 [2];
  DWORD local_30;
  DWORD local_2c;
  ulonglong local_18;
  
  local_18 = DAT_180418010 ^ (ulonglong)auStack88;
  hObject = (HANDLE)CreateToolhelp32Snapshot(4,0);
  if (hObject != (HANDLE)0xffffffffffffffff) {
    local_38[0] = 0x1c;
    iVar2 = Thread32First(hObject,local_38);
    if (iVar2 != 0) {
      do {
        if (((0xf < local_38[0]) && (DVar3 = GetCurrentProcessId(), local_2c == DVar3)) &&
           (DVar3 = GetCurrentThreadId(), hHeap = DAT_18041eba0, local_30 != DVar3)) {
          lpMem = *param_1;
          if (lpMem == (LPVOID)0x0) {
            *(undefined4 *)(param_1 + 1) = 0x80;
            lpMem = HeapAlloc(hHeap,0,0x200);
            *param_1 = lpMem;
            if (lpMem == (LPVOID)0x0) goto LAB_180013554;
          }
          else if (*(uint *)(param_1 + 1) <= *(uint *)((longlong)param_1 + 0xc)) {
            uVar1 = *(uint *)(param_1 + 1) * 2;
            *(uint *)(param_1 + 1) = uVar1;
            lpMem = HeapReAlloc(hHeap,0,lpMem,(ulonglong)uVar1 << 2);
            if (lpMem == (LPVOID)0x0) goto LAB_180013554;
            *param_1 = lpMem;
          }
          puVar4 = (uint *)((longlong)param_1 + 0xc);
          *(DWORD *)((longlong)lpMem + (ulonglong)*puVar4 * 4) = local_30;
          *puVar4 = *puVar4 + 1;
        }
        local_38[0] = 0x1c;
        iVar2 = Thread32Next(hObject,local_38);
      } while (iVar2 != 0);
      DVar3 = GetLastError();
      if (DVar3 != 0x12) {
LAB_180013554:
        if (*param_1 != (LPVOID)0x0) {
          HeapFree(DAT_18041eba0,0,*param_1);
          *param_1 = (LPVOID)0x0;
        }
      }
    }
    CloseHandle(hObject);
  }
  FUN_18000e8c0(local_18 ^ (ulonglong)auStack88);
  return;
}



ulonglong FUN_18000d1d8(undefined8 param_1,longlong param_2,ulonglong param_3)

{
  byte *pbVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  
  uVar3 = 0;
  uVar2 = 0xcbf29ce484222325;
  if (param_3 != 0) {
    do {
      pbVar1 = (byte *)(uVar3 + param_2);
      uVar3 = uVar3 + 1;
      uVar2 = (uVar2 ^ *pbVar1) * 0x100000001b3;
    } while (uVar3 < param_3);
  }
  return uVar2;
}



void FUN_18000d20c(undefined8 *param_1)

{
  *param_1 = std::
             wstring_convert<class_std::codecvt_utf8_utf16<wchar_t,1114111,0>,wchar_t,class_std::allocator<wchar_t>,class_std::allocator<char>_>
             ::vftable;
  FUN_180008a34(param_1 + 8);
  if (0xf < (ulonglong)param_1[7]) {
    FUN_180003f84(param_1[4],param_1[7] + 1);
  }
  param_1[6] = 0;
  *(undefined *)(param_1 + 4) = 0;
  param_1[7] = 0xf;
  FUN_18000d3e4(param_1 + 2);
  return;
}



undefined8 *
FUN_18000d260(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  _Locimp *p_Var1;
  undefined8 *this;
  undefined8 *puVar2;
  
  *param_1 = std::
             wstring_convert<class_std::codecvt_utf8_utf16<wchar_t,1114111,0>,wchar_t,class_std::allocator<wchar_t>,class_std::allocator<char>_>
             ::vftable;
  puVar2 = param_1;
  p_Var1 = std::locale::_Init(true);
  param_1[3] = p_Var1;
  param_1[4] = 0;
  param_1[6] = 0;
  param_1[7] = 0xf;
  *(undefined *)(param_1 + 4) = 0;
  param_1[8] = 0;
  param_1[10] = 0;
  param_1[0xb] = 7;
  *(undefined2 *)(param_1 + 8) = 0;
  *(undefined2 *)(param_1 + 0xd) = 0;
  *(undefined *)((longlong)param_1 + 0x6a) = 0;
  this = (undefined8 *)operator_new(0x40);
  std::codecvt<wchar_t,char,struct__Mbstatet>::codecvt_wchar_t_char_struct__Mbstatet_
            ((codecvt_wchar_t_char_struct__Mbstatet_ *)this,0);
  *this = std::codecvt_utf8_utf16<wchar_t,1114111,0>::vftable;
  FUN_18000d338(param_1,this,param_3,param_4,puVar2);
  return param_1;
}



undefined8 * FUN_18000d2f8(undefined8 *param_1,uint param_2)

{
  *param_1 = std::codecvt_utf8_utf16<wchar_t,1114111,0>::vftable;
  std::codecvt<wchar_t,char,struct__Mbstatet>::_codecvt_wchar_t_char_struct__Mbstatet_
            ((codecvt_wchar_t_char_struct__Mbstatet_ *)param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_18000d338(longlong param_1,facet *param_2)

{
  longlong *this;
  __uint64 _Var1;
  undefined8 *puVar2;
  undefined local_18 [8];
  longlong *local_10;
  
  *(undefined8 *)(param_1 + 0x60) = 0;
  *(facet **)(param_1 + 8) = param_2;
  this = (longlong *)std::locale::_Locimp::_New_Locimp(*(_Locimp **)(param_1 + 0x18));
  local_10 = this;
  if (param_2 != (facet *)0x0) {
    _Var1 = std::locale::id::operator_unsigned___int64((id *)id_exref);
    std::locale::_Locimp::_Addfac((_Locimp *)this,param_2,_Var1);
    *(undefined4 *)(this + 4) = 0;
    std::_Yarn<char>::operator_((_Yarn_char_ *)(this + 5),"*");
  }
  if (*(longlong **)(param_1 + 0x18) != this) {
    puVar2 = (undefined8 *)(**(code **)(**(longlong **)(param_1 + 0x18) + 0x10))();
    if (puVar2 != (undefined8 *)0x0) {
      (**(code **)*puVar2)(puVar2,1);
    }
    *(longlong **)(param_1 + 0x18) = this;
    (**(code **)(*this + 8))(this);
  }
  FUN_18000d3e4(local_18);
  *(undefined8 *)(param_1 + 0x70) = 0;
  return;
}



void FUN_18000d3e4(longlong param_1)

{
  undefined8 *puVar1;
  
  if (*(longlong **)(param_1 + 8) != (longlong *)0x0) {
    puVar1 = (undefined8 *)(**(code **)(**(longlong **)(param_1 + 8) + 0x10))();
    if (puVar1 != (undefined8 *)0x0) {
      (**(code **)*puVar1)(puVar1,1);
    }
  }
  return;
}



undefined4 * FUN_18000d410(undefined4 *param_1,int param_2,uint param_3)

{
  byte bVar1;
  byte bVar2;
  uint uVar3;
  undefined4 local_58;
  undefined4 uStack84;
  undefined4 uStack80;
  undefined4 uStack76;
  undefined4 local_48;
  undefined4 uStack68;
  undefined4 uStack64;
  undefined4 uStack60;
  undefined4 local_38;
  undefined4 uStack52;
  undefined4 uStack48;
  undefined4 uStack44;
  undefined4 local_28;
  undefined4 uStack36;
  undefined4 uStack32;
  undefined4 uStack28;
  undefined8 local_18;
  
  uVar3 = param_3 >> 7;
  bVar2 = (byte)uVar3 & 1;
  bVar1 = (byte)(param_3 >> 6) & 1;
  if (param_2 == 0) {
    FUN_18000d668(param_1,param_3,uVar3 & 0xffffff00 | (uint)bVar1,bVar2);
  }
  else if (param_2 == 1) {
    FUN_18000d71c(param_1,param_3,uVar3 & 0xffffff00 | (uint)bVar1,bVar2);
  }
  else if (param_2 == 2) {
    FUN_18000d7d0(param_1,param_3,uVar3 & 0xffffff00 | (uint)bVar1,bVar2);
  }
  else if (param_2 == 3) {
    FUN_18000d884(param_1,param_3,uVar3 & 0xffffff00 | (uint)bVar1,bVar2);
  }
  else if ((param_2 == 4) || (param_2 == 5)) {
    FUN_18000d508(param_1,param_3,uVar3 & 0xffffff00 | (uint)bVar1,bVar2);
  }
  else if (param_2 == 6) {
    FUN_18000d938(param_1,param_3,uVar3 & 0xffffff00 | (uint)bVar1,bVar2);
  }
  else if (param_2 == 7) {
    FUN_18000d5bc(param_1,param_3,uVar3 & 0xffffff00 | (uint)bVar1);
  }
  else if (param_2 == 8) {
    FUN_18000d9ec(param_1,param_3,uVar3 & 0xffffff00 | (uint)bVar1,bVar2);
  }
  else {
    memset(&local_58,0,0x48);
    *param_1 = local_58;
    param_1[1] = uStack84;
    param_1[2] = uStack80;
    param_1[3] = uStack76;
    param_1[4] = local_48;
    param_1[5] = uStack68;
    param_1[6] = uStack64;
    param_1[7] = uStack60;
    param_1[8] = local_38;
    param_1[9] = uStack52;
    param_1[10] = uStack48;
    param_1[0xb] = uStack44;
    param_1[0xc] = local_28;
    param_1[0xd] = uStack36;
    param_1[0xe] = uStack32;
    param_1[0xf] = uStack28;
    *(undefined8 *)(param_1 + 0x10) = local_18;
  }
  return param_1;
}



undefined8 * FUN_18000d508(undefined8 *param_1,uint param_2,char param_3,char param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  undefined *puVar3;
  longlong lVar4;
  
  uVar1 = (ulonglong)(param_2 & 0x3f);
  if (param_3 == '\0') {
    if (param_4 == '\0') {
      lVar2 = (longlong)*(int *)(&DAT_1800d50c0 + uVar1 * 4);
      lVar4 = lVar2 * 0xd8;
      *param_1 = (&PTR_DAT_1801ef6a8)[lVar2 * 0x1b];
      *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1801ef6a0 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1801ef700 + lVar4);
      *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1801ef6d8 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1801ef6b0 + lVar4);
      param_1[3] = (&PTR_PTR_s_rw_internal_upscaled_color_1801ef708)[lVar2 * 0x1b];
      param_1[4] = (&PTR_DAT_1801ef710)[lVar2 * 0x1b];
      param_1[5] = (&PTR_PTR_s_r_exposure_1801ef6e0)[lVar2 * 0x1b];
      param_1[6] = (&PTR_DAT_1801ef6e8)[lVar2 * 0x1b];
      param_1[7] = (&PTR_PTR_s_cbFSR2_1801ef6b8)[lVar2 * 0x1b];
      puVar3 = (&PTR_DAT_1801ef6c0)[lVar2 * 0x1b];
    }
    else {
      lVar2 = (longlong)*(int *)(&DAT_180080b90 + uVar1 * 4);
      lVar4 = lVar2 * 0xd8;
      *param_1 = (&PTR_DAT_18002e498)[lVar2 * 0x1b];
      *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_18002e490 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_18002e4f0 + lVar4);
      *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_18002e4c8 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_18002e4a0 + lVar4);
      param_1[3] = (&PTR_PTR_s_rw_internal_upscaled_color_18002e4f8)[lVar2 * 0x1b];
      param_1[4] = (&PTR_DAT_18002e500)[lVar2 * 0x1b];
      param_1[5] = (&PTR_PTR_s_r_motion_vectors_18002e4d0)[lVar2 * 0x1b];
      param_1[6] = (&PTR_DAT_18002e4d8)[lVar2 * 0x1b];
      param_1[7] = (&PTR_PTR_s_cbFSR2_18002e4a8)[lVar2 * 0x1b];
      puVar3 = (&PTR_DAT_18002e4b0)[lVar2 * 0x1b];
    }
  }
  else if (param_4 == '\0') {
    lVar2 = (longlong)*(int *)(&DAT_18020b530 + uVar1 * 4);
    lVar4 = lVar2 * 0xd8;
    *param_1 = (&PTR_DAT_18012f168)[lVar2 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_18012f160 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_18012f1c0 + lVar4);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_18012f198 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_18012f170 + lVar4);
    param_1[3] = (&PTR_PTR_s_rw_internal_upscaled_color_18012f1c8)[lVar2 * 0x1b];
    param_1[4] = (&PTR_DAT_18012f1d0)[lVar2 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_exposure_18012f1a0)[lVar2 * 0x1b];
    param_1[6] = (&PTR_DAT_18012f1a8)[lVar2 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbFSR2_18012f178)[lVar2 * 0x1b];
    puVar3 = (&PTR_DAT_18012f180)[lVar2 * 0x1b];
  }
  else {
    lVar2 = (longlong)*(int *)(&DAT_1801a5e00 + uVar1 * 4);
    lVar4 = lVar2 * 0xd8;
    *param_1 = (&PTR_DAT_1801b62b8)[lVar2 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1801b62b0 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1801b6310 + lVar4);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1801b62e8 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1801b62c0 + lVar4);
    param_1[3] = (&PTR_PTR_s_rw_internal_upscaled_color_1801b6318)[lVar2 * 0x1b];
    param_1[4] = (&PTR_DAT_1801b6320)[lVar2 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_exposure_1801b62f0)[lVar2 * 0x1b];
    param_1[6] = (&PTR_DAT_1801b62f8)[lVar2 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbFSR2_1801b62c8)[lVar2 * 0x1b];
    puVar3 = (&PTR_DAT_1801b62d0)[lVar2 * 0x1b];
  }
  param_1[8] = puVar3;
  return param_1;
}



undefined8 * FUN_18000d5bc(undefined8 *param_1,uint param_2,char param_3)

{
  longlong lVar1;
  undefined *puVar2;
  longlong lVar3;
  
  if (param_3 == '\0') {
    lVar1 = (longlong)*(int *)(&DAT_18005d280 + (ulonglong)(param_2 & 0x3f) * 4);
    lVar3 = lVar1 * 0xd8;
    *param_1 = (&PTR_DAT_18005d4a8)[lVar1 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_18005d4a0 + lVar3);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_18005d500 + lVar3);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_18005d4d8 + lVar3);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_18005d4b0 + lVar3);
    param_1[3] = (&PTR_PTR_s_rw_img_mip_shading_change_18005d508)[lVar1 * 0x1b];
    param_1[4] = (&PTR_DAT_18005d510)[lVar1 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_input_color_jittered_18005d4e0)[lVar1 * 0x1b];
    param_1[6] = (&PTR_DAT_18005d4e8)[lVar1 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbFSR2_18005d4b8)[lVar1 * 0x1b];
    puVar2 = (&PTR_DAT_18005d4c0)[lVar1 * 0x1b];
  }
  else {
    lVar1 = (longlong)*(int *)(&DAT_1800cd120 + (ulonglong)(param_2 & 0x3f) * 4);
    lVar3 = lVar1 * 0xd8;
    *param_1 = (&PTR_DAT_18023de78)[lVar1 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_18023de70 + lVar3);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_18023ded0 + lVar3);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_18023dea8 + lVar3);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_18023de80 + lVar3);
    param_1[3] = (&PTR_PTR_s_rw_img_mip_shading_change_18023ded8)[lVar1 * 0x1b];
    param_1[4] = (&PTR_DAT_18023dee0)[lVar1 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_input_color_jittered_18023deb0)[lVar1 * 0x1b];
    param_1[6] = (&PTR_DAT_18023deb8)[lVar1 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbFSR2_18023de88)[lVar1 * 0x1b];
    puVar2 = (&PTR_DAT_18023de90)[lVar1 * 0x1b];
  }
  param_1[8] = puVar2;
  return param_1;
}



undefined8 * FUN_18000d668(undefined8 *param_1,uint param_2,char param_3,char param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  undefined *puVar3;
  longlong lVar4;
  
  uVar1 = (ulonglong)(param_2 & 0x3f);
  if (param_3 == '\0') {
    if (param_4 == '\0') {
      lVar2 = (longlong)*(int *)(&DAT_180100fb0 + uVar1 * 4);
      lVar4 = lVar2 * 0xd8;
      *param_1 = (&PTR_DAT_1801ef2e8)[lVar2 * 0x1b];
      *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1801ef2e0 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1801ef340 + lVar4);
      *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1801ef318 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1801ef2f0 + lVar4);
      param_1[3] = (&PTR_PTR_s_rw_reconstructed_previous_neares_1801ef348)[lVar2 * 0x1b];
      param_1[4] = (&PTR_DAT_1801ef350)[lVar2 * 0x1b];
      param_1[5] = (&PTR_PTR_s_r_input_color_jittered_1801ef320)[lVar2 * 0x1b];
      param_1[6] = (&PTR_DAT_1801ef328)[lVar2 * 0x1b];
      param_1[7] = (&PTR_PTR_s_cbFSR2_1801ef2f8)[lVar2 * 0x1b];
      puVar3 = (&PTR_DAT_1801ef300)[lVar2 * 0x1b];
    }
    else {
      lVar2 = (longlong)*(int *)(&DAT_1800a0c70 + uVar1 * 4);
      lVar4 = lVar2 * 0xd8;
      *param_1 = (&PTR_DAT_180037848)[lVar2 * 0x1b];
      *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_180037840 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1800378a0 + lVar4);
      *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_180037878 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_180037850 + lVar4);
      param_1[3] = (&PTR_PTR_s_rw_reconstructed_previous_neares_1800378a8)[lVar2 * 0x1b];
      param_1[4] = (&PTR_DAT_1800378b0)[lVar2 * 0x1b];
      param_1[5] = (&PTR_PTR_s_r_input_color_jittered_180037880)[lVar2 * 0x1b];
      param_1[6] = (&PTR_DAT_180037888)[lVar2 * 0x1b];
      param_1[7] = (&PTR_PTR_s_cbFSR2_180037858)[lVar2 * 0x1b];
      puVar3 = (&PTR_DAT_180037860)[lVar2 * 0x1b];
    }
  }
  else if (param_4 == '\0') {
    lVar2 = (longlong)*(int *)(&DAT_1800b7280 + uVar1 * 4);
    lVar4 = lVar2 * 0xd8;
    *param_1 = (&PTR_DAT_180146148)[lVar2 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_180146140 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1801461a0 + lVar4);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_180146178 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_180146150 + lVar4);
    param_1[3] = (&PTR_PTR_s_rw_reconstructed_previous_neares_1801461a8)[lVar2 * 0x1b];
    param_1[4] = (&PTR_DAT_1801461b0)[lVar2 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_input_color_jittered_180146180)[lVar2 * 0x1b];
    param_1[6] = (&PTR_DAT_180146188)[lVar2 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbFSR2_180146158)[lVar2 * 0x1b];
    puVar3 = (&PTR_DAT_180146160)[lVar2 * 0x1b];
  }
  else {
    lVar2 = (longlong)*(int *)(&DAT_1801be100 + uVar1 * 4);
    lVar4 = lVar2 * 0xd8;
    *param_1 = (&PTR_DAT_180177b58)[lVar2 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_180177b50 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_180177bb0 + lVar4);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_180177b88 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_180177b60 + lVar4);
    param_1[3] = (&PTR_PTR_s_rw_reconstructed_previous_neares_180177bb8)[lVar2 * 0x1b];
    param_1[4] = (&PTR_DAT_180177bc0)[lVar2 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_input_color_jittered_180177b90)[lVar2 * 0x1b];
    param_1[6] = (&PTR_DAT_180177b98)[lVar2 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbFSR2_180177b68)[lVar2 * 0x1b];
    puVar3 = (&PTR_DAT_180177b70)[lVar2 * 0x1b];
  }
  param_1[8] = puVar3;
  return param_1;
}



undefined8 * FUN_18000d71c(undefined8 *param_1,uint param_2,char param_3,char param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  undefined *puVar3;
  longlong lVar4;
  
  uVar1 = (ulonglong)(param_2 & 0x3f);
  if (param_3 == '\0') {
    if (param_4 == '\0') {
      lVar2 = (longlong)*(int *)(&DAT_1801d8740 + uVar1 * 4);
      lVar4 = lVar2 * 0xd8;
      *param_1 = (&PTR_DAT_180223348)[lVar2 * 0x1b];
      *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_180223340 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1802233a0 + lVar4);
      *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_180223378 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_180223350 + lVar4);
      param_1[3] = (&PTR_PTR_s_rw_depth_clip_1802233a8)[lVar2 * 0x1b];
      param_1[4] = (&PTR_DAT_1802233b0)[lVar2 * 0x1b];
      param_1[5] = (&PTR_PTR_s_r_reconstructed_previous_nearest_180223380)[lVar2 * 0x1b];
      param_1[6] = (&PTR_DAT_180223388)[lVar2 * 0x1b];
      param_1[7] = (&PTR_PTR_s_cbFSR2_180223358)[lVar2 * 0x1b];
      puVar3 = (&PTR_DAT_180223360)[lVar2 * 0x1b];
    }
    else {
      lVar2 = (longlong)*(int *)(&DAT_180037bb0 + uVar1 * 4);
      lVar4 = lVar2 * 0xd8;
      *param_1 = (&PTR_DAT_18008b108)[lVar2 * 0x1b];
      *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_18008b100 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_18008b160 + lVar4);
      *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_18008b138 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_18008b110 + lVar4);
      param_1[3] = (&PTR_PTR_s_rw_depth_clip_18008b168)[lVar2 * 0x1b];
      param_1[4] = (&PTR_DAT_18008b170)[lVar2 * 0x1b];
      param_1[5] = (&PTR_PTR_s_r_reconstructed_previous_nearest_18008b140)[lVar2 * 0x1b];
      param_1[6] = (&PTR_DAT_18008b148)[lVar2 * 0x1b];
      param_1[7] = (&PTR_PTR_s_cbFSR2_18008b118)[lVar2 * 0x1b];
      puVar3 = (&PTR_DAT_18008b120)[lVar2 * 0x1b];
    }
  }
  else if (param_4 == '\0') {
    lVar2 = (longlong)*(int *)(&DAT_1801b61a0 + uVar1 * 4);
    lVar4 = lVar2 * 0xd8;
    *param_1 = (&PTR_DAT_1801a1bb8)[lVar2 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1801a1bb0 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1801a1c10 + lVar4);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1801a1be8 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1801a1bc0 + lVar4);
    param_1[3] = (&PTR_PTR_s_rw_depth_clip_1801a1c18)[lVar2 * 0x1b];
    param_1[4] = (&PTR_DAT_1801a1c20)[lVar2 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_reconstructed_previous_nearest_1801a1bf0)[lVar2 * 0x1b];
    param_1[6] = (&PTR_DAT_1801a1bf8)[lVar2 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbFSR2_1801a1bc8)[lVar2 * 0x1b];
    puVar3 = (&PTR_DAT_1801a1bd0)[lVar2 * 0x1b];
  }
  else {
    lVar2 = (longlong)*(int *)(&DAT_1801ca500 + uVar1 * 4);
    lVar4 = lVar2 * 0xd8;
    *param_1 = (&PTR_DAT_1800cb428)[lVar2 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1800cb420 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1800cb480 + lVar4);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1800cb458 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1800cb430 + lVar4);
    param_1[3] = (&PTR_PTR_s_rw_depth_clip_1800cb488)[lVar2 * 0x1b];
    param_1[4] = (&PTR_DAT_1800cb490)[lVar2 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_reconstructed_previous_nearest_1800cb460)[lVar2 * 0x1b];
    param_1[6] = (&PTR_DAT_1800cb468)[lVar2 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbFSR2_1800cb438)[lVar2 * 0x1b];
    puVar3 = (&PTR_DAT_1800cb440)[lVar2 * 0x1b];
  }
  param_1[8] = puVar3;
  return param_1;
}



undefined8 * FUN_18000d7d0(undefined8 *param_1,uint param_2,char param_3,char param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  undefined *puVar3;
  longlong lVar4;
  
  uVar1 = (ulonglong)(param_2 & 0x3f);
  if (param_3 == '\0') {
    if (param_4 == '\0') {
      lVar2 = (longlong)*(int *)(&DAT_1800bf340 + uVar1 * 4);
      lVar4 = lVar2 * 0xd8;
      *param_1 = (&PTR_DAT_1801f6b98)[lVar2 * 0x1b];
      *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1801f6b90 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1801f6bf0 + lVar4);
      *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1801f6bc8 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1801f6ba0 + lVar4);
      param_1[3] = (&PTR_PTR_s_rw_reconstructed_previous_neares_1801f6bf8)[lVar2 * 0x1b];
      param_1[4] = (&PTR_DAT_1801f6c00)[lVar2 * 0x1b];
      param_1[5] = (&PTR_PTR_s_r_motion_vectors_1801f6bd0)[lVar2 * 0x1b];
      param_1[6] = (&PTR_DAT_1801f6bd8)[lVar2 * 0x1b];
      param_1[7] = (&PTR_PTR_s_cbFSR2_1801f6ba8)[lVar2 * 0x1b];
      puVar3 = (&PTR_DAT_1801f6bb0)[lVar2 * 0x1b];
    }
    else {
      lVar2 = (longlong)*(int *)(&DAT_180080a20 + uVar1 * 4);
      lVar4 = lVar2 * 0xd8;
      *param_1 = (&PTR_DAT_18009c548)[lVar2 * 0x1b];
      *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_18009c540 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_18009c5a0 + lVar4);
      *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_18009c578 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_18009c550 + lVar4);
      param_1[3] = (&PTR_PTR_s_rw_reconstructed_previous_neares_18009c5a8)[lVar2 * 0x1b];
      param_1[4] = (&PTR_DAT_18009c5b0)[lVar2 * 0x1b];
      param_1[5] = (&PTR_PTR_s_r_motion_vectors_18009c580)[lVar2 * 0x1b];
      param_1[6] = (&PTR_DAT_18009c588)[lVar2 * 0x1b];
      param_1[7] = (&PTR_PTR_s_cbFSR2_18009c558)[lVar2 * 0x1b];
      puVar3 = (&PTR_DAT_18009c560)[lVar2 * 0x1b];
    }
  }
  else if (param_4 == '\0') {
    lVar2 = (longlong)*(int *)(&DAT_1801d8560 + uVar1 * 4);
    lVar4 = lVar2 * 0xd8;
    *param_1 = (&PTR_DAT_180170a28)[lVar2 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_180170a20 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_180170a80 + lVar4);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_180170a58 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_180170a30 + lVar4);
    param_1[3] = (&PTR_PTR_s_rw_reconstructed_previous_neares_180170a88)[lVar2 * 0x1b];
    param_1[4] = (&PTR_DAT_180170a90)[lVar2 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_motion_vectors_180170a60)[lVar2 * 0x1b];
    param_1[6] = (&PTR_DAT_180170a68)[lVar2 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbFSR2_180170a38)[lVar2 * 0x1b];
    puVar3 = (&PTR_DAT_180170a40)[lVar2 * 0x1b];
  }
  else {
    lVar2 = (longlong)*(int *)(&DAT_18015bef0 + uVar1 * 4);
    lVar4 = lVar2 * 0xd8;
    *param_1 = (&PTR_DAT_1802051d8)[lVar2 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1802051d0 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_180205230 + lVar4);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_180205208 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1802051e0 + lVar4);
    param_1[3] = (&PTR_PTR_s_rw_reconstructed_previous_neares_180205238)[lVar2 * 0x1b];
    param_1[4] = (&PTR_DAT_180205240)[lVar2 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_motion_vectors_180205210)[lVar2 * 0x1b];
    param_1[6] = (&PTR_DAT_180205218)[lVar2 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbFSR2_1802051e8)[lVar2 * 0x1b];
    puVar3 = (&PTR_DAT_1802051f0)[lVar2 * 0x1b];
  }
  param_1[8] = puVar3;
  return param_1;
}



undefined8 * FUN_18000d884(undefined8 *param_1,uint param_2,char param_3,char param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  undefined *puVar3;
  longlong lVar4;
  
  uVar1 = (ulonglong)(param_2 & 0x3f);
  if (param_3 == '\0') {
    if (param_4 == '\0') {
      lVar2 = (longlong)*(int *)(&DAT_18023dd70 + uVar1 * 4);
      lVar4 = lVar2 * 0xd8;
      *param_1 = (&PTR_DAT_1801328f8)[lVar2 * 0x1b];
      *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1801328f0 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_180132950 + lVar4);
      *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_180132928 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_180132900 + lVar4);
      param_1[3] = (&PTR_PTR_s_rw_lock_status_180132958)[lVar2 * 0x1b];
      param_1[4] = (&PTR_DAT_180132960)[lVar2 * 0x1b];
      param_1[5] = (&PTR_PTR_s_r_lock_status_180132930)[lVar2 * 0x1b];
      param_1[6] = (&PTR_DAT_180132938)[lVar2 * 0x1b];
      param_1[7] = (&PTR_PTR_s_cbFSR2_180132908)[lVar2 * 0x1b];
      puVar3 = (&PTR_DAT_180132910)[lVar2 * 0x1b];
    }
    else {
      lVar2 = (longlong)*(int *)(&DAT_18005d380 + uVar1 * 4);
      lVar4 = lVar2 * 0xd8;
      *param_1 = (&PTR_DAT_1800a8d98)[lVar2 * 0x1b];
      *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1800a8d90 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1800a8df0 + lVar4);
      *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1800a8dc8 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1800a8da0 + lVar4);
      param_1[3] = (&PTR_PTR_s_rw_lock_status_1800a8df8)[lVar2 * 0x1b];
      param_1[4] = (&PTR_DAT_1800a8e00)[lVar2 * 0x1b];
      param_1[5] = (&PTR_PTR_s_r_lock_status_1800a8dd0)[lVar2 * 0x1b];
      param_1[6] = (&PTR_DAT_1800a8dd8)[lVar2 * 0x1b];
      param_1[7] = (&PTR_PTR_s_cbFSR2_1800a8da8)[lVar2 * 0x1b];
      puVar3 = (&PTR_DAT_1800a8db0)[lVar2 * 0x1b];
    }
  }
  else if (param_4 == '\0') {
    lVar2 = (longlong)*(int *)(&DAT_1800b8de0 + uVar1 * 4);
    lVar4 = lVar2 * 0xd8;
    *param_1 = (&PTR_DAT_18016a918)[lVar2 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_18016a910 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_18016a970 + lVar4);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_18016a948 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_18016a920 + lVar4);
    param_1[3] = (&PTR_PTR_s_rw_lock_status_18016a978)[lVar2 * 0x1b];
    param_1[4] = (&PTR_DAT_18016a980)[lVar2 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_lock_status_18016a950)[lVar2 * 0x1b];
    param_1[6] = (&PTR_DAT_18016a958)[lVar2 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbFSR2_18016a928)[lVar2 * 0x1b];
    puVar3 = (&PTR_DAT_18016a930)[lVar2 * 0x1b];
  }
  else {
    lVar2 = (longlong)*(int *)(&DAT_1801406d0 + uVar1 * 4);
    lVar4 = lVar2 * 0xd8;
    *param_1 = (&PTR_DAT_1801d8668)[lVar2 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1801d8660 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1801d86c0 + lVar4);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1801d8698 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1801d8670 + lVar4);
    param_1[3] = (&PTR_PTR_s_rw_lock_status_1801d86c8)[lVar2 * 0x1b];
    param_1[4] = (&PTR_DAT_1801d86d0)[lVar2 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_lock_status_1801d86a0)[lVar2 * 0x1b];
    param_1[6] = (&PTR_DAT_1801d86a8)[lVar2 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbFSR2_1801d8678)[lVar2 * 0x1b];
    puVar3 = (&PTR_DAT_1801d8680)[lVar2 * 0x1b];
  }
  param_1[8] = puVar3;
  return param_1;
}



undefined8 * FUN_18000d938(undefined8 *param_1,uint param_2,char param_3,char param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  undefined *puVar3;
  longlong lVar4;
  
  uVar1 = (ulonglong)(param_2 & 0x3f);
  if (param_3 == '\0') {
    if (param_4 == '\0') {
      lVar2 = (longlong)*(int *)(&DAT_180060790 + uVar1 * 4);
      lVar4 = lVar2 * 0xd8;
      *param_1 = (&PTR_DAT_180024c98)[lVar2 * 0x1b];
      *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_180024c90 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_180024cf0 + lVar4);
      *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_180024cc8 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_180024ca0 + lVar4);
      param_1[3] = (&PTR_PTR_s_rw_upscaled_output_180024cf8)[lVar2 * 0x1b];
      param_1[4] = (&PTR_DAT_180024d00)[lVar2 * 0x1b];
      param_1[5] = (&PTR_PTR_s_r_exposure_180024cd0)[lVar2 * 0x1b];
      param_1[6] = (&PTR_DAT_180024cd8)[lVar2 * 0x1b];
      param_1[7] = (&PTR_PTR_s_cbFSR2_180024ca8)[lVar2 * 0x1b];
      puVar3 = (&PTR_DAT_180024cb0)[lVar2 * 0x1b];
    }
    else {
      lVar2 = (longlong)*(int *)(&DAT_1801464b0 + uVar1 * 4);
      lVar4 = lVar2 * 0xd8;
      *param_1 = (&PTR_DAT_18016e768)[lVar2 * 0x1b];
      *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_18016e760 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_18016e7c0 + lVar4);
      *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_18016e798 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_18016e770 + lVar4);
      param_1[3] = (&PTR_PTR_s_rw_upscaled_output_18016e7c8)[lVar2 * 0x1b];
      param_1[4] = (&PTR_DAT_18016e7d0)[lVar2 * 0x1b];
      param_1[5] = (&PTR_PTR_s_r_exposure_18016e7a0)[lVar2 * 0x1b];
      param_1[6] = (&PTR_DAT_18016e7a8)[lVar2 * 0x1b];
      param_1[7] = (&PTR_PTR_s_cbFSR2_18016e778)[lVar2 * 0x1b];
      puVar3 = (&PTR_DAT_18016e780)[lVar2 * 0x1b];
    }
  }
  else if (param_4 == '\0') {
    lVar2 = (longlong)*(int *)(&DAT_1801ce7d0 + uVar1 * 4);
    lVar4 = lVar2 * 0xd8;
    *param_1 = (&PTR_DAT_1801d83b8)[lVar2 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1801d83b0 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1801d8410 + lVar4);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1801d83e8 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1801d83c0 + lVar4);
    param_1[3] = (&PTR_PTR_s_rw_upscaled_output_1801d8418)[lVar2 * 0x1b];
    param_1[4] = (&PTR_DAT_1801d8420)[lVar2 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_exposure_1801d83f0)[lVar2 * 0x1b];
    param_1[6] = (&PTR_DAT_1801d83f8)[lVar2 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbFSR2_1801d83c8)[lVar2 * 0x1b];
    puVar3 = (&PTR_DAT_1801d83d0)[lVar2 * 0x1b];
  }
  else {
    lVar2 = (longlong)*(int *)(&DAT_18020d8f0 + uVar1 * 4);
    lVar4 = lVar2 * 0xd8;
    *param_1 = (&PTR_DAT_1801988c8)[lVar2 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1801988c0 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_180198920 + lVar4);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1801988f8 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1801988d0 + lVar4);
    param_1[3] = (&PTR_PTR_s_rw_upscaled_output_180198928)[lVar2 * 0x1b];
    param_1[4] = (&PTR_DAT_180198930)[lVar2 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_exposure_180198900)[lVar2 * 0x1b];
    param_1[6] = (&PTR_DAT_180198908)[lVar2 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbFSR2_1801988d8)[lVar2 * 0x1b];
    puVar3 = (&PTR_DAT_1801988e0)[lVar2 * 0x1b];
  }
  param_1[8] = puVar3;
  return param_1;
}



undefined8 * FUN_18000d9ec(undefined8 *param_1,uint param_2,char param_3,char param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  undefined *puVar3;
  longlong lVar4;
  
  uVar1 = (ulonglong)(param_2 & 0x3f);
  if (param_3 == '\0') {
    if (param_4 == '\0') {
      lVar2 = (longlong)*(int *)(&DAT_1800cb520 + uVar1 * 4);
      lVar4 = lVar2 * 0xd8;
      *param_1 = (&PTR_DAT_1801a5cf8)[lVar2 * 0x1b];
      *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1801a5cf0 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1801a5d50 + lVar4);
      *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1801a5d28 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1801a5d00 + lVar4);
      param_1[3] = (&PTR_PTR_s_rw_output_reactive_mask_1801a5d58)[lVar2 * 0x1b];
      param_1[4] = (&PTR_DAT_1801a5d60)[lVar2 * 0x1b];
      param_1[5] = (&PTR_PTR_s_r_input_color_pre_alpha_1801a5d30)[lVar2 * 0x1b];
      param_1[6] = (&PTR_DAT_1801a5d38)[lVar2 * 0x1b];
      param_1[7] = (&PTR_PTR_s_cbGenerateReactive_1801a5d08)[lVar2 * 0x1b];
      puVar3 = (&PTR_DAT_1801a5d10)[lVar2 * 0x1b];
    }
    else {
      lVar2 = (longlong)*(int *)(&DAT_1800a4d40 + uVar1 * 4);
      lVar4 = lVar2 * 0xd8;
      *param_1 = (&PTR_DAT_1800629b8)[lVar2 * 0x1b];
      *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1800629b0 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_180062a10 + lVar4);
      *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1800629e8 + lVar4);
      *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1800629c0 + lVar4);
      param_1[3] = (&PTR_PTR_s_rw_output_reactive_mask_180062a18)[lVar2 * 0x1b];
      param_1[4] = (&PTR_DAT_180062a20)[lVar2 * 0x1b];
      param_1[5] = (&PTR_PTR_s_r_input_color_pre_alpha_1800629f0)[lVar2 * 0x1b];
      param_1[6] = (&PTR_DAT_1800629f8)[lVar2 * 0x1b];
      param_1[7] = (&PTR_PTR_s_cbGenerateReactive_1800629c8)[lVar2 * 0x1b];
      puVar3 = (&PTR_DAT_1800629d0)[lVar2 * 0x1b];
    }
  }
  else if (param_4 == '\0') {
    lVar2 = (longlong)*(int *)(&DAT_18012aed0 + uVar1 * 4);
    lVar4 = lVar2 * 0xd8;
    *param_1 = (&PTR_DAT_1800d4fb8)[lVar2 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1800d4fb0 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1800d5010 + lVar4);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1800d4fe8 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1800d4fc0 + lVar4);
    param_1[3] = (&PTR_PTR_s_rw_output_reactive_mask_1800d5018)[lVar2 * 0x1b];
    param_1[4] = (&PTR_DAT_1800d5020)[lVar2 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_input_color_pre_alpha_1800d4ff0)[lVar2 * 0x1b];
    param_1[6] = (&PTR_DAT_1800d4ff8)[lVar2 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbGenerateReactive_1800d4fc8)[lVar2 * 0x1b];
    puVar3 = (&PTR_DAT_1800d4fd0)[lVar2 * 0x1b];
  }
  else {
    lVar2 = (longlong)*(int *)(&DAT_18020da00 + uVar1 * 4);
    lVar4 = lVar2 * 0xd8;
    *param_1 = (&PTR_DAT_1800bcf88)[lVar2 * 0x1b];
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1800bcf80 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1800bcfe0 + lVar4);
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1800bcfb8 + lVar4);
    *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1800bcf90 + lVar4);
    param_1[3] = (&PTR_PTR_s_rw_output_reactive_mask_1800bcfe8)[lVar2 * 0x1b];
    param_1[4] = (&PTR_DAT_1800bcff0)[lVar2 * 0x1b];
    param_1[5] = (&PTR_PTR_s_r_input_color_pre_alpha_1800bcfc0)[lVar2 * 0x1b];
    param_1[6] = (&PTR_DAT_1800bcfc8)[lVar2 * 0x1b];
    param_1[7] = (&PTR_PTR_s_cbGenerateReactive_1800bcf98)[lVar2 * 0x1b];
    puVar3 = (&PTR_DAT_1800bcfa0)[lVar2 * 0x1b];
  }
  param_1[8] = puVar3;
  return param_1;
}



void FUN_18000daa0(LPVOID *param_1)

{
  HANDLE hThread;
  uint uVar1;
  ulonglong uVar2;
  
  if (*param_1 != (LPVOID)0x0) {
    uVar2 = 0;
    if (*(int *)((longlong)param_1 + 0xc) != 0) {
      do {
        hThread = OpenThread(0x5a,0,*(DWORD *)((longlong)*param_1 + uVar2 * 4));
        if (hThread != (HANDLE)0x0) {
          ResumeThread(hThread);
          CloseHandle(hThread);
        }
        uVar1 = (int)uVar2 + 1;
        uVar2 = (ulonglong)uVar1;
      } while (uVar1 < *(uint *)((longlong)param_1 + 0xc));
    }
    HeapFree(DAT_18041eba0,0,*param_1);
  }
  return;
}



undefined8 *
FUN_18000db14(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3,undefined8 *param_4,
             undefined4 *param_5)

{
  void *_Dst;
  undefined8 uVar1;
  
  _Dst = operator_new(0xd0);
  memset(_Dst,0,0xd0);
  uVar1 = FUN_18000db88(_Dst,*param_2,*param_3,*param_4,*param_5);
  *param_1 = uVar1;
  return param_1;
}



void FUN_18000db88(undefined8 *param_1,undefined8 param_2,undefined8 param_3,longlong *param_4,
                  undefined4 param_5)

{
  longlong **pplVar1;
  undefined auStack136 [32];
  undefined8 *local_68;
  undefined local_60 [16];
  undefined4 local_50;
  undefined4 local_48;
  undefined4 local_40;
  ulonglong local_28;
  
  local_28 = DAT_180418010 ^ (ulonglong)auStack136;
  *param_1 = param_2;
  pplVar1 = (longlong **)(param_1 + 1);
  *pplVar1 = (longlong *)0x0;
  param_1[2] = 0;
  *(undefined4 *)(param_1 + 3) = 0;
  *(undefined4 *)((longlong)param_1 + 0x1c) = param_5;
  *(undefined4 *)(param_1 + 4) = 0xffffffff;
  *(undefined4 *)((longlong)param_1 + 0x24) = 0xffffffff;
  *(undefined4 *)(param_1 + 5) = 0xffffffff;
  *(undefined4 *)((longlong)param_1 + 0x2c) = 1;
  param_1[6] = 0;
  *(undefined (*) [16])(param_1 + 7) = ZEXT816(0);
  *(undefined (*) [16])(param_1 + 9) = ZEXT816(0);
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  *(undefined (*) [16])(param_1 + 0xd) = ZEXT816(0);
  *(undefined (*) [16])(param_1 + 0xf) = ZEXT816(0);
  param_1[0x11] = 0;
  param_1[0x12] = 0;
  *(undefined (*) [16])(param_1 + 0x13) = ZEXT816(0);
  param_1[0x15] = 0;
  param_1[0x16] = 0;
  *(undefined (*) [16])(param_1 + 0x17) = ZEXT816(0);
  param_1[0x19] = 0;
  local_68 = param_1;
  (**(code **)(*param_4 + 0x50))(param_4,local_60);
  *(undefined4 *)(param_1 + 2) = local_50;
  *(undefined4 *)((longlong)param_1 + 0x14) = local_48;
  *(undefined4 *)(param_1 + 3) = local_40;
  FUN_18000dca0(pplVar1,param_4);
  (**(code **)(**pplVar1 + 0x30))(*pplVar1,param_3);
  FUN_18000e8c0(local_28 ^ (ulonglong)auStack136);
  return;
}



longlong ** FUN_18000dca0(longlong **param_1,longlong *param_2)

{
  longlong *local_res8;
  
  if (*param_1 != param_2) {
    if (param_2 != (longlong *)0x0) {
      (**(code **)(*param_2 + 8))(param_2);
    }
    local_res8 = *param_1;
    *param_1 = param_2;
    FUN_18000e0d4(&local_res8);
  }
  return param_1;
}



void FUN_18000dce8(longlong *param_1,int param_2,undefined4 param_3)

{
  void *pvVar1;
  undefined auStack520 [32];
  undefined4 local_1e8;
  void *local_1d8;
  undefined4 local_1d0 [2];
  undefined8 local_1c8;
  ulonglong local_1c0;
  undefined4 local_1b8;
  undefined4 local_1b4;
  undefined4 local_1b0;
  undefined8 local_1ac;
  undefined4 local_1a4;
  undefined4 local_1a0;
  undefined4 local_198 [2];
  undefined8 local_190;
  undefined8 local_188;
  undefined4 local_180;
  undefined4 local_17c;
  undefined4 local_178;
  undefined8 local_174;
  undefined8 local_16c;
  undefined4 local_160 [2];
  undefined8 local_158;
  undefined8 local_150;
  undefined4 local_148;
  undefined4 local_144;
  undefined4 local_140;
  undefined8 local_13c;
  undefined4 local_134;
  undefined4 local_130;
  undefined4 local_128 [2];
  undefined8 local_120;
  undefined8 local_118;
  undefined4 local_110;
  undefined4 local_10c;
  undefined4 local_108;
  undefined8 local_104;
  undefined4 local_fc;
  undefined4 local_f8;
  undefined8 local_e0;
  undefined4 local_d8;
  undefined4 local_d0;
  undefined8 local_a8;
  undefined4 local_a0;
  undefined4 local_98;
  undefined8 local_70;
  undefined4 local_68;
  undefined4 local_60;
  ulonglong local_48;
  
  local_48 = DAT_180418010 ^ (ulonglong)auStack520;
  local_1d0[0] = 3;
  local_1c8 = 0;
  local_1b4 = 0x10001;
  local_1b0 = 0x3d;
  local_1ac = 1;
  local_1a4 = 0;
  local_1a0 = 4;
  local_1c0 = (longlong)param_2;
  local_1b8 = param_3;
  pvVar1 = operator_new(0xd0);
  local_1d8 = pvVar1;
  memset(pvVar1,0,0xd0);
  local_1e8 = 0x40;
  local_1d8 = (void *)FUN_18000474c(pvVar1,param_1[1],L"Reactive Mask",local_1d0);
  FUN_18000e004(param_1 + 0xc,&local_1d8);
  pvVar1 = local_1d8;
  if (local_1d8 != (void *)0x0) {
    FUN_18000e0d4((longlong)local_1d8 + 8);
    free(pvVar1);
  }
  (**(code **)(**(longlong **)(param_1[6] + 8) + 0x50))();
  local_198[0] = 3;
  local_190 = 0;
  local_188 = local_e0;
  local_180 = local_d8;
  local_17c = 0x10001;
  local_178 = local_d0;
  local_174 = 1;
  local_16c = 0;
  pvVar1 = operator_new(0xd0);
  local_1d8 = pvVar1;
  memset(pvVar1,0,0xd0);
  local_1e8 = 0x40;
  local_1d8 = (void *)FUN_18000474c(pvVar1,param_1[1],L"History DepthTex",local_198);
  FUN_18000e004(param_1 + 0xe,&local_1d8);
  pvVar1 = local_1d8;
  if (local_1d8 != (void *)0x0) {
    FUN_18000e0d4((longlong)local_1d8 + 8);
    free(pvVar1);
  }
  (**(code **)(**(longlong **)(param_1[5] + 8) + 0x50))();
  local_160[0] = 3;
  local_158 = 0;
  local_150 = local_a8;
  local_148 = local_a0;
  local_144 = 0x10001;
  local_140 = local_98;
  local_13c = 1;
  local_134 = 0;
  local_130 = 4;
  pvVar1 = operator_new(0xd0);
  local_1d8 = pvVar1;
  memset(pvVar1,0,0xd0);
  local_1e8 = 0x40;
  local_1d8 = (void *)FUN_18000474c(pvVar1,param_1[1],L"DebugTex",local_160);
  FUN_18000e004(param_1 + 0xf,&local_1d8);
  pvVar1 = local_1d8;
  if (local_1d8 != (void *)0x0) {
    FUN_18000e0d4((longlong)local_1d8 + 8);
    free(pvVar1);
  }
  (**(code **)(**(longlong **)(param_1[8] + 8) + 0x50))();
  local_128[0] = 3;
  local_120 = 0;
  local_118 = local_70;
  local_110 = local_68;
  local_10c = 0x10001;
  local_108 = local_60;
  local_104 = 1;
  local_fc = 0;
  local_f8 = 4;
  pvVar1 = operator_new(0xd0);
  local_1d8 = pvVar1;
  memset(pvVar1,0,0xd0);
  local_1e8 = 0x40;
  local_1d8 = (void *)FUN_18000474c(pvVar1,param_1[1],L"OutputMotionTex",local_128);
  FUN_18000e004(param_1 + 0xd,&local_1d8);
  pvVar1 = local_1d8;
  if (local_1d8 != (void *)0x0) {
    FUN_18000e0d4((longlong)local_1d8 + 8);
    free(pvVar1);
  }
  (**(code **)(*param_1 + 0x28))(param_1,(longlong)param_2 & 0xffffffff,param_3);
  FUN_18000e8c0(local_48 ^ (ulonglong)auStack520);
  return;
}



void ** FUN_18000e004(void **param_1,void **param_2)

{
  void *pvVar1;
  void *_Memory;
  
  if (param_1 != param_2) {
    pvVar1 = *param_2;
    *param_2 = (void *)0x0;
    _Memory = *param_1;
    *param_1 = pvVar1;
    if (_Memory != (void *)0x0) {
      FUN_18000e0d4((longlong)_Memory + 8);
      free(_Memory);
    }
  }
  return param_1;
}



void FUN_18000e03c(longlong param_1,int param_2,int param_3)

{
  longlong lVar1;
  
  FUN_180005010(*(undefined8 *)(param_1 + 0x80),*(undefined8 *)(param_1 + 0x30),
                *(undefined8 *)(param_1 + 0x38),*(undefined8 *)(param_1 + 0x40),
                *(undefined8 *)(param_1 + 0x70),*(undefined8 *)(param_1 + 0x48),
                *(undefined8 *)(param_1 + 0x60),*(undefined8 *)(param_1 + 0x68),
                *(undefined8 *)(param_1 + 0x28),*(undefined8 *)(param_1 + 0x78));
  lVar1 = *(longlong *)(param_1 + 0x80);
  *(int *)(lVar1 + 0x18) = (param_2 + 0xf) / 0x10;
  *(int *)(lVar1 + 0x1c) = (param_3 + 0xf) / 0x10;
  *(undefined *)(param_1 + 0x20) = 1;
  return;
}



void FUN_18000e0d4(longlong **param_1)

{
  longlong *plVar1;
  
  plVar1 = *param_1;
  if (plVar1 != (longlong *)0x0) {
    *param_1 = (longlong *)0x0;
    (**(code **)(*plVar1 + 0x10))();
  }
  return;
}



void FUN_18000e0f4(longlong **param_1)

{
  longlong *plVar1;
  
  plVar1 = *param_1;
  if (plVar1 != (longlong *)0x0) {
    *param_1 = (longlong *)0x0;
    (**(code **)(*plVar1 + 0x10))();
  }
  return;
}



void FUN_18000e118(void **param_1)

{
  longlong *plVar1;
  
  FUN_180003eb4(param_1 + 0x2061);
  plVar1 = (longlong *)param_1[2];
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x18))(plVar1,1);
  }
  if (*param_1 != (void *)0x0) {
    free(*param_1);
  }
  return;
}



undefined4 * FUN_18000e154(undefined4 *param_1,undefined4 *param_2)

{
  longlong *plVar1;
  undefined8 uVar2;
  undefined8 *puVar3;
  undefined8 local_res8;
  
  *param_1 = *param_2;
  param_1[1] = param_2[1];
  param_1[2] = param_2[2];
  puVar3 = (undefined8 *)(param_2 + 4);
  uVar2 = 0;
  if (&local_res8 != puVar3) {
    uVar2 = *puVar3;
    *puVar3 = 0;
  }
  plVar1 = *(longlong **)(param_1 + 4);
  *(undefined8 *)(param_1 + 4) = uVar2;
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))();
  }
  param_1[6] = param_2[6];
  param_1[7] = param_2[7];
  param_1[8] = param_2[8];
  puVar3 = (undefined8 *)(param_2 + 10);
  uVar2 = 0;
  if (&local_res8 != puVar3) {
    uVar2 = *puVar3;
    *puVar3 = 0;
  }
  plVar1 = *(longlong **)(param_1 + 10);
  *(undefined8 *)(param_1 + 10) = uVar2;
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))();
  }
  param_1[0xc] = param_2[0xc];
  param_1[0xd] = param_2[0xd];
  param_1[0xe] = param_2[0xe];
  puVar3 = (undefined8 *)(param_2 + 0x10);
  uVar2 = 0;
  if (&local_res8 != puVar3) {
    uVar2 = *puVar3;
    *puVar3 = 0;
  }
  plVar1 = *(longlong **)(param_1 + 0x10);
  *(undefined8 *)(param_1 + 0x10) = uVar2;
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))();
  }
  param_1[0x12] = param_2[0x12];
  param_1[0x13] = param_2[0x13];
  param_1[0x14] = param_2[0x14];
  puVar3 = (undefined8 *)(param_2 + 0x16);
  uVar2 = 0;
  if (&local_res8 != puVar3) {
    uVar2 = *puVar3;
    *puVar3 = 0;
  }
  plVar1 = *(longlong **)(param_1 + 0x16);
  *(undefined8 *)(param_1 + 0x16) = uVar2;
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))();
  }
  return param_1;
}



void FUN_18000e278(int *param_1,int param_2,int *param_3)

{
  int iVar1;
  int iVar2;
  undefined auStack72 [32];
  longlong local_28;
  longlong local_20;
  ulonglong local_18;
  
  local_18 = DAT_180418010 ^ (ulonglong)auStack72;
  if (*param_1 + param_2 <= param_1[1]) {
    (**(code **)(**(longlong **)(param_1 + 4) + 0x48))(*(longlong **)(param_1 + 4),&local_28);
    local_28 = local_28 + (longlong)param_1[2] * (longlong)*param_1;
    (**(code **)(**(longlong **)(param_1 + 4) + 0x50))(*(longlong **)(param_1 + 4),&local_20);
    iVar1 = *param_1;
    iVar2 = param_1[2];
    *param_1 = iVar1 + param_2;
    *(longlong *)(param_3 + 4) = local_20 + (longlong)iVar2 * (longlong)iVar1;
    *(longlong *)(param_3 + 2) = local_28;
    *param_3 = param_2;
    param_3[1] = iVar2;
  }
  FUN_18000e8c0(local_18 ^ (ulonglong)auStack72);
  return;
}



void FUN_18000e32c(longlong param_1)

{
  if (*(longlong *)(param_1 + 0x10) != 0) {
    FUN_18000e344();
  }
  return;
}



void * FUN_18000e344(void *param_1)

{
  FUN_18000e368();
  free(param_1);
  return param_1;
}



void FUN_18000e368(longlong param_1)

{
  FUN_180003f84(*(longlong *)(param_1 + 0x58),
                *(longlong *)(param_1 + 0x60) - *(longlong *)(param_1 + 0x58) & 0xfffffffffffffff8);
  *(undefined8 *)(param_1 + 0x58) = 0;
  *(undefined8 *)(param_1 + 0x60) = 0;
  *(undefined8 *)(param_1 + 0x68) = 0;
  FUN_18000e3f4();
  FUN_180003f84(*(undefined8 *)(param_1 + 0x48),0x20);
  if (*(longlong *)(param_1 + 0x28) != 0) {
    FUN_18000e450(*(longlong *)(param_1 + 0x28),*(undefined8 *)(param_1 + 0x30));
    FUN_180003f84(*(longlong *)(param_1 + 0x28),
                  *(longlong *)(param_1 + 0x38) - *(longlong *)(param_1 + 0x28) & 0xfffffffffffffff8
                 );
    *(undefined8 *)(param_1 + 0x28) = 0;
    *(undefined8 *)(param_1 + 0x30) = 0;
    *(undefined8 *)(param_1 + 0x38) = 0;
  }
  if (*(longlong *)(param_1 + 8) != 0) {
    FUN_1800030d8();
  }
  return;
}



void FUN_18000e3f4(undefined8 param_1,undefined8 *param_2)

{
  void *_Memory;
  undefined8 *puVar1;
  undefined8 *puVar2;
  
  *(undefined8 *)param_2[1] = 0;
  puVar2 = (undefined8 *)*param_2;
  while (puVar2 != (undefined8 *)0x0) {
    _Memory = (void *)puVar2[3];
    puVar1 = (undefined8 *)*puVar2;
    if (_Memory != (void *)0x0) {
      FUN_18000e118(_Memory);
      free(_Memory);
    }
    FUN_180003f84(puVar2,0x20);
    puVar2 = puVar1;
  }
  return;
}



void FUN_18000e428(longlong *param_1)

{
  if (*param_1 != param_1[1]) {
    FUN_18000e450(*param_1);
    param_1[1] = *param_1;
  }
  return;
}



void FUN_18000e450(void **param_1,void **param_2)

{
  if (param_1 != param_2) {
    do {
      if (*param_1 != (void *)0x0) {
        free(*param_1);
      }
      param_1 = param_1 + 1;
    } while (param_1 != param_2);
    return;
  }
  return;
}



void FUN_18000e48c(longlong param_1)

{
  void *_Memory;
  
  _Memory = *(void **)(param_1 + 0x10);
  if (_Memory != (void *)0x0) {
    FUN_180008a34((longlong)_Memory + 0xa0);
    FUN_1800029b4((longlong)_Memory + 0x50);
    free(_Memory);
  }
  return;
}



undefined8 *
FUN_18000e4c4(undefined8 param_1,undefined8 *param_2,longlong *param_3,ulonglong param_4)

{
  undefined8 *puVar1;
  
  puVar1 = *(undefined8 **)(DAT_18041ebd8 + 8 + (DAT_18041ebf0 & param_4) * 0x10);
  if (puVar1 == DAT_18041ebc8) {
    *param_2 = DAT_18041ebc8;
LAB_18000e4f3:
    param_2[1] = 0;
  }
  else {
    for (; *param_3 != puVar1[2]; puVar1 = (undefined8 *)puVar1[1]) {
      if (puVar1 == *(undefined8 **)(DAT_18041ebd8 + (DAT_18041ebf0 & param_4) * 0x10)) {
        *param_2 = puVar1;
        goto LAB_18000e4f3;
      }
    }
    *param_2 = *puVar1;
    param_2[1] = puVar1;
  }
  return param_2;
}



void FUN_18000e544(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  undefined8 uVar1;
  undefined8 *puVar2;
  undefined8 local_res10;
  undefined8 local_res18;
  undefined8 local_res20;
  
  local_res10 = param_2;
  local_res18 = param_3;
  local_res20 = param_4;
  uVar1 = __acrt_iob_func(1);
  puVar2 = (undefined8 *)FUN_18000e594();
  __stdio_common_vfprintf(*puVar2,uVar1,param_1,0,&local_res10);
  return;
}



undefined * FUN_18000e594(void)

{
  return &DAT_18041eb80;
}



void thunk_FUN_180008a34(undefined8 *param_1)

{
  if (7 < (ulonglong)param_1[3]) {
    FUN_180003f84(*param_1,param_1[3] * 2 + 2);
  }
  param_1[2] = 0;
  *(undefined2 *)param_1 = 0;
  param_1[3] = 7;
  return;
}



void FUN_18000e5a4(longlong *param_1)

{
  if (param_1 != (longlong *)0x0) {
    (**(code **)(*param_1 + 0x10))(param_1,1);
  }
  return;
}



void * FUN_18000e5c0(void *param_1,ulonglong param_2)

{
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_18000e5e4(undefined8 param_1,undefined8 param_2,longlong *param_3)

{
  char cVar1;
  longlong *plVar2;
  
  cVar1 = *(char *)((longlong)param_3 + 0x19);
  while (cVar1 == '\0') {
    FUN_18000e5e4(param_1,param_2,param_3[2]);
    plVar2 = (longlong *)*param_3;
    FUN_18001494c(param_3 + 7,param_3 + 7,*(undefined8 *)(param_3[7] + 8));
    FUN_180003f84(param_3[7],0x40);
    FUN_180003f84(param_3,0x48);
    param_3 = plVar2;
    cVar1 = *(char *)((longlong)plVar2 + 0x19);
  }
  return;
}



void FUN_18000e610(longlong param_1)

{
  undefined8 uVar1;
  ulonglong uVar2;
  undefined8 *puVar3;
  
  if (*(longlong *)(param_1 + 0x10) != 0) {
    uVar2 = *(ulonglong *)(param_1 + 0x38) >> 3;
    if (uVar2 < *(ulonglong *)(param_1 + 0x10) || uVar2 == *(ulonglong *)(param_1 + 0x10)) {
      FUN_18000e3f4();
      *(undefined8 *)*(undefined8 *)(param_1 + 8) = *(undefined8 *)(param_1 + 8);
      *(longlong *)(*(longlong *)(param_1 + 8) + 8) = *(longlong *)(param_1 + 8);
      *(undefined8 *)(param_1 + 0x10) = 0;
      puVar3 = *(undefined8 **)(param_1 + 0x18);
      uVar1 = *(undefined8 *)(param_1 + 8);
      uVar2 = (*(longlong *)(param_1 + 0x20) - (longlong)puVar3) + 7U >> 3;
      if (*(undefined8 **)(ulonglong *)(param_1 + 0x20) <= puVar3 &&
          puVar3 != *(undefined8 **)(ulonglong *)(param_1 + 0x20)) {
        uVar2 = 0;
      }
      if (uVar2 != 0) {
        for (; uVar2 != 0; uVar2 = uVar2 - 1) {
          *puVar3 = uVar1;
          puVar3 = puVar3 + 1;
        }
      }
    }
    else {
      FUN_180017660(param_1,**(undefined8 **)(param_1 + 8),*(undefined8 **)(param_1 + 8));
    }
  }
  return;
}



undefined8 NVSDK_NGX_D3D12_Init(void)

{
                    // 0xe640  8  NVSDK_NGX_D3D12_Init
                    // 0xe640  9  NVSDK_NGX_D3D12_Init_Ext
                    // 0xe640  10  NVSDK_NGX_D3D12_Init_ProjectID
                    // 0xe640  11  NVSDK_NGX_D3D12_Init_with_ProjectID
  return 1;
}



undefined4 * FUN_18000e650(undefined8 param_1,undefined4 *param_2,undefined4 param_3)

{
  *param_2 = param_3;
  *(undefined8 *)(param_2 + 2) = param_1;
  return param_2;
}



char * FUN_18000e660(void)

{
  return "generic";
}



char * FUN_18000e670(void)

{
  return "system";
}



char * FUN_18000e680(void)

{
  return "Bad optional access";
}



undefined8 FUN_18000e690(void)

{
  return 0;
}



undefined8 FUN_18000e6a0(longlong param_1)

{
  return *(undefined8 *)(param_1 + 8);
}



undefined4 FUN_18000e6b0(longlong param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}



undefined4 FUN_18000e6c0(longlong param_1)

{
  return *(undefined4 *)(*(longlong *)(param_1 + 8) + 8);
}



undefined4 FUN_18000e6d0(longlong param_1)

{
  return *(undefined4 *)(param_1 + 8);
}



undefined4 FUN_18000e6e0(longlong param_1)

{
  return **(undefined4 **)(param_1 + 8);
}



undefined4 FUN_18000e6f0(longlong param_1)

{
  return *(undefined4 *)(param_1 + 0x10);
}



undefined4 FUN_18000e700(longlong param_1)

{
  return *(undefined4 *)(*(longlong *)(param_1 + 8) + 4);
}



undefined FUN_18000e710(void)

{
  return 0;
}



undefined8 FUN_18000e720(void)

{
  return 0;
}



undefined8 FUN_18000e730(void)

{
  return 6;
}



undefined8
FUN_18000e740(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
             undefined8 *param_5)

{
  *param_5 = param_3;
  return 3;
}



void FUN_18000e750(longlong param_1)

{
  FUN_180003f84(*(longlong *)(param_1 + 0x18),
                *(longlong *)(param_1 + 0x20) - *(longlong *)(param_1 + 0x18) & 0xfffffffffffffff8);
  *(undefined8 *)(param_1 + 0x18) = 0;
  *(undefined8 *)(param_1 + 0x20) = 0;
  *(undefined8 *)(param_1 + 0x28) = 0;
  FUN_180003f50();
  FUN_180003f84(*(undefined8 *)(param_1 + 8),0x20);
  return;
}



ulonglong FUN_18000e798(void)

{
  UINT UVar1;
  BOOL BVar2;
  ulonglong uVar3;
  
  UVar1 = ___lc_codepage_func();
  uVar3 = 0xfde9;
  if (UVar1 != 0xfde9) {
    BVar2 = AreFileApisANSI();
    uVar3 = (ulonglong)(BVar2 == 0);
  }
  return uVar3;
}



// Library Function - Single Match
//  __std_fs_convert_narrow_to_wide
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8
__std_fs_convert_narrow_to_wide(UINT param_1,LPCSTR param_2,int param_3,LPWSTR param_4,int param_5)

{
  int iVar1;
  DWORD DStack20;
  
  iVar1 = MultiByteToWideChar(param_1,8,param_2,param_3,param_4,param_5);
  if (iVar1 == 0) {
    DStack20 = GetLastError();
  }
  else {
    DStack20 = 0;
  }
  return CONCAT44(DStack20,iVar1);
}



ulonglong FUN_18000e808(DWORD param_1,longlong *param_2)

{
  int iVar1;
  DWORD DVar2;
  ulonglong uVar3;
  byte *pbVar4;
  uint local_res18 [4];
  
  iVar1 = GetLocaleInfoEx(L"!x-sys-default-locale",0x20000001,(LPWSTR)local_res18,2);
  local_res18[0] = -(uint)(iVar1 != 0) & local_res18[0];
  DVar2 = FormatMessageA(0x1300,(LPCVOID)0x0,param_1,local_res18[0],(LPSTR)param_2,0,(va_list *)0x0)
  ;
  uVar3 = (ulonglong)DVar2;
  if (DVar2 != 0) {
    pbVar4 = (byte *)(*param_2 + -1 + uVar3);
    do {
      if ((&DAT_18001e200)[*pbVar4] == '\0') {
        return uVar3;
      }
      pbVar4 = pbVar4 + -1;
      uVar3 = uVar3 - 1;
    } while (uVar3 != 0);
  }
  return uVar3;
}



HLOCAL LocalFree(HLOCAL hMem)

{
  HLOCAL pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000e89c. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = LocalFree(hMem);
  return pvVar1;
}



// WARNING: Exceeded maximum restarts with more pending

_Facet_base * __thiscall std::locale::facet::_Decref(facet *this)

{
  _Facet_base *p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x00018000e8a3. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = (_Facet_base *)_Decref();
  return p_Var1;
}



// WARNING: Exceeded maximum restarts with more pending

void __thiscall std::locale::facet::_Incref(facet *this)

{
                    // WARNING: Could not recover jumptable at 0x00018000e8a9. Too many branches
                    // WARNING: Treating indirect jump as call
  _Incref();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_18000e8c0(longlong param_1)

{
  code *pcVar1;
  BOOL BVar2;
  undefined *puVar3;
  undefined auStack56 [8];
  undefined auStack48 [48];
  
  if ((param_1 == DAT_180418010) && ((short)((ulonglong)param_1 >> 0x30) == 0)) {
    return;
  }
  puVar3 = auStack56;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(2);
    puVar3 = auStack48;
  }
  *(undefined8 *)(puVar3 + -8) = 0x18000f483;
  capture_previous_context(&DAT_18041e680);
  _DAT_18041e5f0 = *(undefined8 *)(puVar3 + 0x38);
  _DAT_18041e718 = puVar3 + 0x40;
  _DAT_18041e700 = *(undefined8 *)(puVar3 + 0x40);
  _DAT_18041e5e0 = 0xc0000409;
  _DAT_18041e5e4 = 1;
  _DAT_18041e5f8 = 1;
  DAT_18041e600 = 2;
  *(longlong *)(puVar3 + 0x20) = DAT_180418010;
  *(undefined8 *)(puVar3 + 0x28) = DAT_180418008;
  *(undefined8 *)(puVar3 + -8) = 0x18000f525;
  DAT_18041e778 = _DAT_18041e5f0;
  __raise_securityfailure(&PTR_DAT_18001e408);
  return;
}



undefined8 * FUN_18000e8e0(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = type_info::vftable;
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void free(void *_Memory)

{
  free(_Memory);
  return;
}



void free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x00018000facc. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



// Library Function - Single Match
//  void * __ptr64 __cdecl operator new(unsigned __int64)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void * operator_new(__uint64 param_1)

{
  code *pcVar1;
  int iVar2;
  void *pvVar3;
  
  do {
    pvVar3 = malloc(param_1);
    if (pvVar3 != (void *)0x0) {
      return pvVar3;
    }
    iVar2 = _callnewh(param_1);
  } while (iVar2 != 0);
  if (param_1 == 0xffffffffffffffff) {
    FUN_18000f5e0();
    pcVar1 = (code *)swi(3);
    pvVar3 = (void *)(*pcVar1)();
    return pvVar3;
  }
  FUN_18000f5c0();
  pcVar1 = (code *)swi(3);
  pvVar3 = (void *)(*pcVar1)();
  return pvVar3;
}



void FUN_18000ea80(int *param_1)

{
  ulonglong uVar1;
  longlong in_GS_OFFSET;
  
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18041e550);
  uVar1 = (ulonglong)DAT_18041eb54;
  DAT_180418000 = DAT_180418000 + 1;
  *param_1 = DAT_180418000;
  *(int *)(*(longlong *)(*(longlong *)(in_GS_OFFSET + 0x58) + uVar1 * 8) + 4) = DAT_180418000;
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18041e550);
  if (DAT_18041e580 == (code *)0x0) {
    SetEvent(DAT_18041e548);
                    // WARNING: Could not recover jumptable at 0x00018000eb82. Too many branches
                    // WARNING: Treating indirect jump as call
    ResetEvent(DAT_18041e548);
    return;
  }
                    // WARNING: Could not recover jumptable at 0x00018000fc80. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_18041e580)(&DAT_18041e540);
  return;
}



// Library Function - Single Match
//  _Init_thread_header
// 
// Library: Visual Studio 2019 Release

void _Init_thread_header(int *param_1)

{
  longlong in_GS_OFFSET;
  
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18041e550);
  do {
    if (*param_1 == 0) {
      *param_1 = -1;
LAB_18000eb34:
                    // WARNING: Could not recover jumptable at 0x00018000eb40. Too many branches
                    // WARNING: Treating indirect jump as call
      LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18041e550);
      return;
    }
    if (*param_1 != -1) {
      *(undefined4 *)
       (*(longlong *)(*(longlong *)(in_GS_OFFSET + 0x58) + (ulonglong)DAT_18041eb54 * 8) + 4) =
           DAT_180418000;
      goto LAB_18000eb34;
    }
    _Init_thread_wait();
  } while( true );
}



// Library Function - Single Match
//  _Init_thread_wait
// 
// Library: Visual Studio 2019 Release

void _Init_thread_wait(DWORD param_1)

{
  if (DAT_18041e578 == (code *)0x0) {
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18041e550);
    WaitForSingleObjectEx(DAT_18041e548,param_1,0);
                    // WARNING: Could not recover jumptable at 0x00018000ebe8. Too many branches
                    // WARNING: Treating indirect jump as call
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18041e550);
    return;
  }
                    // WARNING: Could not recover jumptable at 0x00018000fc80. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_18041e578)(&DAT_18041e540,&DAT_18041e550,param_1);
  return;
}



void thunk_FUN_18000f754(__uint64 param_1)

{
  operator_new(param_1);
  return;
}



// Library Function - Single Match
//  __scrt_acquire_startup_lock
// 
// Library: Visual Studio 2019 Release

ulonglong __scrt_acquire_startup_lock(void)

{
  ulonglong uVar1;
  ulonglong uVar2;
  longlong in_GS_OFFSET;
  bool bVar3;
  
  uVar2 = __scrt_is_ucrt_dll_in_use();
  if ((int)uVar2 == 0) {
LAB_18000ec26:
    uVar2 = uVar2 & 0xffffffffffffff00;
  }
  else {
    uVar1 = *(ulonglong *)(*(longlong *)(in_GS_OFFSET + 0x30) + 8);
    do {
      LOCK();
      bVar3 = DAT_18041e590 == 0;
      DAT_18041e590 = DAT_18041e590 ^ (ulonglong)bVar3 * (DAT_18041e590 ^ uVar1);
      uVar2 = !bVar3 * DAT_18041e590;
      if (bVar3) goto LAB_18000ec26;
    } while (uVar1 != uVar2);
    uVar2 = CONCAT71((int7)(uVar2 >> 8),1);
  }
  return uVar2;
}



// Library Function - Single Match
//  __scrt_dllmain_after_initialize_c
// 
// Library: Visual Studio 2019 Release

undefined4 __scrt_dllmain_after_initialize_c(void)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = __scrt_is_ucrt_dll_in_use();
  if (iVar1 == 0) {
    uVar2 = NVSDK_NGX_D3D12_Init();
    iVar1 = _configure_narrow_argv(uVar2);
    if (iVar1 != 0) {
      return 0;
    }
    _initialize_narrow_environment();
  }
  else {
    FUN_18000f768();
  }
  return 1;
}



// Library Function - Single Match
//  __scrt_dllmain_before_initialize_c
// 
// Library: Visual Studio 2019 Release

bool __scrt_dllmain_before_initialize_c(void)

{
  char cVar1;
  
  cVar1 = __scrt_initialize_onexit_tables(0);
  return cVar1 != '\0';
}



// Library Function - Single Match
//  __scrt_dllmain_crt_thread_attach
// 
// Library: Visual Studio 2019 Release

undefined __scrt_dllmain_crt_thread_attach(void)

{
  char cVar1;
  
  cVar1 = FUN_18000fb1c();
  if (cVar1 != '\0') {
    cVar1 = FUN_18000fb1c();
    if (cVar1 != '\0') {
      return 1;
    }
    FUN_18000fb1c();
  }
  return 0;
}



// Library Function - Single Match
//  __scrt_dllmain_crt_thread_detach
// 
// Library: Visual Studio 2019 Release

undefined __scrt_dllmain_crt_thread_detach(void)

{
  FUN_18000fb1c();
  FUN_18000fb1c();
  return 1;
}



// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall

void FUN_18000ecc0(undefined8 param_1,int param_2,undefined8 param_3,code *param_4,
                  undefined4 param_5,undefined8 param_6)

{
  int iVar1;
  
  iVar1 = __scrt_is_ucrt_dll_in_use();
  if ((iVar1 == 0) && (param_2 == 1)) {
    (*param_4)(param_1,0,param_3);
  }
                    // WARNING: Could not recover jumptable at 0x00018000fade. Too many branches
                    // WARNING: Treating indirect jump as call
  _seh_filter_dll(param_5,param_6);
  return;
}



void FUN_18000ed20(void)

{
  int iVar1;
  
  iVar1 = __scrt_is_ucrt_dll_in_use();
  if (iVar1 != 0) {
                    // WARNING: Could not recover jumptable at 0x00018000fafc. Too many branches
                    // WARNING: Treating indirect jump as call
    _execute_onexit_table(&DAT_18041e5a0);
    return;
  }
  iVar1 = FUN_18000e690();
  if (iVar1 == 0) {
    _cexit();
  }
  return;
}



// Library Function - Single Match
//  __scrt_dllmain_uninitialize_critical
// 
// Library: Visual Studio 2019 Release

void __scrt_dllmain_uninitialize_critical(void)

{
  FUN_18000fb1c(0);
  FUN_18000fb1c();
  return;
}



// Library Function - Single Match
//  __scrt_initialize_crt
// 
// Library: Visual Studio 2019 Release

ulonglong __scrt_initialize_crt(int param_1)

{
  ulonglong uVar1;
  
  if (param_1 == 0) {
    DAT_18041e598 = 1;
  }
  FUN_18000f768();
  uVar1 = FUN_18000fb1c();
  if ((char)uVar1 != '\0') {
    uVar1 = FUN_18000fb1c();
    if ((char)uVar1 != '\0') {
      return uVar1 & 0xffffffffffffff00 | 1;
    }
    uVar1 = FUN_18000fb1c(0);
  }
  return uVar1 & 0xffffffffffffff00;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __scrt_initialize_onexit_tables
// 
// Library: Visual Studio 2019 Release

undefined8 __scrt_initialize_onexit_tables(uint param_1)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  
  if (DAT_18041e599 == '\0') {
    if (1 < param_1) {
      FUN_18000f608(5);
      pcVar1 = (code *)swi(3);
      uVar3 = (*pcVar1)();
      return uVar3;
    }
    iVar2 = __scrt_is_ucrt_dll_in_use();
    if ((iVar2 == 0) || (param_1 != 0)) {
      _DAT_18041e5a0 = 0xffffffff;
      uRam000000018041e5a4 = 0xffffffff;
      uRam000000018041e5a8 = 0xffffffff;
      uRam000000018041e5ac = 0xffffffff;
      _DAT_18041e5b0 = 0xffffffffffffffff;
      _DAT_18041e5b8 = 0xffffffff;
      uRam000000018041e5bc = 0xffffffff;
      uRam000000018041e5c0 = 0xffffffff;
      uRam000000018041e5c4 = 0xffffffff;
      _DAT_18041e5c8 = 0xffffffffffffffff;
    }
    else {
      iVar2 = _initialize_onexit_table(&DAT_18041e5a0);
      if ((iVar2 != 0) || (iVar2 = _initialize_onexit_table(&DAT_18041e5b8), iVar2 != 0)) {
        return 0;
      }
    }
    DAT_18041e599 = '\x01';
  }
  return 1;
}



// WARNING: Removing unreachable block (ram,0x00018000eec9)

ulonglong FUN_18000ee3c(longlong param_1)

{
  ulonglong uVar1;
  uint7 uVar2;
  IMAGE_SECTION_HEADER *pIVar3;
  
  uVar1 = 0;
  for (pIVar3 = &IMAGE_SECTION_HEADER_180000218; pIVar3 != (IMAGE_SECTION_HEADER *)&DAT_180000308;
      pIVar3 = pIVar3 + 1) {
    if (((ulonglong)(uint)pIVar3->VirtualAddress <= param_1 - 0x180000000U) &&
       (uVar1 = (ulonglong)(uint)(pIVar3->Misc + pIVar3->VirtualAddress),
       param_1 - 0x180000000U < uVar1)) goto LAB_18000eeb2;
  }
  pIVar3 = (IMAGE_SECTION_HEADER *)0x0;
LAB_18000eeb2:
  if (pIVar3 == (IMAGE_SECTION_HEADER *)0x0) {
    uVar1 = uVar1 & 0xffffffffffffff00;
  }
  else {
    uVar2 = (uint7)(uVar1 >> 8);
    if ((int)pIVar3->Characteristics < 0) {
      uVar1 = (ulonglong)uVar2 << 8;
    }
    else {
      uVar1 = CONCAT71(uVar2,1);
    }
  }
  return uVar1;
}



// Library Function - Single Match
//  __scrt_release_startup_lock
// 
// Library: Visual Studio 2019 Release

void __scrt_release_startup_lock(char param_1)

{
  int iVar1;
  
  iVar1 = __scrt_is_ucrt_dll_in_use();
  if ((iVar1 != 0) && (param_1 == '\0')) {
    DAT_18041e590 = 0;
  }
  return;
}



// Library Function - Single Match
//  __scrt_uninitialize_crt
// 
// Library: Visual Studio 2019 Release

undefined __scrt_uninitialize_crt(undefined param_1,char param_2)

{
  if ((DAT_18041e598 == '\0') || (param_2 == '\0')) {
    FUN_18000fb1c();
    FUN_18000fb1c(param_1);
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _onexit
// 
// Library: Visual Studio 2019 Release

_onexit_t _onexit(_onexit_t _Func)

{
  int iVar1;
  _onexit_t p_Var2;
  
  if (_DAT_18041e5a0 == -1) {
    iVar1 = _crt_atexit();
  }
  else {
    iVar1 = _register_onexit_function(&DAT_18041e5a0);
  }
  p_Var2 = (_onexit_t)0x0;
  if (iVar1 == 0) {
    p_Var2 = _Func;
  }
  return p_Var2;
}



// Library Function - Single Match
//  atexit
// 
// Library: Visual Studio 2019 Release

int atexit(void *param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = _onexit((_onexit_t)param_1);
  return (p_Var1 != (_onexit_t)0x0) - 1;
}



// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// WARNING: Exceeded maximum restarts with more pending
// Library Function - Single Match
//  void __cdecl `eh vector destructor iterator'(void * __ptr64,unsigned __int64,unsigned
// __int64,void (__cdecl*)(void * __ptr64))
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void _eh_vector_destructor_iterator_
               (void *param_1,__uint64 param_2,__uint64 param_3,FuncDef3 *param_4)

{
  void *pvVar1;
  
  pvVar1 = (void *)(param_2 * param_3 + (longlong)param_1);
  while( true ) {
    if (param_3 == 0) break;
    pvVar1 = (void *)((longlong)pvVar1 - param_2);
    (*param_4)(pvVar1,_guard_dispatch_icall);
    param_3 = param_3 - 1;
  }
  return;
}



// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// WARNING: Exceeded maximum restarts with more pending
// Library Function - Single Match
//  void __cdecl __ArrayUnwind(void * __ptr64,unsigned __int64,unsigned __int64,void (__cdecl*)(void
// * __ptr64))
// 
// Library: Visual Studio 2019 Release

void __ArrayUnwind(void *param_1,__uint64 param_2,__uint64 param_3,FuncDef4 *param_4)

{
  __uint64 _Var1;
  
  for (_Var1 = 0; _Var1 != param_3; _Var1 = _Var1 + 1) {
    param_1 = (void *)((longlong)param_1 - param_2);
    (*param_4)(param_1);
  }
  return;
}



// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  int __cdecl dllmain_crt_dispatch(struct HINSTANCE__ * __ptr64 const,unsigned long,void * __ptr64
// const)
// 
// Library: Visual Studio 2019 Release

int dllmain_crt_dispatch(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  code *pcVar1;
  bool bVar2;
  byte bVar3;
  char cVar4;
  int iVar5;
  code **ppcVar6;
  undefined *puVar7;
  
  if (param_2 == 0) {
    iVar5 = dllmain_crt_process_detach(param_3 != (void *)0x0);
    return iVar5;
  }
  if (param_2 != 1) {
    if (param_2 == 2) {
      bVar3 = __scrt_dllmain_crt_thread_attach();
    }
    else {
      if (param_2 != 3) {
        return 1;
      }
      bVar3 = __scrt_dllmain_crt_thread_detach();
    }
    return (int)bVar3;
  }
  puVar7 = (undefined *)0x0;
  cVar4 = __scrt_initialize_crt(0);
  if (cVar4 != '\0') {
    bVar3 = __scrt_acquire_startup_lock();
    bVar2 = true;
    if (_DAT_18041e588 != 0) {
      FUN_18000f608(7);
      pcVar1 = (code *)swi(3);
      iVar5 = (*pcVar1)();
      return iVar5;
    }
    _DAT_18041e588 = 1;
    cVar4 = __scrt_dllmain_before_initialize_c();
    if (cVar4 != '\0') {
      _RTC_Initialize();
      FUN_18000f9cc();
      __scrt_initialize_default_local_stdio_options();
      puVar7 = &DAT_18001d4e8;
      iVar5 = _initterm_e(&DAT_18001d4e8,&DAT_18001d4f8);
      if ((iVar5 == 0) && (cVar4 = __scrt_dllmain_after_initialize_c(), cVar4 != '\0')) {
        puVar7 = &DAT_18001d4c8;
        _initterm(&DAT_18001d4c8,&DAT_18001d4e0);
        _DAT_18041e588 = 2;
        bVar2 = false;
      }
    }
    __scrt_release_startup_lock((ulonglong)puVar7 & 0xffffffffffffff00 | (ulonglong)bVar3);
    if (!bVar2) {
      ppcVar6 = (code **)FUN_18000fa0c();
      if ((*ppcVar6 != (code *)0x0) && (cVar4 = FUN_18000ee3c(ppcVar6), cVar4 != '\0')) {
        (**ppcVar6)(param_1,2,param_3,_guard_dispatch_icall);
      }
      DAT_18041e5d0 = DAT_18041e5d0 + 1;
      return 1;
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  int __cdecl dllmain_crt_process_detach(bool)
// 
// Library: Visual Studio 2019 Release

int dllmain_crt_process_detach(bool param_1)

{
  code *pcVar1;
  byte bVar2;
  char cVar3;
  uint uVar4;
  int iVar5;
  undefined7 in_register_00000009;
  ulonglong uVar6;
  undefined8 in_R8;
  undefined8 in_R9;
  byte bVar7;
  
  uVar6 = CONCAT71(in_register_00000009,param_1);
  if (DAT_18041e5d0 < 1) {
    uVar4 = 0;
  }
  else {
    DAT_18041e5d0 = DAT_18041e5d0 + -1;
    bVar2 = __scrt_acquire_startup_lock();
    if (_DAT_18041e588 != 2) {
      FUN_18000f608(7);
      pcVar1 = (code *)swi(3);
      iVar5 = (*pcVar1)();
      return iVar5;
    }
    bVar7 = bVar2;
    FUN_18000ed20();
    FUN_18000f9dc();
    _RTC_Terminate();
    _DAT_18041e588 = 0;
    uVar6 = uVar6 & 0xffffffffffffff00 | (ulonglong)bVar2;
    __scrt_release_startup_lock(uVar6);
    cVar3 = __scrt_uninitialize_crt
                      (uVar6 & 0xffffffffffffff00 | (ulonglong)param_1,0,in_R8,in_R9,bVar7);
    uVar4 = -(uint)(cVar3 != '\0') & 1;
    __scrt_dllmain_uninitialize_critical();
  }
  return uVar4;
}



// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// WARNING: Removing unreachable block (ram,0x00018000f2f6)
// WARNING: Removing unreachable block (ram,0x00018000f287)
// WARNING: Removing unreachable block (ram,0x00018000f339)

int entry(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  int iVar1;
  
  if (param_2 == 1) {
    __security_init_cookie();
  }
  if ((param_2 == 0) && (DAT_18041e5d0 < 1)) {
    iVar1 = 0;
  }
  else if ((1 < param_2 - 1) || (iVar1 = dllmain_crt_dispatch(param_1,param_2,param_3), iVar1 != 0))
  {
    iVar1 = FUN_18000fb20(param_1,param_2,param_3);
    if ((param_2 == 1) && (iVar1 == 0)) {
      FUN_18000fb20(param_1,0,param_3);
      dllmain_crt_process_detach(param_3 != (void *)0x0);
    }
    if (((param_2 == 0) || (param_2 == 3)) &&
       (iVar1 = dllmain_crt_dispatch(param_1,param_2,param_3), iVar1 != 0)) {
      iVar1 = 1;
    }
  }
  return iVar1;
}



// Library Function - Single Match
//  __GSHandlerCheck
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8
__GSHandlerCheck(undefined8 param_1,undefined8 param_2,undefined8 param_3,longlong param_4)

{
  __GSHandlerCheckCommon(param_2,param_4,*(undefined8 *)(param_4 + 0x38));
  return 1;
}



// Library Function - Single Match
//  __GSHandlerCheckCommon
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __GSHandlerCheckCommon(ulonglong param_1,longlong param_2,uint *param_3)

{
  ulonglong uVar1;
  ulonglong uVar2;
  
  uVar2 = param_1;
  if ((*(byte *)param_3 & 4) != 0) {
    uVar2 = (longlong)(int)param_3[1] + param_1 & (longlong)(int)-param_3[2];
  }
  uVar1 = (ulonglong)*(uint *)(*(longlong *)(param_2 + 0x10) + 8);
  if ((*(byte *)(uVar1 + 3 + *(longlong *)(param_2 + 8)) & 0xf) != 0) {
    param_1 = param_1 + (*(byte *)(uVar1 + 3 + *(longlong *)(param_2 + 8)) & 0xfffffff0);
  }
  FUN_18000e8c0(param_1 ^ *(ulonglong *)((longlong)(int)(*param_3 & 0xfffffff8) + uVar2));
  return;
}



// Library Function - Single Match
//  __raise_securityfailure
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __raise_securityfailure(_EXCEPTION_POINTERS *param_1)

{
  HANDLE hProcess;
  
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter(param_1);
  hProcess = GetCurrentProcess();
                    // WARNING: Could not recover jumptable at 0x00018000f451. Too many branches
                    // WARNING: Treating indirect jump as call
  TerminateProcess(hProcess,0xc0000409);
  return;
}



// Library Function - Single Match
//  capture_previous_context
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void capture_previous_context(PCONTEXT param_1)

{
  DWORD64 ControlPc;
  PRUNTIME_FUNCTION FunctionEntry;
  int iVar1;
  DWORD64 local_res8;
  ulonglong local_res10;
  PVOID local_res18 [2];
  
  RtlCaptureContext();
  ControlPc = param_1->Rip;
  iVar1 = 0;
  do {
    FunctionEntry = RtlLookupFunctionEntry(ControlPc,&local_res8,(PUNWIND_HISTORY_TABLE)0x0);
    if (FunctionEntry == (PRUNTIME_FUNCTION)0x0) {
      return;
    }
    RtlVirtualUnwind(0,local_res8,ControlPc,FunctionEntry,param_1,local_res18,&local_res10,
                     (PKNONVOLATILE_CONTEXT_POINTERS)0x0);
    iVar1 = iVar1 + 1;
  } while (iVar1 < 2);
  return;
}



undefined8 * FUN_18000f5a0(undefined8 *param_1)

{
  param_1[2] = 0;
  param_1[1] = "bad allocation";
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



void FUN_18000f5c0(void)

{
  undefined local_28 [40];
  
  FUN_18000f5a0(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_180416018);
}



void FUN_18000f5e0(void)

{
  undefined local_28 [40];
  
  FUN_180014f08(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_1804161e0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_18000f600(void)

{
  _DAT_18041eb50 = 0;
  return;
}



void FUN_18000f608(undefined4 param_1)

{
  code *pcVar1;
  BOOL BVar2;
  LONG LVar3;
  PRUNTIME_FUNCTION FunctionEntry;
  undefined *puVar4;
  undefined8 in_stack_00000000;
  DWORD64 local_res10;
  undefined local_res18 [8];
  undefined local_res20 [8];
  undefined auStack1480 [8];
  undefined auStack1472 [232];
  undefined local_4d8 [152];
  undefined *local_440;
  DWORD64 local_3e0;
  
  puVar4 = auStack1480;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(param_1);
    puVar4 = auStack1472;
  }
  *(undefined8 *)(puVar4 + -8) = 0x18000f63c;
  FUN_18000f600(3);
  *(undefined8 *)(puVar4 + -8) = 0x18000f64d;
  memset(local_4d8,0,0x4d0);
  *(undefined8 *)(puVar4 + -8) = 0x18000f657;
  RtlCaptureContext(local_4d8);
  *(undefined8 *)(puVar4 + -8) = 0x18000f671;
  FunctionEntry = RtlLookupFunctionEntry(local_3e0,&local_res10,(PUNWIND_HISTORY_TABLE)0x0);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0) {
    *(undefined8 *)(puVar4 + 0x38) = 0;
    *(undefined **)(puVar4 + 0x30) = local_res18;
    *(undefined **)(puVar4 + 0x28) = local_res20;
    *(undefined **)(puVar4 + 0x20) = local_4d8;
    *(undefined8 *)(puVar4 + -8) = 0x18000f6b2;
    RtlVirtualUnwind(0,local_res10,local_3e0,FunctionEntry,*(PCONTEXT *)(puVar4 + 0x20),
                     *(PVOID **)(puVar4 + 0x28),*(PDWORD64 *)(puVar4 + 0x30),
                     *(PKNONVOLATILE_CONTEXT_POINTERS *)(puVar4 + 0x38));
  }
  local_440 = &stack0x00000008;
  *(undefined8 *)(puVar4 + -8) = 0x18000f6e4;
  memset(puVar4 + 0x50,0,0x98);
  *(undefined8 *)(puVar4 + 0x60) = in_stack_00000000;
  *(undefined4 *)(puVar4 + 0x50) = 0x40000015;
  *(undefined4 *)(puVar4 + 0x54) = 1;
  *(undefined8 *)(puVar4 + -8) = 0x18000f706;
  BVar2 = IsDebuggerPresent();
  *(undefined **)(puVar4 + 0x40) = puVar4 + 0x50;
  *(undefined **)(puVar4 + 0x48) = local_4d8;
  *(undefined8 *)(puVar4 + -8) = 0x18000f727;
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  *(undefined8 *)(puVar4 + -8) = 0x18000f732;
  LVar3 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)(puVar4 + 0x40));
  if ((LVar3 == 0) && (BVar2 != 1)) {
    *(undefined8 *)(puVar4 + -8) = 0x18000f742;
    FUN_18000f600(3);
  }
  return;
}



void FUN_18000f754(__uint64 param_1)

{
  operator_new(param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x00018000f832)
// WARNING: Removing unreachable block (ram,0x00018000f7a2)
// WARNING: Removing unreachable block (ram,0x00018000f77b)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_18000f768(void)

{
  int *piVar1;
  uint *puVar2;
  longlong lVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  byte in_XCR0;
  
  piVar1 = (int *)cpuid_basic_info(0);
  uVar6 = 0;
  puVar2 = (uint *)cpuid_Version_info(1);
  uVar4 = puVar2[3];
  if ((piVar1[2] ^ 0x49656e69U | piVar1[3] ^ 0x6c65746eU | piVar1[1] ^ 0x756e6547U) == 0) {
    _DAT_180418028 = 0xffffffffffffffff;
    uVar5 = *puVar2 & 0xfff3ff0;
    _DAT_180418020 = 0x8000;
    if ((((uVar5 == 0x106c0) || (uVar5 == 0x20660)) || (uVar5 == 0x20670)) ||
       ((uVar5 - 0x30650 < 0x21 &&
        ((0x100010001U >> ((ulonglong)(uVar5 - 0x30650) & 0x3f) & 1) != 0)))) {
      DAT_18041eb58 = DAT_18041eb58 | 1;
    }
  }
  if (6 < *piVar1) {
    lVar3 = cpuid_Extended_Feature_Enumeration_info(7);
    uVar6 = *(uint *)(lVar3 + 4);
    if ((uVar6 >> 9 & 1) != 0) {
      DAT_18041eb58 = DAT_18041eb58 | 2;
    }
  }
  _DAT_180418018 = 1;
  DAT_18041801c = 2;
  if ((uVar4 >> 0x14 & 1) != 0) {
    _DAT_180418018 = 2;
    DAT_18041801c = 6;
    if ((((uVar4 >> 0x1b & 1) != 0) && ((uVar4 >> 0x1c & 1) != 0)) && ((in_XCR0 & 6) == 6)) {
      DAT_18041801c = 0xe;
      _DAT_180418018 = 3;
      if ((uVar6 & 0x20) != 0) {
        _DAT_180418018 = 5;
        DAT_18041801c = 0x2e;
        if (((uVar6 & 0xd0030000) == 0xd0030000) && ((in_XCR0 & 0xe0) == 0xe0)) {
          DAT_18041801c = 0x6e;
          _DAT_180418018 = 6;
        }
      }
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __scrt_is_ucrt_dll_in_use
// 
// Library: Visual Studio 2019 Release

bool __scrt_is_ucrt_dll_in_use(void)

{
  return _DAT_180418030 != 0;
}



// Library Function - Single Match
//  __security_init_cookie
// 
// Library: Visual Studio 2019 Release

void __security_init_cookie(void)

{
  DWORD DVar1;
  _FILETIME local_res8;
  _FILETIME local_res10;
  uint local_res18;
  undefined4 uStackX28;
  
  if (DAT_180418010 == 0x2b992ddfa232) {
    local_res10 = (_FILETIME)0x0;
    GetSystemTimeAsFileTime(&local_res10);
    local_res8 = local_res10;
    DVar1 = GetCurrentThreadId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    DVar1 = GetCurrentProcessId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    QueryPerformanceCounter((LARGE_INTEGER *)&local_res18);
    DAT_180418010 =
         ((ulonglong)local_res18 << 0x20 ^ CONCAT44(uStackX28,local_res18) ^ (ulonglong)local_res8 ^
         (ulonglong)&local_res8) & 0xffffffffffff;
    if (DAT_180418010 == 0x2b992ddfa232) {
      DAT_180418010 = 0x2b992ddfa233;
    }
  }
  DAT_180418008 = ~DAT_180418010;
  return;
}



void FUN_18000f9cc(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000f9d3. Too many branches
                    // WARNING: Treating indirect jump as call
  InitializeSListHead((PSLIST_HEADER)&DAT_18041eb60);
  return;
}



void FUN_18000f9dc(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000fac0. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_type_info_destroy_list(&DAT_18041eb60);
  return;
}



undefined * FUN_18000f9e8(void)

{
  return &DAT_18041eb70;
}



// Library Function - Single Match
//  __scrt_initialize_default_local_stdio_options
// 
// Library: Visual Studio 2019 Release

void __scrt_initialize_default_local_stdio_options(void)

{
  ulonglong *puVar1;
  
  puVar1 = (ulonglong *)FUN_18000e594();
  *puVar1 = *puVar1 | 0x24;
  puVar1 = (ulonglong *)FUN_18000f9e8();
  *puVar1 = *puVar1 | 2;
  return;
}



undefined * FUN_18000fa0c(void)

{
  return &DAT_18041eb78;
}



// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  _RTC_Initialize
// 
// Library: Visual Studio 2019 Release

void _RTC_Initialize(void)

{
  code **ppcVar1;
  
  for (ppcVar1 = (code **)&DAT_180413bc0; ppcVar1 < &DAT_180413bc0; ppcVar1 = ppcVar1 + 1) {
    if (*ppcVar1 != (code *)0x0) {
      (**ppcVar1)();
    }
  }
  return;
}



// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  _RTC_Terminate
// 
// Library: Visual Studio 2019 Release

void _RTC_Terminate(void)

{
  code **ppcVar1;
  
  for (ppcVar1 = (code **)&DAT_180413bd0; ppcVar1 < &DAT_180413bd0; ppcVar1 = ppcVar1 + 1) {
    if (*ppcVar1 != (code *)0x0) {
      (**ppcVar1)();
    }
  }
  return;
}



void __CxxFrameHandler4(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000fa90. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler4();
  return;
}



void _purecall(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000fa9c. Too many branches
                    // WARNING: Treating indirect jump as call
  _purecall();
  return;
}



void __current_exception(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000faa8. Too many branches
                    // WARNING: Treating indirect jump as call
  __current_exception();
  return;
}



void __current_exception_context(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000faae. Too many branches
                    // WARNING: Treating indirect jump as call
  __current_exception_context();
  return;
}



// WARNING: Exceeded maximum restarts with more pending

void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo)

{
                    // WARNING: Could not recover jumptable at 0x00018000fab4. Too many branches
                    // WARNING: Treating indirect jump as call
  _CxxThrowException();
  return;
}



void * memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000faba. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



// WARNING: Exceeded maximum restarts with more pending

void terminate(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000fac6. Too many branches
                    // WARNING: Treating indirect jump as call
  terminate();
  return;
}



void free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x00018000facc. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void * malloc(size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000fad2. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = malloc(_Size);
  return pvVar1;
}



int _callnewh(size_t _Size)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000fad8. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _callnewh(_Size);
  return iVar1;
}



void _configure_narrow_argv(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000fae4. Too many branches
                    // WARNING: Treating indirect jump as call
  _configure_narrow_argv();
  return;
}



void _initialize_narrow_environment(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000faea. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_narrow_environment();
  return;
}



void _initialize_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000faf0. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_onexit_table();
  return;
}



void _register_onexit_function(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000faf6. Too many branches
                    // WARNING: Treating indirect jump as call
  _register_onexit_function();
  return;
}



void _crt_atexit(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000fb02. Too many branches
                    // WARNING: Treating indirect jump as call
  _crt_atexit();
  return;
}



void _cexit(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000fb08. Too many branches
                    // WARNING: Treating indirect jump as call
  _cexit();
  return;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000fb0e. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void _initterm_e(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000fb14. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm_e();
  return;
}



undefined FUN_18000fb1c(void)

{
  return 1;
}



undefined8 FUN_18000fb20(undefined8 param_1)

{
  DAT_18041ebb0 = param_1;
  return 1;
}



undefined8 ffxFsr2GetScratchMemorySizeDX12(void)

{
                    // 0xfb30  38  ffxFsr2GetScratchMemorySizeDX12
  return 0x3c250;
}



undefined8 ffxGetCommandListDX12(undefined8 param_1)

{
                    // 0xfb38  43  ffxGetCommandListDX12
                    // 0xfb38  44  ffxGetCommandListVK
                    // 0xfb38  46  ffxGetDeviceDX12
                    // 0xfb38  47  ffxGetDeviceVK
  return param_1;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __chkstk
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010, Visual Studio 2012

void __chkstk(void)

{
  undefined *in_RAX;
  undefined *puVar1;
  undefined *puVar2;
  longlong in_GS_OFFSET;
  undefined local_res8 [32];
  
  puVar1 = local_res8 + -(longlong)in_RAX;
  if (local_res8 < in_RAX) {
    puVar1 = (undefined *)0x0;
  }
  puVar2 = *(undefined **)(in_GS_OFFSET + 0x10);
  if (puVar1 < puVar2) {
    do {
      puVar2 = puVar2 + -0x1000;
      *puVar2 = 0;
    } while ((undefined *)((ulonglong)puVar1 & 0xfffffffffffff000) != puVar2);
  }
  return;
}



void __RTDynamicCast(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000fc1e. Too many branches
                    // WARNING: Treating indirect jump as call
  __RTDynamicCast();
  return;
}



int memcmp(void *_Buf1,void *_Buf2,size_t _Size)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000fc24. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = memcmp(_Buf1,_Buf2,_Size);
  return iVar1;
}



void * memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000fc2a. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



void * memmove(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000fc30. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memmove(_Dst,_Src,_Size);
  return pvVar1;
}



float atanf(float _X)

{
  float fVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000fc36. Too many branches
                    // WARNING: Treating indirect jump as call
  fVar1 = atanf(_X);
  return fVar1;
}



double floor(double _X)

{
  double dVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000fc3c. Too many branches
                    // WARNING: Treating indirect jump as call
  dVar1 = floor(_X);
  return dVar1;
}



float floorf(float _X)

{
  float fVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000fc42. Too many branches
                    // WARNING: Treating indirect jump as call
  fVar1 = floorf(_X);
  return fVar1;
}



void log2(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000fc48. Too many branches
                    // WARNING: Treating indirect jump as call
  log2();
  return;
}



void log2f(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000fc4e. Too many branches
                    // WARNING: Treating indirect jump as call
  log2f();
  return;
}



float powf(float _X,float _Y)

{
  float fVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000fc54. Too many branches
                    // WARNING: Treating indirect jump as call
  fVar1 = powf(_X,_Y);
  return fVar1;
}



float sinf(float _X)

{
  float fVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000fc5a. Too many branches
                    // WARNING: Treating indirect jump as call
  fVar1 = sinf(_X);
  return fVar1;
}



int strcmp(char *_Str1,char *_Str2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000fc60. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = strcmp(_Str1,_Str2);
  return iVar1;
}



float tanf(float _X)

{
  float fVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000fc66. Too many branches
                    // WARNING: Treating indirect jump as call
  fVar1 = tanf(_X);
  return fVar1;
}



// WARNING: This is an inlined function

void _guard_dispatch_icall(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
                    // WARNING: Could not recover jumptable at 0x00018000fc80. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_180010290(undefined8 param_1,longlong param_2)

{
  _eh_vector_destructor_iterator_((void *)(param_2 + 0x60),0x28,0x2e,(FuncDef3 *)&LAB_180007138);
  return;
}



void FUN_180010422(undefined8 param_1,longlong param_2)

{
  if (*(char *)(param_2 + 0x20) == '\0') {
    __ArrayUnwind(*(void **)(param_2 + 0x60),*(__uint64 *)(param_2 + 0x68),
                  *(__uint64 *)(param_2 + 0x70),*(FuncDef4 **)(param_2 + 0x78));
  }
  return;
}



void FUN_1800104ad(undefined8 param_1,longlong param_2)

{
  __scrt_release_startup_lock(*(undefined *)(param_2 + 0x40));
  return;
}



void FUN_1800104c4(undefined8 param_1,longlong param_2)

{
  __scrt_release_startup_lock(*(undefined *)(param_2 + 0x20));
  return;
}



void FUN_1800104dd(void)

{
  __scrt_dllmain_uninitialize_critical();
  return;
}



void FUN_1800104f1(undefined8 *param_1,longlong param_2)

{
  FUN_18000ecc0(*(undefined8 *)(param_2 + 0x60),*(undefined4 *)(param_2 + 0x68),
                *(undefined8 *)(param_2 + 0x70),dllmain_crt_dispatch,*(undefined4 *)*param_1,param_1
               );
  return;
}



undefined8 * FUN_180014420(undefined8 *param_1,undefined8 *param_2)

{
  *param_1 = *param_2;
  param_1[1] = param_2[1];
  *(undefined4 *)(param_1 + 2) = *(undefined4 *)(param_2 + 2);
  FUN_180014554(param_1 + 3,param_2 + 3);
  return param_1;
}



undefined8 * FUN_180014454(undefined8 *param_1,undefined8 param_2,undefined8 param_3)

{
  void *pvVar1;
  longlong lVar2;
  
  *param_1 = param_2;
  param_1[1] = 0;
  param_1[1] = 0;
  pvVar1 = operator_new(0x48);
  param_1[1] = pvVar1;
  FUN_180014420((longlong)pvVar1 + 0x20);
  *(undefined8 *)param_1[1] = param_3;
  *(undefined8 *)(param_1[1] + 8) = param_3;
  *(undefined8 *)(param_1[1] + 0x10) = param_3;
  lVar2 = 0;
  do {
    *(undefined *)(lVar2 + 0x18 + param_1[1]) = 0;
    lVar2 = lVar2 + 1;
  } while (lVar2 < 2);
  return param_1;
}



undefined8 * FUN_1800144f0(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3)

{
  undefined8 uVar1;
  
  *param_1 = *param_2;
  param_1[1] = param_2[1];
  *(undefined4 *)(param_1 + 2) = *(undefined4 *)(param_2 + 2);
  param_1[3] = 0;
  param_1[4] = 0;
  uVar1 = FUN_1800145fc();
  param_1[3] = uVar1;
  param_1[3] = *param_3;
  *param_3 = uVar1;
  uVar1 = param_1[4];
  param_1[4] = param_3[1];
  param_3[1] = uVar1;
  return param_1;
}



longlong * FUN_180014554(longlong *param_1,longlong *param_2,undefined8 param_3,undefined8 param_4)

{
  longlong lVar1;
  undefined8 uVar2;
  longlong lVar3;
  undefined8 *puVar4;
  longlong *plVar5;
  longlong *plVar6;
  
  *param_1 = 0;
  param_1[1] = 0;
  plVar5 = param_1;
  plVar6 = param_1;
  lVar1 = FUN_1800145fc();
  *param_1 = lVar1;
  uVar2 = FUN_180014620(param_1,*(undefined8 *)(*param_2 + 8),lVar1,param_4,plVar5,plVar6);
  *(undefined8 *)(*param_1 + 8) = uVar2;
  param_1[1] = param_2[1];
  puVar4 = (undefined8 *)*param_1;
  if (*(char *)(puVar4[1] + 0x19) == '\0') {
    uVar2 = FUN_1800163c4();
    *puVar4 = uVar2;
    lVar1 = *(longlong *)(*param_1 + 8);
    for (lVar3 = *(longlong *)(lVar1 + 0x10); *(char *)(lVar3 + 0x19) == '\0';
        lVar3 = *(longlong *)(lVar3 + 0x10)) {
      lVar1 = lVar3;
    }
    *(longlong *)(*param_1 + 0x10) = lVar1;
  }
  else {
    *puVar4 = puVar4;
    *(longlong *)(*param_1 + 0x10) = *param_1;
  }
  return param_1;
}



void FUN_1800145fc(void)

{
  void *pvVar1;
  
  pvVar1 = operator_new(0x40);
  *(void **)pvVar1 = pvVar1;
  *(void **)((longlong)pvVar1 + 8) = pvVar1;
  *(void **)((longlong)pvVar1 + 0x10) = pvVar1;
  *(undefined2 *)((longlong)pvVar1 + 0x18) = 0x101;
  return;
}



void FUN_180014620(longlong **param_1,undefined8 *param_2,longlong param_3)

{
  longlong *plVar1;
  longlong *plVar2;
  longlong lVar3;
  undefined auStack88 [32];
  longlong **local_38;
  longlong **local_30;
  undefined8 local_28;
  ulonglong local_20;
  
  local_20 = DAT_180418010 ^ (ulonglong)auStack88;
  plVar1 = *param_1;
  local_38 = param_1;
  if (*(char *)((longlong)param_2 + 0x19) == '\0') {
    local_28 = 0;
    local_30 = param_1;
    plVar2 = (longlong *)operator_new(0x40);
    plVar2[4] = param_2[4];
    plVar2[5] = param_2[5];
    *(undefined4 *)(plVar2 + 6) = *(undefined4 *)(param_2 + 6);
    plVar2[7] = param_2[7];
    *plVar2 = (longlong)plVar1;
    plVar2[2] = (longlong)plVar1;
    *(undefined2 *)(plVar2 + 3) = 0;
    plVar2[1] = param_3;
    *(undefined *)(plVar2 + 3) = *(undefined *)(param_2 + 3);
    local_30 = (longlong **)plVar1;
    if (*(char *)((longlong)plVar1 + 0x19) != '\0') {
      local_30 = (longlong **)plVar2;
    }
    lVar3 = FUN_180014620(param_1,*param_2,plVar2);
    *plVar2 = lVar3;
    lVar3 = FUN_180014620(param_1,param_2[2],plVar2);
    plVar2[2] = lVar3;
  }
  FUN_18000e8c0(local_20 ^ (ulonglong)auStack88);
  return;
}



void FUN_180014730(longlong *param_1,undefined8 *param_2,longlong *param_3)

{
  longlong lVar1;
  int iVar2;
  longlong *plVar3;
  undefined8 uVar4;
  longlong **pplVar5;
  undefined auStack120 [32];
  longlong *local_58;
  undefined4 uStack80;
  undefined4 uStack76;
  longlong *local_38;
  longlong *plStack48;
  ulonglong local_28;
  
  local_28 = DAT_180418010 ^ (ulonglong)auStack120;
  lVar1 = *param_1;
  plStack48 = (longlong *)0x0;
  local_38 = param_1;
  plVar3 = (longlong *)operator_new(0x40);
  plVar3[4] = *param_3;
  plVar3[5] = param_3[1];
  *(undefined4 *)(plVar3 + 6) = *(undefined4 *)(param_3 + 2);
  plVar3[7] = param_3[3];
  *plVar3 = lVar1;
  plVar3[1] = lVar1;
  plVar3[2] = lVar1;
  *(undefined2 *)(plVar3 + 3) = 0;
  pplVar5 = *(longlong ***)(*param_1 + 8);
  local_58 = (longlong *)pplVar5;
  plStack48 = plVar3;
  do {
    uStack80 = 0;
    while( true ) {
      if (*(char *)((longlong)pplVar5 + 0x19) != '\0') {
        if (param_1[1] == 0x3ffffffffffffff) {
          std::_Xlength_error("map/set too long");
        }
        local_38 = local_58;
        plStack48 = (longlong *)CONCAT44(uStack76,uStack80);
        uVar4 = FUN_18001614c(param_1,&local_38,plVar3);
        *param_2 = uVar4;
        *(undefined *)(param_2 + 1) = 1;
        FUN_18000e8c0(local_28 ^ (ulonglong)auStack120);
        return;
      }
      local_58 = (longlong *)pplVar5;
      iVar2 = _mbsicmp((uchar *)plVar3[4],(uchar *)pplVar5[4]);
      if (-1 < iVar2) break;
      uStack80 = 1;
      pplVar5 = (longlong **)*pplVar5;
    }
    pplVar5 = (longlong **)pplVar5[2];
  } while( true );
}



void FUN_180014868(undefined8 *param_1,undefined8 *param_2,undefined8 param_3)

{
  code *pcVar1;
  char cVar2;
  undefined4 *puVar3;
  longlong lVar4;
  undefined8 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined auStack136 [32];
  undefined local_68 [16];
  undefined local_58 [16];
  undefined8 local_48;
  ulonglong local_38;
  
  local_38 = DAT_180418010 ^ (ulonglong)auStack136;
  puVar3 = (undefined4 *)FUN_180014a60(param_1,local_58);
  uVar5 = *(undefined8 *)(puVar3 + 4);
  uVar6 = *puVar3;
  uVar7 = puVar3[1];
  uVar8 = puVar3[2];
  uVar9 = puVar3[3];
  local_48 = uVar5;
  cVar2 = FUN_180014ad0();
  if (cVar2 == '\0') {
    if (param_1[1] == 0x38e38e38e38e38e) {
      std::_Xlength_error("map/set too long");
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    lVar4 = FUN_180014454(local_68,param_1,*param_1,param_3);
    uVar5 = *(undefined8 *)(lVar4 + 8);
    *(undefined8 *)(lVar4 + 8) = 0;
    FUN_1800150cc(local_68);
    local_58 = CONCAT412(uVar9,CONCAT48(uVar8,CONCAT44(uVar7,uVar6)));
    uVar5 = FUN_18001614c(param_1,local_58,uVar5);
    *param_2 = uVar5;
    *(undefined *)(param_2 + 1) = 1;
  }
  else {
    *param_2 = uVar5;
    *(undefined *)(param_2 + 1) = 0;
  }
  FUN_18000e8c0(local_38 ^ (ulonglong)auStack136);
  return;
}



void FUN_18001494c(undefined8 param_1,undefined8 param_2,longlong *param_3)

{
  char cVar1;
  longlong *plVar2;
  
  cVar1 = *(char *)((longlong)param_3 + 0x19);
  while (cVar1 == '\0') {
    FUN_18001494c(param_1,param_2,param_3[2]);
    plVar2 = (longlong *)*param_3;
    FUN_180003f84(param_3,0x40);
    param_3 = plVar2;
    cVar1 = *(char *)((longlong)plVar2 + 0x19);
  }
  return;
}



undefined8 * FUN_1800149a0(longlong *param_1,uchar **param_2)

{
  undefined8 *puVar1;
  int iVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  
  puVar1 = (undefined8 *)((undefined8 *)*param_1)[1];
  puVar4 = (undefined8 *)*param_1;
  while (puVar3 = puVar1, *(char *)((longlong)puVar3 + 0x19) == '\0') {
    iVar2 = _mbsicmp((uchar *)puVar3[4],*param_2);
    if (iVar2 < 0) {
      puVar1 = (undefined8 *)puVar3[2];
    }
    else {
      puVar1 = (undefined8 *)*puVar3;
      puVar4 = puVar3;
    }
  }
  if ((*(char *)((longlong)puVar4 + 0x19) == '\0') &&
     (iVar2 = _mbsicmp(*param_2,(uchar *)puVar4[4]), -1 < iVar2)) {
    return puVar4;
  }
  return (undefined8 *)*param_1;
}



undefined8 FUN_180014a1c(undefined8 *param_1,undefined8 param_2)

{
  char cVar1;
  undefined local_28 [16];
  undefined8 local_18;
  
  FUN_180014a60(param_1,local_28,param_2);
  cVar1 = FUN_180014ad0();
  if (cVar1 == '\0') {
    local_18 = *param_1;
  }
  return local_18;
}



undefined8 * FUN_180014a60(longlong *param_1,undefined8 *param_2,uchar **param_3)

{
  longlong lVar1;
  uchar *_Str2;
  uchar *_Str1;
  int iVar2;
  undefined8 *puVar3;
  
  lVar1 = *param_1;
  *(undefined4 *)(param_2 + 1) = 0;
  param_2[2] = lVar1;
  puVar3 = *(undefined8 **)(lVar1 + 8);
  *param_2 = puVar3;
  while (*(char *)((longlong)puVar3 + 0x19) == '\0') {
    _Str2 = *param_3;
    _Str1 = (uchar *)puVar3[4];
    *param_2 = puVar3;
    iVar2 = _mbsicmp(_Str1,_Str2);
    if (-1 < iVar2) {
      param_2[2] = puVar3;
      puVar3 = (undefined8 *)*puVar3;
    }
    else {
      puVar3 = (undefined8 *)puVar3[2];
    }
    *(uint *)(param_2 + 1) = (uint)(-1 < iVar2);
  }
  return param_2;
}



uint FUN_180014ad0(undefined8 param_1,longlong param_2,uchar **param_3)

{
  uint in_EAX;
  byte bVar1;
  
  bVar1 = 0;
  if (*(char *)(param_2 + 0x19) == '\0') {
    in_EAX = _mbsicmp(*param_3,*(uchar **)(param_2 + 0x20));
    bVar1 = 0;
    if (-1 < (int)in_EAX) {
      bVar1 = 1;
    }
  }
  return in_EAX & 0xffffff00 | (uint)bVar1;
}



void ** FUN_180014af8(void **param_1,void *param_2,undefined8 param_3,void *param_4)

{
  void *pvVar1;
  code *pcVar2;
  void **ppvVar3;
  void *pvVar4;
  void *_Dst;
  ulonglong uVar5;
  
  if ((void *)0x7ffffffffffffffe < param_2) {
    std::_Xlength_error("string too long");
    pcVar2 = (code *)swi(3);
    ppvVar3 = (void **)(*pcVar2)();
    return ppvVar3;
  }
  pvVar1 = param_1[3];
  pvVar4 = (void *)FUN_180008b88(param_2,pvVar1);
  uVar5 = (longlong)pvVar4 + 1;
  if (pvVar4 == (void *)0xffffffffffffffff) {
    uVar5 = 0xffffffffffffffff;
  }
  if (0x7fffffffffffffff < uVar5) {
                    // WARNING: Subroutine does not return
    FUN_18001642c();
  }
  _Dst = (void *)FUN_180008bb4(uVar5 * 2);
  param_1[2] = param_2;
  param_1[3] = pvVar4;
  memcpy(_Dst,param_4,(longlong)param_2 * 2);
  *(undefined2 *)((longlong)param_2 * 2 + (longlong)_Dst) = 0;
  if ((void *)0x7 < pvVar1) {
    FUN_180003f84(*param_1,(longlong)pvVar1 * 2 + 2);
  }
  *param_1 = _Dst;
  return param_1;
}



void ** FUN_180014bc0(void **param_1,ulonglong param_2,undefined8 param_3,void *param_4,
                     size_t param_5)

{
  void *_Size;
  void *pvVar1;
  void *_Src;
  code *pcVar2;
  void **ppvVar3;
  void *pvVar4;
  void *_Dst;
  longlong lVar5;
  
  _Size = param_1[2];
  if (0x7fffffffffffffffU - (longlong)_Size < param_2) {
    std::_Xlength_error("string too long");
    pcVar2 = (code *)swi(3);
    ppvVar3 = (void **)(*pcVar2)();
    return ppvVar3;
  }
  pvVar1 = param_1[3];
  pvVar4 = (void *)FUN_180007d30(param_1,(void *)(param_2 + (longlong)_Size));
  lVar5 = (longlong)pvVar4 + 1;
  if (pvVar4 == (void *)0xffffffffffffffff) {
    lVar5 = -1;
  }
  _Dst = (void *)FUN_180008bb4(lVar5);
  param_1[2] = (void *)(param_2 + (longlong)_Size);
  param_1[3] = pvVar4;
  pvVar4 = (void *)((longlong)_Size + (longlong)_Dst);
  if (pvVar1 < (void *)0x10) {
    memcpy(_Dst,param_1,(size_t)_Size);
    memcpy(pvVar4,param_4,param_5);
    *(undefined *)((longlong)pvVar4 + param_5) = 0;
  }
  else {
    _Src = *param_1;
    memcpy(_Dst,_Src,(size_t)_Size);
    memcpy(pvVar4,param_4,param_5);
    *(undefined *)((longlong)pvVar4 + param_5) = 0;
    FUN_180003f84(_Src,(longlong)pvVar1 + 1);
  }
  *param_1 = _Dst;
  return param_1;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_180014db0(undefined8 *param_1,undefined8 *param_2,undefined8 param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined8 uVar5;
  undefined auStack136 [32];
  undefined8 local_68 [3];
  ulonglong local_50;
  undefined local_48 [32];
  undefined8 *local_28;
  undefined4 uStack32;
  undefined4 uStack28;
  ulonglong local_18;
  
  local_18 = DAT_180418010 ^ (ulonglong)auStack136;
  local_28 = param_1;
  uVar5 = FUN_180007e28(local_48,param_3);
  local_28 = (undefined8 *)*param_2;
  uStack32 = *(undefined4 *)(param_2 + 1);
  uStack28 = *(undefined4 *)((longlong)param_2 + 0xc);
  local_28 = (undefined8 *)FUN_1800162c8(local_68,&local_28,uVar5);
  if (0xf < (ulonglong)local_28[3]) {
    local_28 = (undefined8 *)*local_28;
  }
  *param_1 = std::exception::vftable;
  uStack32 = CONCAT31(uStack32._1_3_,1);
  *(undefined (*) [16])(param_1 + 1) = ZEXT816(0);
  __std_exception_copy(&local_28);
  *param_1 = std::runtime_error::vftable;
  if (0xf < local_50) {
    FUN_180003f84(local_68[0],local_50 + 1);
  }
  uVar1 = *(undefined4 *)param_2;
  uVar2 = *(undefined4 *)((longlong)param_2 + 4);
  uVar3 = *(undefined4 *)(param_2 + 1);
  uVar4 = *(undefined4 *)((longlong)param_2 + 0xc);
  *param_1 = std::_System_error::vftable;
  *(undefined4 *)(param_1 + 3) = uVar1;
  *(undefined4 *)((longlong)param_1 + 0x1c) = uVar2;
  *(undefined4 *)(param_1 + 4) = uVar3;
  *(undefined4 *)((longlong)param_1 + 0x24) = uVar4;
  FUN_18000e8c0(local_18 ^ (ulonglong)auStack136);
  return;
}



undefined8 * FUN_180014e88(undefined8 *param_1,longlong param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  
  FUN_180014f4c();
  *param_1 = std::_System_error::vftable;
  uVar1 = *(undefined4 *)(param_2 + 0x1c);
  uVar2 = *(undefined4 *)(param_2 + 0x20);
  uVar3 = *(undefined4 *)(param_2 + 0x24);
  *(undefined4 *)(param_1 + 3) = *(undefined4 *)(param_2 + 0x18);
  *(undefined4 *)((longlong)param_1 + 0x1c) = uVar1;
  *(undefined4 *)(param_1 + 4) = uVar2;
  *(undefined4 *)((longlong)param_1 + 0x24) = uVar3;
  return param_1;
}



undefined8 * FUN_180014ec0(undefined8 *param_1)

{
  FUN_180014f4c();
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



undefined8 * FUN_180014ee4(undefined8 *param_1)

{
  FUN_180014f4c();
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}



undefined8 * FUN_180014f08(undefined8 *param_1)

{
  param_1[2] = 0;
  param_1[1] = "bad array new length";
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}



undefined8 * FUN_180014f28(undefined8 *param_1)

{
  FUN_180014f4c();
  *param_1 = std::bad_optional_access::vftable;
  return param_1;
}



undefined8 * FUN_180014f4c(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  *(undefined (*) [16])(param_1 + 1) = ZEXT816(0);
  __std_exception_copy(param_2 + 8);
  return param_1;
}



undefined8 * FUN_180014f80(undefined8 *param_1)

{
  FUN_180014f4c();
  *param_1 = std::runtime_error::vftable;
  return param_1;
}



undefined8 * FUN_180014fa4(undefined8 *param_1)

{
  FUN_180014e88();
  *param_1 = std::system_error::vftable;
  return param_1;
}



undefined8 * FUN_180014fc8(undefined8 *param_1,undefined4 *param_2)

{
  undefined4 local_38;
  undefined4 uStack52;
  undefined4 uStack48;
  undefined4 uStack44;
  undefined8 local_28 [3];
  ulonglong local_10;
  
  FUN_180007c64(local_28,&DAT_1800ac74e);
  local_38 = *param_2;
  uStack52 = param_2[1];
  uStack48 = param_2[2];
  uStack44 = param_2[3];
  FUN_180014db0(param_1,&local_38,local_28);
  if (0xf < local_10) {
    FUN_180003f84(local_28[0],local_10 + 1);
  }
  *param_1 = std::system_error::vftable;
  return param_1;
}



void FUN_1800150cc(longlong param_1)

{
  longlong lVar1;
  
  lVar1 = *(longlong *)(param_1 + 8);
  if (lVar1 != 0) {
    FUN_18001494c(lVar1 + 0x38,lVar1 + 0x38,*(undefined8 *)(*(longlong *)(lVar1 + 0x38) + 8));
    FUN_180003f84(*(undefined8 *)(lVar1 + 0x38),0x40);
  }
  if (*(longlong *)(param_1 + 8) != 0) {
    FUN_180003f84(*(longlong *)(param_1 + 8),0x48);
  }
  return;
}



void FUN_180015124(undefined8 *param_1)

{
  if (0xf < (ulonglong)param_1[3]) {
    FUN_180003f84(*param_1,param_1[3] + 1);
  }
  param_1[2] = 0;
  *(undefined *)param_1 = 0;
  param_1[3] = 0xf;
  return;
}



void FUN_180015184(longlong *param_1)

{
  FUN_18001494c(param_1,param_1,*(undefined8 *)(*param_1 + 8));
  FUN_180003f84(*param_1,0x40);
  return;
}



void FUN_1800151b0(undefined8 *param_1)

{
  if (*(char *)(param_1 + 4) != '\0') {
    if (0xf < (ulonglong)param_1[3]) {
      FUN_180003f84(*param_1,param_1[3] + 1);
    }
    param_1[2] = 0;
    *(undefined *)param_1 = 0;
    param_1[3] = 0xf;
  }
  return;
}



void FUN_1800151ec(longlong param_1)

{
  longlong *plVar1;
  
  plVar1 = (longlong *)(param_1 + 0x18);
  FUN_18001494c(plVar1,plVar1,*(undefined8 *)(*plVar1 + 8));
  FUN_180003f84(*plVar1,0x40);
  return;
}



longlong * FUN_18001523c(longlong *param_1)

{
  longlong lVar1;
  longlong lVar2;
  longlong lVar3;
  
  lVar3 = *param_1;
  if (*(char *)(*(longlong *)(lVar3 + 0x10) + 0x19) == '\0') {
    lVar2 = FUN_1800163c4(*(longlong *)(lVar3 + 0x10));
  }
  else {
    lVar1 = *(longlong *)(lVar3 + 8);
    while ((lVar2 = lVar1, *(char *)(lVar2 + 0x19) == '\0' && (lVar3 == *(longlong *)(lVar2 + 0x10))
           )) {
      *param_1 = lVar2;
      lVar3 = lVar2;
      lVar1 = *(longlong *)(lVar2 + 8);
    }
  }
  *param_1 = lVar2;
  return param_1;
}



void * FUN_180015284(void *param_1,ulonglong param_2)

{
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined8 * FUN_1800152a8(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = std::exception::vftable;
  __std_exception_destroy(param_1 + 1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined8 * FUN_1800152ec(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = std::exception::vftable;
  __std_exception_destroy(param_1 + 1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_180015330(longlong param_1,ulonglong param_2,ulonglong param_3,longlong param_4,
                  ulonglong param_5,undefined8 param_6,char param_7)

{
  ulonglong *puVar1;
  int iVar2;
  ulonglong uVar3;
  undefined8 uVar4;
  undefined auStack248 [32];
  char local_d8;
  ulonglong local_d0;
  ulonglong local_c8;
  int local_c0;
  longlong local_b8;
  ulonglong local_b0 [2];
  undefined local_a0 [16];
  uint local_90;
  undefined8 local_88;
  undefined local_80 [24];
  longlong local_68 [2];
  ulonglong local_58;
  
  local_58 = DAT_180418010 ^ (ulonglong)auStack248;
  local_a0 = CONCAT88(local_a0._0_8_,param_2);
  local_d0 = param_5;
  local_b8 = param_4;
  local_b0[0] = param_3;
  if (((param_7 == '\0') || (param_5 == 0)) ||
     (iVar2 = FUN_1800155a4(param_1,&local_d0), param_5 = local_d0, -1 < iVar2)) {
    local_c8 = 0;
    local_c0 = 0;
    local_d0 = param_2;
    uVar3 = FUN_180014a1c(param_1 + 0x20,&local_d0);
    if (uVar3 == *(ulonglong *)(param_1 + 0x20)) {
      if (param_7 != '\0') {
        iVar2 = FUN_1800155a4(param_1,local_a0);
        if (iVar2 < 0) goto LAB_18001556c;
        param_2 = local_a0._0_8_;
      }
      local_c0 = *(int *)(param_1 + 0x48) + 1;
      *(int *)(param_1 + 0x48) = local_c0;
      local_c8 = 0;
      if ((param_5 != 0) && (local_c8 = 0, param_3 == 0)) {
        local_c8 = param_5;
      }
      local_a0 = ZEXT816(0);
      local_d0 = param_2;
      uVar4 = FUN_1800145fc();
      local_a0 = CONCAT88(local_a0._8_8_,uVar4);
      FUN_1800144f0(local_80,&local_d0,local_a0);
      FUN_18001494c(local_a0,local_a0,*(undefined8 *)(local_a0._0_8_ + 8));
      FUN_180003f84(local_a0._0_8_,0x40);
      FUN_180014868(param_1 + 0x20,&local_d0,local_80);
      uVar3 = local_d0;
      FUN_18001494c(local_68,local_68,*(undefined8 *)(local_68[0] + 8));
      FUN_180003f84(local_68[0],0x40);
    }
    if (param_3 != 0) {
      puVar1 = (ulonglong *)(uVar3 + 0x38);
      local_a0 = ZEXT816(param_3);
      local_90 = 0;
      uVar3 = FUN_1800149a0();
      *(int *)(param_1 + 0x48) = *(int *)(param_1 + 0x48) + 1;
      local_d0._0_4_ = *(uint *)(param_1 + 0x48);
      local_d0 = local_d0 & 0xffffffff00000000 | (ulonglong)(uint)local_d0;
      if (param_4 == 0) {
        param_4 = param_1 + 0x18;
        local_b8 = param_4;
      }
      local_d8 = *(char *)(param_1 + 0x41);
      if (param_7 != '\0') {
        if ((((local_d8 != '\0') || (uVar3 == *puVar1)) &&
            (iVar2 = FUN_1800155a4(param_1,local_b0), param_3 = local_b0[0], iVar2 < 0)) ||
           (iVar2 = FUN_1800155a4(), iVar2 < 0)) goto LAB_18001556c;
        param_4 = local_b8;
      }
      if ((uVar3 == *puVar1) || (local_d8 != '\0')) {
        uVar3 = 0;
        if (param_5 != 0) {
          uVar3 = param_5;
        }
        local_a0 = CONCAT88(uVar3,param_3);
        local_88 = 0;
        local_90 = (uint)local_d0;
        FUN_180014730(puVar1,local_b0,local_a0);
        uVar3 = local_b0[0];
      }
      *(longlong *)(uVar3 + 0x38) = param_4;
    }
  }
LAB_18001556c:
  FUN_18000e8c0(local_58 ^ (ulonglong)auStack248);
  return;
}



undefined8 FUN_1800155a4(longlong param_1,void **param_2)

{
  longlong lVar1;
  longlong **pplVar2;
  code *pcVar3;
  void *_Dst;
  undefined8 uVar4;
  longlong *plVar5;
  longlong lVar6;
  
  lVar1 = -1;
  do {
    lVar6 = lVar1;
    lVar1 = lVar6 + 1;
  } while (*(char *)((longlong)*param_2 + lVar6 + 1) != '\0');
  _Dst = (void *)thunk_FUN_18000f754(lVar6 + 2,&DAT_18001e1ff);
  if (_Dst == (void *)0x0) {
    uVar4 = 0xfffffffe;
  }
  else {
    memcpy(_Dst,*param_2,lVar6 + 2);
    lVar1 = *(longlong *)(param_1 + 0x30);
    if (*(longlong *)(param_1 + 0x38) == 0x666666666666666) {
      std::_Xlength_error("list too long");
      pcVar3 = (code *)swi(3);
      uVar4 = (*pcVar3)();
      return uVar4;
    }
    plVar5 = (longlong *)operator_new(0x28);
    plVar5[2] = (longlong)_Dst;
    plVar5[3] = 0;
    *(undefined4 *)(plVar5 + 4) = 0;
    *(longlong *)(param_1 + 0x38) = *(longlong *)(param_1 + 0x38) + 1;
    pplVar2 = *(longlong ***)(lVar1 + 8);
    *plVar5 = lVar1;
    plVar5[1] = (longlong)pplVar2;
    *(longlong **)(lVar1 + 8) = plVar5;
    *pplVar2 = plVar5;
    *param_2 = _Dst;
    uVar4 = 0;
  }
  return uVar4;
}



undefined8
FUN_180015670(longlong param_1,byte **param_2,byte **param_3,byte **param_4,byte **param_5,
             undefined8 *param_6)

{
  byte *pbVar1;
  bool bVar2;
  char cVar3;
  ulonglong uVar4;
  undefined8 uVar5;
  byte bVar6;
  byte *pbVar7;
  byte *pbVar8;
  
  pbVar7 = *param_2;
  *param_6 = 0;
  bVar6 = *pbVar7;
  uVar4 = (ulonglong)&stack0x00000000 | (ulonglong)bVar6;
  do {
    if (bVar6 == 0) {
      return 0;
    }
    do {
      if ((0x20 < (byte)uVar4) || ((0x100002600U >> ((longlong)(char)(byte)uVar4 & 0x3fU) & 1) == 0)
         ) break;
      pbVar7 = pbVar7 + 1;
      *param_2 = pbVar7;
      uVar4 = (ulonglong)*pbVar7;
    } while (*pbVar7 != 0);
    bVar6 = *pbVar7;
    if (bVar6 == 0) {
      return 0;
    }
    if ((bVar6 == 0x3b) || (bVar6 == 0x23)) {
      FUN_180015c18();
    }
    else if (bVar6 == 0x5b) {
      do {
        pbVar7 = pbVar7 + 1;
        *param_2 = pbVar7;
        if ((*pbVar7 == 0) || (0x20 < *pbVar7)) break;
      } while ((0x100002600U >> ((longlong)(char)*pbVar7 & 0x3fU) & 1) != 0);
      *param_3 = pbVar7;
      if (*pbVar7 != 0) {
        bVar6 = *pbVar7;
        do {
          if ((bVar6 == 0x5d) || (pbVar8 = pbVar7, cVar3 = FUN_1800159d8(), cVar3 != '\0')) break;
          pbVar7 = pbVar8 + 1;
          bVar6 = *pbVar7;
          *param_2 = pbVar7;
        } while (bVar6 != 0);
      }
      pbVar8 = pbVar7;
      if (*pbVar7 == 0x5d) goto LAB_18001580c;
    }
    else {
      *param_4 = pbVar7;
      do {
        if ((bVar6 == 0x3d) || (pbVar8 = pbVar7, cVar3 = FUN_1800159d8(), cVar3 != '\0')) break;
        pbVar7 = pbVar8 + 1;
        *param_2 = pbVar7;
        bVar6 = *pbVar7;
      } while (bVar6 != 0);
      if (*pbVar7 == 0x3d) {
        bVar2 = true;
        pbVar8 = pbVar7;
        if (*param_4 != pbVar7) break;
        do {
          cVar3 = FUN_1800159d8();
          if (cVar3 != '\0') break;
          pbVar7 = pbVar7 + 1;
          *param_2 = pbVar7;
        } while (*pbVar7 != 0);
      }
      else {
        bVar2 = false;
        pbVar8 = pbVar7;
        if (*(char *)(param_1 + 0x45) != '\0') break;
      }
    }
    pbVar7 = *param_2;
    bVar6 = *pbVar7;
    uVar4 = (ulonglong)bVar6;
  } while( true );
  while ((0x100002600U >> ((longlong)(char)*pbVar8 & 0x3fU) & 1) != 0) {
    pbVar1 = pbVar8;
    pbVar8 = pbVar1 + -1;
    if ((pbVar8 < *param_4) || (0x20 < *pbVar8)) break;
  }
  if (!bVar2) {
    if (*pbVar7 != 0) {
      FUN_180015dfc();
    }
    pbVar8[1] = 0;
    return 1;
  }
  *pbVar1 = 0;
  do {
    pbVar8 = pbVar7 + 1;
    bVar6 = *pbVar8;
    *param_2 = pbVar8;
    if (((bVar6 == 0) || (pbVar7 = pbVar8, cVar3 = FUN_1800159d8(), cVar3 != '\0')) ||
       (0x20 < bVar6)) break;
  } while ((0x100002600U >> ((longlong)(char)bVar6 & 0x3fU) & 1) != 0);
  *param_5 = pbVar8;
  bVar6 = *pbVar8;
  while ((bVar6 != 0 && (pbVar7 = pbVar8, cVar3 = FUN_1800159d8(), cVar3 == '\0'))) {
    pbVar8 = pbVar7 + 1;
    bVar6 = *pbVar8;
    *param_2 = pbVar8;
  }
  pbVar7 = pbVar8 + -1;
  if (*pbVar8 != 0) {
    FUN_180015dfc();
  }
  while (((*param_5 <= pbVar7 && (*pbVar7 < 0x21)) &&
         ((0x100002600U >> ((longlong)(char)*pbVar7 & 0x3fU) & 1) != 0))) {
    pbVar7 = pbVar7 + -1;
  }
  pbVar7[1] = 0;
  if ((((*(char *)(param_1 + 0x42) != '\0') && (pbVar8 = *param_5, *pbVar8 == 0x3c)) &&
      (pbVar8[1] == 0x3c)) && (pbVar8[2] == 0x3c)) {
    uVar5 = FUN_180015c18();
    return uVar5;
  }
  if (*(char *)(param_1 + 0x44) == '\0') {
    return 1;
  }
  pbVar8 = *param_5;
  if (pbVar7 <= pbVar8) {
    return 1;
  }
  if (*pbVar8 != 0x22) {
    return 1;
  }
  if (*pbVar7 != 0x22) {
    return 1;
  }
  *param_5 = pbVar8 + 1;
  *pbVar7 = 0;
  return 1;
  while ((0x100002600U >> ((longlong)(char)*pbVar8 & 0x3fU) & 1) != 0) {
LAB_18001580c:
    pbVar1 = pbVar8;
    pbVar8 = pbVar1 + -1;
    if ((pbVar8 < *param_3) || (0x20 < *pbVar8)) break;
  }
  *pbVar1 = 0;
  do {
    pbVar7 = pbVar7 + 1;
    bVar6 = *pbVar7;
    *param_2 = pbVar7;
    if (bVar6 == 0) break;
    cVar3 = FUN_1800159d8();
  } while (cVar3 == '\0');
  *param_4 = (byte *)0x0;
  *param_5 = (byte *)0x0;
  return 1;
}



int FUN_180015970(longlong param_1,undefined8 param_2,char param_3)

{
  longlong *plVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  
  plVar1 = (longlong *)(param_1 + 0x10);
  if (((*plVar1 == 0) && (cVar2 = FUN_180015c18(param_1,param_2,plVar1,0,0), cVar2 != '\0')) &&
     (param_3 != '\0')) {
    iVar3 = FUN_1800155a4(param_1,plVar1);
    iVar4 = 0;
    if (iVar3 < 0) {
      iVar4 = iVar3;
    }
  }
  else {
    iVar4 = 0;
  }
  return iVar4;
}



undefined FUN_1800159d8(undefined8 param_1,char param_2)

{
  if ((param_2 != '\n') && (param_2 != '\r')) {
    return 0;
  }
  return 1;
}



undefined8 FUN_1800159e8(void **param_1,ushort *param_2,size_t param_3)

{
  void *_Size;
  void *pvVar1;
  char cVar2;
  void *_Dst;
  undefined8 uVar3;
  int iVar4;
  undefined8 local_res10 [2];
  undefined8 local_res20;
  undefined8 *puVar5;
  undefined8 local_48;
  undefined *local_40;
  void *local_38 [2];
  
  if (param_2 == (ushort *)0x0) {
LAB_180015b33:
    uVar3 = 0;
  }
  else {
    if (param_3 < 3) {
LAB_180015a3f:
      if (param_3 == 0) goto LAB_180015b33;
    }
    else {
      iVar4 = *param_2 - 0xbbef;
      if (iVar4 == 0) {
        iVar4 = *(byte *)(param_2 + 1) - 0xbf;
      }
      if (iVar4 == 0) {
        param_2 = (ushort *)((longlong)param_2 + 3);
        param_3 = param_3 - 3;
        if (*param_1 == (void *)0x0) {
          *(undefined *)(param_1 + 8) = 1;
        }
        goto LAB_180015a3f;
      }
    }
    if (param_3 == 0xffffffffffffffff) {
      uVar3 = 0xffffffff;
    }
    else {
      _Size = (void *)(param_3 + 1);
      _Dst = (void *)thunk_FUN_18000f754(_Size);
      if (_Dst == (void *)0x0) {
        uVar3 = 0xfffffffe;
      }
      else {
        memset(_Dst,0,(size_t)_Size);
        memcpy(_Dst,param_2,param_3);
        local_48 = 0;
        local_res20 = 0;
        local_res10[0] = 0;
        pvVar1 = *param_1;
        local_40 = &DAT_1800ac74e;
        local_38[0] = _Dst;
        uVar3 = FUN_180015970(param_1,local_38,
                              param_3 & 0xffffffffffffff00 | (ulonglong)(pvVar1 != (void *)0x0));
        while (-1 < (int)uVar3) {
          puVar5 = local_res10;
          cVar2 = FUN_180015670(param_1,local_38,&local_40,&local_48,&local_res20,puVar5);
          if (cVar2 == '\0') {
            if (pvVar1 == (void *)0x0) {
              *param_1 = _Dst;
              param_1[1] = _Size;
            }
            else {
              free(_Dst);
            }
            goto LAB_180015b33;
          }
          uVar3 = FUN_180015330(param_1,local_40,local_48,local_res20,local_res10[0],puVar5,
                                pvVar1 != (void *)0x0);
        }
      }
    }
  }
  return uVar3;
}



undefined4 FUN_180015b4c(undefined8 param_1,FILE *param_2)

{
  int iVar1;
  long lVar2;
  undefined4 uVar3;
  void *_DstBuf;
  size_t sVar4;
  size_t _Count;
  
  iVar1 = fseek(param_2,0,2);
  if (iVar1 == 0) {
    lVar2 = ftell(param_2);
    if (-1 < lVar2) {
      if (lVar2 == 0) {
        return 0;
      }
      _Count = (size_t)lVar2;
      _DstBuf = (void *)thunk_FUN_18000f754(_Count + 1,&DAT_18001e1ff);
      if (_DstBuf == (void *)0x0) {
        return 0xfffffffe;
      }
      *(undefined *)(_Count + (longlong)_DstBuf) = 0;
      fseek(param_2,0,0);
      sVar4 = fread(_DstBuf,1,_Count,param_2);
      if (sVar4 == _Count) {
        uVar3 = FUN_1800159e8(param_1,_DstBuf,sVar4);
      }
      else {
        uVar3 = 0xfffffffd;
      }
      free(_DstBuf);
      return uVar3;
    }
  }
  return 0xfffffffd;
}



undefined8 FUN_180015c18(byte *param_1,byte **param_2,byte **param_3,uchar *param_4,char param_5)

{
  byte bVar1;
  byte *_Src;
  char cVar2;
  int iVar3;
  byte *pbVar4;
  byte **ppbVar5;
  byte bVar6;
  byte *pbVar7;
  byte *_Str1;
  size_t _Size;
  ulonglong uVar8;
  byte *local_res8;
  
  _Str1 = *param_2;
  *param_3 = _Str1;
  bVar6 = *_Str1;
  ppbVar5 = param_2;
  local_res8 = param_1;
  do {
    uVar8 = 0x100002600;
    if (param_4 == (uchar *)0x0) {
      while ((pbVar7 = *param_2, *pbVar7 != 0x3b && (*pbVar7 != 0x23))) {
        if (param_5 == '\0') goto LAB_180015db1;
        _Size = 0;
        local_res8 = pbVar7;
        while ((pbVar7 = local_res8, *local_res8 < 0x21 &&
               ((uVar8 >> ((longlong)(char)*local_res8 & 0x3fU) & 1) != 0))) {
          ppbVar5 = (byte **)((ulonglong)ppbVar5 & 0xffffffffffffff00);
          cVar2 = FUN_1800159d8();
          if (cVar2 == '\0') {
            local_res8 = pbVar7 + 1;
          }
          else {
            _Size = (size_t)((int)_Size + 1);
            ppbVar5 = &local_res8;
            FUN_180015dfc();
          }
        }
        if ((*local_res8 != 0x3b) && (*local_res8 != 0x23)) goto LAB_180015db1;
        if (0 < (int)_Size) {
          ppbVar5 = (byte **)CONCAT71((int7)((ulonglong)ppbVar5 >> 8),10);
          memset(_Str1,(int)ppbVar5,_Size);
          _Str1 = _Str1 + (_Size & 0xffffffff);
          uVar8 = 0x100002600;
        }
        *param_2 = pbVar7;
      }
    }
    _Src = *param_2;
    bVar6 = *_Src;
    pbVar7 = _Src;
    while ((bVar6 != 0 && (pbVar4 = pbVar7, cVar2 = FUN_1800159d8(), cVar2 == '\0'))) {
      pbVar7 = pbVar4 + 1;
      bVar6 = *pbVar7;
      *param_2 = pbVar7;
    }
    if (_Str1 < _Src) {
      memmove(_Str1,_Src,(longlong)pbVar7 - (longlong)_Src);
      uVar8 = 0x100002600;
      _Str1[(longlong)pbVar7 - (longlong)_Src] = 0;
    }
    bVar6 = *pbVar7;
    *pbVar7 = 0;
    if (param_4 != (uchar *)0x0) {
      do {
        pbVar4 = pbVar7;
        pbVar7 = pbVar4 + -1;
        if ((pbVar7 <= _Str1) || (0x20 < *pbVar7)) break;
      } while ((uVar8 >> ((longlong)(char)*pbVar7 & 0x3fU) & 1) != 0);
      bVar1 = *pbVar4;
      *pbVar4 = 0;
      iVar3 = _mbsicmp(_Str1,param_4);
      if ((-1 < iVar3) && (iVar3 = _mbsicmp(param_4,_Str1), -1 < iVar3)) {
LAB_180015db1:
        pbVar7 = *param_2;
        if (*param_3 != pbVar7) {
          _Str1[-1] = 0;
          if ((param_4 != (uchar *)0x0) && (bVar6 != 0)) {
            *pbVar7 = bVar6;
            FUN_180015dfc();
          }
          return 1;
        }
        *param_3 = (byte *)0x0;
        return 0;
      }
      *pbVar4 = bVar1;
      pbVar7 = *param_2;
    }
    if (bVar6 == 0) {
      return 1;
    }
    *pbVar7 = bVar6;
    ppbVar5 = param_2;
    FUN_180015dfc();
    _Str1[(longlong)pbVar7 - (longlong)_Src] = 10;
    _Str1 = _Str1 + ((longlong)pbVar7 - (longlong)_Src) + 1;
  } while( true );
}



void FUN_180015dfc(undefined8 param_1,char **param_2)

{
  char *pcVar1;
  longlong lVar2;
  
  pcVar1 = *param_2;
  if ((*pcVar1 != '\r') || (lVar2 = 2, pcVar1[1] != '\n')) {
    lVar2 = 1;
  }
  *param_2 = pcVar1 + lVar2;
  return;
}



void FUN_180015e1c(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  longlong *plVar1;
  longlong lVar2;
  undefined auStack56 [32];
  undefined8 local_18;
  ulonglong local_10;
  
  local_10 = DAT_180418010 ^ (ulonglong)auStack56;
  local_18 = param_2;
  FUN_18001523c(&local_18,param_2,param_3,param_2);
  lVar2 = FUN_180015ea8(param_1,param_2);
  plVar1 = (longlong *)(lVar2 + 0x38);
  FUN_18001494c(plVar1,plVar1,*(undefined8 *)(*plVar1 + 8));
  FUN_180003f84(*plVar1,0x40);
  FUN_180003f84(lVar2,0x48);
  FUN_18000e8c0(local_10 ^ (ulonglong)auStack56);
  return;
}



longlong ** FUN_180015ea8(longlong *param_1,longlong **param_2)

{
  undefined uVar1;
  longlong **pplVar2;
  longlong **pplVar3;
  longlong **pplVar4;
  longlong **pplVar5;
  longlong **local_res10;
  
  local_res10 = param_2;
  FUN_18001523c(&local_res10);
  pplVar4 = (longlong **)*param_2;
  pplVar5 = (longlong **)param_2[2];
  if (((*(char *)((longlong)pplVar4 + 0x19) == '\0') &&
      (pplVar5 = pplVar4, *(char *)((longlong)param_2[2] + 0x19) == '\0')) &&
     (pplVar5 = (longlong **)local_res10[2], local_res10 != param_2)) {
    pplVar4[1] = (longlong *)local_res10;
    *local_res10 = *param_2;
    pplVar4 = local_res10;
    if (local_res10 != (longlong **)param_2[2]) {
      pplVar4 = (longlong **)local_res10[1];
      if (*(char *)((longlong)pplVar5 + 0x19) == '\0') {
        pplVar5[1] = (longlong *)pplVar4;
      }
      *pplVar4 = (longlong *)pplVar5;
      local_res10[2] = param_2[2];
      param_2[2][1] = (longlong)local_res10;
    }
    if (*(longlong ***)(*param_1 + 8) == param_2) {
      *(longlong ***)(*param_1 + 8) = local_res10;
    }
    else {
      pplVar2 = (longlong **)param_2[1];
      if ((longlong **)*pplVar2 == param_2) {
        *pplVar2 = (longlong *)local_res10;
      }
      else {
        pplVar2[2] = (longlong *)local_res10;
      }
    }
    uVar1 = *(undefined *)(local_res10 + 3);
    local_res10[1] = param_2[1];
    *(undefined *)(local_res10 + 3) = *(undefined *)(param_2 + 3);
    *(undefined *)(param_2 + 3) = uVar1;
  }
  else {
    pplVar2 = (longlong **)param_2[1];
    if (*(char *)((longlong)pplVar5 + 0x19) == '\0') {
      pplVar5[1] = (longlong *)pplVar2;
    }
    if (*(longlong ***)(*param_1 + 8) == param_2) {
      *(longlong ***)(*param_1 + 8) = pplVar5;
    }
    else if ((longlong **)*pplVar2 == param_2) {
      *pplVar2 = (longlong *)pplVar5;
    }
    else {
      pplVar2[2] = (longlong *)pplVar5;
    }
    pplVar3 = (longlong **)*param_1;
    pplVar4 = pplVar2;
    if ((longlong **)*pplVar3 == param_2) {
      if (*(char *)((longlong)pplVar5 + 0x19) == '\0') {
        pplVar2 = (longlong **)FUN_1800163c4(pplVar5);
      }
      *pplVar3 = (longlong *)pplVar2;
    }
    if (*(longlong ***)(*param_1 + 0x10) == param_2) {
      pplVar2 = pplVar4;
      if (*(char *)((longlong)pplVar5 + 0x19) == '\0') {
        pplVar2 = pplVar5;
        for (pplVar3 = (longlong **)pplVar5[2]; *(char *)((longlong)pplVar3 + 0x19) == '\0';
            pplVar3 = (longlong **)pplVar3[2]) {
          pplVar2 = pplVar3;
        }
      }
      *(longlong ***)(*param_1 + 0x10) = pplVar2;
    }
  }
  if (*(char *)(param_2 + 3) == '\x01') {
    if (pplVar5 != *(longlong ***)(*param_1 + 8)) {
      do {
        pplVar2 = pplVar4;
        if (*(char *)(pplVar5 + 3) != '\x01') break;
        pplVar4 = (longlong **)*pplVar2;
        pplVar3 = pplVar2;
        if (pplVar5 == pplVar4) {
          pplVar4 = (longlong **)pplVar2[2];
          if (*(char *)(pplVar4 + 3) == '\0') {
            *(undefined *)(pplVar4 + 3) = 1;
            *(undefined *)(pplVar2 + 3) = 0;
            FUN_18001627c(param_1,pplVar2);
            pplVar4 = (longlong **)pplVar3[2];
          }
          if (*(char *)((longlong)pplVar4 + 0x19) == '\0') {
            if ((*(char *)(*pplVar4 + 3) != '\x01') || (*(char *)(pplVar4[2] + 3) != '\x01')) {
              if (*(char *)(pplVar4[2] + 3) == '\x01') {
                *(undefined *)(*pplVar4 + 3) = 1;
                *(undefined *)(pplVar4 + 3) = 0;
                FUN_1800163e0(param_1);
                pplVar4 = (longlong **)pplVar3[2];
              }
              *(undefined *)(pplVar4 + 3) = *(undefined *)(pplVar3 + 3);
              *(undefined *)(pplVar3 + 3) = 1;
              *(undefined *)(pplVar4[2] + 3) = 1;
              FUN_18001627c(param_1,pplVar3);
              break;
            }
LAB_1800160ce:
            *(undefined *)(pplVar4 + 3) = 0;
          }
        }
        else {
          if (*(char *)(pplVar4 + 3) == '\0') {
            *(undefined *)(pplVar4 + 3) = 1;
            *(undefined *)(pplVar2 + 3) = 0;
            FUN_1800163e0(param_1,pplVar2);
            pplVar4 = (longlong **)*pplVar3;
          }
          if (*(char *)((longlong)pplVar4 + 0x19) == '\0') {
            if ((*(char *)(pplVar4[2] + 3) == '\x01') && (*(char *)(*pplVar4 + 3) == '\x01'))
            goto LAB_1800160ce;
            if (*(char *)(*pplVar4 + 3) == '\x01') {
              *(undefined *)(pplVar4[2] + 3) = 1;
              *(undefined *)(pplVar4 + 3) = 0;
              FUN_18001627c(param_1);
              pplVar4 = (longlong **)*pplVar3;
            }
            *(undefined *)(pplVar4 + 3) = *(undefined *)(pplVar3 + 3);
            *(undefined *)(pplVar3 + 3) = 1;
            *(undefined *)(*pplVar4 + 3) = 1;
            FUN_1800163e0(param_1,pplVar3);
            break;
          }
        }
        pplVar4 = (longlong **)pplVar3[1];
        pplVar5 = pplVar2;
      } while (pplVar2 != *(longlong ***)(*param_1 + 8));
    }
    *(undefined *)(pplVar5 + 3) = 1;
  }
  if (param_1[1] != 0) {
    param_1[1] = param_1[1] + -1;
  }
  return param_2;
}



longlong * FUN_18001614c(longlong **param_1,longlong **param_2,longlong *param_3)

{
  longlong **pplVar1;
  longlong lVar2;
  longlong *plVar3;
  longlong *plVar4;
  longlong *plVar5;
  longlong **pplVar6;
  
  param_1[1] = (longlong *)((longlong)param_1[1] + 1);
  pplVar6 = (longlong **)*param_1;
  pplVar1 = (longlong **)*param_2;
  param_3[1] = (longlong)pplVar1;
  if (pplVar1 == pplVar6) {
    *pplVar6 = param_3;
    pplVar6[1] = param_3;
    pplVar6[2] = param_3;
    *(undefined *)(param_3 + 3) = 1;
  }
  else {
    if (*(int *)(param_2 + 1) == 0) {
      pplVar1[2] = param_3;
      if (pplVar1 == (longlong **)pplVar6[2]) {
        pplVar6[2] = param_3;
      }
    }
    else {
      *pplVar1 = param_3;
      if (pplVar1 == (longlong **)*pplVar6) {
        *pplVar6 = param_3;
      }
    }
    lVar2 = param_3[1];
    plVar5 = param_3;
    while (*(char *)(lVar2 + 0x18) == '\0') {
      plVar4 = (longlong *)plVar5[1];
      plVar3 = *(longlong **)plVar4[1];
      if (plVar4 == plVar3) {
        plVar3 = ((longlong **)plVar4[1])[2];
        if (*(char *)(plVar3 + 3) == '\0') {
LAB_180016207:
          *(undefined *)(plVar4 + 3) = 1;
          *(undefined *)(plVar3 + 3) = 1;
          *(undefined *)(*(longlong *)(plVar5[1] + 8) + 0x18) = 0;
          plVar5 = *(longlong **)(plVar5[1] + 8);
        }
        else {
          if (plVar5 == (longlong *)plVar4[2]) {
            FUN_18001627c(param_1,plVar4);
            plVar5 = plVar4;
          }
          *(undefined *)(plVar5[1] + 0x18) = 1;
          *(undefined *)(*(longlong *)(plVar5[1] + 8) + 0x18) = 0;
          FUN_1800163e0(param_1,*(undefined8 *)(plVar5[1] + 8));
        }
      }
      else {
        if (*(char *)(plVar3 + 3) == '\0') goto LAB_180016207;
        if (plVar5 == (longlong *)*plVar4) {
          FUN_1800163e0(param_1,plVar4);
          plVar5 = plVar4;
        }
        *(undefined *)(plVar5[1] + 0x18) = 1;
        *(undefined *)(*(longlong *)(plVar5[1] + 8) + 0x18) = 0;
        FUN_18001627c(param_1,*(undefined8 *)(plVar5[1] + 8));
      }
      lVar2 = plVar5[1];
    }
    *(undefined *)(pplVar6[1] + 3) = 1;
  }
  return param_3;
}



void FUN_18001627c(longlong *param_1,longlong *param_2)

{
  longlong **pplVar1;
  longlong **pplVar2;
  
  pplVar1 = (longlong **)param_2[2];
  param_2[2] = (longlong)*pplVar1;
  if (*(char *)((longlong)*pplVar1 + 0x19) == '\0') {
    *(longlong **)((longlong)*pplVar1 + 8) = param_2;
  }
  pplVar1[1] = (longlong *)param_2[1];
  if (param_2 == *(longlong **)(*param_1 + 8)) {
    *(longlong ***)(*param_1 + 8) = pplVar1;
  }
  else {
    pplVar2 = (longlong **)param_2[1];
    if (param_2 == *pplVar2) {
      *pplVar2 = (longlong *)pplVar1;
    }
    else {
      pplVar2[2] = (longlong *)pplVar1;
    }
  }
  *pplVar1 = param_2;
  param_2[1] = (longlong)pplVar1;
  return;
}



void FUN_1800162c8(undefined8 *param_1,undefined4 *param_2,undefined4 *param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined8 ***pppuVar4;
  undefined auStack120 [40];
  undefined8 ***local_50 [2];
  undefined8 local_40;
  ulonglong local_38;
  undefined4 *local_30;
  ulonglong local_28;
  
  local_28 = DAT_180418010 ^ (ulonglong)auStack120;
  local_30 = param_3;
  if (*(longlong *)(param_3 + 4) != 0) {
    FUN_180016490(param_3,&DAT_18001e4c0,2);
  }
  (**(code **)(**(longlong **)(param_2 + 2) + 0x10))(*(longlong **)(param_2 + 2),local_50,*param_2);
  pppuVar4 = local_50;
  if (0xf < local_38) {
    pppuVar4 = local_50[0];
  }
  FUN_180016490(param_3,pppuVar4,local_40);
  if (0xf < local_38) {
    FUN_180003f84(local_50[0],local_38 + 1);
  }
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  uVar1 = param_3[1];
  uVar2 = param_3[2];
  uVar3 = param_3[3];
  *(undefined4 *)param_1 = *param_3;
  *(undefined4 *)((longlong)param_1 + 4) = uVar1;
  *(undefined4 *)(param_1 + 1) = uVar2;
  *(undefined4 *)((longlong)param_1 + 0xc) = uVar3;
  uVar1 = param_3[5];
  uVar2 = param_3[6];
  uVar3 = param_3[7];
  *(undefined4 *)(param_1 + 2) = param_3[4];
  *(undefined4 *)((longlong)param_1 + 0x14) = uVar1;
  *(undefined4 *)(param_1 + 3) = uVar2;
  *(undefined4 *)((longlong)param_1 + 0x1c) = uVar3;
  *(undefined8 *)(param_3 + 4) = 0;
  *(undefined8 *)(param_3 + 6) = 0xf;
  *(undefined *)param_3 = 0;
  *(undefined8 *)(param_3 + 4) = 0;
  *(undefined *)param_3 = 0;
  *(undefined8 *)(param_3 + 6) = 0xf;
  FUN_18000e8c0(local_28 ^ (ulonglong)auStack120);
  return;
}



longlong ** FUN_1800163c4(longlong **param_1)

{
  char cVar1;
  longlong **pplVar2;
  longlong **pplVar3;
  
  cVar1 = *(char *)((longlong)*param_1 + 0x19);
  pplVar2 = (longlong **)*param_1;
  while (pplVar3 = pplVar2, cVar1 == '\0') {
    pplVar2 = (longlong **)*pplVar3;
    cVar1 = *(char *)((longlong)pplVar2 + 0x19);
    param_1 = pplVar3;
  }
  return param_1;
}



void FUN_1800163e0(longlong *param_1,longlong *param_2)

{
  longlong lVar1;
  longlong *plVar2;
  
  lVar1 = *param_2;
  *param_2 = *(longlong *)(lVar1 + 0x10);
  if (*(char *)(*(longlong *)(lVar1 + 0x10) + 0x19) == '\0') {
    *(longlong **)(*(longlong *)(lVar1 + 0x10) + 8) = param_2;
  }
  *(longlong *)(lVar1 + 8) = param_2[1];
  if (param_2 == *(longlong **)(*param_1 + 8)) {
    *(longlong *)(*param_1 + 8) = lVar1;
  }
  else {
    plVar2 = (longlong *)param_2[1];
    if (param_2 == (longlong *)plVar2[2]) {
      plVar2[2] = lVar1;
    }
    else {
      *plVar2 = lVar1;
    }
  }
  *(longlong **)(lVar1 + 0x10) = param_2;
  param_2[1] = lVar1;
  return;
}



void FUN_18001642c(void)

{
  undefined **local_28;
  undefined local_20 [16];
  
  local_20 = ZEXT816(0x18001e510);
  local_28 = std::bad_array_new_length::vftable;
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_28,(ThrowInfo *)&DAT_1804161e0);
}



void FUN_180016464(void)

{
  undefined **local_28;
  undefined local_20 [16];
  
  local_28 = std::bad_optional_access::vftable;
  local_20 = ZEXT816(0);
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_28,(ThrowInfo *)&DAT_180416150);
}



undefined8 * FUN_180016490(undefined8 *param_1,void *param_2,size_t param_3)

{
  longlong lVar1;
  undefined8 *puVar2;
  
  lVar1 = param_1[2];
  if ((ulonglong)(param_1[3] - lVar1) < param_3) {
    param_1 = (undefined8 *)FUN_180014bc0(param_1,param_3,param_3,param_2,param_3);
  }
  else {
    param_1[2] = lVar1 + param_3;
    puVar2 = param_1;
    if (0xf < (ulonglong)param_1[3]) {
      puVar2 = (undefined8 *)*param_1;
    }
    memmove((void *)((longlong)puVar2 + lVar1),param_2,param_3);
    *(undefined *)((longlong)(void *)((longlong)puVar2 + lVar1) + param_3) = 0;
  }
  return param_1;
}



undefined8 * FUN_180016504(undefined8 *param_1,void *param_2,ulonglong param_3)

{
  undefined8 *_Dst;
  
  if (param_3 < (ulonglong)param_1[3] || param_3 == param_1[3]) {
    _Dst = param_1;
    if (7 < (ulonglong)param_1[3]) {
      _Dst = (undefined8 *)*param_1;
    }
    param_1[2] = param_3;
    memmove(_Dst,param_2,param_3 * 2);
    *(undefined2 *)(param_3 * 2 + (longlong)_Dst) = 0;
  }
  else {
    param_1 = (undefined8 *)FUN_180014af8(param_1,param_3,param_3,param_2);
  }
  return param_1;
}



int * FUN_180016564(undefined8 param_1,int *param_2,int param_3)

{
  int iVar1;
  undefined **ppuVar2;
  
  if (param_3 == 0) {
    *param_2 = 0;
    *(undefined ***)(param_2 + 2) = &PTR_vftable_180419a30;
  }
  else {
    iVar1 = std::_Winerror_map(param_3);
    if (iVar1 == 0) {
      *param_2 = param_3;
      ppuVar2 = &PTR_vftable_180419a40;
    }
    else {
      *param_2 = iVar1;
      ppuVar2 = &PTR_vftable_180419a30;
    }
    *(undefined ***)(param_2 + 2) = ppuVar2;
  }
  return param_2;
}



longlong FUN_1800165bc(longlong param_1,int *param_2,int param_3)

{
  uint7 uVar1;
  
  uVar1 = (uint7)((ulonglong)*(longlong *)(param_2 + 2) >> 8);
  if ((*(longlong *)(param_1 + 8) == *(longlong *)(*(longlong *)(param_2 + 2) + 8)) &&
     (*param_2 == param_3)) {
    return CONCAT71(uVar1,1);
  }
  return (ulonglong)uVar1 << 8;
}



undefined8 FUN_1800165d8(longlong *param_1,undefined4 param_2,int *param_3)

{
  int *piVar1;
  undefined8 uVar2;
  undefined local_18 [16];
  
  piVar1 = (int *)(**(code **)(*param_1 + 0x18))(param_1,local_18,param_2);
  if ((*(longlong *)(*(longlong *)(piVar1 + 2) + 8) == *(longlong *)(*(longlong *)(param_3 + 2) + 8)
      ) && (*piVar1 == *param_3)) {
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



undefined8 FUN_180016614(undefined8 param_1,undefined8 param_2,int param_3)

{
  char *pcVar1;
  
  if (param_3 == 0) {
    pcVar1 = "success";
  }
  else {
    pcVar1 = std::_Syserror_map(param_3);
  }
  FUN_180007c64(param_2,pcVar1);
  return param_2;
}



void FUN_180016648(undefined8 param_1,undefined8 *param_2,undefined4 param_3)

{
  undefined auStack88 [40];
  undefined8 *local_30;
  HLOCAL local_28;
  longlong local_20;
  ulonglong local_18;
  
  local_18 = DAT_180418010 ^ (ulonglong)auStack88;
  local_28 = (HLOCAL)0x0;
  local_30 = param_2;
  local_20 = FUN_18000e808(param_3,&local_28);
  *param_2 = 0;
  param_2[2] = 0;
  param_2[3] = 0;
  if (local_20 == 0) {
    FUN_180007c9c(param_2,"unknown error",0xd);
  }
  else {
    FUN_180007c9c(param_2,local_28,local_20);
  }
  LocalFree(local_28);
  FUN_18000e8c0(local_18 ^ (ulonglong)auStack88);
  return;
}



void FUN_1800166fc(undefined8 param_1,undefined2 *param_2,undefined8 *param_3,undefined8 *param_4)

{
  bool bVar1;
  longlong lVar2;
  ulonglong uVar3;
  int iVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined *puVar7;
  undefined auStack248 [32];
  undefined local_d8;
  undefined *local_c8;
  undefined local_b8 [32];
  undefined local_98 [32];
  undefined8 *local_78;
  undefined8 *local_70;
  undefined local_68;
  undefined7 uStack103;
  longlong local_58;
  ulonglong local_50;
  char local_48;
  ulonglong local_40;
  
  local_40 = DAT_180418010 ^ (ulonglong)auStack248;
  local_c8 = local_b8;
  local_78 = param_3;
  local_70 = param_4;
  uVar5 = FUN_180007e28(local_b8,param_4);
  uVar6 = FUN_180007e28(local_98,param_3);
  local_d8 = 1;
  FUN_180016d08(param_1,&local_68,uVar6,uVar5);
  uVar3 = local_50;
  lVar2 = local_58;
  if (local_48 != '\0') {
    puVar7 = &local_68;
    if (0xf < local_50) {
      puVar7 = (undefined *)CONCAT71(uStack103,local_68);
    }
    if (local_58 == 4) {
      iVar4 = memcmp(puVar7,&DAT_1800ac820,4);
      if (iVar4 != 0) goto LAB_1800167ab;
      bVar1 = true;
    }
    else {
LAB_1800167ab:
      bVar1 = false;
    }
    if (bVar1) {
      *param_2 = 0x101;
      goto LAB_1800167fb;
    }
    if (local_48 == '\0') goto LAB_1800167f6;
    puVar7 = &local_68;
    if (0xf < uVar3) {
      puVar7 = (undefined *)CONCAT71(uStack103,local_68);
    }
    if (lVar2 == 5) {
      iVar4 = memcmp(puVar7,"false",5);
      if (iVar4 != 0) goto LAB_1800167e8;
      bVar1 = true;
    }
    else {
LAB_1800167e8:
      bVar1 = false;
    }
    if (bVar1) {
      *param_2 = 0x100;
      goto LAB_1800167fb;
    }
  }
LAB_1800167f6:
  *(undefined *)((longlong)param_2 + 1) = 0;
LAB_1800167fb:
  if (local_48 != '\0') {
    if (0xf < uVar3) {
      FUN_180003f84(CONCAT71(uStack103,local_68),uVar3 + 1);
    }
    local_58 = 0;
    local_50 = 0xf;
    local_68 = 0;
  }
  if (0xf < (ulonglong)param_3[3]) {
    FUN_180003f84(*param_3,param_3[3] + 1);
  }
  param_3[2] = 0;
  *(undefined *)param_3 = 0;
  param_3[3] = 0xf;
  if (0xf < (ulonglong)param_4[3]) {
    FUN_180003f84(*param_4,param_4[3] + 1);
  }
  param_4[2] = 0;
  *(undefined *)param_4 = 0;
  param_4[3] = 0xf;
  FUN_18000e8c0(local_40 ^ (ulonglong)auStack248);
  return;
}



void FUN_1800168b0(undefined8 param_1,undefined4 *param_2,undefined8 *param_3,undefined8 *param_4)

{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined4 extraout_XMM0_Da;
  undefined auStack264 [32];
  undefined local_e8;
  undefined4 *local_d8;
  undefined *local_d0;
  undefined local_c0 [32];
  undefined local_a0 [32];
  undefined8 *local_80;
  undefined8 *local_78;
  undefined local_70;
  undefined7 uStack111;
  undefined8 local_60;
  ulonglong uStack88;
  char local_50;
  ulonglong local_48;
  
  local_48 = DAT_180418010 ^ (ulonglong)auStack264;
  local_d0 = local_c0;
  local_d8 = param_2;
  local_80 = param_3;
  local_78 = param_4;
  uVar1 = FUN_180007e28(local_c0,param_4);
  uVar2 = FUN_180007e28(local_a0,param_3);
  local_e8 = 0;
  FUN_180016d08(param_1,&local_70,uVar2,uVar1);
  if (local_50 == '\0') {
    FUN_180016464();
  }
  FUN_180017174(&local_70);
  *param_2 = extraout_XMM0_Da;
  *(undefined *)(param_2 + 1) = 1;
  if (local_50 != '\0') {
    if (0xf < uStack88) {
      FUN_180003f84(CONCAT71(uStack111,local_70),uStack88 + 1);
    }
    local_60 = 0;
    uStack88 = 0xf;
    local_70 = 0;
  }
  if (0xf < (ulonglong)param_3[3]) {
    FUN_180003f84(*param_3,param_3[3] + 1);
  }
  param_3[2] = 0;
  *(undefined *)param_3 = 0;
  param_3[3] = 0xf;
  if (0xf < (ulonglong)param_4[3]) {
    FUN_180003f84(*param_4,param_4[3] + 1);
  }
  param_4[2] = 0;
  *(undefined *)param_4 = 0;
  param_4[3] = 0xf;
  FUN_18000e8c0(local_48 ^ (ulonglong)auStack264);
  return;
}



void FUN_180016b50(undefined8 param_1,undefined4 *param_2,undefined8 *param_3,undefined8 *param_4)

{
  bool bVar1;
  longlong lVar2;
  ulonglong uVar3;
  int iVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined *puVar7;
  undefined auStack248 [32];
  undefined local_d8;
  undefined *local_c8;
  undefined local_b8 [32];
  undefined local_98 [32];
  undefined8 *local_78;
  undefined8 *local_70;
  undefined local_68;
  undefined7 uStack103;
  longlong local_58;
  ulonglong local_50;
  char local_48;
  ulonglong local_40;
  
  local_40 = DAT_180418010 ^ (ulonglong)auStack248;
  local_c8 = local_b8;
  local_78 = param_3;
  local_70 = param_4;
  uVar5 = FUN_180007e28(local_b8,param_4);
  uVar6 = FUN_180007e28(local_98,param_3);
  local_d8 = 1;
  FUN_180016d08(param_1,&local_68,uVar6,uVar5);
  uVar3 = local_50;
  lVar2 = local_58;
  if (local_48 == '\0') {
LAB_180016c4e:
    *(undefined *)(param_2 + 1) = 0;
  }
  else {
    puVar7 = &local_68;
    if (0xf < local_50) {
      puVar7 = (undefined *)CONCAT71(uStack103,local_68);
    }
    if (local_58 == 6) {
      iVar4 = memcmp(puVar7,"normal",6);
      if (iVar4 != 0) goto LAB_180016bff;
      bVar1 = true;
    }
    else {
LAB_180016bff:
      bVar1 = false;
    }
    if (bVar1) {
      *param_2 = 0;
    }
    else {
      if (local_48 == '\0') goto LAB_180016c4e;
      puVar7 = &local_68;
      if (0xf < uVar3) {
        puVar7 = (undefined *)CONCAT71(uStack103,local_68);
      }
      if (lVar2 == 8) {
        iVar4 = memcmp(puVar7,"extended",8);
        if (iVar4 != 0) goto LAB_180016c3f;
        bVar1 = true;
      }
      else {
LAB_180016c3f:
        bVar1 = false;
      }
      if (!bVar1) goto LAB_180016c4e;
      *param_2 = 1;
    }
    *(undefined *)(param_2 + 1) = 1;
  }
  if (local_48 != '\0') {
    if (0xf < uVar3) {
      FUN_180003f84(CONCAT71(uStack103,local_68),uVar3 + 1);
    }
    local_58 = 0;
    local_50 = 0xf;
    local_68 = 0;
  }
  if (0xf < (ulonglong)param_3[3]) {
    FUN_180003f84(*param_3,param_3[3] + 1);
  }
  param_3[2] = 0;
  *(undefined *)param_3 = 0;
  param_3[3] = 0xf;
  if (0xf < (ulonglong)param_4[3]) {
    FUN_180003f84(*param_4,param_4[3] + 1);
  }
  param_4[2] = 0;
  *(undefined *)param_4 = 0;
  param_4[3] = 0xf;
  FUN_18000e8c0(local_40 ^ (ulonglong)auStack248);
  return;
}



void FUN_180016d08(longlong param_1,longlong param_2,undefined8 *param_3,undefined8 *param_4,
                  char param_5)

{
  ulonglong *puVar1;
  ulonglong uVar2;
  int iVar3;
  undefined8 *puVar4;
  longlong lVar5;
  longlong lVar6;
  byte *pbVar7;
  byte *pbVar8;
  byte *pbVar9;
  undefined *puVar10;
  byte *pbVar11;
  undefined8 *puVar12;
  undefined auStack248 [32];
  longlong local_d8;
  undefined8 *local_d0;
  undefined8 local_c8;
  undefined4 local_c0;
  undefined8 *local_a8;
  undefined8 *local_a0;
  byte local_98;
  undefined7 uStack151;
  longlong local_88;
  ulonglong uStack128;
  byte local_78;
  undefined7 uStack119;
  undefined8 local_68;
  ulonglong uStack96;
  ulonglong local_58;
  
  local_58 = DAT_180418010 ^ (ulonglong)auStack248;
  puVar12 = param_4;
  if (0xf < (ulonglong)param_4[3]) {
    puVar12 = (undefined8 *)*param_4;
  }
  puVar1 = param_3 + 3;
  puVar4 = param_3;
  if (0xf < *puVar1) {
    puVar4 = (undefined8 *)*param_3;
  }
  local_d8 = param_2;
  local_a8 = param_3;
  local_a0 = param_4;
  if ((puVar4 == (undefined8 *)0x0) || (puVar12 == (undefined8 *)0x0)) {
LAB_180016db7:
    puVar10 = &DAT_1800ac704;
  }
  else {
    local_c8 = 0;
    local_c0 = 0;
    local_d0 = puVar4;
    lVar5 = FUN_180014a1c((longlong *)(param_1 + 0x70),&local_d0);
    if (lVar5 == *(longlong *)(param_1 + 0x70)) goto LAB_180016db7;
    local_c8 = 0;
    local_c0 = 0;
    local_d0 = puVar12;
    lVar6 = FUN_1800149a0((longlong *)(lVar5 + 0x38),&local_d0);
    if (lVar6 == *(longlong *)(lVar5 + 0x38)) goto LAB_180016db7;
    puVar10 = *(undefined **)(lVar6 + 0x38);
  }
  FUN_180007c64(&local_78,puVar10);
  FUN_180007e28(&local_98,&local_78);
  pbVar9 = (byte *)CONCAT71(uStack151,local_98);
  pbVar8 = &local_98;
  if (0xf < uStack128) {
    pbVar8 = pbVar9;
  }
  pbVar7 = &local_98;
  if (0xf < uStack128) {
    pbVar7 = pbVar9;
  }
  pbVar7 = pbVar7 + local_88;
  pbVar11 = &local_98;
  if (0xf < uStack128) {
    pbVar11 = pbVar9;
  }
  if (pbVar11 != pbVar7) {
    lVar5 = (longlong)pbVar8 - (longlong)pbVar11;
    do {
      iVar3 = tolower((uint)*pbVar11);
      pbVar11[lVar5] = (byte)iVar3;
      pbVar11 = pbVar11 + 1;
    } while (pbVar11 != pbVar7);
    pbVar9 = (byte *)CONCAT71(uStack151,local_98);
  }
  uVar2 = uStack128;
  pbVar8 = &local_98;
  if (0xf < uStack128) {
    pbVar8 = pbVar9;
  }
  if ((local_88 == 4) && (iVar3 = memcmp(pbVar8,&DAT_1800ac704,4), iVar3 == 0)) {
    *(undefined *)(param_2 + 0x20) = 0;
    if (uVar2 < 0x10) goto LAB_180016e9f;
  }
  else {
    pbVar9 = &local_78;
    if (param_5 != '\0') {
      pbVar9 = &local_98;
    }
    FUN_180007e28(param_2,pbVar9);
    *(undefined *)(param_2 + 0x20) = 1;
    if (uStack128 < 0x10) goto LAB_180016e9f;
    pbVar9 = (byte *)CONCAT71(uStack151,local_98);
    uVar2 = uStack128;
  }
  FUN_180003f84(pbVar9,uVar2 + 1);
LAB_180016e9f:
  local_98 = 0;
  local_88 = 0;
  uStack128 = 0xf;
  if (0xf < uStack96) {
    FUN_180003f84(0,CONCAT71(uStack119,local_78),uStack96 + 1);
  }
  local_78 = 0;
  local_68 = 0;
  uStack96 = 0xf;
  if (0xf < *puVar1) {
    FUN_180003f84(0,*param_3,*puVar1 + 1);
  }
  param_3[2] = 0;
  *(undefined *)param_3 = 0;
  *puVar1 = 0xf;
  if (0xf < (ulonglong)param_4[3]) {
    FUN_180003f84(*param_4,param_4[3] + 1);
  }
  param_4[2] = 0;
  *(undefined *)param_4 = 0;
  param_4[3] = 0xf;
  FUN_18000e8c0(local_58 ^ (ulonglong)auStack248);
  return;
}



void FUN_180016f70(undefined8 param_1,undefined4 *param_2,undefined8 *param_3,undefined8 *param_4)

{
  undefined *puVar1;
  bool bVar2;
  longlong lVar3;
  ulonglong uVar4;
  int iVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined *puVar8;
  undefined auStack264 [32];
  undefined local_e8;
  undefined *local_d8;
  undefined local_c8 [32];
  undefined local_a8 [32];
  undefined8 *local_88;
  undefined8 *local_80;
  undefined local_78;
  undefined7 uStack119;
  longlong local_68;
  ulonglong local_60;
  char local_58;
  ulonglong local_50;
  
  local_50 = DAT_180418010 ^ (ulonglong)auStack264;
  local_d8 = local_c8;
  local_88 = param_3;
  local_80 = param_4;
  uVar6 = FUN_180007e28(local_c8,param_4);
  uVar7 = FUN_180007e28(local_a8,param_3);
  local_e8 = 1;
  FUN_180016d08(param_1,&local_78,uVar7,uVar6);
  uVar4 = local_60;
  lVar3 = local_68;
  puVar1 = (undefined *)CONCAT71(uStack119,local_78);
  if (local_58 == '\0') {
LAB_1800170b9:
    *(undefined *)(param_2 + 1) = 0;
  }
  else {
    puVar8 = &local_78;
    if (0xf < local_60) {
      puVar8 = puVar1;
    }
    if (local_68 == 6) {
      iVar5 = memcmp(puVar8,"config",6);
      if (iVar5 != 0) goto LAB_180017028;
      bVar2 = true;
    }
    else {
LAB_180017028:
      bVar2 = false;
    }
    if (bVar2) {
      *param_2 = 0;
    }
    else {
      if (local_58 == '\0') goto LAB_1800170b9;
      puVar8 = &local_78;
      if (0xf < uVar4) {
        puVar8 = puVar1;
      }
      if (lVar3 == 0xd) {
        iVar5 = memcmp(puVar8,"cyberpunk2077",0xd);
        if (iVar5 != 0) goto LAB_18001706a;
        bVar2 = true;
      }
      else {
LAB_18001706a:
        bVar2 = false;
      }
      if (bVar2) {
        *param_2 = 1;
      }
      else {
        if (local_58 == '\0') goto LAB_1800170b9;
        puVar8 = &local_78;
        if (0xf < uVar4) {
          puVar8 = puVar1;
        }
        if (lVar3 == 4) {
          iVar5 = memcmp(puVar8,&DAT_1800ac71c,4);
          if (iVar5 != 0) goto LAB_1800170a7;
          bVar2 = true;
        }
        else {
LAB_1800170a7:
          bVar2 = false;
        }
        if (!bVar2) goto LAB_1800170b9;
        *param_2 = 2;
      }
    }
    *(undefined *)(param_2 + 1) = 1;
  }
  if (local_58 != '\0') {
    if (0xf < uVar4) {
      FUN_180003f84(puVar1,uVar4 + 1);
    }
    local_68 = 0;
    local_78 = 0;
    local_60 = 0xf;
  }
  if (0xf < (ulonglong)param_3[3]) {
    FUN_180003f84(*param_3,param_3[3] + 1);
  }
  param_3[2] = 0;
  *(undefined *)param_3 = 0;
  param_3[3] = 0xf;
  if (0xf < (ulonglong)param_4[3]) {
    FUN_180003f84(*param_4,param_4[3] + 1);
  }
  param_4[2] = 0;
  *(undefined *)param_4 = 0;
  param_4[3] = 0xf;
  FUN_18000e8c0(local_50 ^ (ulonglong)auStack264);
  return;
}



void FUN_180017174(undefined8 *param_1)

{
  code *pcVar1;
  int *piVar2;
  undefined auStack56 [32];
  undefined8 *local_18;
  ulonglong local_10;
  
  local_10 = DAT_180418010 ^ (ulonglong)auStack56;
  piVar2 = _errno();
  if (0xf < (ulonglong)param_1[3]) {
    param_1 = (undefined8 *)*param_1;
  }
  *piVar2 = 0;
  strtof(param_1,&local_18);
  if (param_1 == local_18) {
    std::_Xinvalid_argument("invalid stof argument");
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  if (*piVar2 == 0x22) {
    std::_Xout_of_range("stof argument out of range");
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  FUN_18000e8c0(local_10 ^ (ulonglong)auStack56);
  return;
}



char * FUN_1800171f4(longlong param_1)

{
  char *pcVar1;
  
  pcVar1 = "Unknown exception";
  if (*(longlong *)(param_1 + 8) != 0) {
    pcVar1 = *(char **)(param_1 + 8);
  }
  return pcVar1;
}



void FUN_180017254(undefined8 *param_1)

{
  FUN_18000e3f4(param_1,*param_1);
  FUN_180003f84(*param_1,0x20);
  return;
}



void FUN_1800172ac(void **param_1)

{
  void *_Memory;
  
  _Memory = *param_1;
  if (_Memory != (void *)0x0) {
    FUN_180008a34((longlong)_Memory + 0xa0);
    FUN_1800029b4((longlong)_Memory + 0x50);
    free(_Memory);
  }
  return;
}



void FUN_1800172e4(void **param_1)

{
  void *_Memory;
  
  _Memory = *param_1;
  if (_Memory != (void *)0x0) {
    FUN_18000e118(_Memory);
    free(_Memory);
  }
  return;
}



void FUN_180017310(longlong param_1)

{
  FUN_180003f84(*(longlong *)(param_1 + 0x18),
                *(longlong *)(param_1 + 0x20) - *(longlong *)(param_1 + 0x18) & 0xfffffffffffffff8);
  *(undefined8 *)(param_1 + 0x18) = 0;
  *(undefined8 *)(param_1 + 0x20) = 0;
  *(undefined8 *)(param_1 + 0x28) = 0;
  FUN_18000e3f4();
  FUN_180003f84(*(undefined8 *)(param_1 + 8),0x20);
  return;
}



void FUN_180017358(longlong *param_1)

{
  if (*param_1 != 0) {
    FUN_18000e450(*param_1,param_1[1]);
    FUN_180003f84(*param_1,param_1[2] - *param_1 & 0xfffffffffffffff8);
    *param_1 = 0;
    param_1[1] = 0;
    param_1[2] = 0;
  }
  return;
}



void FUN_18001739c(longlong *param_1)

{
  longlong *plVar1;
  void *_Memory;
  
  plVar1 = (longlong *)param_1[2];
  param_1[2] = *plVar1;
  _Memory = (void *)plVar1[3];
  if (_Memory != (void *)0x0) {
    FUN_18000e118(_Memory);
    free(_Memory);
  }
  FUN_180003f84(plVar1,0x20);
  *(longlong *)(*param_1 + 8) = *(longlong *)(*param_1 + 8) + -1;
  return;
}



ulonglong FUN_1800173fc(float *param_1,ulonglong param_2)

{
  ulonglong uVar1;
  uint uVar2;
  ulonglong in_RAX;
  longlong lVar3;
  int iVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  float fVar7;
  undefined auVar8 [16];
  
  uVar1 = *(ulonglong *)(param_1 + 0xe);
  if ((longlong)param_2 < 0) {
    in_RAX = param_2 >> 1 | (ulonglong)((uint)param_2 & 1);
    fVar7 = (float)in_RAX + (float)in_RAX;
  }
  else {
    fVar7 = (float)param_2;
  }
  fVar7 = fVar7 / *param_1;
  auVar8 = ZEXT416((uint)fVar7);
  iVar4 = (int)fVar7;
  if ((iVar4 != -0x80000000) && ((float)iVar4 != fVar7)) {
    uVar2 = movmskps((int)in_RAX,ZEXT816(CONCAT44(fVar7,fVar7)));
    auVar8 = ZEXT416((uint)(float)(iVar4 + (uVar2 & 1 ^ 1)));
  }
  lVar3 = 0;
  if ((9.223372e+18 <= SUB164(auVar8,0)) &&
     (fVar7 = SUB164(auVar8,0) - 9.223372e+18, auVar8 = CONCAT124(SUB1612(auVar8 >> 0x20,0),fVar7),
     fVar7 < 9.223372e+18)) {
    lVar3 = -0x8000000000000000;
  }
  uVar5 = (longlong)SUB164(auVar8,0) + lVar3;
  uVar6 = 8;
  if (8 < uVar5) {
    uVar6 = uVar5;
  }
  if (uVar6 <= uVar1) {
    return uVar1;
  }
  if ((uVar1 < 0x200) && (uVar6 <= uVar1 * 8)) {
    uVar6 = uVar1 * 8;
  }
  return uVar6;
}



longlong FUN_180017610(longlong param_1,longlong param_2)

{
  int iVar1;
  
  iVar1 = __std_type_info_compare(param_2 + 8,0x180419450);
  if (iVar1 == 0) {
    param_1 = param_1 + 0x10;
  }
  else {
    param_1 = 0;
  }
  return param_1;
}



void FUN_18001763c(longlong param_1)

{
  longlong *plVar1;
  longlong *plVar2;
  longlong *plVar3;
  longlong **pplVar4;
  code *pcVar5;
  longlong **pplVar6;
  ulonglong uVar7;
  longlong *plVar8;
  longlong lVar9;
  longlong *plVar10;
  
  uVar7 = FUN_1800173fc(param_1,*(longlong *)(param_1 + 0x10) + 1);
  for (lVar9 = 0x3f; 0xfffffffffffffffU >> lVar9 == 0; lVar9 = lVar9 + -1) {
  }
  if ((ulonglong)(1 << ((byte)lVar9 & 0x3f)) < uVar7) {
    std::_Xlength_error("invalid hash bucket count");
    pcVar5 = (code *)swi(3);
    (*pcVar5)();
    return;
  }
  plVar1 = *(longlong **)(param_1 + 8);
  uVar7 = uVar7 - 1 | 1;
  lVar9 = 0x3f;
  if (uVar7 != 0) {
    for (; uVar7 >> lVar9 == 0; lVar9 = lVar9 + -1) {
    }
  }
  lVar9 = 1 << ((char)lVar9 + 1U & 0x3f);
  FUN_180002034(param_1 + 0x18,lVar9 * 2,plVar1);
  *(longlong *)(param_1 + 0x38) = lVar9;
  *(longlong *)(param_1 + 0x30) = lVar9 + -1;
  plVar10 = **(longlong ***)(param_1 + 8);
LAB_180017529:
  do {
    if (plVar10 == plVar1) {
      return;
    }
    plVar2 = (longlong *)*plVar10;
    plVar8 = plVar10 + 2;
    uVar7 = FUN_18000d1d8();
    lVar9 = *(longlong *)(param_1 + 0x18);
    uVar7 = uVar7 & *(ulonglong *)(param_1 + 0x30);
    if (*(longlong **)(lVar9 + uVar7 * 0x10) == plVar1) {
      *(longlong **)(lVar9 + uVar7 * 0x10) = plVar10;
LAB_18001755c:
      *(longlong **)(lVar9 + 8 + uVar7 * 0x10) = plVar10;
      plVar10 = plVar2;
      goto LAB_180017529;
    }
    pplVar6 = *(longlong ***)(lVar9 + 8 + uVar7 * 0x10);
    if (*(int *)plVar8 == *(int *)(pplVar6 + 2)) {
      plVar8 = *pplVar6;
      if (plVar8 != plVar10) {
        plVar3 = (longlong *)plVar10[1];
        *plVar3 = (longlong)plVar2;
        pplVar6 = (longlong **)plVar2[1];
        *pplVar6 = plVar8;
        pplVar4 = (longlong **)plVar8[1];
        *pplVar4 = plVar10;
        plVar8[1] = (longlong)pplVar6;
        plVar2[1] = (longlong)plVar3;
        plVar10[1] = (longlong)pplVar4;
      }
      goto LAB_18001755c;
    }
    do {
      pplVar4 = pplVar6 + 1;
      if (*(longlong ***)(lVar9 + uVar7 * 0x10) == pplVar6) {
        plVar8 = (longlong *)plVar10[1];
        *plVar8 = (longlong)plVar2;
        plVar3 = (longlong *)plVar2[1];
        *plVar3 = (longlong)pplVar6;
        pplVar6 = (longlong **)*pplVar4;
        *pplVar6 = plVar10;
        *pplVar4 = plVar3;
        plVar2[1] = (longlong)plVar8;
        plVar10[1] = (longlong)pplVar6;
        *(longlong **)(lVar9 + uVar7 * 0x10) = plVar10;
        plVar10 = plVar2;
        goto LAB_180017529;
      }
      pplVar6 = (longlong **)*pplVar4;
    } while (*(int *)plVar8 != *(int *)(pplVar6 + 2));
    plVar8 = *pplVar6;
    plVar3 = (longlong *)plVar10[1];
    *plVar3 = (longlong)plVar2;
    pplVar6 = (longlong **)plVar2[1];
    *pplVar6 = plVar8;
    pplVar4 = (longlong **)plVar8[1];
    *pplVar4 = plVar10;
    plVar8[1] = (longlong)pplVar6;
    plVar2[1] = (longlong)plVar3;
    plVar10[1] = (longlong)pplVar4;
    plVar10 = plVar2;
  } while( true );
}



longlong FUN_180017660(longlong param_1,longlong param_2,longlong param_3)

{
  longlong lVar1;
  longlong *plVar2;
  longlong lVar3;
  ulonglong uVar4;
  longlong *plVar5;
  longlong lVar6;
  longlong lVar7;
  longlong **local_58;
  longlong *local_50;
  longlong local_48;
  
  if (param_2 == param_3) {
    return param_3;
  }
  lVar1 = *(longlong *)(param_1 + 0x18);
  local_58 = (longlong **)(param_1 + 8);
  plVar2 = *local_58;
  plVar5 = *(longlong **)(param_2 + 8);
  lVar6 = param_2;
  local_50 = plVar5;
  local_48 = param_2;
  uVar4 = FUN_18000d1d8(param_1,param_2 + 0x10,4);
  uVar4 = uVar4 & *(ulonglong *)(param_1 + 0x30);
  lVar7 = *(longlong *)(lVar1 + 8 + uVar4 * 0x10);
  lVar3 = *(longlong *)(lVar1 + uVar4 * 0x10);
  do {
    FUN_18001739c(&local_58);
    if (lVar6 == lVar7) {
      if (lVar3 == param_2) {
        *(longlong **)(lVar1 + uVar4 * 0x10) = plVar2;
        plVar5 = plVar2;
      }
      *(longlong **)(lVar1 + 8 + uVar4 * 0x10) = plVar5;
      lVar7 = local_48;
      while (local_48 = lVar7, lVar7 != param_3) {
        uVar4 = FUN_18000d1d8();
        uVar4 = uVar4 & *(ulonglong *)(param_1 + 0x30);
        lVar3 = *(longlong *)(lVar1 + 8 + uVar4 * 0x10);
        while (FUN_18001739c(&local_58), lVar7 != lVar3) {
          lVar7 = local_48;
          if (local_48 == param_3) {
            *(longlong *)(lVar1 + uVar4 * 0x10) = local_48;
            goto LAB_180017763;
          }
        }
        *(longlong **)(lVar1 + uVar4 * 0x10) = plVar2;
        *(longlong **)(lVar1 + 8 + uVar4 * 0x10) = plVar2;
        lVar7 = local_48;
      }
      goto LAB_180017763;
    }
    lVar6 = local_48;
  } while (local_48 != param_3);
  if (lVar3 == param_2) {
    *(longlong *)(lVar1 + uVar4 * 0x10) = local_48;
  }
LAB_180017763:
  *local_50 = local_48;
  *(longlong **)(local_48 + 8) = local_50;
  return param_3;
}



void FUN_1800177a4(longlong *param_1)

{
  if (*param_1 != 0) {
    FUN_18000e344();
  }
  return;
}



void FUN_1800177c8(longlong *param_1)

{
  longlong *plVar1;
  
  plVar1 = (longlong *)param_1[2];
  param_1[2] = *plVar1;
  FUN_180003f84(plVar1,0x20);
  *(longlong *)(*param_1 + 8) = *(longlong *)(*param_1 + 8) + -1;
  return;
}



longlong FUN_1800177f4(longlong param_1,longlong param_2,longlong param_3)

{
  longlong lVar1;
  longlong *plVar2;
  longlong lVar3;
  ulonglong uVar4;
  longlong *plVar5;
  longlong lVar6;
  longlong lVar7;
  longlong **local_58;
  longlong *local_50;
  longlong local_48;
  
  if (param_2 == param_3) {
    return param_3;
  }
  lVar1 = *(longlong *)(param_1 + 0x18);
  local_58 = (longlong **)(param_1 + 8);
  plVar2 = *local_58;
  plVar5 = *(longlong **)(param_2 + 8);
  lVar6 = param_2;
  local_50 = plVar5;
  local_48 = param_2;
  uVar4 = FUN_18000d1d8(param_1,param_2 + 0x10,8);
  uVar4 = uVar4 & *(ulonglong *)(param_1 + 0x30);
  lVar7 = *(longlong *)(lVar1 + 8 + uVar4 * 0x10);
  lVar3 = *(longlong *)(lVar1 + uVar4 * 0x10);
  do {
    FUN_1800177c8(&local_58);
    if (lVar6 == lVar7) {
      if (lVar3 == param_2) {
        *(longlong **)(lVar1 + uVar4 * 0x10) = plVar2;
        plVar5 = plVar2;
      }
      *(longlong **)(lVar1 + 8 + uVar4 * 0x10) = plVar5;
      lVar7 = local_48;
      while (local_48 = lVar7, lVar7 != param_3) {
        uVar4 = FUN_18000d1d8();
        uVar4 = uVar4 & *(ulonglong *)(param_1 + 0x30);
        lVar3 = *(longlong *)(lVar1 + 8 + uVar4 * 0x10);
        while (FUN_1800177c8(&local_58), lVar7 != lVar3) {
          lVar7 = local_48;
          if (local_48 == param_3) {
            *(longlong *)(lVar1 + uVar4 * 0x10) = local_48;
            goto LAB_1800178f7;
          }
        }
        *(longlong **)(lVar1 + uVar4 * 0x10) = plVar2;
        *(longlong **)(lVar1 + 8 + uVar4 * 0x10) = plVar2;
        lVar7 = local_48;
      }
      goto LAB_1800178f7;
    }
    lVar6 = local_48;
  } while (local_48 != param_3);
  if (lVar3 == param_2) {
    *(longlong *)(lVar1 + uVar4 * 0x10) = local_48;
  }
LAB_1800178f7:
  *local_50 = local_48;
  *(longlong **)(local_48 + 8) = local_50;
  return param_3;
}



void FUN_180017930(longlong param_1)

{
  undefined8 uVar1;
  ulonglong uVar2;
  undefined8 *puVar3;
  
  if (*(longlong *)(param_1 + 0x10) != 0) {
    uVar2 = *(ulonglong *)(param_1 + 0x38) >> 3;
    if (uVar2 < *(ulonglong *)(param_1 + 0x10) || uVar2 == *(ulonglong *)(param_1 + 0x10)) {
      FUN_180003f50();
      *(undefined8 *)*(undefined8 *)(param_1 + 8) = *(undefined8 *)(param_1 + 8);
      *(longlong *)(*(longlong *)(param_1 + 8) + 8) = *(longlong *)(param_1 + 8);
      *(undefined8 *)(param_1 + 0x10) = 0;
      puVar3 = *(undefined8 **)(param_1 + 0x18);
      uVar1 = *(undefined8 *)(param_1 + 8);
      uVar2 = (*(longlong *)(param_1 + 0x20) - (longlong)puVar3) + 7U >> 3;
      if (*(undefined8 **)(ulonglong *)(param_1 + 0x20) <= puVar3 &&
          puVar3 != *(undefined8 **)(ulonglong *)(param_1 + 0x20)) {
        uVar2 = 0;
      }
      if (uVar2 != 0) {
        for (; uVar2 != 0; uVar2 = uVar2 - 1) {
          *puVar3 = uVar1;
          puVar3 = puVar3 + 1;
        }
      }
    }
    else {
      FUN_1800177f4(param_1,**(undefined8 **)(param_1 + 8),*(undefined8 **)(param_1 + 8));
    }
  }
  return;
}



undefined8 NVSDK_NGX_D3D12_AllocateParameters(undefined8 *param_1)

{
  void *_Dst;
  undefined8 uVar1;
  
                    // 0x179b4  1  NVSDK_NGX_D3D12_AllocateParameters
                    // 0x179b4  5  NVSDK_NGX_D3D12_GetCapabilityParameters
                    // 0x179b4  15  NVSDK_NGX_VULKAN_AllocateParameters
                    // 0x179b4  20  NVSDK_NGX_VULKAN_GetCapabilityParameters
  _Dst = operator_new(0x90);
  memset(_Dst,0,0x90);
  uVar1 = FUN_1800025e0(_Dst);
  *param_1 = uVar1;
  return 1;
}



undefined8 NVSDK_NGX_D3D12_DestroyParameters(void *param_1)

{
                    // 0x179fc  3  NVSDK_NGX_D3D12_DestroyParameters
                    // 0x179fc  18  NVSDK_NGX_VULKAN_DestroyParameters
  free(param_1);
  return 1;
}



undefined8
NVSDK_NGX_D3D12_GetScratchBufferSize(undefined8 param_1,undefined8 param_2,undefined8 *param_3)

{
                    // 0x17a14  7  NVSDK_NGX_D3D12_GetScratchBufferSize
  *param_3 = 0x3c250;
  return 1;
}



undefined4
NVSDK_NGX_VULKAN_CreateFeature
          (undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined8 param_4)

{
  undefined4 uVar1;
  longlong *plVar2;
  undefined local_18 [8];
  longlong local_10;
  
                    // 0x17a24  16  NVSDK_NGX_VULKAN_CreateFeature
  plVar2 = (longlong *)FUN_18000328c(local_18);
  uVar1 = NVSDK_NGX_VULKAN_CreateFeature1
                    (*(undefined8 *)(*plVar2 + 0x10),param_1,param_2,param_3,param_4);
  if (local_10 != 0) {
    FUN_1800030d8();
  }
  return uVar1;
}



// WARNING: Could not reconcile some variable overlaps

void NVSDK_NGX_VULKAN_CreateFeature1
               (undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
               longlong *param_5)

{
  char *pcVar1;
  code *pcVar2;
  longlong lVar3;
  longlong lVar4;
  undefined8 uVar5;
  ulonglong _Size;
  void *_Dst;
  char cVar6;
  undefined auStack296 [32];
  code *local_108;
  undefined local_f8 [16];
  longlong local_e8;
  void *local_e0;
  uint local_d8;
  undefined4 uStack212;
  undefined4 uStack208;
  undefined4 uStack204;
  undefined4 local_c8;
  undefined4 uStack196;
  undefined4 uStack192;
  undefined4 uStack188;
  undefined4 local_b8;
  undefined4 uStack180;
  undefined4 uStack176;
  undefined4 uStack172;
  undefined4 local_a8;
  undefined4 uStack164;
  undefined4 uStack160;
  undefined4 uStack156;
  undefined4 local_98;
  undefined4 uStack148;
  undefined4 uStack144;
  undefined4 uStack140;
  undefined4 local_88;
  undefined4 uStack132;
  undefined4 uStack128;
  undefined4 uStack124;
  undefined4 local_78;
  undefined4 uStack116;
  undefined4 uStack112;
  undefined4 uStack108;
  undefined4 uStack104;
  undefined4 uStack100;
  undefined4 uStack96;
  undefined4 uStack92;
  undefined4 uStack88;
  undefined4 uStack84;
  undefined8 local_50;
  undefined local_48 [16];
  ulonglong local_38;
  
                    // 0x17a90  17  NVSDK_NGX_VULKAN_CreateFeature1
  local_38 = DAT_180418010 ^ (ulonglong)auStack296;
  local_108 = (code *)((ulonglong)local_108 & 0xffffffff00000000);
  lVar3 = __RTDynamicCast(param_4,0,&struct_NVSDK_NGX_Parameter_RTTI_Type_Descriptor,
                          &struct_NvParameter_RTTI_Type_Descriptor);
  local_48 = ZEXT816(0);
  FUN_18000328c(local_48);
  lVar4 = FUN_180003754(local_48._0_8_);
  uVar5 = FUN_1800034c0(&local_e0,*local_48._0_8_);
  FUN_180003444(lVar4,uVar5);
  if (local_e0 != (void *)0x0) {
    free(local_e0);
  }
  *param_5 = lVar4 + 8;
  local_d8 = *(uint *)(lVar4 + 0x10278);
  uStack212 = *(undefined4 *)(lVar4 + 0x1027c);
  uStack208 = *(undefined4 *)(lVar4 + 0x10280);
  uStack204 = *(undefined4 *)(lVar4 + 0x10284);
  local_c8 = *(undefined4 *)(lVar4 + 0x10288);
  uStack196 = *(undefined4 *)(lVar4 + 0x1028c);
  uStack192 = *(undefined4 *)(lVar4 + 0x10290);
  uStack188 = *(undefined4 *)(lVar4 + 0x10294);
  local_b8 = *(undefined4 *)(lVar4 + 0x10298);
  uStack180 = *(undefined4 *)(lVar4 + 0x1029c);
  uStack176 = *(undefined4 *)(lVar4 + 0x102a0);
  uStack172 = *(undefined4 *)(lVar4 + 0x102a4);
  local_a8 = *(undefined4 *)(lVar4 + 0x102a8);
  uStack164 = *(undefined4 *)(lVar4 + 0x102ac);
  uStack160 = *(undefined4 *)(lVar4 + 0x102b0);
  uStack156 = *(undefined4 *)(lVar4 + 0x102b4);
  local_98 = *(undefined4 *)(lVar4 + 0x102b8);
  uStack148 = *(undefined4 *)(lVar4 + 0x102bc);
  uStack144 = *(undefined4 *)(lVar4 + 0x102c0);
  uStack140 = *(undefined4 *)(lVar4 + 0x102c4);
  local_88 = *(undefined4 *)(lVar4 + 0x102c8);
  uStack132 = *(undefined4 *)(lVar4 + 0x102cc);
  uStack128 = *(undefined4 *)(lVar4 + 0x102d0);
  uStack124 = *(undefined4 *)(lVar4 + 0x102d4);
  local_78 = *(undefined4 *)(lVar4 + 0x102d8);
  uStack116 = *(undefined4 *)(lVar4 + 0x102dc);
  uStack112 = *(undefined4 *)(lVar4 + 0x102e0);
  uStack108 = *(undefined4 *)(lVar4 + 0x102e4);
  uStack88 = *(undefined4 *)(lVar4 + 0x102f8);
  uStack84 = *(undefined4 *)(lVar4 + 0x102fc);
  local_50 = *(undefined8 *)(lVar4 + 0x10300);
  uStack104 = *(undefined4 *)(lVar4 + 0x102e8);
  uStack100 = *(undefined4 *)(lVar4 + 0x102ec);
  uStack96 = *(undefined4 *)(lVar4 + 0x102f0);
  uStack92 = *(undefined4 *)(lVar4 + 0x102f4);
  _Size = ffxFsr2GetScratchMemorySizeVK(local_48._0_8_[4]);
  local_e8 = 0;
  local_f8 = ZEXT816(0);
  if (_Size != 0) {
    if (0x7fffffffffffffff < _Size) {
      std::_Xlength_error(s_vector_too_long_1800ac8e0);
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    _Dst = (void *)FUN_180008bb4(_Size);
    local_f8 = CONCAT88(local_f8._8_8_,_Dst);
    local_e8 = (longlong)_Dst + _Size;
    memset(_Dst,0,_Size);
    local_f8 = CONCAT88((longlong)_Dst + _Size,local_f8._0_8_);
  }
  FUN_180003474((undefined8 *)(lVar4 + 0x10308),local_f8);
  if (local_f8._0_8_ != 0) {
    FUN_180003f84(local_f8._0_8_,local_e8 - local_f8._0_8_);
  }
  local_108 = vkGetDeviceProcAddr_exref;
  ffxFsr2GetInterfaceVK(&uStack192,*(undefined8 *)(lVar4 + 0x10308),_Size,local_48._0_8_[4]);
  uStack212 = *(undefined4 *)(lVar3 + 8);
  pcVar1 = *local_48._0_8_;
  uStack208 = *(undefined4 *)(lVar3 + 0xc);
  uStack204 = *(undefined4 *)(lVar3 + 0x10);
  local_c8 = *(undefined4 *)(lVar3 + 0x14);
  if (pcVar1[1] == '\0') {
    cVar6 = *(char *)(lVar3 + 0x50);
  }
  else {
    cVar6 = *pcVar1;
  }
  local_d8 = 0;
  if (cVar6 != '\0') {
    local_d8 = 8;
  }
  if (pcVar1[3] == '\0') {
    cVar6 = *(char *)(lVar3 + 0x51);
  }
  else {
    cVar6 = pcVar1[2];
  }
  if (cVar6 != '\0') {
    local_d8 = local_d8 | 0x20;
  }
  if (pcVar1[5] == '\0') {
    cVar6 = *(char *)(lVar3 + 0x52);
  }
  else {
    cVar6 = pcVar1[4];
  }
  if (cVar6 != '\0') {
    local_d8 = local_d8 | 1;
  }
  if (pcVar1[7] == '\0') {
    cVar6 = *(char *)(lVar3 + 0x54);
  }
  else {
    cVar6 = pcVar1[6];
  }
  if (cVar6 != '\0') {
    local_d8 = local_d8 | 4;
  }
  if (pcVar1[9] == '\0') {
    cVar6 = *(char *)(lVar3 + 0x55) == '\0';
  }
  else {
    cVar6 = pcVar1[8];
  }
  if (cVar6 != '\0') {
    local_d8 = local_d8 | 2;
  }
  local_50 = param_1;
  ffxFsr2ContextCreate(lVar4 + 0x18,&local_d8);
  if (local_48._8_8_ != 0) {
    FUN_1800030d8();
  }
  FUN_18000e8c0(local_38 ^ (ulonglong)auStack296);
  return;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void NVSDK_NGX_VULKAN_EvaluateFeature(undefined8 param_1,undefined4 *param_2,undefined8 param_3)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  longlong **pplVar6;
  longlong **pplVar7;
  char cVar8;
  longlong *plVar9;
  undefined8 uVar10;
  void *pvVar11;
  undefined8 *puVar12;
  longlong lVar13;
  longlong lVar14;
  undefined4 *puVar15;
  longlong lVar16;
  double dVar17;
  undefined auStack1800 [32];
  undefined4 local_6e8;
  undefined4 local_6e0;
  undefined4 local_6d8;
  wchar_t *local_6d0;
  undefined4 local_6c8;
  longlong **local_6b8;
  undefined8 local_6b0;
  longlong *local_6a8;
  undefined local_6a0 [8];
  longlong local_698;
  undefined local_690 [16];
  undefined local_680 [184];
  longlong **local_5c8;
  undefined8 local_5c0;
  undefined8 *local_5b8;
  undefined4 uStack1456;
  undefined4 uStack1452;
  undefined8 local_5a8;
  undefined4 local_5a0;
  undefined4 uStack1436;
  undefined4 uStack1432;
  undefined4 uStack1428;
  undefined4 local_590;
  undefined4 uStack1420;
  undefined4 uStack1416;
  undefined4 uStack1412;
  undefined4 local_580;
  undefined4 uStack1404;
  undefined4 uStack1400;
  undefined4 uStack1396;
  undefined4 local_570;
  undefined4 uStack1388;
  undefined4 uStack1384;
  undefined4 uStack1380;
  undefined4 local_560;
  undefined4 uStack1372;
  undefined4 uStack1368;
  undefined4 uStack1364;
  undefined4 local_550;
  undefined4 uStack1356;
  undefined4 uStack1352;
  undefined4 uStack1348;
  undefined4 local_540;
  undefined4 uStack1340;
  undefined4 uStack1336;
  undefined4 uStack1332;
  undefined4 local_530;
  undefined4 uStack1324;
  undefined4 uStack1320;
  undefined4 uStack1316;
  undefined4 local_520;
  undefined4 uStack1308;
  undefined4 uStack1304;
  undefined4 uStack1300;
  undefined4 local_510;
  undefined4 uStack1292;
  undefined4 uStack1288;
  undefined4 uStack1284;
  undefined4 local_500;
  undefined4 uStack1276;
  undefined4 uStack1272;
  undefined4 uStack1268;
  undefined8 local_4f0;
  undefined4 local_4e8;
  undefined4 uStack1252;
  undefined4 uStack1248;
  undefined4 uStack1244;
  undefined4 local_4d8;
  undefined4 uStack1236;
  undefined4 uStack1232;
  undefined4 uStack1228;
  undefined4 local_4c8;
  undefined4 uStack1220;
  undefined4 uStack1216;
  undefined4 uStack1212;
  undefined4 local_4b8;
  undefined4 uStack1204;
  undefined4 uStack1200;
  undefined4 uStack1196;
  undefined4 local_4a8;
  undefined4 uStack1188;
  undefined4 uStack1184;
  undefined4 uStack1180;
  undefined4 local_498;
  undefined4 uStack1172;
  undefined4 uStack1168;
  undefined4 uStack1164;
  undefined4 local_488;
  undefined4 uStack1156;
  undefined4 uStack1152;
  undefined4 uStack1148;
  undefined4 local_478;
  undefined4 uStack1140;
  undefined4 uStack1136;
  undefined4 uStack1132;
  undefined4 local_468;
  undefined4 uStack1124;
  undefined4 uStack1120;
  undefined4 uStack1116;
  undefined4 local_458;
  undefined4 uStack1108;
  undefined4 uStack1104;
  undefined4 uStack1100;
  undefined4 local_448;
  undefined4 uStack1092;
  undefined4 uStack1088;
  undefined4 uStack1084;
  undefined8 local_438;
  undefined4 local_430;
  undefined4 uStack1068;
  undefined4 uStack1064;
  undefined4 uStack1060;
  undefined4 local_420;
  undefined4 uStack1052;
  undefined4 uStack1048;
  undefined4 uStack1044;
  undefined4 local_410;
  undefined4 uStack1036;
  undefined4 uStack1032;
  undefined4 uStack1028;
  undefined4 local_400;
  undefined4 uStack1020;
  undefined4 uStack1016;
  undefined4 uStack1012;
  undefined4 local_3f0;
  undefined4 uStack1004;
  undefined4 uStack1000;
  undefined4 uStack996;
  undefined4 local_3e0;
  undefined4 uStack988;
  undefined4 uStack984;
  undefined4 uStack980;
  undefined4 local_3d0;
  undefined4 uStack972;
  undefined4 uStack968;
  undefined4 uStack964;
  undefined4 local_3c0;
  undefined4 uStack956;
  undefined4 uStack952;
  undefined4 uStack948;
  undefined4 local_3b0;
  undefined4 uStack940;
  undefined4 uStack936;
  undefined4 uStack932;
  undefined4 local_3a0;
  undefined4 uStack924;
  undefined4 uStack920;
  undefined4 uStack916;
  undefined4 local_390;
  undefined4 uStack908;
  undefined4 uStack904;
  undefined4 uStack900;
  undefined8 local_380;
  undefined4 local_378;
  undefined4 uStack884;
  undefined4 uStack880;
  undefined4 uStack876;
  undefined4 local_368;
  undefined4 uStack868;
  undefined4 uStack864;
  undefined4 uStack860;
  undefined4 local_358;
  undefined4 uStack852;
  undefined4 uStack848;
  undefined4 uStack844;
  undefined4 local_348;
  undefined4 uStack836;
  undefined4 uStack832;
  undefined4 uStack828;
  undefined4 local_338;
  undefined4 uStack820;
  undefined4 uStack816;
  undefined4 uStack812;
  undefined4 local_328;
  undefined4 uStack804;
  undefined4 uStack800;
  undefined4 uStack796;
  undefined4 local_318;
  undefined4 uStack788;
  undefined4 uStack784;
  undefined4 uStack780;
  undefined4 local_308;
  undefined4 uStack772;
  undefined4 uStack768;
  undefined4 uStack764;
  undefined4 local_2f8;
  undefined4 uStack756;
  undefined4 uStack752;
  undefined4 uStack748;
  undefined4 local_2e8;
  undefined4 uStack740;
  undefined4 uStack736;
  undefined4 uStack732;
  undefined4 local_2d8;
  undefined4 uStack724;
  undefined4 uStack720;
  undefined4 uStack716;
  undefined8 local_2c8;
  undefined4 local_2c0;
  undefined4 uStack700;
  undefined4 uStack696;
  undefined4 uStack692;
  undefined4 local_2b0;
  undefined4 uStack684;
  undefined4 uStack680;
  undefined4 uStack676;
  undefined4 local_2a0;
  undefined4 uStack668;
  undefined4 uStack664;
  undefined4 uStack660;
  undefined4 local_290;
  undefined4 uStack652;
  undefined4 uStack648;
  undefined4 uStack644;
  undefined4 local_280;
  undefined4 uStack636;
  undefined4 uStack632;
  undefined4 uStack628;
  undefined4 local_270;
  undefined4 uStack620;
  undefined4 uStack616;
  undefined4 uStack612;
  undefined4 local_260;
  undefined4 uStack604;
  undefined4 uStack600;
  undefined4 uStack596;
  undefined4 local_250;
  undefined4 uStack588;
  undefined4 uStack584;
  undefined4 uStack580;
  undefined4 local_240;
  undefined4 uStack572;
  undefined4 uStack568;
  undefined4 uStack564;
  undefined4 local_230;
  undefined4 uStack556;
  undefined4 uStack552;
  undefined4 uStack548;
  undefined4 local_220;
  undefined4 uStack540;
  undefined4 uStack536;
  undefined4 uStack532;
  undefined8 local_210;
  undefined4 local_208;
  undefined4 uStack516;
  undefined4 uStack512;
  undefined4 uStack508;
  undefined4 local_1f8;
  undefined4 uStack500;
  undefined4 uStack496;
  undefined4 uStack492;
  undefined4 local_1e8;
  undefined4 uStack484;
  undefined4 uStack480;
  undefined4 uStack476;
  undefined4 local_1d8;
  undefined4 uStack468;
  undefined4 uStack464;
  undefined4 uStack460;
  undefined4 local_1c8;
  undefined4 uStack452;
  undefined4 uStack448;
  undefined4 uStack444;
  undefined4 local_1b8;
  undefined4 uStack436;
  undefined4 uStack432;
  undefined4 uStack428;
  undefined4 local_1a8;
  undefined4 uStack420;
  undefined4 uStack416;
  undefined4 uStack412;
  undefined4 local_198;
  undefined4 uStack404;
  undefined4 uStack400;
  undefined4 uStack396;
  undefined4 local_188;
  undefined4 uStack388;
  undefined4 uStack384;
  undefined4 uStack380;
  undefined4 local_178;
  undefined4 uStack372;
  undefined4 uStack368;
  undefined4 uStack364;
  undefined4 local_168;
  undefined4 uStack356;
  undefined4 uStack352;
  undefined4 uStack348;
  undefined8 local_158;
  undefined4 local_150;
  undefined4 uStack332;
  undefined4 uStack328;
  undefined4 uStack324;
  undefined4 local_140;
  undefined4 uStack316;
  undefined4 uStack312;
  undefined4 uStack308;
  undefined4 local_130;
  undefined4 uStack300;
  undefined4 uStack296;
  undefined4 uStack292;
  undefined4 local_120;
  undefined4 uStack284;
  undefined4 uStack280;
  undefined4 uStack276;
  undefined4 local_110;
  undefined4 uStack268;
  undefined4 uStack264;
  undefined4 uStack260;
  undefined4 local_100;
  undefined4 uStack252;
  undefined4 uStack248;
  undefined4 uStack244;
  undefined4 local_f0;
  undefined4 uStack236;
  undefined4 uStack232;
  undefined4 uStack228;
  undefined4 local_e0;
  undefined4 uStack220;
  undefined4 uStack216;
  undefined4 uStack212;
  undefined4 local_d0;
  undefined4 uStack204;
  undefined4 uStack200;
  undefined4 uStack196;
  undefined4 local_c0;
  undefined4 uStack188;
  undefined4 uStack184;
  undefined4 uStack180;
  undefined4 local_b0;
  undefined4 uStack172;
  undefined4 uStack168;
  undefined4 uStack164;
  undefined8 local_a0;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined local_80;
  undefined4 local_7c;
  float local_78;
  undefined4 local_74;
  undefined local_70;
  undefined4 local_6c;
  undefined4 local_68;
  float local_64;
  undefined local_58 [16];
  ulonglong local_48;
  
                    // 0x17d2c  19  NVSDK_NGX_VULKAN_EvaluateFeature
  local_48 = DAT_180418010 ^ (ulonglong)auStack1800;
  local_58 = ZEXT816(0);
  local_6b0 = param_1;
  FUN_18000328c(local_58);
  local_6a8 = local_58._0_8_;
  plVar9 = (longlong *)FUN_18000328c(local_6a0);
  lVar14 = *plVar9;
  lVar16 = lVar14 + 0x40;
  uVar10 = FUN_18000d1d8();
  FUN_180003954(lVar16,&local_5b8,param_2,uVar10);
  lVar13 = CONCAT44(uStack1452,uStack1456);
  if (lVar13 == 0) {
    FUN_180003ce8();
    local_5c8 = (longlong **)(lVar14 + 0x48);
    pvVar11 = operator_new(0x20);
    *(undefined4 *)((longlong)pvVar11 + 0x10) = *param_2;
    *(undefined8 *)((longlong)pvVar11 + 0x18) = 0;
    cVar8 = FUN_180003ff0(lVar16);
    if (cVar8 != '\0') {
      FUN_18001763c(lVar16);
      puVar12 = (undefined8 *)FUN_180003954(lVar16,local_690,(longlong)pvVar11 + 0x10,uVar10);
      local_5b8 = (undefined8 *)*puVar12;
      uStack1456 = *(undefined4 *)(puVar12 + 1);
      uStack1452 = *(undefined4 *)((longlong)puVar12 + 0xc);
    }
    local_5c0 = 0;
    lVar13 = FUN_18000399c(lVar16,uVar10,local_5b8,pvVar11);
    FUN_180003fbc(&local_5c8);
  }
  local_5c8 = *(longlong ***)(lVar13 + 0x18);
  if (local_698 != 0) {
    FUN_1800030d8();
  }
  local_6e8 = 0;
  lVar14 = __RTDynamicCast(param_3,0,&struct_NVSDK_NGX_Parameter_RTTI_Type_Descriptor,
                           &struct_NvParameter_RTTI_Type_Descriptor);
  local_5b8 = *(undefined8 **)(lVar14 + 0x60);
  puVar12 = *(undefined8 **)(lVar14 + 0x68);
  puVar1 = *(undefined8 **)(lVar14 + 0x70);
  puVar2 = *(undefined8 **)(lVar14 + 0x88);
  puVar3 = *(undefined8 **)(lVar14 + 0x58);
  puVar4 = *(undefined8 **)(lVar14 + 0x80);
  puVar5 = *(undefined8 **)(lVar14 + 0x78);
  local_6b8 = local_5c8 + 3;
  memset(&local_5a8,0,0x548);
  local_5a8 = local_6b0;
  if (local_5b8 != (undefined8 *)0x0) {
    local_6c8 = 2;
    local_6d0 = L"FSR2_InputColor";
    local_6d8 = *(undefined4 *)((longlong)local_5b8 + 0x24);
    local_6e0 = *(undefined4 *)((longlong)local_5b8 + 0x2c);
    local_6e8 = *(undefined4 *)(local_5b8 + 5);
    puVar15 = (undefined4 *)ffxGetTextureResourceVK(local_680,local_6b8,local_5b8[1],*local_5b8);
    local_5a0 = *puVar15;
    uStack1436 = puVar15[1];
    uStack1432 = puVar15[2];
    uStack1428 = puVar15[3];
    local_590 = puVar15[4];
    uStack1420 = puVar15[5];
    uStack1416 = puVar15[6];
    uStack1412 = puVar15[7];
    local_580 = puVar15[8];
    uStack1404 = puVar15[9];
    uStack1400 = puVar15[10];
    uStack1396 = puVar15[0xb];
    local_570 = puVar15[0xc];
    uStack1388 = puVar15[0xd];
    uStack1384 = puVar15[0xe];
    uStack1380 = puVar15[0xf];
    local_560 = puVar15[0x10];
    uStack1372 = puVar15[0x11];
    uStack1368 = puVar15[0x12];
    uStack1364 = puVar15[0x13];
    local_550 = puVar15[0x14];
    uStack1356 = puVar15[0x15];
    uStack1352 = puVar15[0x16];
    uStack1348 = puVar15[0x17];
    local_540 = puVar15[0x18];
    uStack1340 = puVar15[0x19];
    uStack1336 = puVar15[0x1a];
    uStack1332 = puVar15[0x1b];
    local_530 = puVar15[0x1c];
    uStack1324 = puVar15[0x1d];
    uStack1320 = puVar15[0x1e];
    uStack1316 = puVar15[0x1f];
    local_520 = puVar15[0x20];
    uStack1308 = puVar15[0x21];
    uStack1304 = puVar15[0x22];
    uStack1300 = puVar15[0x23];
    local_510 = puVar15[0x24];
    uStack1292 = puVar15[0x25];
    uStack1288 = puVar15[0x26];
    uStack1284 = puVar15[0x27];
    local_500 = puVar15[0x28];
    uStack1276 = puVar15[0x29];
    uStack1272 = puVar15[0x2a];
    uStack1268 = puVar15[0x2b];
    local_4f0 = *(undefined8 *)(puVar15 + 0x2c);
  }
  pplVar6 = local_6b8;
  if (puVar12 != (undefined8 *)0x0) {
    local_6c8 = 2;
    local_6d0 = L"FSR2_InputDepth";
    local_6d8 = *(undefined4 *)((longlong)puVar12 + 0x24);
    local_6e0 = *(undefined4 *)((longlong)puVar12 + 0x2c);
    local_6e8 = *(undefined4 *)(puVar12 + 5);
    puVar15 = (undefined4 *)ffxGetTextureResourceVK(local_680,local_6b8,puVar12[1],*puVar12);
    local_4e8 = *puVar15;
    uStack1252 = puVar15[1];
    uStack1248 = puVar15[2];
    uStack1244 = puVar15[3];
    local_4d8 = puVar15[4];
    uStack1236 = puVar15[5];
    uStack1232 = puVar15[6];
    uStack1228 = puVar15[7];
    local_4c8 = puVar15[8];
    uStack1220 = puVar15[9];
    uStack1216 = puVar15[10];
    uStack1212 = puVar15[0xb];
    local_4b8 = puVar15[0xc];
    uStack1204 = puVar15[0xd];
    uStack1200 = puVar15[0xe];
    uStack1196 = puVar15[0xf];
    local_4a8 = puVar15[0x10];
    uStack1188 = puVar15[0x11];
    uStack1184 = puVar15[0x12];
    uStack1180 = puVar15[0x13];
    local_498 = puVar15[0x14];
    uStack1172 = puVar15[0x15];
    uStack1168 = puVar15[0x16];
    uStack1164 = puVar15[0x17];
    local_488 = puVar15[0x18];
    uStack1156 = puVar15[0x19];
    uStack1152 = puVar15[0x1a];
    uStack1148 = puVar15[0x1b];
    local_478 = puVar15[0x1c];
    uStack1140 = puVar15[0x1d];
    uStack1136 = puVar15[0x1e];
    uStack1132 = puVar15[0x1f];
    local_468 = puVar15[0x20];
    uStack1124 = puVar15[0x21];
    uStack1120 = puVar15[0x22];
    uStack1116 = puVar15[0x23];
    local_458 = puVar15[0x24];
    uStack1108 = puVar15[0x25];
    uStack1104 = puVar15[0x26];
    uStack1100 = puVar15[0x27];
    local_448 = puVar15[0x28];
    uStack1092 = puVar15[0x29];
    uStack1088 = puVar15[0x2a];
    uStack1084 = puVar15[0x2b];
    local_438 = *(undefined8 *)(puVar15 + 0x2c);
  }
  if (puVar1 != (undefined8 *)0x0) {
    local_6c8 = 2;
    local_6d0 = L"FSR2_InputMotionVectors";
    local_6d8 = *(undefined4 *)((longlong)puVar1 + 0x24);
    local_6e0 = *(undefined4 *)((longlong)puVar1 + 0x2c);
    local_6e8 = *(undefined4 *)(puVar1 + 5);
    puVar15 = (undefined4 *)ffxGetTextureResourceVK(local_680,pplVar6,puVar1[1],*puVar1);
    local_430 = *puVar15;
    uStack1068 = puVar15[1];
    uStack1064 = puVar15[2];
    uStack1060 = puVar15[3];
    local_420 = puVar15[4];
    uStack1052 = puVar15[5];
    uStack1048 = puVar15[6];
    uStack1044 = puVar15[7];
    local_410 = puVar15[8];
    uStack1036 = puVar15[9];
    uStack1032 = puVar15[10];
    uStack1028 = puVar15[0xb];
    local_400 = puVar15[0xc];
    uStack1020 = puVar15[0xd];
    uStack1016 = puVar15[0xe];
    uStack1012 = puVar15[0xf];
    local_3f0 = puVar15[0x10];
    uStack1004 = puVar15[0x11];
    uStack1000 = puVar15[0x12];
    uStack996 = puVar15[0x13];
    local_3e0 = puVar15[0x14];
    uStack988 = puVar15[0x15];
    uStack984 = puVar15[0x16];
    uStack980 = puVar15[0x17];
    local_3d0 = puVar15[0x18];
    uStack972 = puVar15[0x19];
    uStack968 = puVar15[0x1a];
    uStack964 = puVar15[0x1b];
    local_3c0 = puVar15[0x1c];
    uStack956 = puVar15[0x1d];
    uStack952 = puVar15[0x1e];
    uStack948 = puVar15[0x1f];
    local_3b0 = puVar15[0x20];
    uStack940 = puVar15[0x21];
    uStack936 = puVar15[0x22];
    uStack932 = puVar15[0x23];
    local_3a0 = puVar15[0x24];
    uStack924 = puVar15[0x25];
    uStack920 = puVar15[0x26];
    uStack916 = puVar15[0x27];
    local_390 = puVar15[0x28];
    uStack908 = puVar15[0x29];
    uStack904 = puVar15[0x2a];
    uStack900 = puVar15[0x2b];
    local_380 = *(undefined8 *)(puVar15 + 0x2c);
  }
  if (puVar2 != (undefined8 *)0x0) {
    local_6c8 = 2;
    local_6d0 = L"FSR2_InputExposure";
    local_6d8 = *(undefined4 *)((longlong)puVar2 + 0x24);
    local_6e0 = *(undefined4 *)((longlong)puVar2 + 0x2c);
    local_6e8 = *(undefined4 *)(puVar2 + 5);
    puVar15 = (undefined4 *)ffxGetTextureResourceVK(local_680,pplVar6,puVar2[1],*puVar2);
    local_378 = *puVar15;
    uStack884 = puVar15[1];
    uStack880 = puVar15[2];
    uStack876 = puVar15[3];
    local_368 = puVar15[4];
    uStack868 = puVar15[5];
    uStack864 = puVar15[6];
    uStack860 = puVar15[7];
    local_358 = puVar15[8];
    uStack852 = puVar15[9];
    uStack848 = puVar15[10];
    uStack844 = puVar15[0xb];
    local_348 = puVar15[0xc];
    uStack836 = puVar15[0xd];
    uStack832 = puVar15[0xe];
    uStack828 = puVar15[0xf];
    local_338 = puVar15[0x10];
    uStack820 = puVar15[0x11];
    uStack816 = puVar15[0x12];
    uStack812 = puVar15[0x13];
    local_328 = puVar15[0x14];
    uStack804 = puVar15[0x15];
    uStack800 = puVar15[0x16];
    uStack796 = puVar15[0x17];
    local_318 = puVar15[0x18];
    uStack788 = puVar15[0x19];
    uStack784 = puVar15[0x1a];
    uStack780 = puVar15[0x1b];
    local_308 = puVar15[0x1c];
    uStack772 = puVar15[0x1d];
    uStack768 = puVar15[0x1e];
    uStack764 = puVar15[0x1f];
    local_2f8 = puVar15[0x20];
    uStack756 = puVar15[0x21];
    uStack752 = puVar15[0x22];
    uStack748 = puVar15[0x23];
    local_2e8 = puVar15[0x24];
    uStack740 = puVar15[0x25];
    uStack736 = puVar15[0x26];
    uStack732 = puVar15[0x27];
    local_2d8 = puVar15[0x28];
    uStack724 = puVar15[0x29];
    uStack720 = puVar15[0x2a];
    uStack716 = puVar15[0x2b];
    local_2c8 = *(undefined8 *)(puVar15 + 0x2c);
  }
  if (puVar3 != (undefined8 *)0x0) {
    local_6c8 = 2;
    local_6d0 = L"FSR2_InputReactiveMap";
    local_6d8 = *(undefined4 *)((longlong)puVar3 + 0x24);
    local_6e0 = *(undefined4 *)((longlong)puVar3 + 0x2c);
    local_6e8 = *(undefined4 *)(puVar3 + 5);
    puVar15 = (undefined4 *)ffxGetTextureResourceVK(local_680,pplVar6,puVar3[1],*puVar3);
    local_2c0 = *puVar15;
    uStack700 = puVar15[1];
    uStack696 = puVar15[2];
    uStack692 = puVar15[3];
    local_2b0 = puVar15[4];
    uStack684 = puVar15[5];
    uStack680 = puVar15[6];
    uStack676 = puVar15[7];
    local_2a0 = puVar15[8];
    uStack668 = puVar15[9];
    uStack664 = puVar15[10];
    uStack660 = puVar15[0xb];
    local_290 = puVar15[0xc];
    uStack652 = puVar15[0xd];
    uStack648 = puVar15[0xe];
    uStack644 = puVar15[0xf];
    local_280 = puVar15[0x10];
    uStack636 = puVar15[0x11];
    uStack632 = puVar15[0x12];
    uStack628 = puVar15[0x13];
    local_270 = puVar15[0x14];
    uStack620 = puVar15[0x15];
    uStack616 = puVar15[0x16];
    uStack612 = puVar15[0x17];
    local_260 = puVar15[0x18];
    uStack604 = puVar15[0x19];
    uStack600 = puVar15[0x1a];
    uStack596 = puVar15[0x1b];
    local_250 = puVar15[0x1c];
    uStack588 = puVar15[0x1d];
    uStack584 = puVar15[0x1e];
    uStack580 = puVar15[0x1f];
    local_240 = puVar15[0x20];
    uStack572 = puVar15[0x21];
    uStack568 = puVar15[0x22];
    uStack564 = puVar15[0x23];
    local_230 = puVar15[0x24];
    uStack556 = puVar15[0x25];
    uStack552 = puVar15[0x26];
    uStack548 = puVar15[0x27];
    local_220 = puVar15[0x28];
    uStack540 = puVar15[0x29];
    uStack536 = puVar15[0x2a];
    uStack532 = puVar15[0x2b];
    local_210 = *(undefined8 *)(puVar15 + 0x2c);
  }
  if (puVar4 != (undefined8 *)0x0) {
    local_6c8 = 2;
    local_6d0 = L"FSR2_TransparencyAndCompositionMap";
    local_6d8 = *(undefined4 *)((longlong)puVar4 + 0x24);
    local_6e0 = *(undefined4 *)((longlong)puVar4 + 0x2c);
    local_6e8 = *(undefined4 *)(puVar4 + 5);
    puVar15 = (undefined4 *)ffxGetTextureResourceVK(local_680,pplVar6,puVar4[1],*puVar4);
    local_208 = *puVar15;
    uStack516 = puVar15[1];
    uStack512 = puVar15[2];
    uStack508 = puVar15[3];
    local_1f8 = puVar15[4];
    uStack500 = puVar15[5];
    uStack496 = puVar15[6];
    uStack492 = puVar15[7];
    local_1e8 = puVar15[8];
    uStack484 = puVar15[9];
    uStack480 = puVar15[10];
    uStack476 = puVar15[0xb];
    local_1d8 = puVar15[0xc];
    uStack468 = puVar15[0xd];
    uStack464 = puVar15[0xe];
    uStack460 = puVar15[0xf];
    local_1c8 = puVar15[0x10];
    uStack452 = puVar15[0x11];
    uStack448 = puVar15[0x12];
    uStack444 = puVar15[0x13];
    local_1b8 = puVar15[0x14];
    uStack436 = puVar15[0x15];
    uStack432 = puVar15[0x16];
    uStack428 = puVar15[0x17];
    local_1a8 = puVar15[0x18];
    uStack420 = puVar15[0x19];
    uStack416 = puVar15[0x1a];
    uStack412 = puVar15[0x1b];
    local_198 = puVar15[0x1c];
    uStack404 = puVar15[0x1d];
    uStack400 = puVar15[0x1e];
    uStack396 = puVar15[0x1f];
    local_188 = puVar15[0x20];
    uStack388 = puVar15[0x21];
    uStack384 = puVar15[0x22];
    uStack380 = puVar15[0x23];
    local_178 = puVar15[0x24];
    uStack372 = puVar15[0x25];
    uStack368 = puVar15[0x26];
    uStack364 = puVar15[0x27];
    local_168 = puVar15[0x28];
    uStack356 = puVar15[0x29];
    uStack352 = puVar15[0x2a];
    uStack348 = puVar15[0x2b];
    local_158 = *(undefined8 *)(puVar15 + 0x2c);
  }
  if (puVar5 != (undefined8 *)0x0) {
    local_6c8 = 1;
    local_6d0 = L"FSR2_OutputUpscaledColor";
    local_6d8 = *(undefined4 *)((longlong)puVar5 + 0x24);
    local_6e0 = *(undefined4 *)((longlong)puVar5 + 0x2c);
    local_6e8 = *(undefined4 *)(puVar5 + 5);
    puVar15 = (undefined4 *)ffxGetTextureResourceVK(local_680,pplVar6,puVar5[1],*puVar5);
    local_150 = *puVar15;
    uStack332 = puVar15[1];
    uStack328 = puVar15[2];
    uStack324 = puVar15[3];
    local_140 = puVar15[4];
    uStack316 = puVar15[5];
    uStack312 = puVar15[6];
    uStack308 = puVar15[7];
    local_130 = puVar15[8];
    uStack300 = puVar15[9];
    uStack296 = puVar15[10];
    uStack292 = puVar15[0xb];
    local_120 = puVar15[0xc];
    uStack284 = puVar15[0xd];
    uStack280 = puVar15[0xe];
    uStack276 = puVar15[0xf];
    local_110 = puVar15[0x10];
    uStack268 = puVar15[0x11];
    uStack264 = puVar15[0x12];
    uStack260 = puVar15[0x13];
    local_100 = puVar15[0x14];
    uStack252 = puVar15[0x15];
    uStack248 = puVar15[0x16];
    uStack244 = puVar15[0x17];
    local_f0 = puVar15[0x18];
    uStack236 = puVar15[0x19];
    uStack232 = puVar15[0x1a];
    uStack228 = puVar15[0x1b];
    local_e0 = puVar15[0x1c];
    uStack220 = puVar15[0x1d];
    uStack216 = puVar15[0x1e];
    uStack212 = puVar15[0x1f];
    local_d0 = puVar15[0x20];
    uStack204 = puVar15[0x21];
    uStack200 = puVar15[0x22];
    uStack196 = puVar15[0x23];
    local_c0 = puVar15[0x24];
    uStack188 = puVar15[0x25];
    uStack184 = puVar15[0x26];
    uStack180 = puVar15[0x27];
    local_b0 = puVar15[0x28];
    uStack172 = puVar15[0x29];
    uStack168 = puVar15[0x2a];
    uStack164 = puVar15[0x2b];
    local_a0 = *(undefined8 *)(puVar15 + 0x2c);
  }
  local_98 = *(undefined4 *)(lVar14 + 0x40);
  local_94 = *(undefined4 *)(lVar14 + 0x44);
  local_90 = *(undefined4 *)(lVar14 + 0x38);
  local_8c = *(undefined4 *)(lVar14 + 0x3c);
  local_70 = *(undefined *)(lVar14 + 0x34);
  lVar13 = *local_6a8;
  local_7c = FUN_180018d6c(*(undefined4 *)(lVar14 + 0x30),lVar13,*(undefined8 *)(lVar13 + 0x14));
  if (*(char *)(lVar13 + 0xb) == '\0') {
    local_80 = *(undefined *)(lVar14 + 0x53);
  }
  else {
    local_80 = *(undefined *)(lVar13 + 10);
  }
  dVar17 = (double)FUN_180018db4();
  pplVar7 = local_5c8;
  local_78 = (float)(dVar17 - _DAT_18041ecc0);
  local_74 = 0x3f800000;
  local_88 = *(undefined4 *)(lVar14 + 8);
  local_84 = *(undefined4 *)(lVar14 + 0xc);
  _DAT_18041ecc0 = dVar17;
  local_68 = (**(code **)(**local_5c8 + 8))();
  local_6c = (**(code **)(**pplVar7 + 0x10))();
  local_64 = (float)(**(code **)**pplVar7)();
  local_64 = local_64 * 0.01745329;
  ffxFsr2ContextDispatch(pplVar6,&local_5a8);
  if (local_58._8_8_ != 0) {
    FUN_1800030d8();
  }
  FUN_18000e8c0(local_48 ^ (ulonglong)auStack1800);
  return;
}



// WARNING: Could not reconcile some variable overlaps

void NVSDK_NGX_VULKAN_GetScratchBufferSize
               (undefined8 param_1,undefined8 param_2,undefined8 *param_3)

{
  undefined8 uVar1;
  undefined auStack72 [32];
  undefined local_28 [16];
  ulonglong local_18;
  
                    // 0x18510  22  NVSDK_NGX_VULKAN_GetScratchBufferSize
  local_18 = DAT_180418010 ^ (ulonglong)auStack72;
  local_28 = ZEXT816(0);
  FUN_18000328c(local_28);
  uVar1 = ffxFsr2GetScratchMemorySizeVK(*(undefined8 *)(local_28._0_8_ + 0x20));
  *param_3 = uVar1;
  if (local_28._8_8_ != 0) {
    FUN_1800030d8();
  }
  FUN_18000e8c0(local_18 ^ (ulonglong)auStack72);
  return;
}



undefined8
NVSDK_NGX_VULKAN_Init
          (undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
          undefined8 param_5)

{
  longlong *plVar1;
  undefined local_18 [8];
  longlong local_10;
  
                    // 0x18574  23  NVSDK_NGX_VULKAN_Init
  plVar1 = (longlong *)FUN_18000328c(local_18);
  *(undefined8 *)(*plVar1 + 0x10) = param_5;
  if (local_10 != 0) {
    FUN_1800030d8();
  }
  plVar1 = (longlong *)FUN_18000328c(local_18);
  *(undefined8 *)(*plVar1 + 0x18) = param_3;
  if (local_10 != 0) {
    FUN_1800030d8();
  }
  plVar1 = (longlong *)FUN_18000328c(local_18);
  *(undefined8 *)(*plVar1 + 0x20) = param_4;
  if (local_10 != 0) {
    FUN_1800030d8();
  }
  return 1;
}



void NVSDK_NGX_VULKAN_Init_ProjectID(void)

{
  undefined8 in_R9;
  undefined8 in_stack_00000028;
  undefined8 in_stack_00000030;
  undefined8 in_stack_00000038;
  undefined8 in_stack_00000040;
  undefined4 in_stack_00000048;
  
                    // 0x185fc  24  NVSDK_NGX_VULKAN_Init_ProjectID
                    // 0x185fc  25  NVSDK_NGX_VULKAN_Init_with_ProjectID
  NVSDK_NGX_VULKAN_Init
            (0x1337,in_R9,in_stack_00000028,in_stack_00000030,in_stack_00000038,in_stack_00000040,
             in_stack_00000048);
  return;
}



void NVSDK_NGX_VULKAN_ReleaseFeature(undefined4 *param_1)

{
  longlong lVar1;
  char cVar2;
  longlong *plVar3;
  undefined8 uVar4;
  void *pvVar5;
  undefined4 *puVar6;
  longlong lVar7;
  undefined8 *puVar8;
  longlong lVar9;
  undefined auStack136 [32];
  undefined local_68 [8];
  longlong local_60;
  undefined local_58 [16];
  undefined4 local_48;
  undefined4 uStack68;
  undefined4 uStack64;
  undefined4 uStack60;
  longlong local_38;
  undefined8 local_30;
  ulonglong local_28;
  
                    // 0x18644  26  NVSDK_NGX_VULKAN_ReleaseFeature
  local_28 = DAT_180418010 ^ (ulonglong)auStack136;
  plVar3 = (longlong *)FUN_18000328c(local_68);
  lVar1 = *plVar3;
  lVar9 = lVar1 + 0x40;
  uVar4 = FUN_18000d1d8();
  FUN_180003954(lVar9,&local_48,param_1,uVar4);
  lVar7 = CONCAT44(uStack60,uStack64);
  if (lVar7 == 0) {
    FUN_180003ce8();
    local_38 = lVar1 + 0x48;
    pvVar5 = operator_new(0x20);
    *(undefined4 *)((longlong)pvVar5 + 0x10) = *param_1;
    *(undefined8 *)((longlong)pvVar5 + 0x18) = 0;
    cVar2 = FUN_180003ff0(lVar9);
    if (cVar2 != '\0') {
      FUN_18001763c(lVar9);
      puVar6 = (undefined4 *)FUN_180003954(lVar9,local_58,(longlong)pvVar5 + 0x10,uVar4);
      local_48 = *puVar6;
      uStack68 = puVar6[1];
      uStack64 = puVar6[2];
      uStack60 = puVar6[3];
    }
    local_30 = 0;
    lVar7 = FUN_18000399c(lVar9,uVar4,CONCAT44(uStack68,local_48),pvVar5);
    FUN_180003fbc(&local_38);
  }
  lVar1 = *(longlong *)(lVar7 + 0x18);
  if (local_60 != 0) {
    FUN_1800030d8();
  }
  if (lVar1 != -0x18) {
    FUN_180003b00();
  }
  puVar8 = (undefined8 *)FUN_18000328c(local_68);
  FUN_180003db0(*puVar8,param_1);
  if (local_60 != 0) {
    FUN_1800030d8();
  }
  FUN_18000e8c0(local_28 ^ (ulonglong)auStack136);
  return;
}



undefined8 NVSDK_NGX_VULKAN_Shutdown(void)

{
  longlong *plVar1;
  undefined local_18 [8];
  longlong local_10;
  
                    // 0x18788  27  NVSDK_NGX_VULKAN_Shutdown
                    // 0x18788  28  NVSDK_NGX_VULKAN_Shutdown1
  plVar1 = (longlong *)FUN_18000328c(local_18);
  *(undefined8 *)(*plVar1 + 0x10) = 0;
  if (local_10 != 0) {
    FUN_1800030d8();
  }
  plVar1 = (longlong *)FUN_18000328c(local_18);
  *(undefined8 *)(*plVar1 + 0x18) = 0;
  if (local_10 != 0) {
    FUN_1800030d8();
  }
  plVar1 = (longlong *)FUN_18000328c(local_18);
  *(undefined8 *)(*plVar1 + 0x20) = 0;
  if (local_10 != 0) {
    FUN_1800030d8();
  }
  plVar1 = (longlong *)FUN_18000328c(local_18);
  FUN_18000e428(*plVar1 + 0x28);
  if (local_10 != 0) {
    FUN_1800030d8();
  }
  plVar1 = (longlong *)FUN_18000328c(local_18);
  FUN_18000e610(*plVar1 + 0x40);
  if (local_10 != 0) {
    FUN_1800030d8();
  }
  return 1;
}



void FUN_180018844(longlong *param_1)

{
  void *_Memory;
  
  (**(code **)(*param_1 + 0x10))();
  _Memory = (void *)param_1[0x17];
  param_1[0x17] = 0;
  if (_Memory != (void *)0x0) {
    FUN_180002a84(_Memory);
    free(_Memory);
  }
  return;
}



void FUN_18001888c(longlong param_1,longlong *param_2)

{
  longlong *plVar1;
  undefined auStack56 [32];
  undefined8 local_18;
  ulonglong local_10;
  
  plVar1 = *(longlong **)(param_1 + 0x80);
  local_10 = DAT_180418010 ^ (ulonglong)auStack56;
  (**(code **)(*plVar1 + 8))();
  local_18 = *(undefined8 *)(plVar1[10] + 0x60);
  (**(code **)(*param_2 + 0xe0))(param_2,1,&local_18);
  (**(code **)(*param_2 + 0xe8))(param_2,plVar1[2]);
  (**(code **)(*param_2 + 0xf8))(param_2,0,plVar1[6]);
  (**(code **)(*param_2 + 200))(param_2,plVar1[1]);
  (**(code **)(*param_2 + 0x70))
            (param_2,*(undefined4 *)(plVar1 + 3),*(undefined4 *)((longlong)plVar1 + 0x1c),1);
  FUN_18000e8c0(local_10 ^ (ulonglong)auStack56);
  return;
}



// WARNING: Removing unreachable block (ram,0x0001800072f6)
// WARNING: Removing unreachable block (ram,0x000180007324)
// WARNING: Removing unreachable block (ram,0x000180011972)
// WARNING: Removing unreachable block (ram,0x0001800072c8)
// WARNING: Removing unreachable block (ram,0x00018000721a)
// WARNING: Removing unreachable block (ram,0x000180011987)
// WARNING: Removing unreachable block (ram,0x000180007221)

void FUN_1800188e8(undefined8 param_1,undefined8 param_2,ulonglong param_3,longlong param_4)

{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = FUN_180007480();
  iVar2 = (int)param_3;
  switch(uVar1) {
  case 7:
  case 0xe:
    *(int *)(param_4 + 8) = iVar2;
    return;
  case 8:
  case 0xf:
    *(int *)(param_4 + 0xc) = iVar2;
    return;
  case 9:
    *(int *)(param_4 + 0x18) = iVar2;
    return;
  case 10:
    *(bool *)(param_4 + 0x1c) = iVar2 != 0;
    return;
  case 0xb:
    *(bool *)(param_4 + 0x1d) = iVar2 != 0;
    break;
  case 0xc:
    *(int *)(param_4 + 0x10) = iVar2;
    return;
  case 0xd:
    *(int *)(param_4 + 0x14) = iVar2;
    return;
  case 0x14:
    *(int *)(param_4 + 0x30) = iVar2;
    return;
  case 0x17:
    *(int *)(param_4 + 0x20) = iVar2;
    return;
  case 0x18:
    *(int *)(param_4 + 0x24) = iVar2;
    return;
  case 0x19:
    *(byte *)(param_4 + 0x52) = (byte)param_3 & 1;
    *(byte *)(param_4 + 0x53) = (byte)((param_3 & 0xffffffff) >> 5) & 1;
    *(bool *)(param_4 + 0x50) = (param_3 & 8) != 0;
    *(bool *)(param_4 + 0x54) = (param_3 & 4) != 0;
    *(bool *)(param_4 + 0x55) = (param_3 & 2) != 0;
    return;
  case 0x1b:
    *(ulonglong *)(param_4 + 0x60) = param_3;
    break;
  case 0x1c:
    *(ulonglong *)(param_4 + 0x70) = param_3;
    break;
  case 0x1d:
    *(ulonglong *)(param_4 + 0x68) = param_3;
    break;
  case 0x1e:
    *(ulonglong *)(param_4 + 0x78) = param_3;
    break;
  case 0x1f:
    *(ulonglong *)(param_4 + 0x80) = param_3;
    break;
  case 0x20:
    *(ulonglong *)(param_4 + 0x88) = param_3;
    break;
  case 0x21:
    *(ulonglong *)(param_4 + 0x58) = param_3;
    break;
  case 0x24:
    *(bool *)(param_4 + 0x34) = iVar2 != 0;
    return;
  case 0x25:
    *(int *)(param_4 + 0x38) = iVar2;
    return;
  case 0x26:
    *(int *)(param_4 + 0x3c) = iVar2;
    return;
  case 0x27:
    *(int *)(param_4 + 0x40) = iVar2;
    return;
  case 0x28:
    *(int *)(param_4 + 0x44) = iVar2;
    return;
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x0001800072f6)
// WARNING: Removing unreachable block (ram,0x000180007324)
// WARNING: Removing unreachable block (ram,0x000180011972)
// WARNING: Removing unreachable block (ram,0x0001800072c8)
// WARNING: Removing unreachable block (ram,0x00018000721a)
// WARNING: Removing unreachable block (ram,0x000180011987)
// WARNING: Removing unreachable block (ram,0x000180007221)

void FUN_1800188f8(longlong param_1,undefined8 param_2,ulonglong param_3)

{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = FUN_180007480();
  iVar2 = (int)param_3;
  switch(uVar1) {
  case 7:
  case 0xe:
    *(int *)(param_1 + 8) = iVar2;
    return;
  case 8:
  case 0xf:
    *(int *)(param_1 + 0xc) = iVar2;
    return;
  case 9:
    *(int *)(param_1 + 0x18) = iVar2;
    return;
  case 10:
    *(bool *)(param_1 + 0x1c) = iVar2 != 0;
    return;
  case 0xb:
    *(bool *)(param_1 + 0x1d) = iVar2 != 0;
    break;
  case 0xc:
    *(int *)(param_1 + 0x10) = iVar2;
    return;
  case 0xd:
    *(int *)(param_1 + 0x14) = iVar2;
    return;
  case 0x14:
    *(int *)(param_1 + 0x30) = iVar2;
    return;
  case 0x17:
    *(int *)(param_1 + 0x20) = iVar2;
    return;
  case 0x18:
    *(int *)(param_1 + 0x24) = iVar2;
    return;
  case 0x19:
    *(byte *)(param_1 + 0x52) = (byte)param_3 & 1;
    *(byte *)(param_1 + 0x53) = (byte)((param_3 & 0xffffffff) >> 5) & 1;
    *(bool *)(param_1 + 0x50) = (param_3 & 8) != 0;
    *(bool *)(param_1 + 0x54) = (param_3 & 4) != 0;
    *(bool *)(param_1 + 0x55) = (param_3 & 2) != 0;
    return;
  case 0x1b:
    *(ulonglong *)(param_1 + 0x60) = param_3;
    break;
  case 0x1c:
    *(ulonglong *)(param_1 + 0x70) = param_3;
    break;
  case 0x1d:
    *(ulonglong *)(param_1 + 0x68) = param_3;
    break;
  case 0x1e:
    *(ulonglong *)(param_1 + 0x78) = param_3;
    break;
  case 0x1f:
    *(ulonglong *)(param_1 + 0x80) = param_3;
    break;
  case 0x20:
    *(ulonglong *)(param_1 + 0x88) = param_3;
    break;
  case 0x21:
    *(ulonglong *)(param_1 + 0x58) = param_3;
    break;
  case 0x24:
    *(bool *)(param_1 + 0x34) = iVar2 != 0;
    return;
  case 0x25:
    *(int *)(param_1 + 0x38) = iVar2;
    return;
  case 0x26:
    *(int *)(param_1 + 0x3c) = iVar2;
    return;
  case 0x27:
    *(int *)(param_1 + 0x40) = iVar2;
    return;
  case 0x28:
    *(int *)(param_1 + 0x44) = iVar2;
    return;
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x0001800072f6)
// WARNING: Removing unreachable block (ram,0x000180007324)
// WARNING: Removing unreachable block (ram,0x000180011972)
// WARNING: Removing unreachable block (ram,0x0001800072c8)
// WARNING: Removing unreachable block (ram,0x00018000721a)
// WARNING: Removing unreachable block (ram,0x000180011987)
// WARNING: Removing unreachable block (ram,0x000180007221)

void FUN_180018904(longlong param_1,undefined8 param_2,ulonglong param_3)

{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = FUN_180007480();
  iVar2 = (int)param_3;
  switch(uVar1) {
  case 7:
  case 0xe:
    *(int *)(param_1 + 8) = iVar2;
    return;
  case 8:
  case 0xf:
    *(int *)(param_1 + 0xc) = iVar2;
    return;
  case 9:
    *(int *)(param_1 + 0x18) = iVar2;
    return;
  case 10:
    *(bool *)(param_1 + 0x1c) = iVar2 != 0;
    return;
  case 0xb:
    *(bool *)(param_1 + 0x1d) = iVar2 != 0;
    break;
  case 0xc:
    *(int *)(param_1 + 0x10) = iVar2;
    return;
  case 0xd:
    *(int *)(param_1 + 0x14) = iVar2;
    return;
  case 0x14:
    *(int *)(param_1 + 0x30) = iVar2;
    return;
  case 0x17:
    *(int *)(param_1 + 0x20) = iVar2;
    return;
  case 0x18:
    *(int *)(param_1 + 0x24) = iVar2;
    return;
  case 0x19:
    *(byte *)(param_1 + 0x52) = (byte)param_3 & 1;
    *(byte *)(param_1 + 0x53) = (byte)((param_3 & 0xffffffff) >> 5) & 1;
    *(bool *)(param_1 + 0x50) = (param_3 & 8) != 0;
    *(bool *)(param_1 + 0x54) = (param_3 & 4) != 0;
    *(bool *)(param_1 + 0x55) = (param_3 & 2) != 0;
    return;
  case 0x1b:
    *(ulonglong *)(param_1 + 0x60) = param_3;
    break;
  case 0x1c:
    *(ulonglong *)(param_1 + 0x70) = param_3;
    break;
  case 0x1d:
    *(ulonglong *)(param_1 + 0x68) = param_3;
    break;
  case 0x1e:
    *(ulonglong *)(param_1 + 0x78) = param_3;
    break;
  case 0x1f:
    *(ulonglong *)(param_1 + 0x80) = param_3;
    break;
  case 0x20:
    *(ulonglong *)(param_1 + 0x88) = param_3;
    break;
  case 0x21:
    *(ulonglong *)(param_1 + 0x58) = param_3;
    break;
  case 0x24:
    *(bool *)(param_1 + 0x34) = iVar2 != 0;
    return;
  case 0x25:
    *(int *)(param_1 + 0x38) = iVar2;
    return;
  case 0x26:
    *(int *)(param_1 + 0x3c) = iVar2;
    return;
  case 0x27:
    *(int *)(param_1 + 0x40) = iVar2;
    return;
  case 0x28:
    *(int *)(param_1 + 0x44) = iVar2;
    return;
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x0001800072f6)
// WARNING: Removing unreachable block (ram,0x000180007324)
// WARNING: Removing unreachable block (ram,0x000180011972)
// WARNING: Removing unreachable block (ram,0x0001800072c8)
// WARNING: Removing unreachable block (ram,0x00018000721a)
// WARNING: Removing unreachable block (ram,0x000180011987)
// WARNING: Removing unreachable block (ram,0x000180007221)

void FUN_180018910(longlong param_1,undefined8 param_2,ulonglong param_3)

{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = FUN_180007480();
  iVar2 = (int)param_3;
  switch(uVar1) {
  case 7:
  case 0xe:
    *(int *)(param_1 + 8) = iVar2;
    return;
  case 8:
  case 0xf:
    *(int *)(param_1 + 0xc) = iVar2;
    return;
  case 9:
    *(int *)(param_1 + 0x18) = iVar2;
    return;
  case 10:
    *(bool *)(param_1 + 0x1c) = iVar2 != 0;
    return;
  case 0xb:
    *(bool *)(param_1 + 0x1d) = iVar2 != 0;
    break;
  case 0xc:
    *(int *)(param_1 + 0x10) = iVar2;
    return;
  case 0xd:
    *(int *)(param_1 + 0x14) = iVar2;
    return;
  case 0x14:
    *(int *)(param_1 + 0x30) = iVar2;
    return;
  case 0x17:
    *(int *)(param_1 + 0x20) = iVar2;
    return;
  case 0x18:
    *(int *)(param_1 + 0x24) = iVar2;
    return;
  case 0x19:
    *(byte *)(param_1 + 0x52) = (byte)param_3 & 1;
    *(byte *)(param_1 + 0x53) = (byte)((param_3 & 0xffffffff) >> 5) & 1;
    *(bool *)(param_1 + 0x50) = (param_3 & 8) != 0;
    *(bool *)(param_1 + 0x54) = (param_3 & 4) != 0;
    *(bool *)(param_1 + 0x55) = (param_3 & 2) != 0;
    return;
  case 0x1b:
    *(ulonglong *)(param_1 + 0x60) = param_3;
    break;
  case 0x1c:
    *(ulonglong *)(param_1 + 0x70) = param_3;
    break;
  case 0x1d:
    *(ulonglong *)(param_1 + 0x68) = param_3;
    break;
  case 0x1e:
    *(ulonglong *)(param_1 + 0x78) = param_3;
    break;
  case 0x1f:
    *(ulonglong *)(param_1 + 0x80) = param_3;
    break;
  case 0x20:
    *(ulonglong *)(param_1 + 0x88) = param_3;
    break;
  case 0x21:
    *(ulonglong *)(param_1 + 0x58) = param_3;
    break;
  case 0x24:
    *(bool *)(param_1 + 0x34) = iVar2 != 0;
    return;
  case 0x25:
    *(int *)(param_1 + 0x38) = iVar2;
    return;
  case 0x26:
    *(int *)(param_1 + 0x3c) = iVar2;
    return;
  case 0x27:
    *(int *)(param_1 + 0x40) = iVar2;
    return;
  case 0x28:
    *(int *)(param_1 + 0x44) = iVar2;
    return;
  }
  return;
}



// Library Function - Single Match
//  public: void * __ptr64 __cdecl MRECmpImpl::`scalar deleting destructor'(unsigned int) __ptr64
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void * __thiscall MRECmpImpl::_scalar_deleting_destructor_(MRECmpImpl *this,uint param_1)

{
  FUN_180003e80(this + 0x10);
  if ((param_1 & 1) != 0) {
    free(this);
  }
  return this;
}



void FUN_180018954(undefined8 *param_1,longlong *param_2)

{
  longlong **pplVar1;
  
  pplVar1 = (longlong **)(param_1 + 3);
  if (*(char *)(param_1 + 4) != '\0') {
    (**(code **)(**pplVar1 + 0x50))(*pplVar1,param_1[2],0);
    (**(code **)*param_1)(param_1,*pplVar1);
    (**(code **)(**pplVar1 + 0x48))();
    *(undefined *)(param_1 + 4) = 0;
  }
                    // WARNING: Could not recover jumptable at 0x0001800189b3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_2 + 0xd8))(param_2,*pplVar1);
  return;
}



void FUN_180018a88(undefined8 *param_1,undefined8 param_2)

{
  undefined auStack72 [32];
  undefined8 local_28;
  undefined local_20;
  ulonglong local_18;
  
  local_18 = DAT_180418010 ^ (ulonglong)auStack72;
  local_20 = 1;
  *param_1 = std::exception::vftable;
  *(undefined (*) [16])(param_1 + 1) = ZEXT816(0);
  local_28 = param_2;
  __std_exception_copy(&local_28);
  *param_1 = std::invalid_argument::vftable;
  FUN_18000e8c0(local_18 ^ (ulonglong)auStack72);
  return;
}



void FUN_180018b10(longlong param_1,longlong *param_2,int param_3,undefined4 *param_4)

{
  undefined auStack104 [32];
  undefined4 local_48;
  undefined4 local_44;
  undefined8 local_40;
  undefined4 local_38;
  int local_34;
  int local_30;
  ulonglong local_28;
  
  local_28 = DAT_180418010 ^ (ulonglong)auStack104;
  if (*(int *)(param_1 + 0x1c) != param_3) {
    local_48 = 0;
    local_44 = 0;
    local_38 = 0xffffffff;
    local_40 = *(undefined8 *)(param_1 + 8);
    local_34 = *(int *)(param_1 + 0x1c);
    local_30 = param_3;
    (**(code **)(*param_2 + 0xd0))(param_2,1,&local_48);
    if (param_4 != (undefined4 *)0x0) {
      *param_4 = *(undefined4 *)(param_1 + 0x1c);
    }
    *(int *)(param_1 + 0x1c) = param_3;
  }
  FUN_18000e8c0(local_28 ^ (ulonglong)auStack104);
  return;
}



void FUN_180018b94(undefined8 *param_1,longlong *param_2)

{
  undefined8 *puVar1;
  undefined auStack120 [32];
  longlong local_58;
  undefined local_48 [16];
  undefined4 local_38;
  undefined4 local_30;
  undefined4 local_28;
  ulonglong local_10;
  
  local_10 = DAT_180418010 ^ (ulonglong)auStack120;
  (**(code **)(*param_2 + 0x50))(param_2,local_48);
  puVar1 = param_1 + 1;
  *(undefined4 *)(param_1 + 2) = local_38;
  *(undefined4 *)((longlong)param_1 + 0x14) = local_30;
  *(undefined4 *)(param_1 + 3) = local_28;
  FUN_18000dca0(puVar1,param_2);
  if (*(int *)(param_1 + 4) != -1) {
    (**(code **)(**(longlong **)*param_1 + 0x90))
              (*(longlong **)*param_1,*puVar1,param_1 + 7,
               (longlong)*(int *)(param_1[6] + 4) * (longlong)*(int *)(param_1 + 4) +
               *(longlong *)(param_1[6] + 8));
  }
  if (*(int *)((longlong)param_1 + 0x24) != -1) {
    local_58 = (longlong)*(int *)(param_1[0xc] + 4) * (longlong)*(int *)((longlong)param_1 + 0x24) +
               *(longlong *)(param_1[0xc] + 8);
    (**(code **)(**(longlong **)*param_1 + 0x98))(*(longlong **)*param_1,*puVar1,0,param_1 + 0xd);
  }
  if (*(int *)(param_1 + 5) != -1) {
    (**(code **)(**(longlong **)*param_1 + 0xa0))
              (*(longlong **)*param_1,*puVar1,param_1 + 0x13,
               (longlong)*(int *)(param_1[0x12] + 4) * (longlong)*(int *)(param_1 + 5) +
               *(longlong *)(param_1[0x12] + 8));
  }
  FUN_18000e8c0(local_10 ^ (ulonglong)auStack120);
  return;
}



undefined8 *
FUN_180018ca8(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 *param_4)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  void *pvVar5;
  
  *param_1 = param_2;
  param_1[1] = 0;
  param_1[1] = 0;
  pvVar5 = operator_new(0x38);
  param_1[1] = pvVar5;
  puVar1 = (undefined4 *)*param_4;
  *(undefined8 *)((longlong)pvVar5 + 0x10) = 0;
  *(undefined8 *)((longlong)pvVar5 + 0x20) = 0;
  *(undefined8 *)((longlong)pvVar5 + 0x28) = 0;
  uVar2 = puVar1[1];
  uVar3 = puVar1[2];
  uVar4 = puVar1[3];
  *(undefined4 *)((longlong)pvVar5 + 0x10) = *puVar1;
  *(undefined4 *)((longlong)pvVar5 + 0x14) = uVar2;
  *(undefined4 *)((longlong)pvVar5 + 0x18) = uVar3;
  *(undefined4 *)((longlong)pvVar5 + 0x1c) = uVar4;
  uVar2 = puVar1[5];
  uVar3 = puVar1[6];
  uVar4 = puVar1[7];
  *(undefined4 *)((longlong)pvVar5 + 0x20) = puVar1[4];
  *(undefined4 *)((longlong)pvVar5 + 0x24) = uVar2;
  *(undefined4 *)((longlong)pvVar5 + 0x28) = uVar3;
  *(undefined4 *)((longlong)pvVar5 + 0x2c) = uVar4;
  *(undefined8 *)(puVar1 + 4) = 0;
  *(undefined8 *)(puVar1 + 6) = 0xf;
  *(undefined *)puVar1 = 0;
  *(undefined4 *)((longlong)pvVar5 + 0x30) = 0;
  return param_1;
}



ulonglong FUN_180018d6c(ulonglong param_1,undefined8 param_2,undefined8 param_3)

{
  float fVar1;
  
  fVar1 = (float)param_1;
  if ((char)((ulonglong)param_3 >> 0x20) != '\0' && (int)param_3 == 1) {
    if (1.0 <= fVar1) {
      return 0x3f800000;
    }
    if (fVar1 <= -1.0) {
      return 0;
    }
    fVar1 = fVar1 * 0.5 + 0.495;
  }
  return param_1 & 0xffffffff00000000 | (ulonglong)(uint)fVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180018db4(void)

{
  ULONGLONG UVar1;
  longlong in_GS_OFFSET;
  double dVar2;
  undefined auStack56 [32];
  longlong local_18;
  ulonglong local_10;
  
  local_10 = DAT_180418010 ^ (ulonglong)auStack56;
  if (*(int *)(*(longlong *)(*(longlong *)(in_GS_OFFSET + 0x58) + (ulonglong)DAT_18041eb54 * 8) + 4)
      < _DAT_18041eca8) {
    _Init_thread_header(&DAT_18041eca8);
    if (_DAT_18041eca8 == -1) {
      _DAT_18041ec58 = QueryPerformanceFrequency((LARGE_INTEGER *)&DAT_18041ecb0);
      FUN_18000ea80(&DAT_18041eca8);
    }
  }
  if (_DAT_18041ec58 == 0) {
    UVar1 = GetTickCount64();
    if ((longlong)UVar1 < 0) {
      dVar2 = (double)(UVar1 >> 1 | (ulonglong)((uint)UVar1 & 1));
      dVar2 = dVar2 + dVar2;
    }
    else {
      dVar2 = (double)UVar1;
    }
  }
  else {
    QueryPerformanceCounter(&local_18);
    dVar2 = ((double)local_18 * 1000.0) / (double)_DAT_18041ecb0;
  }
  FUN_18000e8c0(dVar2,local_10 ^ (ulonglong)auStack56);
  return;
}



undefined8 *
FUN_180018e98(undefined8 *param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined8 *puVar3;
  
  puVar3 = (undefined8 *)operator_new(0x18);
  uVar1 = *param_4;
  uVar2 = *param_3;
  *(undefined4 *)(puVar3 + 1) = *param_2;
  *(undefined4 *)((longlong)puVar3 + 0xc) = uVar1;
  *(undefined4 *)(puVar3 + 2) = uVar2;
  *puVar3 = ViewMatrixHook::Configured::vftable;
  *param_1 = puVar3;
  return param_1;
}



undefined (**) [16] FUN_180018f10(undefined (**param_1) [16])

{
  undefined (*pauVar1) [16];
  HMODULE pHVar2;
  
  pauVar1 = (undefined (*) [16])operator_new(0x10);
  *pauVar1 = ZEXT816(0);
  *(undefined8 *)(*pauVar1 + 8) = 0;
  *(undefined ***)*pauVar1 = ViewMatrixHook::RDR2::vftable;
  pHVar2 = GetModuleHandleW(L"RDR2.exe");
  *(HMODULE *)(*pauVar1 + 8) = pHVar2 + 0xfa01b8;
  *param_1 = pauVar1;
  return param_1;
}



void FUN_180018f74(uint param_1,int param_2)

{
  ulonglong uVar1;
  float fVar2;
  undefined auVar3 [16];
  
  uVar1 = (ulonglong)param_1;
  if (0 < (int)param_1) {
    auVar3 = ZEXT416((uint)(float)param_2);
    do {
      fVar2 = floorf((float)(int)uVar1 / SUB164(auVar3,0));
      uVar1 = (ulonglong)fVar2;
    } while (0 < (int)uVar1);
  }
  return;
}



undefined8 ffxFsr2ContextDestroy(longlong param_1)

{
  undefined8 uVar1;
  
                    // 0x18ff8  30  ffxFsr2ContextDestroy
  if (param_1 == 0) {
    return 0x80000000;
  }
  uVar1 = FUN_180003b00();
  return uVar1;
}



undefined8 ffxFsr2ContextDispatch(longlong param_1,longlong param_2)

{
  undefined8 uVar1;
  
                    // 0x19008  31  ffxFsr2ContextDispatch
  if ((param_1 == 0) || (param_2 == 0)) {
    uVar1 = 0x80000000;
  }
  else if ((*(uint *)(param_2 + 0x520) < *(uint *)(param_1 + 4) ||
            *(uint *)(param_2 + 0x520) == *(uint *)(param_1 + 4)) &&
          (*(uint *)(param_2 + 0x524) < *(uint *)(param_1 + 8) ||
           *(uint *)(param_2 + 0x524) == *(uint *)(param_1 + 8))) {
    if (*(longlong *)(param_1 + 0x120) != 0) {
      uVar1 = FUN_18000aec0();
      return uVar1;
    }
    uVar1 = 0x8000000c;
  }
  else {
    uVar1 = 0x8000000b;
  }
  return uVar1;
}



// WARNING: Function: __chkstk replaced with injection: alloca_probe

void ffxFsr2ContextGenerateReactiveMask(longlong param_1,longlong *param_2)

{
  longlong lVar1;
  longlong lVar2;
  undefined auStack15248 [32];
  undefined4 local_3b70 [2];
  undefined local_3b68 [7568];
  undefined local_1dd8 [3568];
  uint local_fe8;
  uint local_fe4;
  undefined4 local_fe0;
  undefined local_fdc [4];
  undefined local_fd8 [60];
  wchar_t local_f9c [64];
  wchar_t local_f1c [960];
  undefined local_79c [64];
  wchar_t local_75c [512];
  undefined4 local_35c;
  undefined4 local_358;
  undefined4 local_354;
  undefined4 local_350;
  undefined4 local_34c;
  wchar_t local_154 [134];
  ulonglong local_48;
  undefined8 uStack64;
  
                    // 0x1904c  32  ffxFsr2ContextGenerateReactiveMask
  uStack64 = 0x18001906e;
  local_48 = DAT_180418010 ^ (ulonglong)auStack15248;
  if ((((param_1 != 0) && (param_2 != (longlong *)0x0)) && (*param_2 != 0)) &&
     (*(longlong *)(param_1 + 0x120) != 0)) {
    if (*(char *)(param_1 + 0x8001) != '\0') {
      FUN_180004050();
      *(undefined *)(param_1 + 0x8001) = 0;
    }
    lVar2 = *param_2;
    local_fe8 = *(int *)(param_2 + 0x46) + 7U >> 3;
    local_fe4 = *(int *)((longlong)param_2 + 0x234) + 7U >> 3;
    memset(local_1dd8,0,0x1d88);
    lVar1 = param_1 + 0x18;
    (**(code **)(param_1 + 0x38))(lVar1,param_2 + 1,local_fdc);
    (**(code **)(param_1 + 0x38))(lVar1,param_2 + 0x18,local_fd8);
    (**(code **)(param_1 + 0x38))(lVar1,param_2 + 0x2f,local_79c);
    wcscpy_s(local_f9c,0x40,(wchar_t *)(param_1 + 0x751c));
    wcscpy_s(local_f1c,0x40,(wchar_t *)(param_1 + 0x75a4));
    wcscpy_s(local_75c,0x40,(wchar_t *)(param_1 + 0x70dc));
    local_fe0 = 1;
    memcpy(local_1dd8,(void *)(param_1 + 0x70b8),0xdf0);
    local_358 = *(undefined4 *)(param_2 + 0x47);
    local_354 = *(undefined4 *)((longlong)param_2 + 0x23c);
    local_34c = *(undefined4 *)((longlong)param_2 + 0x244);
    local_350 = *(undefined4 *)(param_2 + 0x48);
    local_35c = 0x10;
    wcscpy_s(local_154,0x40,(wchar_t *)(param_1 + 0x7d9c));
    local_3b70[0] = 2;
    memcpy(local_3b68,local_1dd8,0x1d88);
    (**(code **)(param_1 + 0x68))(lVar1,local_3b70);
    (**(code **)(param_1 + 0x70))(lVar1,lVar2);
  }
  FUN_18000e8c0(local_48 ^ (ulonglong)auStack15248);
  return;
}



undefined8 ffxFsr2GetJitterOffset(float *param_1,float *param_2,int param_3,int param_4)

{
  undefined8 uVar1;
  int iVar2;
  float fVar3;
  
                    // 0x1928c  35  ffxFsr2GetJitterOffset
  if ((param_1 == (float *)0x0) || (param_2 == (float *)0x0)) {
    uVar1 = 0x80000000;
  }
  else if (param_4 < 1) {
    uVar1 = 0x8000000a;
  }
  else {
    iVar2 = param_3 % param_4 + 1;
    fVar3 = (float)FUN_180018f74(iVar2,2);
    *param_1 = fVar3 - 0.5;
    fVar3 = (float)FUN_180018f74(iVar2,3);
    uVar1 = 0;
    *param_2 = fVar3 - 0.5;
  }
  return uVar1;
}



int ffxFsr2GetJitterPhaseCount(int param_1,int param_2)

{
  float fVar1;
  
                    // 0x1930c  36  ffxFsr2GetJitterPhaseCount
  fVar1 = powf((float)param_2 / (float)param_1,2.0);
  return (int)(fVar1 * 8.0);
}



bool ffxFsr2ResourceIsNull(longlong *param_1)

{
                    // 0x19340  41  ffxFsr2ResourceIsNull
  return *param_1 == 0;
}



ulonglong FUN_180019348(undefined8 param_1,undefined8 param_2,longlong param_3,longlong param_4,
                       ulonglong param_5)

{
  int iVar1;
  longlong lVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  longlong local_res18;
  longlong local_28 [2];
  
  lVar2 = param_3;
  uVar3 = param_5;
  while( true ) {
    if ((uVar3 == 0) || (lVar2 == param_4)) goto LAB_1800193f7;
    iVar1 = FUN_18000cf20(param_1,param_2,lVar2,param_4,local_28,&param_5,(longlong)&param_5 + 2,
                          &local_res18);
    if (iVar1 != 0) break;
    lVar2 = local_28[0];
    if (local_res18 == (longlong)&param_5 + 2) {
      uVar3 = uVar3 - 1;
    }
  }
  if (iVar1 == 3) {
    uVar4 = param_4 - lVar2;
    if (uVar3 < (ulonglong)(param_4 - lVar2)) {
      uVar4 = uVar3;
    }
    lVar2 = lVar2 + uVar4;
  }
LAB_1800193f7:
  uVar3 = lVar2 - param_3 & 0xffffffff;
  if (0x7fffffff < lVar2 - param_3) {
    uVar3 = 0x7fffffff;
  }
  return uVar3;
}



undefined8 * FUN_180019424(undefined8 *param_1)

{
  FUN_180014f4c();
  *param_1 = std::range_error::vftable;
  return param_1;
}



void * FUN_180019460(void *param_1,ulonglong param_2)

{
  FUN_18000d20c();
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined8 * FUN_180019494(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = std::exception::vftable;
  __std_exception_destroy(param_1 + 1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_1800194d8(void)

{
  undefined auStack88 [32];
  undefined **local_38;
  undefined local_30 [16];
  char *local_20;
  undefined local_18;
  ulonglong local_10;
  
  local_10 = DAT_180418010 ^ (ulonglong)auStack88;
  local_38 = std::exception::vftable;
  local_20 = "bad conversion";
  local_18 = 1;
  local_30 = ZEXT816(0);
  __std_exception_copy(&local_20,local_30);
  local_38 = std::range_error::vftable;
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_38,(ThrowInfo *)&DAT_180416308);
}



ulonglong thunk_FUN_180019348(undefined8 param_1,undefined8 param_2,longlong param_3,
                             longlong param_4,ulonglong param_5)

{
  int iVar1;
  longlong lVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  longlong lStackX24;
  longlong alStack40 [2];
  
  lVar2 = param_3;
  uVar3 = param_5;
  while( true ) {
    if ((uVar3 == 0) || (lVar2 == param_4)) goto LAB_1800193f7;
    iVar1 = FUN_18000cf20(param_1,param_2,lVar2,param_4,alStack40,&param_5,(longlong)&param_5 + 2,
                          &lStackX24);
    if (iVar1 != 0) break;
    lVar2 = alStack40[0];
    if (lStackX24 == (longlong)&param_5 + 2) {
      uVar3 = uVar3 - 1;
    }
  }
  if (iVar1 == 3) {
    uVar4 = param_4 - lVar2;
    if (uVar3 < (ulonglong)(param_4 - lVar2)) {
      uVar4 = uVar3;
    }
    lVar2 = lVar2 + uVar4;
  }
LAB_1800193f7:
  uVar3 = lVar2 - param_3 & 0xffffffff;
  if (0x7fffffff < lVar2 - param_3) {
    uVar3 = 0x7fffffff;
  }
  return uVar3;
}



bool FUN_180019548(undefined8 param_1,ushort *param_2,ushort *param_3,ushort *param_4,
                  ushort **param_5,byte *param_6,byte *param_7,byte **param_8)

{
  ushort *puVar1;
  bool bVar2;
  int iVar3;
  ushort uVar4;
  uint uVar5;
  byte bVar6;
  byte *pbVar7;
  uint uVar8;
  uint uVar9;
  
  *param_5 = param_3;
  *param_8 = param_6;
  puVar1 = *param_5;
  while ((puVar1 != param_4 && (uVar8 = 1, *param_8 != param_7))) {
    bVar2 = false;
    uVar4 = *puVar1;
    uVar5 = (uint)uVar4;
    if (*param_2 < 2) {
      if ((ushort)(uVar4 + 0x2800) < 0x400) {
        bVar2 = true;
        uVar5 = uVar5 * 0x400 + 0xfca10000;
      }
    }
    else {
      if (0x3ff < (ushort)(uVar4 + 0x2400)) {
        return (bool)2;
      }
      uVar5 = (uint)*param_2 << 10 | uVar4 - 0xdc00;
    }
    if (uVar5 < 0x80) {
      bVar6 = (byte)uVar5;
      uVar8 = 0;
LAB_18001962f:
      uVar9 = uVar8 + 1;
    }
    else {
      if (uVar5 < 0x800) {
        bVar6 = (byte)(uVar5 >> 6) | 0xc0;
        goto LAB_18001962f;
      }
      if (uVar5 < 0x10000) {
        uVar8 = 2;
        bVar6 = (byte)(uVar5 >> 0xc) | 0xe0;
        goto LAB_18001962f;
      }
      uVar8 = 3;
      bVar6 = (byte)(uVar5 >> 0x12) | 0xf0;
      uVar9 = 1;
      if (!bVar2) {
        uVar9 = 3;
      }
    }
    if ((longlong)param_7 - (longlong)*param_8 < (longlong)(ulonglong)uVar9) break;
    *param_5 = puVar1 + 1;
    if ((bVar2) || (uVar8 < 3)) {
      **param_8 = bVar6;
      *param_8 = *param_8 + 1;
      uVar9 = uVar9 - 1;
    }
    pbVar7 = *param_8;
    if (0 < (int)uVar9) {
      iVar3 = uVar8 * 6;
      do {
        iVar3 = iVar3 + -6;
        uVar9 = uVar9 - 1;
        *pbVar7 = (byte)(uVar5 >> ((byte)iVar3 & 0x1f)) & 0x3f | 0x80;
        *param_8 = *param_8 + 1;
        pbVar7 = *param_8;
      } while (0 < (int)uVar9);
    }
    if (bVar2) {
      uVar4 = (ushort)(uVar5 >> 10);
    }
    else {
      uVar4 = 1;
    }
    *param_2 = uVar4;
    puVar1 = *param_5;
  }
  return param_3 == *param_5;
}



undefined4 FUN_180019700(int param_1)

{
  undefined4 uVar1;
  
  if (param_1 < 0x23) {
    if (param_1 == 0x22) {
      return 9;
    }
    if (param_1 == 1) {
      return 1;
    }
    if (param_1 == 2) {
      return 2;
    }
    uVar1 = 8;
    if (param_1 == 10) {
      return 3;
    }
    if (param_1 == 0x10) {
      return 4;
    }
    if (param_1 != 0x1a) {
      if (param_1 == 0x1b) {
        return 6;
      }
      if (param_1 != 0x1c) {
        return 0;
      }
      return 7;
    }
  }
  else if (param_1 == 0x24) {
    uVar1 = 10;
  }
  else {
    if (param_1 == 0x2a) {
      return 5;
    }
    uVar1 = 0xc;
    if (param_1 == 0x36) {
      return 0xb;
    }
    if (param_1 == 0x38) {
      return 0xd;
    }
    if (param_1 != 0x39) {
      if (param_1 == 0x3a) {
        return 0xe;
      }
      if (param_1 != 0x3d) {
        return 0;
      }
      return 0xf;
    }
  }
  return uVar1;
}



undefined8 ffxGetDX12ResourcePtr(longlong param_1,ulonglong param_2)

{
                    // 0x197a4  45  ffxGetDX12ResourcePtr
  return *(undefined8 *)
          (((longlong)*(int *)(param_1 + 0x7f54 + (param_2 & 0xffffffff) * 4) + 0x10e5) * 0x38 +
          *(longlong *)(param_1 + 0x78));
}



void ffxGetResourceDX12(longlong **param_1,undefined8 param_2,longlong *param_3,undefined8 param_4,
                       undefined4 param_5,uint param_6)

{
  int iVar1;
  undefined4 uVar2;
  longlong lVar3;
  longlong lVar4;
  int *piVar5;
  undefined auStack104 [32];
  undefined local_48 [56];
  ulonglong local_10;
  
                    // 0x197c4  48  ffxGetResourceDX12
  local_10 = DAT_180418010 ^ (ulonglong)auStack104;
  memset(param_1,0,0xb8);
  *(undefined4 *)((longlong)param_1 + 0xa4) = param_5;
  param_1[0x16] = (longlong *)(ulonglong)param_6;
  *param_1 = param_3;
  if (param_3 != (longlong *)0x0) {
    lVar4 = *param_3;
    *(undefined4 *)(param_1 + 0x14) = 0;
    lVar3 = (**(code **)(lVar4 + 0x50))(param_3,local_48);
    lVar4 = *param_3;
    *(undefined4 *)(param_1 + 0x12) = *(undefined4 *)(lVar3 + 0x10);
    lVar3 = (**(code **)(lVar4 + 0x50))(param_3,local_48);
    lVar4 = *param_3;
    *(undefined4 *)((longlong)param_1 + 0x94) = *(undefined4 *)(lVar3 + 0x18);
    lVar3 = (**(code **)(lVar4 + 0x50))(param_3,local_48);
    lVar4 = *param_3;
    *(uint *)(param_1 + 0x13) = (uint)*(ushort *)(lVar3 + 0x1c);
    lVar3 = (**(code **)(lVar4 + 0x50))(param_3);
    lVar4 = *param_3;
    *(uint *)((longlong)param_1 + 0x9c) = (uint)*(ushort *)(lVar3 + 0x1e);
    lVar4 = (**(code **)(lVar4 + 0x50))(param_3,local_48);
    uVar2 = FUN_180019700(*(undefined4 *)(lVar4 + 0x20));
    *(undefined4 *)((longlong)param_1 + 0x8c) = uVar2;
    piVar5 = (int *)(**(code **)(*param_3 + 0x50))(param_3);
    iVar1 = *piVar5;
    if (iVar1 == 1) {
      *(undefined4 *)(param_1 + 0x11) = 0;
    }
    else if (iVar1 == 2) {
      *(undefined4 *)(param_1 + 0x11) = 1;
    }
    else if (iVar1 == 3) {
      *(undefined4 *)(param_1 + 0x11) = 2;
    }
    else if (iVar1 == 4) {
      *(undefined4 *)(param_1 + 0x11) = 3;
    }
  }
  FUN_18000e8c0(local_10 ^ (ulonglong)auStack104);
  return;
}



undefined8 FUN_18001ab70(longlong param_1,int param_2)

{
  longlong lVar1;
  longlong *plVar2;
  uint uVar3;
  ulonglong uVar4;
  
  lVar1 = *(longlong *)(param_1 + 0x60);
  if (param_2 != -1) {
    plVar2 = (longlong *)((longlong)param_2 * 0x158 + 0x3b360 + lVar1);
    if (*(int *)((longlong)plVar2 + 0x24) == 0) {
      if (plVar2[2] != 0) {
        (**(code **)(lVar1 + 0x88))(*(undefined8 *)(lVar1 + 8),plVar2[2],0);
        plVar2[2] = 0;
      }
    }
    else {
      if (plVar2[9] != 0) {
        (**(code **)(lVar1 + 0x80))(*(undefined8 *)(lVar1 + 8),plVar2[9],0);
        plVar2[9] = 0;
      }
      uVar4 = 0;
      if (*(int *)(plVar2 + 7) != 0) {
        do {
          if (plVar2[uVar4 + 10] != 0) {
            (**(code **)(lVar1 + 0x80))(*(undefined8 *)(lVar1 + 8),plVar2[uVar4 + 10],0);
            plVar2[uVar4 + 10] = 0;
          }
          uVar3 = (int)uVar4 + 1;
          uVar4 = (ulonglong)uVar3;
        } while (uVar3 < *(uint *)(plVar2 + 7));
      }
      if (*plVar2 != 0) {
        (**(code **)(lVar1 + 0x78))(*(undefined8 *)(lVar1 + 8),*plVar2,0);
        *plVar2 = 0;
      }
    }
    if (plVar2[3] != 0) {
      (**(code **)(lVar1 + 0xd0))(*(undefined8 *)(lVar1 + 8),plVar2[3],0);
      plVar2[3] = 0;
    }
  }
  return 0;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_18001acf8(longlong param_1,undefined4 *param_2)

{
  longlong lVar1;
  undefined8 *puVar2;
  int iVar3;
  uint uVar4;
  longlong lVar5;
  undefined auStack1512 [32];
  undefined local_5c8 [16];
  undefined8 local_5b8;
  undefined local_5b0 [16];
  undefined local_5a0 [16];
  undefined local_590 [16];
  undefined local_580 [16];
  undefined8 local_570;
  undefined4 local_568 [2];
  undefined *local_560;
  undefined4 local_478 [2];
  undefined *local_470;
  undefined4 local_388 [2];
  undefined *local_380;
  ulonglong local_38;
  
  local_38 = DAT_180418010 ^ (ulonglong)auStack1512;
  lVar1 = *(longlong *)(param_1 + 0x60);
  *param_2 = 0;
  uVar4 = 0;
  *(undefined2 *)(param_2 + 3) = 0;
  param_2[1] = 0x20;
  param_2[2] = 0x20;
  puVar2 = *(undefined8 **)(param_1 + 0x60);
  if (*(int *)(lVar1 + 0x41cd0) != 0) {
    do {
      lVar5 = (ulonglong)uVar4 * 0x104;
      iVar3 = strcmp((char *)(*(longlong *)(lVar1 + 0x41cd8) + lVar5),"VK_EXT_subgroup_size_control"
                    );
      if (iVar3 == 0) {
        local_5b0 = CONCAT124(SUB1612(ZEXT816(0) >> 0x20,0),0x3b9e38e8);
        local_5a0 = ZEXT816(0);
        memset(local_388,0,0x348);
        local_380 = local_5b0;
        local_388[0] = 0x3b9bb079;
        vkGetPhysicalDeviceProperties2(*puVar2,local_388);
        param_2[1] = local_5a0._0_4_;
        param_2[2] = local_5a0._4_4_;
      }
      iVar3 = strcmp((char *)(*(longlong *)(lVar1 + 0x41cd8) + lVar5),"VK_KHR_shader_float16_int8");
      if (iVar3 == 0) {
        local_5c8 = CONCAT124(SUB1612(ZEXT816(0) >> 0x20,0),0x3b9c0a50);
        local_5b8 = 0;
        memset(local_568,0,0xf0);
        local_560 = local_5c8;
        local_568[0] = 0x3b9bb078;
        vkGetPhysicalDeviceFeatures2(*puVar2,local_568);
        *(bool *)(param_2 + 3) = (int)local_5b8 != 0;
      }
      iVar3 = strcmp((char *)(*(longlong *)(lVar1 + 0x41cd8) + lVar5),
                     "VK_KHR_acceleration_structure");
      if (iVar3 == 0) {
        local_590 = CONCAT124(SUB1612(ZEXT816(0) >> 0x20,0),0x3b9d13fd);
        local_580 = ZEXT816(0);
        local_570 = 0;
        memset(local_478,0,0xf0);
        local_470 = local_590;
        local_478[0] = 0x3b9bb078;
        vkGetPhysicalDeviceFeatures2(*puVar2,local_478);
        *(bool *)((longlong)param_2 + 0xd) = local_580._0_4_ != 0;
      }
      uVar4 = uVar4 + 1;
    } while (uVar4 < *(uint *)(lVar1 + 0x41cd0));
  }
  FUN_18000e8c0(local_38 ^ (ulonglong)auStack1512);
  return;
}



undefined8 * FUN_18001b0e0(undefined8 *param_1,longlong param_2,ulonglong param_3,void *param_4)

{
  uint uVar1;
  undefined4 local_38;
  undefined8 local_34;
  undefined4 local_2c;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
  local_18 = param_3 & 0xffffffff;
  uVar1 = *(uint *)(param_2 + 0x414b8);
  param_1[1] = 0;
  param_1[2] = local_18;
  *param_1 = *(undefined8 *)(param_2 + 0x40bb8 + (ulonglong)uVar1 * 0x10);
  if (param_4 != (void *)0x0) {
    memcpy(*(void **)(param_2 + 0x40bc0 + (ulonglong)uVar1 * 0x10),param_4,local_18);
    if ((*(byte *)(param_2 + 0x40bb0) & 4) == 0) {
      local_28 = *(undefined8 *)(param_2 + 0x40ba8);
      local_34 = 0;
      local_2c = 0;
      local_20 = (ulonglong)(uint)(*(int *)(param_2 + 0x414b8) << 8);
      local_38 = 6;
      (**(code **)(param_2 + 0x100))(*(undefined8 *)(param_2 + 8),1,&local_38);
    }
  }
  *(int *)(param_2 + 0x414b8) = *(int *)(param_2 + 0x414b8) + 1;
  *(uint *)(param_2 + 0x414b8) =
       *(uint *)(param_2 + 0x414b8) & -(uint)(*(uint *)(param_2 + 0x414b8) < 0x90);
  return param_1;
}



void FUN_18001b1a8(longlong param_1,int *param_2,ulonglong param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  uint uVar4;
  undefined4 uVar5;
  ulonglong uVar6;
  uint uVar7;
  longlong lVar8;
  undefined8 uVar9;
  longlong lVar10;
  int iVar11;
  int iVar12;
  
  param_3 = param_3 & 0xffffffff;
  lVar10 = (longlong)*param_2 * 0x158;
  uVar2 = FUN_18001c130();
  iVar11 = (int)param_3;
  if (*(int *)(lVar10 + 0x3b384 + param_1) == 0) {
    uVar9 = *(undefined8 *)(lVar10 + 0x3b370 + param_1);
    lVar8 = (ulonglong)*(uint *)(param_1 + 0x41cc4) * 0x38;
    *(undefined4 *)(lVar8 + 0x41940 + param_1) = 0x2c;
    *(undefined8 *)(lVar8 + 0x41948 + param_1) = 0;
    uVar3 = FUN_18001c130();
    *(undefined8 *)(lVar8 + 0x41970 + param_1) = 0xffffffffffffffff;
    *(undefined4 *)(lVar8 + 0x41954 + param_1) = uVar2;
    *(undefined8 *)(lVar8 + 0x41960 + param_1) = uVar9;
    *(undefined4 *)(lVar8 + 0x41950 + param_1) = uVar3;
    *(undefined8 *)(lVar8 + 0x41958 + param_1) = 0;
    *(undefined8 *)(lVar8 + 0x41968 + param_1) = 0;
    uVar7 = 0x800;
    iVar12 = *(int *)(lVar10 + 0x3b3a0 + param_1);
    if (((iVar12 == 1) || (iVar12 == 2)) || ((iVar12 != 4 && ((iVar12 == 6 || (iVar12 != 8)))))) {
      uVar4 = 0x800;
    }
    else {
      uVar4 = 0x1000;
    }
    *(uint *)(param_1 + 0x41cc8) = *(uint *)(param_1 + 0x41cc8) | uVar4;
    if (((iVar11 != 1) && (iVar11 != 2)) && ((iVar11 == 4 || ((iVar11 != 6 && (iVar11 == 8)))))) {
      uVar7 = 0x1000;
    }
    *(uint *)(param_1 + 0x41ccc) = *(uint *)(param_1 + 0x41ccc) | uVar7;
    *(int *)(lVar10 + 0x3b3a0 + param_1) = iVar11;
    *(int *)(param_1 + 0x41cc4) = *(int *)(param_1 + 0x41cc4) + 1;
  }
  else {
    uVar6 = (ulonglong)*(uint *)(param_1 + 0x41cc0);
    uVar9 = *(undefined8 *)(lVar10 + 0x3b360 + param_1);
    uVar3 = *(undefined4 *)(lVar10 + 0x3b368 + param_1);
    uVar1 = *(undefined4 *)(lVar10 + 0x3b398 + param_1);
    lVar8 = uVar6 * 9;
    *(undefined4 *)(param_1 + 0x414c0 + uVar6 * 0x48) = 0x2d;
    *(undefined8 *)(param_1 + 0x414c8 + uVar6 * 0x48) = 0;
    uVar5 = FUN_18001c130(*(undefined4 *)(lVar10 + 0x3b3a0 + param_1));
    *(undefined4 *)(param_1 + 0x414d0 + lVar8 * 8) = uVar5;
    *(undefined4 *)(param_1 + 0x414d4 + lVar8 * 8) = uVar2;
    uVar2 = 0;
    if (*(char *)(lVar10 + 0x3b4b0 + param_1) == '\0') {
      uVar2 = FUN_18001c218(*(undefined4 *)(lVar10 + 0x3b3a0 + param_1));
    }
    iVar12 = (int)param_3;
    *(undefined4 *)(param_1 + 0x414d8 + lVar8 * 8) = uVar2;
    uVar2 = FUN_18001c218(param_3 & 0xffffffff);
    *(undefined8 *)(param_1 + 0x414e8 + lVar8 * 8) = uVar9;
    *(undefined4 *)(param_1 + 0x414dc + lVar8 * 8) = uVar2;
    *(undefined8 *)(param_1 + 0x414e0 + lVar8 * 8) = 0;
    *(undefined4 *)(param_1 + 0x414f0 + lVar8 * 8) = uVar3;
    *(undefined4 *)(param_1 + 0x414f4 + lVar8 * 8) = 0;
    *(undefined4 *)(param_1 + 0x414f8 + lVar8 * 8) = uVar1;
    *(undefined4 *)(param_1 + 0x414fc + lVar8 * 8) = 0;
    *(undefined4 *)(param_1 + 0x41500 + lVar8 * 8) = 1;
    uVar7 = 0x800;
    iVar11 = *(int *)(lVar10 + 0x3b3a0 + param_1);
    if (((iVar11 == 1) || (iVar11 == 2)) || ((iVar11 != 4 && ((iVar11 == 6 || (iVar11 != 8)))))) {
      uVar4 = 0x800;
    }
    else {
      uVar4 = 0x1000;
    }
    *(uint *)(param_1 + 0x41cc8) = *(uint *)(param_1 + 0x41cc8) | uVar4;
    if (((iVar12 != 1) && (iVar12 != 2)) && ((iVar12 == 4 || ((iVar12 != 6 && (iVar12 == 8)))))) {
      uVar7 = 0x1000;
    }
    *(uint *)(param_1 + 0x41ccc) = *(uint *)(param_1 + 0x41ccc) | uVar7;
    *(int *)(lVar10 + 0x3b3a0 + param_1) = iVar12;
    *(int *)(param_1 + 0x41cc0) = *(int *)(param_1 + 0x41cc0) + 1;
  }
  if (*(char *)(lVar10 + 0x3b4b0 + param_1) != '\0') {
    *(undefined *)(lVar10 + 0x3b4b0 + param_1) = 0;
  }
  return;
}



void FUN_18001b424(longlong param_1,longlong param_2,undefined8 param_3)

{
  undefined8 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 *puVar13;
  undefined8 *puVar14;
  undefined4 *puVar15;
  undefined8 *puVar16;
  longlong lVar17;
  undefined auStack472 [32];
  undefined4 local_1b8;
  undefined4 *local_1b0;
  undefined8 local_1a8 [4];
  int iStack388;
  undefined4 uStack368;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_30;
  undefined4 uStack44;
  undefined4 uStack40;
  undefined4 uStack36;
  ulonglong local_20;
  
  local_20 = DAT_180418010 ^ (ulonglong)auStack472;
  lVar17 = 2;
  puVar13 = (undefined4 *)(param_1 + 0x3b360 + (ulonglong)*(uint *)(param_2 + 0x18) * 0x158);
  puVar14 = local_1a8;
  do {
    puVar16 = puVar14;
    puVar15 = puVar13;
    uVar2 = puVar15[1];
    uVar3 = puVar15[2];
    uVar4 = puVar15[3];
    uVar5 = puVar15[4];
    uVar6 = puVar15[5];
    uVar7 = puVar15[6];
    uVar8 = puVar15[7];
    *(undefined4 *)puVar16 = *puVar15;
    *(undefined4 *)((longlong)puVar16 + 4) = uVar2;
    *(undefined4 *)(puVar16 + 1) = uVar3;
    *(undefined4 *)((longlong)puVar16 + 0xc) = uVar4;
    uVar2 = puVar15[8];
    uVar3 = puVar15[9];
    uVar4 = puVar15[10];
    uVar9 = puVar15[0xb];
    *(undefined4 *)(puVar16 + 2) = uVar5;
    *(undefined4 *)((longlong)puVar16 + 0x14) = uVar6;
    *(undefined4 *)(puVar16 + 3) = uVar7;
    *(undefined4 *)((longlong)puVar16 + 0x1c) = uVar8;
    uVar5 = puVar15[0xc];
    uVar6 = puVar15[0xd];
    uVar7 = puVar15[0xe];
    uVar8 = puVar15[0xf];
    *(undefined4 *)(puVar16 + 4) = uVar2;
    *(undefined4 *)((longlong)puVar16 + 0x24) = uVar3;
    *(undefined4 *)(puVar16 + 5) = uVar4;
    *(undefined4 *)((longlong)puVar16 + 0x2c) = uVar9;
    uVar2 = puVar15[0x10];
    uVar3 = puVar15[0x11];
    uVar4 = puVar15[0x12];
    uVar9 = puVar15[0x13];
    *(undefined4 *)(puVar16 + 6) = uVar5;
    *(undefined4 *)((longlong)puVar16 + 0x34) = uVar6;
    *(undefined4 *)(puVar16 + 7) = uVar7;
    *(undefined4 *)((longlong)puVar16 + 0x3c) = uVar8;
    uVar5 = puVar15[0x14];
    uVar6 = puVar15[0x15];
    uVar7 = puVar15[0x16];
    uVar8 = puVar15[0x17];
    *(undefined4 *)(puVar16 + 8) = uVar2;
    *(undefined4 *)((longlong)puVar16 + 0x44) = uVar3;
    *(undefined4 *)(puVar16 + 9) = uVar4;
    *(undefined4 *)((longlong)puVar16 + 0x4c) = uVar9;
    uVar2 = puVar15[0x18];
    uVar3 = puVar15[0x19];
    uVar4 = puVar15[0x1a];
    uVar9 = puVar15[0x1b];
    *(undefined4 *)(puVar16 + 10) = uVar5;
    *(undefined4 *)((longlong)puVar16 + 0x54) = uVar6;
    *(undefined4 *)(puVar16 + 0xb) = uVar7;
    *(undefined4 *)((longlong)puVar16 + 0x5c) = uVar8;
    uVar5 = puVar15[0x1c];
    uVar6 = puVar15[0x1d];
    uVar7 = puVar15[0x1e];
    uVar8 = puVar15[0x1f];
    *(undefined4 *)(puVar16 + 0xc) = uVar2;
    *(undefined4 *)((longlong)puVar16 + 100) = uVar3;
    *(undefined4 *)(puVar16 + 0xd) = uVar4;
    *(undefined4 *)((longlong)puVar16 + 0x6c) = uVar9;
    *(undefined4 *)(puVar16 + 0xe) = uVar5;
    *(undefined4 *)((longlong)puVar16 + 0x74) = uVar6;
    *(undefined4 *)(puVar16 + 0xf) = uVar7;
    *(undefined4 *)((longlong)puVar16 + 0x7c) = uVar8;
    lVar17 = lVar17 + -1;
    puVar13 = puVar15 + 0x20;
    puVar14 = puVar16 + 0x10;
  } while (lVar17 != 0);
  uVar2 = puVar15[0x21];
  uVar3 = puVar15[0x22];
  uVar4 = puVar15[0x23];
  uVar5 = puVar15[0x24];
  uVar6 = puVar15[0x25];
  uVar7 = puVar15[0x26];
  uVar8 = puVar15[0x27];
  *(undefined4 *)(puVar16 + 0x10) = puVar15[0x20];
  *(undefined4 *)((longlong)puVar16 + 0x84) = uVar2;
  *(undefined4 *)(puVar16 + 0x11) = uVar3;
  *(undefined4 *)((longlong)puVar16 + 0x8c) = uVar4;
  uVar9 = puVar15[0x28];
  uVar10 = puVar15[0x29];
  uVar11 = puVar15[0x2a];
  uVar12 = puVar15[0x2b];
  *(undefined4 *)(puVar16 + 0x12) = uVar5;
  *(undefined4 *)((longlong)puVar16 + 0x94) = uVar6;
  *(undefined4 *)(puVar16 + 0x13) = uVar7;
  *(undefined4 *)((longlong)puVar16 + 0x9c) = uVar8;
  uVar2 = puVar15[0x2c];
  uVar3 = puVar15[0x2d];
  uVar4 = puVar15[0x2e];
  uVar5 = puVar15[0x2f];
  *(undefined4 *)(puVar16 + 0x14) = uVar9;
  *(undefined4 *)((longlong)puVar16 + 0xa4) = uVar10;
  *(undefined4 *)(puVar16 + 0x15) = uVar11;
  *(undefined4 *)((longlong)puVar16 + 0xac) = uVar12;
  uVar6 = puVar15[0x30];
  uVar7 = puVar15[0x31];
  uVar8 = puVar15[0x32];
  uVar9 = puVar15[0x33];
  uVar1 = *(undefined8 *)(puVar15 + 0x34);
  *(undefined4 *)(puVar16 + 0x16) = uVar2;
  *(undefined4 *)((longlong)puVar16 + 0xb4) = uVar3;
  *(undefined4 *)(puVar16 + 0x17) = uVar4;
  *(undefined4 *)((longlong)puVar16 + 0xbc) = uVar5;
  *(undefined4 *)(puVar16 + 0x18) = uVar6;
  *(undefined4 *)((longlong)puVar16 + 0xc4) = uVar7;
  *(undefined4 *)(puVar16 + 0x19) = uVar8;
  *(undefined4 *)((longlong)puVar16 + 0xcc) = uVar9;
  puVar16[0x1a] = uVar1;
  if (iStack388 != 0) {
    FUN_18001b1a8(param_1,(uint *)(param_2 + 0x18),8);
    FUN_18001c09c(param_1,param_3);
    local_30 = *(undefined4 *)(param_2 + 8);
    uStack44 = *(undefined4 *)(param_2 + 0xc);
    uStack40 = *(undefined4 *)(param_2 + 0x10);
    uStack36 = *(undefined4 *)(param_2 + 0x14);
    local_44 = 0;
    local_3c = 0;
    local_40 = uStack368;
    local_1b0 = &local_48;
    local_1b8 = 1;
    local_48 = 1;
    local_38 = 1;
    (**(code **)(param_1 + 0x140))(param_3,local_1a8[0],7,&local_30);
  }
  FUN_18000e8c0(local_20 ^ (ulonglong)auStack472);
  return;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_18001b5a0(longlong param_1,longlong param_2,undefined8 param_3)

{
  undefined4 uVar1;
  longlong lVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 *puVar12;
  undefined4 *puVar13;
  ulonglong uVar14;
  undefined4 *puVar15;
  undefined4 *puVar16;
  longlong lVar17;
  ulonglong uVar18;
  uint uVar19;
  uint uVar20;
  ulonglong uVar21;
  ulonglong uVar22;
  uint uVar23;
  undefined auStack3784 [32];
  undefined8 local_ea8;
  undefined8 *local_ea0;
  undefined4 local_e98;
  undefined8 local_e90;
  uint local_e88;
  undefined8 local_e80;
  undefined4 local_e78;
  undefined4 uStack3700;
  undefined4 uStack3696;
  undefined4 uStack3692;
  undefined4 local_e68;
  undefined4 uStack3684;
  undefined4 uStack3680;
  undefined4 uStack3676;
  undefined4 local_e58;
  undefined4 uStack3668;
  undefined4 uStack3664;
  undefined4 uStack3660;
  undefined4 local_e48;
  undefined4 uStack3652;
  undefined4 uStack3648;
  undefined4 uStack3644;
  undefined local_e38 [16];
  undefined8 local_e28;
  undefined8 local_e20;
  undefined8 local_e18;
  undefined4 local_e08 [18];
  undefined8 uStack3520;
  undefined8 local_db8 [34];
  undefined4 local_ca8 [4];
  undefined8 uStack3224;
  undefined4 auStack3216 [4];
  undefined8 uStack3200;
  longlong lStack3192;
  undefined4 auStack3184 [562];
  undefined4 local_3a8 [4];
  undefined8 local_398 [10];
  undefined local_348 [8];
  undefined8 auStack832 [95];
  ulonglong local_48;
  
  local_48 = DAT_180418010 ^ (ulonglong)auStack3784;
  lVar2 = *(longlong *)(param_2 + 8);
  uVar18 = 0;
  local_e88 = 0;
  uVar22 = uVar18;
  uVar21 = uVar18;
  uVar14 = uVar18;
  uVar23 = local_e88;
  local_e80 = param_3;
  if (*(int *)(param_2 + 0x18) != 0) {
    do {
      FUN_18001b1a8(param_1,param_2 + 0x1644 + uVar18 * 4);
      lVar17 = 2;
      puVar15 = (undefined4 *)
                ((longlong)*(int *)(param_2 + 0x1644 + uVar18 * 4) * 0x158 + 0x3b360 + param_1);
      puVar12 = local_e08;
      do {
        puVar16 = puVar12;
        puVar13 = puVar15;
        uVar1 = puVar13[1];
        uVar5 = puVar13[2];
        uVar6 = puVar13[3];
        uVar7 = puVar13[4];
        uVar8 = puVar13[5];
        uVar9 = puVar13[6];
        uVar10 = puVar13[7];
        *puVar16 = *puVar13;
        puVar16[1] = uVar1;
        puVar16[2] = uVar5;
        puVar16[3] = uVar6;
        uVar1 = puVar13[8];
        uVar5 = puVar13[9];
        uVar6 = puVar13[10];
        uVar11 = puVar13[0xb];
        puVar16[4] = uVar7;
        puVar16[5] = uVar8;
        puVar16[6] = uVar9;
        puVar16[7] = uVar10;
        uVar7 = puVar13[0xc];
        uVar8 = puVar13[0xd];
        uVar9 = puVar13[0xe];
        uVar10 = puVar13[0xf];
        puVar16[8] = uVar1;
        puVar16[9] = uVar5;
        puVar16[10] = uVar6;
        puVar16[0xb] = uVar11;
        uVar1 = puVar13[0x10];
        uVar5 = puVar13[0x11];
        uVar6 = puVar13[0x12];
        uVar11 = puVar13[0x13];
        puVar16[0xc] = uVar7;
        puVar16[0xd] = uVar8;
        puVar16[0xe] = uVar9;
        puVar16[0xf] = uVar10;
        uVar7 = puVar13[0x14];
        uVar8 = puVar13[0x15];
        uVar9 = puVar13[0x16];
        uVar10 = puVar13[0x17];
        puVar16[0x10] = uVar1;
        puVar16[0x11] = uVar5;
        puVar16[0x12] = uVar6;
        puVar16[0x13] = uVar11;
        uVar1 = puVar13[0x18];
        uVar5 = puVar13[0x19];
        uVar6 = puVar13[0x1a];
        uVar11 = puVar13[0x1b];
        puVar16[0x14] = uVar7;
        puVar16[0x15] = uVar8;
        puVar16[0x16] = uVar9;
        puVar16[0x17] = uVar10;
        uVar7 = puVar13[0x1c];
        uVar8 = puVar13[0x1d];
        uVar9 = puVar13[0x1e];
        uVar10 = puVar13[0x1f];
        puVar16[0x18] = uVar1;
        puVar16[0x19] = uVar5;
        puVar16[0x1a] = uVar6;
        puVar16[0x1b] = uVar11;
        puVar16[0x1c] = uVar7;
        puVar16[0x1d] = uVar8;
        puVar16[0x1e] = uVar9;
        puVar16[0x1f] = uVar10;
        lVar17 = lVar17 + -1;
        puVar15 = puVar13 + 0x20;
        puVar12 = puVar16 + 0x20;
      } while (lVar17 != 0);
      uVar1 = puVar13[0x21];
      uVar5 = puVar13[0x22];
      uVar6 = puVar13[0x23];
      uVar7 = puVar13[0x24];
      uVar8 = puVar13[0x25];
      uVar9 = puVar13[0x26];
      uVar10 = puVar13[0x27];
      puVar16[0x20] = puVar13[0x20];
      puVar16[0x21] = uVar1;
      puVar16[0x22] = uVar5;
      puVar16[0x23] = uVar6;
      uVar1 = puVar13[0x28];
      uVar5 = puVar13[0x29];
      uVar6 = puVar13[0x2a];
      uVar11 = puVar13[0x2b];
      puVar16[0x24] = uVar7;
      puVar16[0x25] = uVar8;
      puVar16[0x26] = uVar9;
      puVar16[0x27] = uVar10;
      uVar7 = puVar13[0x2c];
      uVar8 = puVar13[0x2d];
      uVar9 = puVar13[0x2e];
      uVar10 = puVar13[0x2f];
      puVar16[0x28] = uVar1;
      puVar16[0x29] = uVar5;
      puVar16[0x2a] = uVar6;
      puVar16[0x2b] = uVar11;
      uVar1 = puVar13[0x30];
      uVar5 = puVar13[0x31];
      uVar6 = puVar13[0x32];
      uVar11 = puVar13[0x33];
      uVar3 = *(undefined8 *)(puVar13 + 0x34);
      puVar16[0x2c] = uVar7;
      puVar16[0x2d] = uVar8;
      puVar16[0x2e] = uVar9;
      puVar16[0x2f] = uVar10;
      puVar16[0x30] = uVar1;
      puVar16[0x31] = uVar5;
      puVar16[0x32] = uVar6;
      puVar16[0x33] = uVar11;
      *(undefined8 *)(puVar16 + 0x34) = uVar3;
      memset(&local_e78,0,0x40);
      uVar21 = (ulonglong)((int)uVar22 + 1);
      uVar19 = (int)uVar18 + 1;
      local_ca8[uVar22 * 0x10] = local_e78;
      local_ca8[uVar22 * 0x10 + 1] = uStack3700;
      local_ca8[uVar22 * 0x10 + 2] = uStack3696;
      local_ca8[uVar22 * 0x10 + 3] = uStack3692;
      *(undefined4 *)(&uStack3224 + uVar22 * 8) = local_e68;
      auStack3216[uVar22 * 0x10 + -1] = uStack3684;
      auStack3216[uVar22 * 0x10] = uStack3680;
      auStack3216[uVar22 * 0x10 + 1] = uStack3676;
      auStack3216[uVar22 * 0x10 + 2] = local_e58;
      auStack3216[uVar22 * 0x10 + 3] = uStack3668;
      *(undefined4 *)(&uStack3200 + uVar22 * 8) = uStack3664;
      *(undefined4 *)((longlong)&uStack3200 + uVar22 * 0x40 + 4) = uStack3660;
      *(undefined4 *)(&lStack3192 + uVar22 * 8) = local_e48;
      auStack3184[uVar22 * 0x10 + -1] = uStack3652;
      auStack3184[uVar22 * 0x10] = uStack3648;
      auStack3184[uVar22 * 0x10 + 1] = uStack3644;
      local_ca8[uVar22 * 0x10] = 0x23;
      uVar3 = *(undefined8 *)(lVar2 + 8 + (ulonglong)*(uint *)(lVar2 + 0x28) * 8);
      auStack3216[uVar22 * 0x10 + 1] = 0;
      uVar23 = (int)uVar14 + 1;
      (&uStack3224)[uVar22 * 8] = uVar3;
      auStack3216[uVar22 * 0x10 + 2] = 1;
      auStack3216[uVar22 * 0x10 + 3] = 3;
      *(undefined (*) [16])(local_348 + uVar14 * 0x18) = ZEXT816(0);
      (&uStack3200)[uVar22 * 8] = (undefined (*) [16])(local_348 + uVar14 * 0x18);
      uVar1 = *(undefined4 *)(uVar18 * 0x88 + 0x24 + param_2);
      local_e28 = 0;
      uVar20 = *(uint *)(param_2 + 0x1664 + uVar18 * 4);
      auStack832[uVar14 * 3 + 1] = 0;
      auStack3216[uVar22 * 0x10] = uVar1;
      auStack832[uVar14 * 3] = local_db8[uVar20];
      *(undefined4 *)(auStack832 + uVar14 * 3 + 1) = 1;
      uVar18 = (ulonglong)uVar19;
      uVar22 = uVar21;
      uVar14 = (ulonglong)uVar23;
    } while (uVar19 < *(uint *)(param_2 + 0x18));
  }
  local_e88 = uVar23;
  uVar18 = 0;
  uVar22 = uVar21;
  uVar23 = local_e88;
  if (*(int *)(param_2 + 0x1c) != 0) {
    do {
      FUN_18001b1a8(param_1,param_2 + 0xe04 + uVar18 * 4);
      lVar17 = 2;
      puVar15 = (undefined4 *)
                ((longlong)*(int *)(param_2 + 0xe04 + uVar18 * 4) * 0x158 + 0x3b360 + param_1);
      puVar12 = local_e08;
      do {
        puVar16 = puVar12;
        puVar13 = puVar15;
        uVar1 = puVar13[1];
        uVar5 = puVar13[2];
        uVar6 = puVar13[3];
        uVar7 = puVar13[4];
        uVar8 = puVar13[5];
        uVar9 = puVar13[6];
        uVar10 = puVar13[7];
        *puVar16 = *puVar13;
        puVar16[1] = uVar1;
        puVar16[2] = uVar5;
        puVar16[3] = uVar6;
        uVar1 = puVar13[8];
        uVar5 = puVar13[9];
        uVar6 = puVar13[10];
        uVar11 = puVar13[0xb];
        puVar16[4] = uVar7;
        puVar16[5] = uVar8;
        puVar16[6] = uVar9;
        puVar16[7] = uVar10;
        uVar7 = puVar13[0xc];
        uVar8 = puVar13[0xd];
        uVar9 = puVar13[0xe];
        uVar10 = puVar13[0xf];
        puVar16[8] = uVar1;
        puVar16[9] = uVar5;
        puVar16[10] = uVar6;
        puVar16[0xb] = uVar11;
        uVar1 = puVar13[0x10];
        uVar5 = puVar13[0x11];
        uVar6 = puVar13[0x12];
        uVar11 = puVar13[0x13];
        puVar16[0xc] = uVar7;
        puVar16[0xd] = uVar8;
        puVar16[0xe] = uVar9;
        puVar16[0xf] = uVar10;
        uVar7 = puVar13[0x14];
        uVar8 = puVar13[0x15];
        uVar9 = puVar13[0x16];
        uVar10 = puVar13[0x17];
        puVar16[0x10] = uVar1;
        puVar16[0x11] = uVar5;
        puVar16[0x12] = uVar6;
        puVar16[0x13] = uVar11;
        uVar1 = puVar13[0x18];
        uVar5 = puVar13[0x19];
        uVar6 = puVar13[0x1a];
        uVar11 = puVar13[0x1b];
        puVar16[0x14] = uVar7;
        puVar16[0x15] = uVar8;
        puVar16[0x16] = uVar9;
        puVar16[0x17] = uVar10;
        uVar7 = puVar13[0x1c];
        uVar8 = puVar13[0x1d];
        uVar9 = puVar13[0x1e];
        uVar10 = puVar13[0x1f];
        puVar16[0x18] = uVar1;
        puVar16[0x19] = uVar5;
        puVar16[0x1a] = uVar6;
        puVar16[0x1b] = uVar11;
        puVar16[0x1c] = uVar7;
        puVar16[0x1d] = uVar8;
        puVar16[0x1e] = uVar9;
        puVar16[0x1f] = uVar10;
        lVar17 = lVar17 + -1;
        puVar15 = puVar13 + 0x20;
        puVar12 = puVar16 + 0x20;
      } while (lVar17 != 0);
      uVar1 = puVar13[0x21];
      uVar5 = puVar13[0x22];
      uVar6 = puVar13[0x23];
      uVar7 = puVar13[0x24];
      uVar8 = puVar13[0x25];
      uVar9 = puVar13[0x26];
      uVar10 = puVar13[0x27];
      puVar16[0x20] = puVar13[0x20];
      puVar16[0x21] = uVar1;
      puVar16[0x22] = uVar5;
      puVar16[0x23] = uVar6;
      uVar1 = puVar13[0x28];
      uVar5 = puVar13[0x29];
      uVar6 = puVar13[0x2a];
      uVar11 = puVar13[0x2b];
      puVar16[0x24] = uVar7;
      puVar16[0x25] = uVar8;
      puVar16[0x26] = uVar9;
      puVar16[0x27] = uVar10;
      uVar7 = puVar13[0x2c];
      uVar8 = puVar13[0x2d];
      uVar9 = puVar13[0x2e];
      uVar10 = puVar13[0x2f];
      puVar16[0x28] = uVar1;
      puVar16[0x29] = uVar5;
      puVar16[0x2a] = uVar6;
      puVar16[0x2b] = uVar11;
      uVar1 = puVar13[0x30];
      uVar5 = puVar13[0x31];
      uVar6 = puVar13[0x32];
      uVar11 = puVar13[0x33];
      uVar3 = *(undefined8 *)(puVar13 + 0x34);
      puVar16[0x2c] = uVar7;
      puVar16[0x2d] = uVar8;
      puVar16[0x2e] = uVar9;
      puVar16[0x2f] = uVar10;
      puVar16[0x30] = uVar1;
      puVar16[0x31] = uVar5;
      puVar16[0x32] = uVar6;
      puVar16[0x33] = uVar11;
      *(undefined8 *)(puVar16 + 0x34) = uVar3;
      memset(&local_e78,0,0x40);
      uVar22 = (ulonglong)((int)uVar21 + 1);
      uVar20 = (int)uVar18 + 1;
      local_ca8[uVar21 * 0x10] = local_e78;
      local_ca8[uVar21 * 0x10 + 1] = uStack3700;
      local_ca8[uVar21 * 0x10 + 2] = uStack3696;
      local_ca8[uVar21 * 0x10 + 3] = uStack3692;
      *(undefined4 *)(&uStack3224 + uVar21 * 8) = local_e68;
      auStack3216[uVar21 * 0x10 + -1] = uStack3684;
      auStack3216[uVar21 * 0x10] = uStack3680;
      auStack3216[uVar21 * 0x10 + 1] = uStack3676;
      auStack3216[uVar21 * 0x10 + 2] = local_e58;
      auStack3216[uVar21 * 0x10 + 3] = uStack3668;
      *(undefined4 *)(&uStack3200 + uVar21 * 8) = uStack3664;
      *(undefined4 *)((longlong)&uStack3200 + uVar21 * 0x40 + 4) = uStack3660;
      *(undefined4 *)(&lStack3192 + uVar21 * 8) = local_e48;
      auStack3184[uVar21 * 0x10 + -1] = uStack3652;
      auStack3184[uVar21 * 0x10] = uStack3648;
      auStack3184[uVar21 * 0x10 + 1] = uStack3644;
      local_ca8[uVar21 * 0x10] = 0x23;
      uVar14 = (ulonglong)uVar23;
      (&uStack3224)[uVar21 * 8] =
           *(undefined8 *)(lVar2 + 8 + (ulonglong)*(uint *)(lVar2 + 0x28) * 8);
      auStack3216[uVar21 * 0x10 + 2] = 1;
      auStack3216[uVar21 * 0x10 + 3] = 2;
      *(undefined (*) [16])(local_348 + uVar14 * 0x18) = ZEXT816(0);
      (&uStack3200)[uVar21 * 8] = (undefined (*) [16])(local_348 + uVar14 * 0x18);
      auStack3216[uVar21 * 0x10 + 1] = 0;
      uVar1 = *(undefined4 *)(uVar18 * 0x88 + 0x464 + param_2);
      local_e28 = 0;
      auStack832[uVar14 * 3 + 1] = 0;
      *(undefined4 *)(auStack832 + uVar14 * 3 + 1) = 5;
      auStack832[uVar14 * 3] = uStack3520;
      auStack3216[uVar21 * 0x10] = uVar1;
      uVar18 = (ulonglong)uVar20;
      uVar21 = uVar22;
      uVar23 = uVar23 + 1;
    } while (uVar20 < *(uint *)(param_2 + 0x1c));
  }
  uVar3 = local_e80;
  uVar18 = 0;
  if (*(int *)(param_2 + 0x20) != 0) {
    do {
      memset(&local_e78,0,0x40);
      local_ca8[uVar22 * 0x10] = local_e78;
      local_ca8[uVar22 * 0x10 + 1] = uStack3700;
      local_ca8[uVar22 * 0x10 + 2] = uStack3696;
      local_ca8[uVar22 * 0x10 + 3] = uStack3692;
      *(undefined4 *)(&uStack3224 + uVar22 * 8) = local_e68;
      auStack3216[uVar22 * 0x10 + -1] = uStack3684;
      auStack3216[uVar22 * 0x10] = uStack3680;
      auStack3216[uVar22 * 0x10 + 1] = uStack3676;
      auStack3216[uVar22 * 0x10 + 2] = local_e58;
      auStack3216[uVar22 * 0x10 + 3] = uStack3668;
      *(undefined4 *)(&uStack3200 + uVar22 * 8) = uStack3664;
      *(undefined4 *)((longlong)&uStack3200 + uVar22 * 0x40 + 4) = uStack3660;
      *(undefined4 *)(&lStack3192 + uVar22 * 8) = local_e48;
      auStack3184[uVar22 * 0x10 + -1] = uStack3652;
      auStack3184[uVar22 * 0x10] = uStack3648;
      auStack3184[uVar22 * 0x10 + 1] = uStack3644;
      local_ca8[uVar22 * 0x10] = 0x23;
      uVar4 = *(undefined8 *)(lVar2 + 8 + (ulonglong)*(uint *)(lVar2 + 0x28) * 8);
      auStack3216[uVar22 * 0x10 + 1] = 0;
      (&uStack3224)[uVar22 * 8] = uVar4;
      auStack3216[uVar22 * 0x10 + 2] = 1;
      auStack3216[uVar22 * 0x10 + 3] = 6;
      (&lStack3192)[uVar22 * 8] = (longlong)(local_3a8 + uVar18 * 6);
      auStack3216[uVar22 * 0x10] = *(undefined4 *)(uVar18 * 0x88 + 0xce4 + param_2);
      puVar15 = (undefined4 *)
                FUN_18001b0e0(local_e38,param_1,*(int *)(uVar18 * 0x104 + 0x1a84 + param_2) << 2,
                              param_2 + 0x1a88 + uVar18 * 0x104);
      uVar22 = (ulonglong)((int)uVar22 + 1);
      uVar23 = (int)uVar18 + 1;
      uVar1 = puVar15[1];
      uVar5 = puVar15[2];
      uVar6 = puVar15[3];
      uVar4 = *(undefined8 *)(puVar15 + 4);
      local_3a8[uVar18 * 6] = *puVar15;
      local_3a8[uVar18 * 6 + 1] = uVar1;
      local_3a8[uVar18 * 6 + 2] = uVar5;
      local_3a8[uVar18 * 6 + 3] = uVar6;
      local_398[uVar18 * 3] = uVar4;
      uVar18 = (ulonglong)uVar23;
    } while (uVar23 < *(uint *)(param_2 + 0x20));
  }
  FUN_18001c09c(param_1,uVar3);
  local_ea8 = 0;
  (**(code **)(param_1 + 0xf8))(*(undefined8 *)(param_1 + 8),uVar22,local_ca8,0);
  (**(code **)(param_1 + 0x110))(uVar3,1,*(undefined8 *)(param_2 + 0x10));
  local_e20 = *(undefined8 *)(param_1 + 0x40990);
  local_e90 = 0;
  local_e98 = 0;
  local_e18 = *(undefined8 *)(lVar2 + 8 + (ulonglong)*(uint *)(lVar2 + 0x28) * 8);
  local_ea0 = &local_e20;
  local_ea8 = CONCAT44(local_ea8._4_4_,2);
  (**(code **)(param_1 + 0x118))(uVar3,1,*(undefined8 *)(lVar2 + 0x30),0);
  (**(code **)(param_1 + 0x120))
            (uVar3,*(undefined4 *)(param_2 + 0xdf8),*(undefined4 *)(param_2 + 0xdfc),
             *(undefined4 *)(param_2 + 0xe00));
  *(int *)(lVar2 + 0x28) = *(int *)(lVar2 + 0x28) + 1;
  if (3 < *(uint *)(lVar2 + 0x28)) {
    *(undefined4 *)(lVar2 + 0x28) = 0;
  }
  FUN_18000e8c0(local_48 ^ (ulonglong)auStack3784);
  return;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_18001bb78(longlong param_1,longlong param_2,undefined8 param_3)

{
  undefined8 uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 *puVar14;
  undefined8 *puVar15;
  undefined4 *puVar16;
  longlong lVar17;
  undefined8 *puVar18;
  ulonglong uVar19;
  longlong lVar20;
  uint uVar21;
  undefined auStack2792 [32];
  undefined8 local_ac8;
  undefined8 *local_ac0;
  undefined8 *local_ab8;
  undefined8 local_aa8;
  longlong local_a98;
  uint local_a90;
  uint uStack2700;
  undefined8 local_a78 [2];
  undefined8 local_a68;
  int iStack2644;
  uint uStack2636;
  uint local_a48;
  uint uStack2628;
  uint uStack2624;
  undefined8 local_918;
  undefined8 uStack2320;
  ulonglong local_908;
  undefined8 local_900;
  undefined8 local_8f8;
  undefined8 local_8f0;
  undefined4 local_8e8;
  undefined8 local_8e4;
  undefined8 local_8dc;
  undefined4 local_8d4;
  undefined4 local_8d0;
  undefined4 local_8cc;
  undefined8 local_8c8;
  int aiStack2240 [2];
  undefined8 local_8b8;
  undefined8 uStack2224;
  int local_8a8 [3];
  undefined8 uStack2204;
  undefined4 uStack2196;
  undefined8 uStack2192;
  uint local_888 [528];
  ulonglong local_48;
  
  local_48 = DAT_180418010 ^ (ulonglong)auStack2792;
  lVar20 = 2;
  lVar17 = 2;
  puVar14 = (undefined4 *)(param_1 + 0x3b360 + (longlong)*(int *)(param_2 + 8) * 0x158);
  puVar15 = local_a78;
  do {
    puVar18 = puVar15;
    puVar16 = puVar14;
    uVar3 = puVar16[1];
    uVar4 = puVar16[2];
    uVar5 = puVar16[3];
    uVar6 = puVar16[4];
    uVar7 = puVar16[5];
    uVar8 = puVar16[6];
    uVar9 = puVar16[7];
    *(undefined4 *)puVar18 = *puVar16;
    *(undefined4 *)((longlong)puVar18 + 4) = uVar3;
    *(undefined4 *)(puVar18 + 1) = uVar4;
    *(undefined4 *)((longlong)puVar18 + 0xc) = uVar5;
    uVar3 = puVar16[8];
    uVar4 = puVar16[9];
    uVar5 = puVar16[10];
    uVar10 = puVar16[0xb];
    *(undefined4 *)(puVar18 + 2) = uVar6;
    *(undefined4 *)((longlong)puVar18 + 0x14) = uVar7;
    *(undefined4 *)(puVar18 + 3) = uVar8;
    *(undefined4 *)((longlong)puVar18 + 0x1c) = uVar9;
    uVar6 = puVar16[0xc];
    uVar7 = puVar16[0xd];
    uVar8 = puVar16[0xe];
    uVar9 = puVar16[0xf];
    *(undefined4 *)(puVar18 + 4) = uVar3;
    *(undefined4 *)((longlong)puVar18 + 0x24) = uVar4;
    *(undefined4 *)(puVar18 + 5) = uVar5;
    *(undefined4 *)((longlong)puVar18 + 0x2c) = uVar10;
    uVar3 = puVar16[0x10];
    uVar4 = puVar16[0x11];
    uVar5 = puVar16[0x12];
    uVar10 = puVar16[0x13];
    *(undefined4 *)(puVar18 + 6) = uVar6;
    *(undefined4 *)((longlong)puVar18 + 0x34) = uVar7;
    *(undefined4 *)(puVar18 + 7) = uVar8;
    *(undefined4 *)((longlong)puVar18 + 0x3c) = uVar9;
    uVar6 = puVar16[0x14];
    uVar7 = puVar16[0x15];
    uVar8 = puVar16[0x16];
    uVar9 = puVar16[0x17];
    *(undefined4 *)(puVar18 + 8) = uVar3;
    *(undefined4 *)((longlong)puVar18 + 0x44) = uVar4;
    *(undefined4 *)(puVar18 + 9) = uVar5;
    *(undefined4 *)((longlong)puVar18 + 0x4c) = uVar10;
    uVar3 = puVar16[0x18];
    uVar4 = puVar16[0x19];
    uVar5 = puVar16[0x1a];
    uVar10 = puVar16[0x1b];
    *(undefined4 *)(puVar18 + 10) = uVar6;
    *(undefined4 *)((longlong)puVar18 + 0x54) = uVar7;
    *(undefined4 *)(puVar18 + 0xb) = uVar8;
    *(undefined4 *)((longlong)puVar18 + 0x5c) = uVar9;
    uVar6 = puVar16[0x1c];
    uVar7 = puVar16[0x1d];
    uVar8 = puVar16[0x1e];
    uVar9 = puVar16[0x1f];
    *(undefined4 *)(puVar18 + 0xc) = uVar3;
    *(undefined4 *)((longlong)puVar18 + 100) = uVar4;
    *(undefined4 *)(puVar18 + 0xd) = uVar5;
    *(undefined4 *)((longlong)puVar18 + 0x6c) = uVar10;
    *(undefined4 *)(puVar18 + 0xe) = uVar6;
    *(undefined4 *)((longlong)puVar18 + 0x74) = uVar7;
    *(undefined4 *)(puVar18 + 0xf) = uVar8;
    *(undefined4 *)((longlong)puVar18 + 0x7c) = uVar9;
    lVar17 = lVar17 + -1;
    puVar14 = puVar16 + 0x20;
    puVar15 = puVar18 + 0x10;
  } while (lVar17 != 0);
  uVar3 = puVar16[0x21];
  uVar4 = puVar16[0x22];
  uVar5 = puVar16[0x23];
  uVar6 = puVar16[0x24];
  uVar7 = puVar16[0x25];
  uVar8 = puVar16[0x26];
  uVar9 = puVar16[0x27];
  *(undefined4 *)(puVar18 + 0x10) = puVar16[0x20];
  *(undefined4 *)((longlong)puVar18 + 0x84) = uVar3;
  *(undefined4 *)(puVar18 + 0x11) = uVar4;
  *(undefined4 *)((longlong)puVar18 + 0x8c) = uVar5;
  uVar3 = puVar16[0x28];
  uVar4 = puVar16[0x29];
  uVar5 = puVar16[0x2a];
  uVar10 = puVar16[0x2b];
  *(undefined4 *)(puVar18 + 0x12) = uVar6;
  *(undefined4 *)((longlong)puVar18 + 0x94) = uVar7;
  *(undefined4 *)(puVar18 + 0x13) = uVar8;
  *(undefined4 *)((longlong)puVar18 + 0x9c) = uVar9;
  uVar6 = puVar16[0x2c];
  uVar7 = puVar16[0x2d];
  uVar8 = puVar16[0x2e];
  uVar9 = puVar16[0x2f];
  *(undefined4 *)(puVar18 + 0x14) = uVar3;
  *(undefined4 *)((longlong)puVar18 + 0xa4) = uVar4;
  *(undefined4 *)(puVar18 + 0x15) = uVar5;
  *(undefined4 *)((longlong)puVar18 + 0xac) = uVar10;
  uVar3 = puVar16[0x30];
  uVar4 = puVar16[0x31];
  uVar5 = puVar16[0x32];
  uVar10 = puVar16[0x33];
  uVar1 = *(undefined8 *)(puVar16 + 0x34);
  *(undefined4 *)(puVar18 + 0x16) = uVar6;
  *(undefined4 *)((longlong)puVar18 + 0xb4) = uVar7;
  *(undefined4 *)(puVar18 + 0x17) = uVar8;
  *(undefined4 *)((longlong)puVar18 + 0xbc) = uVar9;
  *(undefined4 *)(puVar18 + 0x18) = uVar3;
  *(undefined4 *)((longlong)puVar18 + 0xc4) = uVar4;
  *(undefined4 *)(puVar18 + 0x19) = uVar5;
  *(undefined4 *)((longlong)puVar18 + 0xcc) = uVar10;
  puVar18[0x1a] = uVar1;
  puVar14 = (undefined4 *)((longlong)*(int *)(param_2 + 0xc) * 0x158 + 0x3b360 + param_1);
  puVar15 = &local_8c8;
  do {
    puVar18 = puVar15;
    puVar16 = puVar14;
    uVar3 = puVar16[1];
    uVar4 = puVar16[2];
    uVar5 = puVar16[3];
    uVar6 = puVar16[4];
    uVar7 = puVar16[5];
    uVar8 = puVar16[6];
    uVar9 = puVar16[7];
    *(undefined4 *)puVar18 = *puVar16;
    *(undefined4 *)((longlong)puVar18 + 4) = uVar3;
    *(undefined4 *)(puVar18 + 1) = uVar4;
    *(undefined4 *)((longlong)puVar18 + 0xc) = uVar5;
    uVar3 = puVar16[8];
    uVar4 = puVar16[9];
    uVar5 = puVar16[10];
    uVar10 = puVar16[0xb];
    *(undefined4 *)(puVar18 + 2) = uVar6;
    *(undefined4 *)((longlong)puVar18 + 0x14) = uVar7;
    *(undefined4 *)(puVar18 + 3) = uVar8;
    *(undefined4 *)((longlong)puVar18 + 0x1c) = uVar9;
    uVar6 = puVar16[0xc];
    uVar7 = puVar16[0xd];
    uVar8 = puVar16[0xe];
    uVar9 = puVar16[0xf];
    *(undefined4 *)(puVar18 + 4) = uVar3;
    *(undefined4 *)((longlong)puVar18 + 0x24) = uVar4;
    *(undefined4 *)(puVar18 + 5) = uVar5;
    *(undefined4 *)((longlong)puVar18 + 0x2c) = uVar10;
    uVar3 = puVar16[0x10];
    uVar4 = puVar16[0x11];
    uVar5 = puVar16[0x12];
    uVar10 = puVar16[0x13];
    *(undefined4 *)(puVar18 + 6) = uVar6;
    *(undefined4 *)((longlong)puVar18 + 0x34) = uVar7;
    *(undefined4 *)(puVar18 + 7) = uVar8;
    *(undefined4 *)((longlong)puVar18 + 0x3c) = uVar9;
    uVar6 = puVar16[0x14];
    uVar7 = puVar16[0x15];
    uVar8 = puVar16[0x16];
    uVar9 = puVar16[0x17];
    *(undefined4 *)(puVar18 + 8) = uVar3;
    *(undefined4 *)((longlong)puVar18 + 0x44) = uVar4;
    *(undefined4 *)(puVar18 + 9) = uVar5;
    *(undefined4 *)((longlong)puVar18 + 0x4c) = uVar10;
    uVar3 = puVar16[0x18];
    uVar4 = puVar16[0x19];
    uVar5 = puVar16[0x1a];
    uVar10 = puVar16[0x1b];
    *(undefined4 *)(puVar18 + 10) = uVar6;
    *(undefined4 *)((longlong)puVar18 + 0x54) = uVar7;
    *(undefined4 *)(puVar18 + 0xb) = uVar8;
    *(undefined4 *)((longlong)puVar18 + 0x5c) = uVar9;
    uVar6 = puVar16[0x1c];
    uVar7 = puVar16[0x1d];
    uVar8 = puVar16[0x1e];
    uVar9 = puVar16[0x1f];
    *(undefined4 *)(puVar18 + 0xc) = uVar3;
    *(undefined4 *)((longlong)puVar18 + 100) = uVar4;
    *(undefined4 *)(puVar18 + 0xd) = uVar5;
    *(undefined4 *)((longlong)puVar18 + 0x6c) = uVar10;
    *(undefined4 *)(puVar18 + 0xe) = uVar6;
    *(undefined4 *)((longlong)puVar18 + 0x74) = uVar7;
    *(undefined4 *)(puVar18 + 0xf) = uVar8;
    *(undefined4 *)((longlong)puVar18 + 0x7c) = uVar9;
    lVar20 = lVar20 + -1;
    puVar14 = puVar16 + 0x20;
    puVar15 = puVar18 + 0x10;
  } while (lVar20 != 0);
  uVar3 = puVar16[0x21];
  uVar4 = puVar16[0x22];
  uVar5 = puVar16[0x23];
  uVar6 = puVar16[0x24];
  uVar7 = puVar16[0x25];
  uVar8 = puVar16[0x26];
  uVar9 = puVar16[0x27];
  *(undefined4 *)(puVar18 + 0x10) = puVar16[0x20];
  *(undefined4 *)((longlong)puVar18 + 0x84) = uVar3;
  *(undefined4 *)(puVar18 + 0x11) = uVar4;
  *(undefined4 *)((longlong)puVar18 + 0x8c) = uVar5;
  uVar10 = puVar16[0x28];
  uVar11 = puVar16[0x29];
  uVar12 = puVar16[0x2a];
  uVar13 = puVar16[0x2b];
  *(undefined4 *)(puVar18 + 0x12) = uVar6;
  *(undefined4 *)((longlong)puVar18 + 0x94) = uVar7;
  *(undefined4 *)(puVar18 + 0x13) = uVar8;
  *(undefined4 *)((longlong)puVar18 + 0x9c) = uVar9;
  uVar3 = puVar16[0x2c];
  uVar4 = puVar16[0x2d];
  uVar5 = puVar16[0x2e];
  uVar6 = puVar16[0x2f];
  *(undefined4 *)(puVar18 + 0x14) = uVar10;
  *(undefined4 *)((longlong)puVar18 + 0xa4) = uVar11;
  *(undefined4 *)(puVar18 + 0x15) = uVar12;
  *(undefined4 *)((longlong)puVar18 + 0xac) = uVar13;
  uVar7 = puVar16[0x30];
  uVar8 = puVar16[0x31];
  uVar9 = puVar16[0x32];
  uVar10 = puVar16[0x33];
  uVar1 = *(undefined8 *)(puVar16 + 0x34);
  *(undefined4 *)(puVar18 + 0x16) = uVar3;
  *(undefined4 *)((longlong)puVar18 + 0xb4) = uVar4;
  *(undefined4 *)(puVar18 + 0x17) = uVar5;
  *(undefined4 *)((longlong)puVar18 + 0xbc) = uVar6;
  *(undefined4 *)(puVar18 + 0x18) = uVar7;
  *(undefined4 *)((longlong)puVar18 + 0xc4) = uVar8;
  *(undefined4 *)(puVar18 + 0x19) = uVar9;
  *(undefined4 *)((longlong)puVar18 + 0xcc) = uVar10;
  puVar18[0x1a] = uVar1;
  local_a98 = param_1;
  FUN_18001b1a8(param_1,param_2 + 8,4);
  FUN_18001b1a8(param_1,(int *)(param_2 + 0xc),8);
  FUN_18001c09c();
  uVar19 = 0;
  if (iStack2644 == 0) {
    if (local_8a8[1] == 0) {
      local_908 = (ulonglong)uStack2636;
      local_ac8 = &local_918;
      uStack2320 = 0;
      local_918 = 0;
      (**(code **)(param_1 + 0x128))(param_3,local_a68,local_8b8);
    }
    else {
      local_8d4 = (undefined4)uStack2204;
      local_8d0 = uStack2204._4_4_;
      local_8cc = uStack2196;
      local_ac0 = &local_900;
      local_ac8 = (undefined8 *)CONCAT44(local_ac8._4_4_,1);
      local_900 = 0;
      local_8f8 = 0;
      local_8f0 = 1;
      local_8e8 = 0;
      local_8e4 = 1;
      local_8dc = 0;
      (**(code **)(param_1 + 0x138))(param_3,local_a68,local_8c8,7);
    }
  }
  else {
    if (uStack2624 != 0) {
      do {
        local_aa8 = 0;
        iVar2 = (int)uVar19;
        uVar21 = iVar2 + 1;
        local_a90 = uStack2636 / uVar21;
        local_918 = CONCAT44(iVar2,1);
        uStack2700 = local_a48 / uVar21;
        uStack2320 = 0x100000000;
        lVar17 = uVar19 * 0x44;
        aiStack2240[uVar19 * 0x11 + -2] = 1;
        aiStack2240[uVar19 * 0x11 + -1] = iVar2;
        aiStack2240[uVar19 * 0x11] = 0;
        aiStack2240[uVar19 * 0x11 + 1] = 1;
        *(undefined8 *)((longlong)&uStack2224 + (uVar19 * 0x11 + -2) * 4) = 0;
        *(undefined8 *)((longlong)&uStack2204 + lVar17) = 0;
        *(undefined4 *)((longlong)&uStack2224 + uVar19 * 0x44) = 0;
        *(undefined4 *)((longlong)&uStack2192 + lVar17 + -4) = 0;
        *(undefined4 *)((longlong)&uStack2224 + lVar17 + 4) = 1;
        *(int *)((longlong)&uStack2224 + lVar17 + 8) = iVar2;
        *(undefined4 *)((longlong)&uStack2224 + lVar17 + 0xc) = 0;
        *(undefined4 *)((longlong)&uStack2224 + lVar17 + 0x10) = 1;
        *(ulonglong *)((longlong)&uStack2192 + lVar17) = CONCAT44(uStack2700,local_a90);
        local_888[uVar19 * 0x11] = uStack2628 / uVar21;
        param_1 = local_a98;
        uVar19 = (ulonglong)uVar21;
      } while (uVar21 < uStack2624);
    }
    local_ab8 = &local_8c8;
    local_ac0 = (undefined8 *)((ulonglong)local_ac0 & 0xffffffff00000000 | (ulonglong)uStack2624);
    local_ac8 = (undefined8 *)CONCAT44(local_ac8._4_4_,7);
    (**(code **)(param_1 + 0x130))(param_3,local_a78[0],6,local_8c8);
  }
  FUN_18000e8c0(local_48 ^ (ulonglong)auStack2792);
  return;
}



undefined4 FUN_18001bf4c(int param_1)

{
  if (param_1 < 0x54) {
    if (param_1 == 0x53) {
      return 9;
    }
    if (param_1 == 9) {
      return 0xf;
    }
    if (param_1 == 0x25) {
      return 7;
    }
    if (param_1 == 0x46) {
      return 0xd;
    }
    if (param_1 == 0x47) {
      return 0xe;
    }
    if (param_1 == 0x4a) {
      return 0xc;
    }
    if (param_1 == 0x4c) {
      return 0xb;
    }
    if (param_1 == 0x51) {
      return 10;
    }
  }
  else {
    if (param_1 == 0x61) {
      return 3;
    }
    if (param_1 == 0x62) {
      return 5;
    }
    if (param_1 == 100) {
      return 0x11;
    }
    if (param_1 == 0x67) {
      return 4;
    }
    if (param_1 == 0x6d) {
      return 2;
    }
    if (param_1 == 0x7a) {
      return 8;
    }
  }
  return 0;
}



void FUN_18001bfec(undefined8 param_1,longlong param_2,uint param_3,uint *param_4)

{
  uint uVar1;
  uint uVar2;
  ulonglong uVar3;
  undefined auStack584 [32];
  uint local_228;
  uint auStack548 [131];
  ulonglong local_18;
  
  local_18 = DAT_180418010 ^ (ulonglong)auStack584;
  vkGetPhysicalDeviceMemoryProperties();
  uVar3 = 0;
  if (local_228 != 0) {
    uVar1 = *(uint *)(param_2 + 0x10);
    do {
      if (((((uVar1 >> ((uint)uVar3 & 0x1f) & 1) != 0) &&
           (uVar2 = auStack548[uVar3 * 2], (param_3 & uVar2) != 0)) &&
          ((param_3 != 1 || ((uVar2 & 2) == 0)))) &&
         (*param_4 = uVar2, (param_3 & 2) != 0 && (uVar2 & 4) != 0)) break;
      uVar2 = (uint)uVar3 + 1;
      uVar3 = (ulonglong)uVar2;
    } while (uVar2 < local_228);
  }
  FUN_18000e8c0(local_18 ^ (ulonglong)auStack584);
  return;
}



void FUN_18001c09c(longlong param_1,undefined8 param_2)

{
  if ((*(int *)(param_1 + 0x41cc0) != 0) || (*(int *)(param_1 + 0x41cc4) != 0)) {
    (**(code **)(param_1 + 0x108))
              (param_2,*(undefined4 *)(param_1 + 0x41cc8),*(undefined4 *)(param_1 + 0x41ccc),1,0,0,
               *(undefined4 *)(param_1 + 0x41cc4),param_1 + 0x41940,*(int *)(param_1 + 0x41cc0),
               param_1 + 0x414c0);
    *(undefined4 *)(param_1 + 0x41cc0) = 0;
    *(undefined4 *)(param_1 + 0x41cc4) = 0;
    *(undefined4 *)(param_1 + 0x41cc8) = 0;
    *(undefined4 *)(param_1 + 0x41ccc) = 0;
  }
  return;
}



undefined8 FUN_18001c130(int param_1)

{
  if (param_1 == 1) {
    return 0x60;
  }
  if (param_1 != 2) {
    if (param_1 == 4) {
      return 0x800;
    }
    if ((param_1 != 6) && (param_1 == 8)) {
      return 0x1000;
    }
  }
  return 0x20;
}



undefined4 FUN_18001c164(int param_1)

{
  if (param_1 < 10) {
    if (param_1 == 9) {
      return 0x53;
    }
    if ((param_1 == 1) || (param_1 == 2)) {
      return 0x6d;
    }
    if (param_1 == 3) {
      return 0x61;
    }
    if (param_1 == 4) {
      return 0x67;
    }
    if (param_1 == 5) {
      return 0x62;
    }
    if ((param_1 == 6) || (param_1 == 7)) {
      return 0x25;
    }
    if (param_1 == 8) {
      return 0x7a;
    }
  }
  else {
    if (param_1 == 10) {
      return 0x51;
    }
    if (param_1 == 0xb) {
      return 0x4c;
    }
    if (param_1 == 0xc) {
      return 0x4a;
    }
    if (param_1 == 0xd) {
      return 0x46;
    }
    if (param_1 == 0xe) {
      return 0x47;
    }
    if (param_1 == 0xf) {
      return 9;
    }
    if (param_1 == 0x10) {
      return 0x10;
    }
    if (param_1 == 0x11) {
      return 100;
    }
  }
  return 0;
}



undefined4 FUN_18001c218(int param_1)

{
  if (param_1 != 1) {
    if (param_1 == 2) {
      return 5;
    }
    if (param_1 == 4) {
      return 6;
    }
    if ((param_1 != 6) && (param_1 == 8)) {
      return 7;
    }
  }
  return 1;
}



undefined8 FUN_18001c248(int param_1)

{
  if (param_1 == 1) {
    return 0;
  }
  if (param_1 != 2) {
    if (param_1 != 3) {
      return 0x7fffffff;
    }
    return 2;
  }
  return 1;
}



void FUN_18001c26c(longlong param_1,code *param_2)

{
  undefined8 uVar1;
  
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkSetDebugUtilsObjectNameEXT");
  *(undefined8 *)(param_1 + 0x18) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkFlushMappedMemoryRanges");
  *(undefined8 *)(param_1 + 0x100) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCreateDescriptorPool");
  *(undefined8 *)(param_1 + 0x20) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCreateSampler");
  *(undefined8 *)(param_1 + 0x28) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCreateDescriptorSetLayout");
  *(undefined8 *)(param_1 + 0x30) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCreateBuffer");
  *(undefined8 *)(param_1 + 0x38) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCreateImage");
  *(undefined8 *)(param_1 + 0x40) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCreateImageView");
  *(undefined8 *)(param_1 + 0x48) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCreateShaderModule");
  *(undefined8 *)(param_1 + 0x50) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCreatePipelineLayout");
  *(undefined8 *)(param_1 + 0x58) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCreateComputePipelines");
  *(undefined8 *)(param_1 + 0x60) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkDestroyPipelineLayout");
  *(undefined8 *)(param_1 + 0x68) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkDestroyPipeline");
  *(undefined8 *)(param_1 + 0x70) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkDestroyImage");
  *(undefined8 *)(param_1 + 0x78) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkDestroyImageView");
  *(undefined8 *)(param_1 + 0x80) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkDestroyBuffer");
  *(undefined8 *)(param_1 + 0x88) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkDestroyDescriptorSetLayout");
  *(undefined8 *)(param_1 + 0x90) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkDestroyDescriptorPool");
  *(undefined8 *)(param_1 + 0x98) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkDestroySampler");
  *(undefined8 *)(param_1 + 0xa0) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkDestroyShaderModule");
  *(undefined8 *)(param_1 + 0xa8) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkGetBufferMemoryRequirements");
  *(undefined8 *)(param_1 + 0xb0) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkGetImageMemoryRequirements");
  *(undefined8 *)(param_1 + 0xb8) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkAllocateDescriptorSets");
  *(undefined8 *)(param_1 + 0xc0) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkAllocateMemory");
  *(undefined8 *)(param_1 + 200) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkFreeMemory");
  *(undefined8 *)(param_1 + 0xd0) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkMapMemory");
  *(undefined8 *)(param_1 + 0xd8) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkUnmapMemory");
  *(undefined8 *)(param_1 + 0xe0) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkBindBufferMemory");
  *(undefined8 *)(param_1 + 0xe8) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkBindImageMemory");
  *(undefined8 *)(param_1 + 0xf0) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkUpdateDescriptorSets");
  *(undefined8 *)(param_1 + 0xf8) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCmdPipelineBarrier");
  *(undefined8 *)(param_1 + 0x108) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCmdBindPipeline");
  *(undefined8 *)(param_1 + 0x110) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCmdBindDescriptorSets");
  *(undefined8 *)(param_1 + 0x118) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCmdDispatch");
  *(undefined8 *)(param_1 + 0x120) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCmdCopyBuffer");
  *(undefined8 *)(param_1 + 0x128) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCmdCopyImage");
  *(undefined8 *)(param_1 + 0x130) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCmdCopyBufferToImage");
  *(undefined8 *)(param_1 + 0x138) = uVar1;
  uVar1 = (*param_2)(*(undefined8 *)(param_1 + 8),"vkCmdClearColorImage");
  *(undefined8 *)(param_1 + 0x140) = uVar1;
  return;
}



undefined8
ffxFsr2GetInterfaceVK
          (undefined8 *param_1,undefined8 *param_2,ulonglong param_3,undefined8 param_4,
          undefined8 param_5)

{
  ulonglong uVar1;
  undefined8 uVar2;
  
                    // 0x1c558  34  ffxFsr2GetInterfaceVK
  if ((param_1 == (undefined8 *)0x0) || (param_2 == (undefined8 *)0x0)) {
    uVar2 = 0x80000000;
  }
  else {
    uVar1 = ffxFsr2GetScratchMemorySizeVK(param_4);
    if (param_3 < uVar1) {
      uVar2 = 0x8000000e;
    }
    else {
      param_1[0xc] = param_2;
      param_1[1] = FUN_18001acf8;
      *param_1 = &LAB_180019904;
      param_1[2] = &LAB_18001a9c0;
      param_1[3] = &LAB_18001a3ac;
      param_1[4] = &LAB_18001af2c;
      param_1[5] = &LAB_18001b0cc;
      param_1[6] = &LAB_18001aee0;
      param_1[7] = FUN_18001ab70;
      param_1[8] = &LAB_180019d98;
      param_1[9] = &LAB_18001aae4;
      param_1[10] = &LAB_18001b000;
      param_1[0xb] = &LAB_18001ac58;
      param_1[0xd] = param_3;
      param_2[2] = param_5;
      uVar2 = 0;
      *param_2 = param_4;
    }
  }
  return uVar2;
}



ulonglong ffxFsr2GetScratchMemorySizeVK(longlong param_1)

{
  uint uVar1;
  uint local_res8 [8];
  
                    // 0x1c658  39  ffxFsr2GetScratchMemorySizeVK
  local_res8[0] = 0;
  uVar1 = 0;
  if (param_1 != 0) {
    vkEnumerateDeviceExtensionProperties(param_1,0,local_res8,0);
    uVar1 = local_res8[0];
  }
  return (ulonglong)uVar1 * 0x104 + 0x41ce7 & 0xfffffffffffffff8;
}



undefined8 *
ffxGetBufferResourceVK
          (undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4,
          undefined8 param_5,undefined4 param_6)

{
                    // 0x1c694  42  ffxGetBufferResourceVK
  memset(param_1,0,0xb8);
  *(undefined4 *)((longlong)param_1 + 0x8c) = 0;
  *(undefined4 *)((longlong)param_1 + 0xa4) = param_6;
  *(undefined4 *)((longlong)param_1 + 0x94) = 1;
  *(undefined4 *)(param_1 + 0x13) = 1;
  *(undefined4 *)((longlong)param_1 + 0x9c) = 1;
  *param_1 = param_3;
  *(undefined4 *)(param_1 + 0x12) = param_4;
  *(undefined *)(param_1 + 0x15) = 0;
  return param_1;
}



undefined8 *
ffxGetTextureResourceVK
          (undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
          undefined4 param_5,undefined4 param_6,int param_7,undefined8 param_8,undefined4 param_9)

{
  undefined4 uVar1;
  int iVar2;
  
                    // 0x1c704  49  ffxGetTextureResourceVK
  memset(param_1,0,0xb8);
  iVar2 = 1;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)((longlong)param_1 + 0xa4) = param_9;
  *(undefined4 *)(param_1 + 0x12) = param_5;
  *(undefined4 *)((longlong)param_1 + 0x94) = param_6;
  *param_1 = param_3;
  param_1[0x16] = param_4;
  *(undefined4 *)(param_1 + 0x11) = 2;
  *(undefined4 *)(param_1 + 0x13) = 1;
  *(undefined4 *)((longlong)param_1 + 0x9c) = 1;
  uVar1 = FUN_18001bf4c(param_7);
  *(undefined4 *)((longlong)param_1 + 0x8c) = uVar1;
  if ((((param_7 != 0x7c) && (param_7 != 0x7e)) && (param_7 = param_7 + -0x80, param_7 != 0)) &&
     ((param_7 != iVar2 && (param_7 - iVar2 != iVar2)))) {
    *(undefined *)(param_1 + 0x15) = 0;
    return param_1;
  }
  *(char *)(param_1 + 0x15) = (char)iVar2;
  return param_1;
}



undefined8 ffxGetVkImage(longlong param_1,uint param_2)

{
  int iVar1;
  
                    // 0x1c7c4  50  ffxGetVkImage
  iVar1 = *(int *)(param_1 + 0x7f54 + (ulonglong)param_2 * 4);
  if (iVar1 == -1) {
    return 0;
  }
  return *(undefined8 *)((longlong)iVar1 * 0x158 + 0x3b360 + *(longlong *)(param_1 + 0x78));
}



void ffxGetVkImageLayout(longlong param_1,ulonglong param_2)

{
                    // 0x1c7f0  51  ffxGetVkImageLayout
  FUN_18001c218(*(undefined4 *)
                 ((longlong)*(int *)(param_1 + 0x7f54 + (param_2 & 0xffffffff) * 4) * 0x158 +
                  0x3b3a0 + *(longlong *)(param_1 + 0x78)));
  return;
}



undefined8 ffxGetVkImageView(longlong param_1,ulonglong param_2)

{
                    // 0x1c814  52  ffxGetVkImageView
  return *(undefined8 *)
          ((longlong)*(int *)(param_1 + 0x7f54 + (param_2 & 0xffffffff) * 4) * 0x158 + 0x3b3a8 +
          *(longlong *)(param_1 + 0x78));
}



undefined8 * FUN_18001c834(undefined8 *param_1,uint param_2)

{
  longlong lVar1;
  longlong lVar2;
  
  lVar1 = (longlong)*(int *)(&DAT_18025d1c0 + (ulonglong)(param_2 >> 1 & 0x40 | param_2 & 0x3f) * 4)
  ;
  lVar2 = lVar1 * 0x1a0;
  *param_1 = (&PTR_DAT_1803b1cd8)[lVar1 * 0x34];
  *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1803b1cd0 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1803b1d58 + lVar2);
  *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1803b1d30 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1803b1dd0 + lVar2);
  param_1[3] = (&PTR_PTR_s_rw_internal_upscaled_color_1803b1d60)[lVar1 * 0x34];
  param_1[4] = (&PTR_DAT_1803b1d68)[lVar1 * 0x34];
  param_1[5] = (&PTR_PTR_s_r_exposure_1803b1d38)[lVar1 * 0x34];
  param_1[6] = (&PTR_DAT_1803b1d40)[lVar1 * 0x34];
  param_1[7] = (&PTR_PTR_s_cbFSR2_1803b1dd8)[lVar1 * 0x34];
  param_1[8] = (&PTR_DAT_1803b1de0)[lVar1 * 0x34];
  return param_1;
}



undefined8 * FUN_18001c8e0(undefined8 *param_1,uint param_2)

{
  longlong lVar1;
  longlong lVar2;
  
  lVar1 = (longlong)*(int *)(&DAT_18025cfb0 + (ulonglong)(param_2 >> 1 & 0x40 | param_2 & 0x3f) * 4)
  ;
  lVar2 = lVar1 * 0x1a0;
  *param_1 = (&PTR_DAT_180341f98)[lVar1 * 0x34];
  *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_180341f90 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_180342018 + lVar2);
  *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_180341ff0 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_180342090 + lVar2);
  param_1[3] = (&PTR_PTR_s_rw_output_reactive_mask_180342020)[lVar1 * 0x34];
  param_1[4] = (&PTR_DAT_180342028)[lVar1 * 0x34];
  param_1[5] = (&PTR_PTR_s_r_input_color_pre_alpha_180341ff8)[lVar1 * 0x34];
  param_1[6] = (&PTR_DAT_180342000)[lVar1 * 0x34];
  param_1[7] = (&PTR_PTR_s_cbGenerateReactive_180342098)[lVar1 * 0x34];
  param_1[8] = (&PTR_DAT_1803420a0)[lVar1 * 0x34];
  return param_1;
}



undefined8 * FUN_18001c98c(undefined8 *param_1,uint param_2)

{
  longlong lVar1;
  longlong lVar2;
  
  lVar1 = (longlong)*(int *)(&DAT_18031bc20 + (ulonglong)(param_2 & 0x3f) * 4);
  lVar2 = lVar1 * 0x1a0;
  *param_1 = (&PTR_DAT_18031bd58)[lVar1 * 0x34];
  *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_18031bd50 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_18031bdd8 + lVar2);
  *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_18031bdb0 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_18031be50 + lVar2);
  param_1[3] = (&PTR_PTR_s_rw_spd_global_atomic_18031bde0)[lVar1 * 0x34];
  param_1[4] = (&PTR_DAT_18031bde8)[lVar1 * 0x34];
  param_1[5] = (&PTR_PTR_s_r_input_color_jittered_18031bdb8)[lVar1 * 0x34];
  param_1[6] = (&PTR_DAT_18031bdc0)[lVar1 * 0x34];
  param_1[7] = (&PTR_PTR_s_cbFSR2_18031be58)[lVar1 * 0x34];
  param_1[8] = (&PTR_DAT_18031be60)[lVar1 * 0x34];
  return param_1;
}



undefined8 * FUN_18001ca2c(undefined8 *param_1,uint param_2)

{
  longlong lVar1;
  longlong lVar2;
  
  lVar1 = (longlong)*(int *)(&DAT_18039b0b0 + (ulonglong)(param_2 >> 1 & 0x40 | param_2 & 0x3f) * 4)
  ;
  lVar2 = lVar1 * 0x1a0;
  *param_1 = (&PTR_DAT_1803ee938)[lVar1 * 0x34];
  *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1803ee930 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1803ee9b8 + lVar2);
  *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1803ee990 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1803eea30 + lVar2);
  param_1[3] = (&PTR_PTR_s_rw_depth_clip_1803ee9c0)[lVar1 * 0x34];
  param_1[4] = (&PTR_DAT_1803ee9c8)[lVar1 * 0x34];
  param_1[5] = (&PTR_PTR_s_r_reconstructed_previous_nearest_1803ee998)[lVar1 * 0x34];
  param_1[6] = (&PTR_DAT_1803ee9a0)[lVar1 * 0x34];
  param_1[7] = (&PTR_PTR_s_cbFSR2_1803eea38)[lVar1 * 0x34];
  param_1[8] = (&PTR_DAT_1803eea40)[lVar1 * 0x34];
  return param_1;
}



undefined8 * FUN_18001cad8(undefined8 *param_1,uint param_2)

{
  longlong lVar1;
  longlong lVar2;
  
  lVar1 = (longlong)*(int *)(&DAT_18040c160 + (ulonglong)(param_2 >> 1 & 0x40 | param_2 & 0x3f) * 4)
  ;
  lVar2 = lVar1 * 0x1a0;
  *param_1 = (&PTR_DAT_180293038)[lVar1 * 0x34];
  *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_180293030 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1802930b8 + lVar2);
  *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_180293090 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_180293130 + lVar2);
  param_1[3] = (&PTR_PTR_s_rw_lock_status_1802930c0)[lVar1 * 0x34];
  param_1[4] = (&PTR_DAT_1802930c8)[lVar1 * 0x34];
  param_1[5] = (&PTR_PTR_s_r_lock_status_180293098)[lVar1 * 0x34];
  param_1[6] = (&PTR_DAT_1802930a0)[lVar1 * 0x34];
  param_1[7] = (&PTR_PTR_s_cbFSR2_180293138)[lVar1 * 0x34];
  param_1[8] = (&PTR_DAT_180293140)[lVar1 * 0x34];
  return param_1;
}



undefined8 * FUN_18001cb84(undefined8 *param_1,uint param_2)

{
  longlong lVar1;
  longlong lVar2;
  
  lVar1 = (longlong)*(int *)(&DAT_18026ed20 + (ulonglong)(param_2 >> 1 & 0x40 | param_2 & 0x3f) * 4)
  ;
  lVar2 = lVar1 * 0x1a0;
  *param_1 = (&PTR_DAT_1803b0fc8)[lVar1 * 0x34];
  *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1803b0fc0 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1803b1048 + lVar2);
  *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1803b1020 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1803b10c0 + lVar2);
  param_1[3] = (&PTR_PTR_s_rw_reconstructed_previous_neares_1803b1050)[lVar1 * 0x34];
  param_1[4] = (&PTR_DAT_1803b1058)[lVar1 * 0x34];
  param_1[5] = (&PTR_PTR_s_r_input_color_jittered_1803b1028)[lVar1 * 0x34];
  param_1[6] = (&PTR_DAT_1803b1030)[lVar1 * 0x34];
  param_1[7] = (&PTR_PTR_s_cbFSR2_1803b10c8)[lVar1 * 0x34];
  param_1[8] = (&PTR_DAT_1803b10d0)[lVar1 * 0x34];
  return param_1;
}



undefined8 * FUN_18001cc30(undefined8 *param_1,uint param_2)

{
  longlong lVar1;
  longlong lVar2;
  
  lVar1 = (longlong)*(int *)(&DAT_180324310 + (ulonglong)(param_2 >> 1 & 0x40 | param_2 & 0x3f) * 4)
  ;
  lVar2 = lVar1 * 0x1a0;
  *param_1 = (&PTR_DAT_180245c08)[lVar1 * 0x34];
  *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_180245c00 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_180245c88 + lVar2);
  *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_180245c60 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_180245d00 + lVar2);
  param_1[3] = (&PTR_PTR_s_rw_upscaled_output_180245c90)[lVar1 * 0x34];
  param_1[4] = (&PTR_DAT_180245c98)[lVar1 * 0x34];
  param_1[5] = (&PTR_PTR_s_r_exposure_180245c68)[lVar1 * 0x34];
  param_1[6] = (&PTR_DAT_180245c70)[lVar1 * 0x34];
  param_1[7] = (&PTR_PTR_s_cbFSR2_180245d08)[lVar1 * 0x34];
  param_1[8] = (&PTR_DAT_180245d10)[lVar1 * 0x34];
  return param_1;
}



undefined8 * FUN_18001ccdc(undefined8 *param_1,uint param_2)

{
  longlong lVar1;
  longlong lVar2;
  
  lVar1 = (longlong)*(int *)(&DAT_180246290 + (ulonglong)(param_2 >> 1 & 0x40 | param_2 & 0x3f) * 4)
  ;
  lVar2 = lVar1 * 0x1a0;
  *param_1 = (&PTR_DAT_1803bbdb8)[lVar1 * 0x34];
  *(undefined4 *)(param_1 + 1) = *(undefined4 *)(&DAT_1803bbdb0 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0xc) = *(undefined4 *)(&DAT_1803bbe38 + lVar2);
  *(undefined4 *)(param_1 + 2) = *(undefined4 *)(&DAT_1803bbe10 + lVar2);
  *(undefined4 *)((longlong)param_1 + 0x14) = *(undefined4 *)(&DAT_1803bbeb0 + lVar2);
  param_1[3] = (&PTR_PTR_s_rw_reconstructed_previous_neares_1803bbe40)[lVar1 * 0x34];
  param_1[4] = (&PTR_DAT_1803bbe48)[lVar1 * 0x34];
  param_1[5] = (&PTR_PTR_s_r_motion_vectors_1803bbe18)[lVar1 * 0x34];
  param_1[6] = (&PTR_DAT_1803bbe20)[lVar1 * 0x34];
  param_1[7] = (&PTR_PTR_s_cbFSR2_1803bbeb8)[lVar1 * 0x34];
  param_1[8] = (&PTR_DAT_1803bbec0)[lVar1 * 0x34];
  return param_1;
}



undefined4 * FUN_18001cd88(undefined4 *param_1,int param_2,undefined4 param_3)

{
  undefined4 local_58;
  undefined4 uStack84;
  undefined4 uStack80;
  undefined4 uStack76;
  undefined4 local_48;
  undefined4 uStack68;
  undefined4 uStack64;
  undefined4 uStack60;
  undefined4 local_38;
  undefined4 uStack52;
  undefined4 uStack48;
  undefined4 uStack44;
  undefined4 local_28;
  undefined4 uStack36;
  undefined4 uStack32;
  undefined4 uStack28;
  undefined8 local_18;
  
  if (param_2 == 0) {
    FUN_18001cb84(param_1,param_3);
  }
  else if (param_2 == 1) {
    FUN_18001ca2c(param_1,param_3);
  }
  else if (param_2 == 2) {
    FUN_18001ccdc(param_1,param_3);
  }
  else if (param_2 == 3) {
    FUN_18001cad8(param_1,param_3);
  }
  else if ((param_2 == 4) || (param_2 == 5)) {
    FUN_18001c834(param_1,param_3);
  }
  else if (param_2 == 6) {
    FUN_18001cc30(param_1,param_3);
  }
  else if (param_2 == 7) {
    FUN_18001c98c(param_1,param_3);
  }
  else if (param_2 == 8) {
    FUN_18001c8e0(param_1,param_3);
  }
  else {
    memset(&local_58,0,0x48);
    *param_1 = local_58;
    param_1[1] = uStack84;
    param_1[2] = uStack80;
    param_1[3] = uStack76;
    param_1[4] = local_48;
    param_1[5] = uStack68;
    param_1[6] = uStack64;
    param_1[7] = uStack60;
    param_1[8] = local_38;
    param_1[9] = uStack52;
    param_1[10] = uStack48;
    param_1[0xb] = uStack44;
    param_1[0xc] = local_28;
    param_1[0xd] = uStack36;
    param_1[0xe] = uStack32;
    param_1[0xf] = uStack28;
    *(undefined8 *)(param_1 + 0x10) = local_18;
  }
  return param_1;
}



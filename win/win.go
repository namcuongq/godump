package win

import (
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT                    = 0x00001000
	PAGE_NOACCESS                 = 0x01
	PROCESS_QUERY_INFORMATION     = 0x0400
	PROCESS_VM_READ               = 0x0010
	MEMORY_BASIC_INFORMATION_FLAG = 0
	TOKEN_ADJUST_PRIVILEGES       = 0x00000020
	TOKEN_QUERY                   = 0x00000008

	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
	IMAGE_SIZEOF_SHORT_NAME          = 8

	VER_NT_WORKSTATION = 0x0000001
)

type (
	DWORD     uint32
	LONG      uint32
	WORD      uint16
	BYTE      uint8
	ULONGLONG uint64
)

type ModuleListStream struct {
	NumberOfModules uint32
	BaseAddress     [8]byte
	Size            uint32
	UnknownField1   uint32
	Timestamp       uint32
	PointerName     uint32
	UnknownField2   [8]byte
	UnknownField3   [8]byte
	UnknownField4   [8]byte
	UnknownField5   [8]byte
	UnknownField6   [8]byte
	UnknownField7   [8]byte
	UnknownField8   [8]byte
	UnknownField9   [8]byte
	UnknownField10  [8]byte
	UnknownField11  [8]byte
}

type Memory64ListStream struct {
	NumberOfEntries       uint64
	MemoryRegionsBaseAddr uint32
}

type CUSTOM_UNICODE_STRING struct {
	Length uint32
	Buffer [31]uint16
}

type OSVERSIONINFOEX struct {
	DwOSVersionInfoSize uint32
	DwMajorVersion      uint32
	DwMinorVersion      uint32
	DwBuildNumber       uint32
	DwPlatformId        uint32
	SzCSDVersion        [128]uint16
	WServicePackMajor   uint16
	WServicePackMinor   uint16
	WSuiteMask          uint16
	WProductType        byte
	WReserved           byte
}

type OBJECT_ATTRIBUTES struct {
	Length                   int
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type Memory64Info struct {
	Address uintptr
	Size    uintptr
}

type Systeminfo struct {
	wProcessorArchitecture      uint16
	wReserved                   uint16
	dwPageSize                  uint32
	lpMinimumApplicationAddress uintptr
	lpMaximumApplicationAddress uintptr
	dwActiveProcessorMask       uintptr
	dwNumberOfProcessors        uint32
	dwProcessorType             uint32
	dwAllocationGranularity     uint32
	wProcessorLevel             uint16
	wProcessorRevision          uint16
}

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect int32
	RegionSize        uintptr
	State             int32
	Protect           int32
	Type              int32
}

type ModuleInfo struct {
	BaseOfDll   uintptr
	SizeOfImage DWORD
	EntryPoint  uintptr
}

type PROCESS_BASIC_INFORMATION struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

type IMAGE_DOS_HEADER struct { // DOS .EXE header
	E_magic    WORD     // Magic number
	E_cblp     WORD     // Bytes on last page of file
	E_cp       WORD     // Pages in file
	E_crlc     WORD     // Relocations
	E_cparhdr  WORD     // Size of header in paragraphs
	E_minalloc WORD     // Minimum extra paragraphs needed
	E_maxalloc WORD     // Maximum extra paragraphs needed
	E_ss       WORD     // Initial (relative) SS value
	E_sp       WORD     // Initial SP value
	E_csum     WORD     // Checksum
	E_ip       WORD     // Initial IP value
	E_cs       WORD     // Initial (relative) CS value
	E_lfarlc   WORD     // File address of relocation table
	E_ovno     WORD     // Overlay number
	E_res      [4]WORD  // Reserved words
	E_oemid    WORD     // OEM identifier (for E_oeminfo)
	E_oeminfo  WORD     // OEM information; E_oemid specific
	E_res2     [10]WORD // Reserved words
	E_lfanew   LONG     // File address of new exe header
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress DWORD
	Size           DWORD
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       DWORD
	TimeDateStamp         DWORD
	MajorVersionv         WORD
	MinorVersion          WORD
	Name                  DWORD
	Base                  DWORD
	NumberOfFunctions     DWORD
	NumberOfNames         DWORD
	AddressOfFunctions    DWORD
	AddressOfNames        DWORD
	AddressOfNameOrdinals DWORD
}

type IMAGE_FILE_HEADER struct {
	Machine              WORD
	NumberOfSections     WORD
	TimeDateStamp        DWORD
	PointerToSymbolTable DWORD
	NumberOfSymbols      DWORD
	SizeOfOptionalHeader WORD
	Characteristics      WORD
}

type IMAGE_NT_HEADERS struct {
	Signature      DWORD
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       WORD
	MajorLinkerVersion          BYTE
	MinorLinkerVersion          BYTE
	SizeOfCode                  DWORD
	SizeOfInitializedData       DWORD
	SizeOfUninitializedData     DWORD
	AddressOfEntryPoint         DWORD
	BaseOfCode                  DWORD
	ImageBase                   ULONGLONG
	SectionAlignment            DWORD
	FileAlignment               DWORD
	MajorOperatingSystemVersion WORD
	MinorOperatingSystemVersion WORD
	MajorImageVersion           WORD
	MinorImageVersion           WORD
	MajorSubsystemVersion       WORD
	MinorSubsystemVersion       WORD
	Win32VersionValue           DWORD
	SizeOfImage                 DWORD
	SizeOfHeaders               DWORD
	CheckSum                    DWORD
	Subsystem                   WORD
	DllCharacteristics          WORD
	SizeOfStackReserve          ULONGLONG
	SizeOfStackCommit           ULONGLONG
	SizeOfHeapReserve           ULONGLONG
	SizeOfHeapCommit            ULONGLONG
	LoaderFlags                 DWORD
	NumberOfRvaAndSizes         DWORD
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

type IMAGE_OPTIONAL_HEADER struct {
	Magic                       WORD
	MajorLinkerVersion          BYTE
	MinorLinkerVersion          BYTE
	SizeOfCode                  DWORD
	SizeOfInitializedData       DWORD
	SizeOfUninitializedData     DWORD
	AddressOfEntryPoint         DWORD
	BaseOfCode                  DWORD
	ImageBase                   ULONGLONG
	SectionAlignment            DWORD
	FileAlignment               DWORD
	MajorOperatingSystemVersion WORD
	MinorOperatingSystemVersion WORD
	MajorImageVersion           WORD
	MinorImageVersion           WORD
	MajorSubsystemVersion       WORD
	MinorSubsystemVersion       WORD
	Win32VersionValue           DWORD
	SizeOfImage                 DWORD
	SizeOfHeaders               DWORD
	CheckSum                    DWORD
	Subsystem                   WORD
	DllCharacteristics          WORD
	SizeOfStackReserve          ULONGLONG
	SizeOfStackCommit           ULONGLONG
	SizeOfHeapReserve           ULONGLONG
	SizeOfHeapCommit            ULONGLONG
	LoaderFlags                 DWORD
	NumberOfRvaAndSizes         DWORD
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

type IMAGE_SECTION_HEADER struct {
	Name                 [IMAGE_SIZEOF_SHORT_NAME]BYTE
	Misc                 DWORD
	VirtualAddress       DWORD
	SizeOfRawData        DWORD
	PointerToRawData     DWORD
	PointerToRelocations DWORD
	PointerToLinenumbers DWORD
	NumberOfRelocations  WORD
	NumberOfLinenumbers  WORD
	Characteristics      DWORD
}

type MinidumpHeader struct {
	Signature          uint32
	Version            uint16
	ImplementationVer  uint16
	NumberOfStreams    uint16
	StreamDirectoryRva uint32
	CheckSum           uint32
	TimeDateStamp      uintptr
}

type MinidumpStreamDirectoryEntry struct {
	StreamType uint32
	Size       uint32
	Location   uint32
}

type CustomUnicodeString struct {
	Length uint32
	Buffer [31]byte
}

type SystemInfoStream struct {
	ProcessorArchitecture uint16
	ProcessorLevel        uint16
	ProcessorRevision     uint16
	NumberOfProcessors    byte
	ProductType           byte
	MajorVersion          uint32
	MinorVersion          uint32
	BuildNumber           uint32
	PlatformId            uint32
	UnknownField1         uint32
	UnknownField2         uint32
	ProcessorFeatures     uintptr
	ProcessorFeatures2    uintptr
	UnknownField3         uint32
	UnknownField14        uint16
	UnknownField15        byte
}

var (
	psapi                    = syscall.NewLazyDLL("psapi.dll")
	procEnumProcessModules   = psapi.NewProc("EnumProcessModules")
	procGetModuleBaseNameW   = psapi.NewProc("GetModuleBaseNameW")
	procGetModuleInformation = psapi.NewProc("GetModuleInformation")

	ntdll                           = syscall.NewLazyDLL("ntdll.dll")
	procNtQueryInformationProcess   = ntdll.NewProc("NtQueryInformationProcess")
	procNtQueryVirtualMemoryProcess = ntdll.NewProc("NtQueryVirtualMemory")
	procNtReadVirtualMemoryProcess  = ntdll.NewProc("NtReadVirtualMemory")
	procRtlGetVersion               = ntdll.NewProc("RtlGetVersion")
	procNtOpenProcess               = ntdll.NewProc("NtOpenProcess")

	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procReadProcessMemory = kernel32.NewProc("ReadProcessMemory")
	procGetSystemInfo     = kernel32.NewProc("GetSystemInfo")
)

func ElevateProcessToken() error {
	//token elevation process sourced from
	//https://stackoverflow.com/questions/39595252/shutting-down-windows-using-golang-code

	type Luid struct {
		lowPart  uint32 // DWORD
		highPart int32  // long
	}
	type LuidAndAttributes struct {
		luid       Luid   // LUID
		attributes uint32 // DWORD
	}

	type TokenPrivileges struct {
		privilegeCount uint32 // DWORD
		privileges     [1]LuidAndAttributes
	}

	const SeDebugPrivilege = "SeDebugPrivilege"
	const tokenAdjustPrivileges = 0x0020
	const tokenQuery = 0x0008
	var hToken uintptr

	user32 := syscall.MustLoadDLL("user32")
	defer user32.Release()

	kernel32 := syscall.MustLoadDLL("kernel32")
	defer user32.Release()

	advapi32 := syscall.MustLoadDLL("advapi32")
	defer advapi32.Release()

	GetCurrentProcess := kernel32.MustFindProc("GetCurrentProcess")
	GetLastError := kernel32.MustFindProc("GetLastError")
	OpenProdcessToken := advapi32.MustFindProc("OpenProcessToken")
	LookupPrivilegeValue := advapi32.MustFindProc("LookupPrivilegeValueW")
	AdjustTokenPrivileges := advapi32.MustFindProc("AdjustTokenPrivileges")

	currentProcess, _, _ := GetCurrentProcess.Call()

	result, _, err := OpenProdcessToken.Call(currentProcess, tokenAdjustPrivileges|tokenQuery, uintptr(unsafe.Pointer(&hToken)))
	if result != 1 {
		return err
	}

	var tkp TokenPrivileges

	result, _, err = LookupPrivilegeValue.Call(uintptr(0), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(SeDebugPrivilege))), uintptr(unsafe.Pointer(&(tkp.privileges[0].luid))))
	if result != 1 {
		return err
	}

	const SePrivilegeEnabled uint32 = 0x00000002

	tkp.privilegeCount = 1
	tkp.privileges[0].attributes = SePrivilegeEnabled

	result, _, err = AdjustTokenPrivileges.Call(hToken, 0, uintptr(unsafe.Pointer(&tkp)), 0, uintptr(0), 0)
	if result != 1 {
		return err
	}

	result, _, _ = GetLastError.Call()
	if result != 0 {
		return err
	}

	return nil
}

func ReadProcessMemory(process syscall.Handle, baseAddress uintptr, buffer *byte, size uintptr, numberOfBytesRead *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procReadProcessMemory.Addr(), 5, uintptr(process), uintptr(baseAddress), uintptr(unsafe.Pointer(buffer)), uintptr(size), uintptr(unsafe.Pointer(numberOfBytesRead)), 0)
	if r1 == 0 {
		err = e1
	}
	return
}

func EnumProcessModules(hProcess syscall.Handle, nSize uintptr) (modules []syscall.Handle, err error) {
	modules = make([]syscall.Handle, nSize)
	var sizeNeeded uint32 = 0
	ret, _, _ := syscall.Syscall6(procEnumProcessModules.Addr(), 4, uintptr(hProcess), uintptr(unsafe.Pointer(&modules[0])), uintptr(nSize), uintptr(unsafe.Pointer(&sizeNeeded)), 0, 0)
	if ret == 0 {
		return nil, err
	}

	return modules, nil
}

func GetModuleInformation(process syscall.Handle, module syscall.Handle, modinfo *ModuleInfo, cb uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetModuleInformation.Addr(), 4, uintptr(process), uintptr(module), uintptr(unsafe.Pointer(modinfo)), uintptr(cb), 0, 0)
	if r1 == 0 {
		err = e1
	}
	return
}

func GetModuleBaseName(process syscall.Handle, module syscall.Handle, baseName *uint16, size uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetModuleBaseNameW.Addr(), 4, uintptr(process), uintptr(module), uintptr(unsafe.Pointer(baseName)), uintptr(size), 0, 0)
	if r1 == 0 {
		err = e1
	}
	return

}

func CustomGetModuleHandle1(p syscall.Handle, dllName string) (uintptr, error) {
	libHandler, err := syscall.LoadDLL(dllName)
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(libHandler.Handle)

	var libInfo ModuleInfo
	_, _, err = syscall.Syscall6(procGetModuleInformation.Addr(), 4, uintptr(p), uintptr(libHandler.Handle), uintptr(unsafe.Pointer(&libInfo)), uintptr(unsafe.Sizeof(libInfo)), 0, 0)
	return libInfo.BaseOfDll, err
}

func CustomGetModuleHandle(p syscall.Handle, dllName string) (uintptr, error) {
	var moduleInfo ModuleInfo
	modules, err := EnumProcessModules(p, 250000)
	if err != nil {
		return 0, err
	}

	for _, moduleHandle := range modules {
		if moduleHandle != 0 {
			modulePathUTF16 := make([]uint16, 128)
			err = GetModuleBaseName(p, moduleHandle, &modulePathUTF16[0], uint32(len(modulePathUTF16)))
			if err != nil {
				return 0, err
			}

			modulePath := syscall.UTF16ToString(modulePathUTF16)
			if strings.HasSuffix(strings.ToLower(modulePath), ".dll") {
				err = GetModuleInformation(p, moduleHandle, &moduleInfo, uint32(unsafe.Sizeof(moduleInfo)))
				if err != nil {
					return 0, err
				}

				if modulePath == dllName {
					return moduleInfo.BaseOfDll, nil
				}
			}

		}
	}
	return 0, nil
}

func RtlGetVersion(lpVersionInformation *OSVERSIONINFOEX) (status uint32) {
	r0, _, _ := syscall.Syscall(procRtlGetVersion.Addr(), 1, uintptr(unsafe.Pointer(lpVersionInformation)), 0, 0)
	return uint32(r0)
}

func GetBuildNumber() OSVERSIONINFOEX {
	var osVersionInfo OSVERSIONINFOEX
	osVersionInfo.DwOSVersionInfoSize = uint32(unsafe.Sizeof(osVersionInfo))
	RtlGetVersion(&osVersionInfo)
	return osVersionInfo
}

func NtOpenProcess(pidStr string) (syscall.Handle, error) {
	var (
		processHandle syscall.Handle
		client_id     CLIENT_ID
		objAttr       OBJECT_ATTRIBUTES
	)
	pid, _ := strconv.Atoi(pidStr)
	client_id.UniqueProcess = uintptr(pid)
	client_id.UniqueThread = uintptr(0)

	_, _, err := syscall.SyscallN(procNtOpenProcess.Addr(),
		uintptr(unsafe.Pointer(&processHandle)),
		PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&client_id)),
	)
	return processHandle, err
}

func GetMaxAddress() (uintptr, error) {
	var sysinfo Systeminfo
	_, _, err := syscall.Syscall(procGetSystemInfo.Addr(), 1, uintptr(unsafe.Pointer(&sysinfo)), 0, 0)
	return sysinfo.lpMaximumApplicationAddress, err
}

func QueryInformationProcess(processHandle syscall.Handle) (PROCESS_BASIC_INFORMATION, error) {
	var pbi PROCESS_BASIC_INFORMATION
	_, _, err := syscall.SyscallN(procNtQueryInformationProcess.Addr(), uintptr(processHandle), 0, uintptr(unsafe.Pointer(&pbi)), uintptr(uint32(unsafe.Sizeof(pbi))), uintptr(0))
	return pbi, err
}

func QueryVirtualMemoryProcess(processHandle syscall.Handle, memAddress uintptr, mbi *MEMORY_BASIC_INFORMATION) {
	syscall.SyscallN(procNtQueryVirtualMemoryProcess.Addr(),
		uintptr(processHandle),
		uintptr(memAddress),
		MEMORY_BASIC_INFORMATION_FLAG,
		uintptr(unsafe.Pointer(mbi)),
		0x30,
		uintptr(0),
	)
}

func ReadVirtualMemoryProcess(processHandle syscall.Handle, buffer *byte, address, size uintptr) {
	syscall.SyscallN(procNtReadVirtualMemoryProcess.Addr(),
		uintptr(processHandle),
		address,
		uintptr(unsafe.Pointer(buffer)),
		size,
		uintptr(0),
	)
}

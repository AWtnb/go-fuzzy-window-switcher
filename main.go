package main

import (
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	user32                    = syscall.MustLoadDLL("user32.dll")
	procEnumWindows           = user32.MustFindProc("EnumWindows")
	procGetWindowTextW        = user32.MustFindProc("GetWindowTextW")
	procGetWindowThreadProcID = user32.MustFindProc("GetWindowThreadProcessId")
	procIsWindowVisible       = user32.MustFindProc("IsWindowVisible")

	kernel32        = syscall.MustLoadDLL("kernel32.dll")
	procOpenProcess = kernel32.MustFindProc("OpenProcess")
	procCloseHandle = kernel32.MustFindProc("CloseHandle")

	psapi                    = syscall.MustLoadDLL("psapi.dll")
	procGetModuleFileNameExW = psapi.MustFindProc("GetModuleFileNameExW")
)

const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
const PROCESS_VM_READ = 0x0010

func EnumWindows(enumFunc uintptr, lparam uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(procEnumWindows.Addr(), uintptr(enumFunc), uintptr(lparam), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func GetWindowText(hwnd syscall.Handle) (string, error) {
	b := make([]uint16, 200)
	maxCount := int32(len(b))
	r0, _, e1 := syscall.SyscallN(procGetWindowTextW.Addr(), uintptr(hwnd), uintptr(unsafe.Pointer(&b[0])), uintptr(maxCount))
	if int32(r0) == 0 {
		if e1 != 0 {
			return "", error(e1)
		}
		return "", syscall.EINVAL
	}
	return syscall.UTF16ToString(b), nil
}

func GetProcessID(hwnd syscall.Handle) (uint32, error) {
	var pid uint32
	_, _, e1 := procGetWindowThreadProcID.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&pid)))
	if pid == 0 {
		return 0, e1
	}
	return pid, nil
}

func GetProcessName(pid uint32) (string, error) {
	hProcess, _, err := procOpenProcess.Call(
		PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ,
		0,
		uintptr(pid),
	)
	if hProcess == 0 {
		return "", err
	}
	defer procCloseHandle.Call(hProcess)

	buf := make([]uint16, syscall.MAX_PATH)
	ret, _, _ := procGetModuleFileNameExW.Call(
		hProcess,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return "", fmt.Errorf("failed to get process name")
	}
	fullPath := syscall.UTF16ToString(buf)

	return filepath.Base(fullPath), nil
}

func IsWindowVisible(hwnd syscall.Handle) bool {
	ret, _, _ := procIsWindowVisible.Call(uintptr(hwnd))
	return ret != 0
}

func FindWindow() {
	cb := syscall.NewCallback(func(h syscall.Handle, p uintptr) uintptr {
		if !IsWindowVisible(h) {
			return 1
		}

		title, _ := GetWindowText(h)
		if title == "" {
			return 1
		}

		pid, err := GetProcessID(h)
		if err != nil {
			return 1
		}

		name, err := GetProcessName(pid)
		if err != nil {
			name = "(unknown)"
		}

		fmt.Printf("PID: %5d | Visible: %-3t | Process: %-20s | Title: %s\n", pid, IsWindowVisible(h), name, title)
		return 1
	})
	EnumWindows(cb, 0)
}

func main() {
	FindWindow()
}

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	user32             = syscall.MustLoadDLL("user32.dll")
	procEnumWindows    = user32.MustFindProc("EnumWindows")
	procGetWindowTextW = user32.MustFindProc("GetWindowTextW")
)

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

func GetWindowText(hwnd syscall.Handle) (text string, err error) {
	b := make([]uint16, 200)
	maxCount := int32(len(b))
	r0, _, e1 := syscall.SyscallN(procGetWindowTextW.Addr(), uintptr(hwnd), uintptr(unsafe.Pointer(&b[0])), uintptr(maxCount))
	if int32(r0) == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	text = syscall.UTF16ToString(b)
	return
}

func FindWindow() {
	cb := syscall.NewCallback(func(h syscall.Handle, p uintptr) uintptr {
		t, err := GetWindowText(h)
		if err != nil {
			// ignore the error
			return 1 // continue enumeration
		}
		fmt.Println(t)
		return 1 // continue enumeration
	})
	EnumWindows(cb, 0)
}

func main() {
	FindWindow()
}

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"unsafe"

	fzf "github.com/junegunn/fzf/src"
)

var (
	user32                    = syscall.MustLoadDLL("user32.dll")
	procEnumWindows           = user32.MustFindProc("EnumWindows")
	procGetWindowTextW        = user32.MustFindProc("GetWindowTextW")
	procGetWindowThreadProcID = user32.MustFindProc("GetWindowThreadProcessId")
	procIsWindowVisible       = user32.MustFindProc("IsWindowVisible")
	procSetForegroundWindow   = user32.MustFindProc("SetForegroundWindow")
	procShowWindow            = user32.MustFindProc("ShowWindow")
	procAttachThreadInput     = user32.MustFindProc("AttachThreadInput")
	procBringWindowToTop      = user32.MustFindProc("BringWindowToTop")

	kernel32               = syscall.MustLoadDLL("kernel32.dll")
	procOpenProcess        = kernel32.MustFindProc("OpenProcess")
	procCloseHandle        = kernel32.MustFindProc("CloseHandle")
	procGetCurrentThreadId = kernel32.MustFindProc("GetCurrentThreadId")

	psapi                    = syscall.MustLoadDLL("psapi.dll")
	procGetModuleFileNameExW = psapi.MustFindProc("GetModuleFileNameExW")
)

const (
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	SW_RESTORE                        = 9
)

func enumWindows(enumFunc uintptr, lparam uintptr) (err error) {
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

func getWindowText(hwnd syscall.Handle) (string, error) {
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

func getProcessID(hwnd syscall.Handle) (uint32, error) {
	var pid uint32
	_, _, e1 := procGetWindowThreadProcID.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&pid)))
	if pid == 0 {
		return 0, e1
	}
	return pid, nil
}

func getProcessName(pid uint32) (string, error) {
	hProcess, _, err := procOpenProcess.Call(
		PROCESS_QUERY_LIMITED_INFORMATION,
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

func isVisibleWindow(hwnd syscall.Handle) bool {
	ret, _, _ := procIsWindowVisible.Call(uintptr(hwnd))
	return ret != 0
}

func isSkippable(name string) bool {
	ss := []string{
		"fzf.exe",
		"explorer.exe",
		"MouseGestureL.exe",
		"TextInputHost.exe",
		"SystemSettings.exe",
		"ApplicationFrameHost.exe",
	}
	return slices.Contains(ss, name)
}

func ForceForegroundWindow(hwnd syscall.Handle) bool {
	var targetPID uint32
	targetTID, _, _ := procGetWindowThreadProcID.Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(&targetPID)),
	)

	currentTID, _, _ := procGetCurrentThreadId.Call()

	procAttachThreadInput.Call(
		currentTID,
		targetTID,
		1, // TRUE: attach
	)

	procShowWindow.Call(uintptr(hwnd), SW_RESTORE)

	procBringWindowToTop.Call(uintptr(hwnd))

	ret, _, _ := procSetForegroundWindow.Call(uintptr(hwnd))

	procAttachThreadInput.Call(
		currentTID,
		targetTID,
		0, // FALSE: detach
	)

	return ret != 0
}

func run() int {

	hwndMap := make(map[string]syscall.Handle)

	inputChan := make(chan string)
	go func() {
		cb := syscall.NewCallback(func(h syscall.Handle, p uintptr) uintptr {
			if !isVisibleWindow(h) {
				return 1
			}

			text, _ := getWindowText(h)
			if text == "" {
				return 1
			}

			pid, err := getProcessID(h)
			if err != nil {
				return 1
			}

			name, err := getProcessName(pid)
			if err != nil || name == "" {
				return 1
			}
			if isSkippable(name) {
				return 1
			}

			s := fmt.Sprintf("%s[%s]", text, name)
			inputChan <- s
			hwndMap[s] = h
			return 1
		})
		enumWindows(cb, 0)
		close(inputChan)
	}()

	var wg sync.WaitGroup
	outputChan := make(chan string)
	wg.Go(func() {
		for s := range outputChan {
			h, ok := hwndMap[s]
			if ok {
				if !ForceForegroundWindow(h) {
					fmt.Printf("Failed to activate window: %s\n", s)
				}
				return
			}
		}
	})

	options, err := fzf.ParseOptions(
		true,
		[]string{"--margin=1", "--no-mouse"},
	)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	options.Input = inputChan
	options.Output = outputChan

	code, err := fzf.Run(options)
	close(outputChan)
	wg.Wait()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	return code
}

func main() {
	os.Exit(run())
}

//go:build windows
// +build windows

package clr

import (
	"errors"
	"syscall"
	"unsafe"
)

// VARTYPE uint16
// UINT uint32
// VT_UI1 = 0x0011
// ULONG uint32
// LONG int32
// USHORT uint16

// from OAld.h

type SafeArray struct {
	cDims      uint16
	fFeatures  uint16
	cbElements uint32
	cLocks     uint32
	pvData     uintptr
	rgsabound  [1]SafeArrayBound
}

type SafeArrayBound struct {
	cElements uint32
	lLbound   int32
}

func StrFromBstrPtr(p uintptr) string {
	return readUnicodeStr(unsafe.Pointer(p))
}

// CreateSafeArray is a wrapper function that takes in a Go byte array and creates a SafeArray containing unsigned bytes
// by making two syscalls and copying raw memory into the correct spot.
func CreateSafeArray(rawBytes []byte) (unsafe.Pointer, error) {

	saPtr, err := CreateEmptySafeArray(0x11, len(rawBytes)) // VT_UI1
	if err != nil {
		return nil, err
	}
	// now we need to use RtlCopyMemory to copy our bytes to the SafeArray
	modNtDll := syscall.MustLoadDLL("ntdll.dll")
	procRtlCopyMemory := modNtDll.MustFindProc("RtlCopyMemory")
	sa := (*SafeArray)(saPtr)
	_, _, err = procRtlCopyMemory.Call(
		sa.pvData,
		uintptr(unsafe.Pointer(&rawBytes[0])),
		uintptr(len(rawBytes)))
	if err != syscall.Errno(0) {
		return nil, err
	}
	return saPtr, nil

}

// CreateEmptySafeArray is a wrapper function that takes an array type and a size and creates a safe array with corresponding
// properties. It returns a pointer to that empty array.
func CreateEmptySafeArray(arrayType int, size int) (unsafe.Pointer, error) {
	modOleAuto := syscall.MustLoadDLL("OleAut32.dll")
	procSafeArrayCreate := modOleAuto.MustFindProc("SafeArrayCreate")

	sab := SafeArrayBound{
		cElements: uint32(size),
		lLbound:   0,
	}
	vt := uint16(arrayType)
	ret, _, err := procSafeArrayCreate.Call(
		uintptr(vt),
		uintptr(1),
		uintptr(unsafe.Pointer(&sab)))

	if err != syscall.Errno(0) {
		return nil, err
	}

	return unsafe.Pointer(ret), nil

}

// SysAllocString converts a Go string to a BTSR string, that is a unicode string prefixed with its length.
// It returns a pointer to the string's content.
func SysAllocString(str string) (unsafe.Pointer, error) {
	modOleAuto := syscall.MustLoadDLL("OleAut32.dll")
	sysAllocString := modOleAuto.MustFindProc("SysAllocString")
	input := utf16Le(str)
	ret, _, err := sysAllocString.Call(
		uintptr(unsafe.Pointer(&input[0])),
	)
	if err != syscall.Errno(0) {
		return nil, err
	}
	return unsafe.Pointer(ret), nil
}

// SysStringLen indicates how long a BSTR is
func SysStringLen(p uintptr) (int, error) {
	modOleAuto := syscall.MustLoadDLL("OleAut32.dll")
	sysAllocString := modOleAuto.MustFindProc("SysStringLen")
	ret, _, err := sysAllocString.Call(
		p,
	)
	if err != syscall.Errno(0) {
		return 0, err
	}
	return int(ret), nil
}

// SafeArrayPutElement pushes an element to the safe array at a given index
func SafeArrayPutElement(array, btsr unsafe.Pointer, index int) (err error) {
	modOleAuto := syscall.MustLoadDLL("OleAut32.dll")
	safeArrayPutElement := modOleAuto.MustFindProc("SafeArrayPutElement")
	_, _, err = safeArrayPutElement.Call(
		uintptr(array),
		uintptr(unsafe.Pointer(&index)),
		uintptr(btsr),
	)
	if err != syscall.Errno(0) {
		return err
	}
	return nil
}

// SafeArrayGetDim returns the dimensions of a safearray
func SafeArrayGetDim(array unsafe.Pointer) (dimensions uintptr, err error) {
	modOleAuto := syscall.MustLoadDLL("OleAut32.dll")
	safeArrayPutElement := modOleAuto.MustFindProc("SafeArrayGetDim")
	dimensions, _, err = safeArrayPutElement.Call(
		uintptr(array),
	)
	if !errors.Is(err, syscall.Errno(0)) {
		return 0, err
	}
	return dimensions, nil
}

// SafeArrayPutElement pushes an element to the safe array at a given index
func SafeArrayGetLBound(array unsafe.Pointer, dim uintptr, plLbound unsafe.Pointer) (ret uintptr, err error) {
	modOleAuto := syscall.MustLoadDLL("OleAut32.dll")
	safeArrayPutElement := modOleAuto.MustFindProc("SafeArrayGetLBound")
	ret, _, err = safeArrayPutElement.Call(
		uintptr(array),
		uintptr(dim),
		uintptr(plLbound),
	)
	if !errors.Is(err, syscall.Errno(0)) {
		return 0, err
	}
	return ret, nil
}

// SafeArrayPutElement pushes an element to the safe array at a given index
func SafeArrayGetUBound(array unsafe.Pointer, dim uintptr, plLbound unsafe.Pointer) (ret uintptr, err error) {
	modOleAuto := syscall.MustLoadDLL("OleAut32.dll")
	safeArrayPutElement := modOleAuto.MustFindProc("SafeArrayGetUBound")
	ret, _, err = safeArrayPutElement.Call(
		uintptr(array),
		uintptr(dim),
		uintptr(plLbound),
	)
	if !errors.Is(err, syscall.Errno(0)) {
		return 0, err
	}
	return ret, nil
}

// SafeArrayPutElement pushes an element to the safe array at a given index
func SafeArrayGetElement(array unsafe.Pointer, indicies uintptr, pObj unsafe.Pointer) (ret uintptr, err error) {
	modOleAuto := syscall.MustLoadDLL("OleAut32.dll")
	safeArrayPutElement := modOleAuto.MustFindProc("SafeArrayGetElement")
	ret, _, err = safeArrayPutElement.Call(
		uintptr(array),
		uintptr(unsafe.Pointer(&indicies)),
		uintptr(pObj),
	)
	if !errors.Is(err, syscall.Errno(0)) {
		return 0, err
	}
	return ret, nil
}

// SafeArrayPutElement pushes an element to the safe array at a given index
func SafeArrayGetElemsize(array unsafe.Pointer) (ret uintptr, err error) {
	modOleAuto := syscall.MustLoadDLL("OleAut32.dll")
	safeArrayPutElement := modOleAuto.MustFindProc("SafeArrayGetElemsize")
	ret, _, err = safeArrayPutElement.Call(
		uintptr(array),
	)
	if !errors.Is(err, syscall.Errno(0)) {
		return 0, err
	}
	return ret, nil
}

// SafeArrayDestroy Destroys an existing array descriptor and all of the data in the array. If objects are stored in the array, Release is called on each object in the array.
func SafeArrayDestroy(array unsafe.Pointer) (err error) {
	modOleAuto := syscall.MustLoadDLL("OleAut32.dll")
	safeArrayPutElement := modOleAuto.MustFindProc("SafeArrayDestroy")
	_, _, err = safeArrayPutElement.Call(
		uintptr(array),
	)
	if !errors.Is(err, syscall.Errno(0)) {
		return err
	}
	return nil
}

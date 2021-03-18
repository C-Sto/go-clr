// +build windows

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	clr "github.com/ropnop/go-clr"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func checkOK(hr uintptr, caller string) {
	if hr != 0x0 {
		log.Fatalf("%s returned 0x%08x", caller, hr)
	}
}

func init() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: EXEfromMemory.exe <exe_file> <exe_args>")
		os.Exit(1)
	}
}

func main() {
	filename := os.Args[1]
	exebytes, err := ioutil.ReadFile(filename)
	must(err)
	runtime.KeepAlive(exebytes)

	var params []string
	if len(os.Args) > 2 {
		params = os.Args[2:]
	}

	var pMetaHost uintptr
	hr := clr.CLRCreateInstance(&clr.CLSID_CLRMetaHost, &clr.IID_ICLRMetaHost, &pMetaHost)
	checkOK(hr, "CLRCreateInstance")
	metaHost := clr.NewICLRMetaHostFromPtr(pMetaHost)

	versionString := "v4.0.30319"
	pwzVersion, _ := syscall.UTF16PtrFromString(versionString)
	var pRuntimeInfo uintptr
	hr = metaHost.GetRuntime(pwzVersion, &clr.IID_ICLRRuntimeInfo, &pRuntimeInfo)
	checkOK(hr, "metahost.GetRuntime")
	runtimeInfo := clr.NewICLRRuntimeInfoFromPtr(pRuntimeInfo)

	var isLoadable bool
	hr = runtimeInfo.IsLoadable(&isLoadable)
	checkOK(hr, "runtimeInfo.IsLoadable")
	if !isLoadable {
		log.Fatal("[!] IsLoadable returned false. Bailing...")
	}

	hr = runtimeInfo.BindAsLegacyV2Runtime()
	checkOK(hr, "runtimeInfo.BindAsLegacyV2Runtime")

	var pRuntimeHost uintptr
	hr = runtimeInfo.GetInterface(&clr.CLSID_CorRuntimeHost, &clr.IID_ICorRuntimeHost, &pRuntimeHost)
	runtimeHost := clr.NewICORRuntimeHostFromPtr(pRuntimeHost)
	hr = runtimeHost.Start()
	checkOK(hr, "runtimeHost.Start")
	fmt.Println("[+] Loaded CLR into this process")

	var pAppDomain uintptr
	var pIUnknown uintptr
	hr = runtimeHost.GetDefaultDomain(&pIUnknown)
	checkOK(hr, "runtimeHost.GetDefaultDomain")
	iu := clr.NewIUnknownFromPtr(pIUnknown)
	hr = iu.QueryInterface(&clr.IID_AppDomain, &pAppDomain)
	checkOK(hr, "iu.QueryInterface")
	appDomain := clr.NewAppDomainFromPtr(pAppDomain)
	fmt.Println("[+] Got default AppDomain")

	fmt.Printf("[+] Loaded %d bytes into memory from %s\n", len(exebytes), filename)

	safeArray, err := clr.CreateSafeArray(exebytes)
	must(err)
	runtime.KeepAlive(safeArray)
	fmt.Println("[+] Created SafeArray from byte array")

	assembly, err := appDomain.Load_3(safeArray)
	must(err)
	fmt.Printf("[+] Executable loaded into memory at %p\n", assembly)

	var pEntryPointInfo uintptr
	hr = assembly.GetEntryPoint(&pEntryPointInfo)
	checkOK(hr, "assembly.GetEntryPoint")
	fmt.Printf("[+] Executable entrypoint found at 0x%x\n", pEntryPointInfo)
	methodInfo := clr.NewMethodInfoFromPtr(pEntryPointInfo)

	var methodSignaturePtr, paramPtr uintptr
	err = methodInfo.GetString(&methodSignaturePtr)
	if err != nil {
		return
	}
	methodSignature := clr.ReadUnicodeStr(unsafe.Pointer(methodSignaturePtr))
	fmt.Printf("[+] Checking if the assembly requires arguments\n")
	if !strings.Contains(methodSignature, "Void Main()") {
		if len(params) < 1 {
			log.Fatal("the assembly requires arguments but none were provided\nUsage: EXEfromMemory.exe <exe_file> <exe_args>")
		}
		if paramPtr, err = clr.PrepareParameters(params); err != nil {
			log.Fatal(fmt.Sprintf("there was an error preparing the assembly arguments:\r\n%s", err))
		}
	}

	var pRetCode uintptr
	nullVariant := clr.Variant{
		VT:  1,
		Val: uintptr(0),
	}
	fmt.Println("[+] Invoking...")
	hr = methodInfo.Invoke_3(
		nullVariant,
		paramPtr,
		&pRetCode)

	fmt.Println("-------")

	checkOK(hr, "methodInfo.Invoke_3")
	fmt.Printf("[+] Executable returned code %d\n", pRetCode)

	appDomain.Release()
	runtimeHost.Release()
	runtimeInfo.Release()
	metaHost.Release()

}

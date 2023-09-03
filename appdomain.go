//go:build windows
// +build windows

package clr

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type AppDomain struct {
	vtbl *AppDomainVtbl
}

type AppDomainVtbl struct {
	QueryInterface            uintptr
	AddRef                    uintptr
	Release                   uintptr
	GetTypeInfoCount          uintptr
	GetTypeInfo               uintptr
	GetIDsOfNames             uintptr
	Invoke                    uintptr
	get_ToString              uintptr
	Equals                    uintptr
	GetHashCode               uintptr
	GetType                   uintptr
	InitializeLifetimeService uintptr
	GetLifetimeService        uintptr
	get_Evidence              uintptr
	add_DomainUnload          uintptr
	remove_DomainUnload       uintptr
	add_AssemblyLoad          uintptr
	remove_AssemblyLoad       uintptr
	add_ProcessExit           uintptr
	remove_ProcessExit        uintptr
	add_TypeResolve           uintptr
	remove_TypeResolve        uintptr
	add_ResourceResolve       uintptr
	remove_ResourceResolve    uintptr
	add_AssemblyResolve       uintptr
	remove_AssemblyResolve    uintptr
	add_UnhandledException    uintptr
	remove_UnhandledException uintptr
	DefineDynamicAssembly     uintptr
	DefineDynamicAssembly_2   uintptr
	DefineDynamicAssembly_3   uintptr
	DefineDynamicAssembly_4   uintptr
	DefineDynamicAssembly_5   uintptr
	DefineDynamicAssembly_6   uintptr
	DefineDynamicAssembly_7   uintptr
	DefineDynamicAssembly_8   uintptr
	DefineDynamicAssembly_9   uintptr
	CreateInstance            uintptr
	CreateInstanceFrom        uintptr
	CreateInstance_2          uintptr
	CreateInstanceFrom_2      uintptr
	CreateInstance_3          uintptr
	CreateInstanceFrom_3      uintptr
	Load                      uintptr
	Load_2                    uintptr
	Load_3                    uintptr
	Load_4                    uintptr
	Load_5                    uintptr
	Load_6                    uintptr
	Load_7                    uintptr
	ExecuteAssembly           uintptr
	ExecuteAssembly_2         uintptr
	ExecuteAssembly_3         uintptr
	get_FriendlyName          uintptr
	get_BaseDirectory         uintptr
	get_RelativeSearchPath    uintptr
	get_ShadowCopyFiles       uintptr
	GetAssemblies             uintptr
	AppendPrivatePath         uintptr
	ClearPrivatePath          uintptr
	SetShadowCopyPath         uintptr
	ClearShadowCopyPath       uintptr
	SetCachePath              uintptr
	SetData                   uintptr
	GetData                   uintptr
	SetAppDomainPolicy        uintptr
	SetThreadPrincipal        uintptr
	SetPrincipalPolicy        uintptr
	DoCallBack                uintptr
	get_DynamicDirectory      uintptr
}

// GetAppDomain is a wrapper function that returns an appDomain from an existing ICORRuntimeHost object
func GetAppDomain(runtimeHost *ICORRuntimeHost) (appDomain *AppDomain, err error) {
	var pAppDomain uintptr
	var pIUnknown uintptr
	hr := runtimeHost.GetDefaultDomain(&pIUnknown)
	err = checkOK(hr, "runtimeHost.GetDefaultDomain")
	if err != nil {
		return
	}
	iu := NewIUnknownFromPtr(pIUnknown)
	hr = iu.QueryInterface(&IID_AppDomain, &pAppDomain)
	err = checkOK(hr, "IUnknown.QueryInterface")
	return NewAppDomainFromPtr(pAppDomain), err
}

// GetAppDomainStr returns an appDomain from the runtime - will use an existing app domain if one exists with the provided string, or create one if it doesn't exist already
func GetAppDomainStr(runtimeHost *ICORRuntimeHost, s string) (AppDomain *AppDomain, err error) {
	var hDomainEnum uintptr
	ihr := runtimeHost.EnumDomains(&hDomainEnum)
	var pIUnknown uintptr

	for {
		ihr = runtimeHost.NextDomain(hDomainEnum, &pIUnknown)
		if ihr != 0 {
			break
		}
		var hr uintptr
		var pAppDomain uintptr
		iu := NewIUnknownFromPtr(pIUnknown)
		hr = iu.QueryInterface(&IID_AppDomain, &pAppDomain)
		err = checkOK(hr, "NextDomain.IUnknown.QueryInterface")
		if err != nil {
			return
		}
		ad := NewAppDomainFromPtr(pAppDomain)
		if ad == nil {
			iu.Release()
			continue
		}

		fn, err := ad.GetFriendlyName()
		if err != nil {
			return nil, err
		}
		if fn != "" && fn == s {
			iu.Release()
			runtimeHost.CloseEnum(hDomainEnum)
			return ad, nil
		}
		iu.Release()
	}

	//did not find an appdomain matching, create one and return it
	return initAppdomain(runtimeHost, s)
}

// GetAppDomainAssembly returns the appdomain that contains the named assembly
func GetAppDomainAssembly(runtimeHost *ICORRuntimeHost, s string) (AppDomain *AppDomain, err error) {
	var hDomainEnum uintptr
	ihr := runtimeHost.EnumDomains(&hDomainEnum)
	var pIUnknown uintptr

	for {
		ihr = runtimeHost.NextDomain(hDomainEnum, &pIUnknown)
		if ihr != 0 {
			break
		}
		var hr uintptr
		var pAppDomain uintptr
		iu := NewIUnknownFromPtr(pIUnknown)
		hr = iu.QueryInterface(&IID_AppDomain, &pAppDomain)
		err = checkOK(hr, "NextDomain.IUnknown.QueryInterface")
		if err != nil {
			return
		}
		ad := NewAppDomainFromPtr(pAppDomain)
		if ad == nil {
			iu.Release()
			continue
		}
		var pAssembly uintptr
		hr = ad.Load_2(s, &pAssembly)
		err = checkOK(hr, "NextDomain.Appdomain.Load_2")
		if err != nil {
			return
		}
		if pAssembly != 0 {
			return ad, nil
		}

		iu.Release()
	}

	//did not find an appdomain matching, create one and return it
	return nil, fmt.Errorf("could not find assembly")
}

func initAppdomain(runtimeHost *ICORRuntimeHost, s string) (AppDomain *AppDomain, err error) {
	var pAppDomain uintptr
	var pIUnknown uintptr
	hr := runtimeHost.CreateDomain(s, &pIUnknown)
	err = checkOK(hr, "runtimeHost.CreateDomain")
	if err != nil {
		return
	}
	iu := NewIUnknownFromPtr(pIUnknown)
	hr = iu.QueryInterface(&IID_AppDomain, &pAppDomain)
	err = checkOK(hr, "IUnknown.QueryInterface")
	iu.Release()
	return NewAppDomainFromPtr(pAppDomain), err
}

func NewAppDomainFromPtr(ppv uintptr) *AppDomain {
	return (*AppDomain)(unsafe.Pointer(ppv))
}

func (obj *AppDomain) QueryInterface(riid *windows.GUID, ppvObject *uintptr) uintptr {
	ret, _, _ := syscall.Syscall(
		obj.vtbl.QueryInterface,
		3,
		uintptr(unsafe.Pointer(obj)),
		uintptr(unsafe.Pointer(riid)),
		uintptr(unsafe.Pointer(ppvObject)))
	return ret
}

func (obj *AppDomain) AddRef() uintptr {
	ret, _, _ := syscall.Syscall(
		obj.vtbl.AddRef,
		1,
		uintptr(unsafe.Pointer(obj)),
		0,
		0)
	return ret
}

func (obj *AppDomain) Release() uintptr {
	ret, _, _ := syscall.Syscall(
		obj.vtbl.Release,
		1,
		uintptr(unsafe.Pointer(obj)),
		0,
		0)
	return ret
}

func (obj *AppDomain) GetHashCode() uintptr {
	ret, _, _ := syscall.Syscall(
		obj.vtbl.GetHashCode,
		2,
		uintptr(unsafe.Pointer(obj)),
		0,
		0)
	return ret
}

func (obj *AppDomain) getFriendlyName(bstrFriendlyname *uintptr) uintptr {
	ret, _, _ := syscall.Syscall(
		obj.vtbl.get_FriendlyName,
		3,
		uintptr(unsafe.Pointer(obj)),
		uintptr(unsafe.Pointer(bstrFriendlyname)),
		0)
	return ret
}

func (obj *AppDomain) GetFriendlyName() (name string, err error) {
	var pbstrFriendlyname uintptr
	hr := obj.getFriendlyName(&pbstrFriendlyname)
	err = checkOK(hr, "appdomain.Getfriendlyname")
	if err != nil {
		return
	}
	return readUnicodeStr(unsafe.Pointer(pbstrFriendlyname)), nil
}

func (obj *AppDomain) Load_3(pRawAssembly uintptr, asmbly *uintptr) uintptr {
	ret, _, _ := syscall.Syscall(
		obj.vtbl.Load_3,
		3,
		uintptr(unsafe.Pointer(obj)),
		uintptr(unsafe.Pointer(pRawAssembly)),
		uintptr(unsafe.Pointer(asmbly)))
	return ret
}

func (obj *AppDomain) Load_2(assemblyString string, asmbly *uintptr) uintptr {
	str, _ := SysAllocString(assemblyString)
	bnstrptr := uintptr(str)
	ret, _, _ := syscall.Syscall(
		obj.vtbl.Load_2,
		3,
		uintptr(unsafe.Pointer(obj)),
		uintptr(bnstrptr),
		uintptr(unsafe.Pointer(asmbly)))
	return ret
}

func (obj *AppDomain) GetAssemblies(asmbly *uintptr) uintptr {
	ret, _, _ := syscall.SyscallN(
		obj.vtbl.GetAssemblies,
		uintptr(unsafe.Pointer(obj)),
		uintptr(unsafe.Pointer(asmbly)))
	return ret
}

func (obj *AppDomain) ListAssemblies() (assemblies []string, err error) {
	var psafeArrayPtr uintptr
	hr := obj.GetAssemblies(&psafeArrayPtr)
	err = checkOK(hr, "appdomain.ListAssemblies.GetAssemblies")
	if err != nil {
		return
	}
	//get dimensions of array (should be 1 for this context always)
	d, err := SafeArrayGetDim(unsafe.Pointer(psafeArrayPtr))
	if err != nil {
		return
	}
	if d != 1 {
		return nil, fmt.Errorf("expected dimension of 1, got %d", d)
	}

	var lbound uintptr
	_, err = SafeArrayGetLBound(unsafe.Pointer(psafeArrayPtr), d, unsafe.Pointer(&lbound))
	if err != nil {
		return
	}

	var ubound uintptr
	_, err = SafeArrayGetUBound(unsafe.Pointer(psafeArrayPtr), d, unsafe.Pointer(&ubound))
	if err != nil {
		return
	}
	arrlen := ubound - lbound
	//avoids allocs (lol, overkill)
	assemblies = make([]string, 0, arrlen)
	for i := lbound; i <= ubound; i++ {
		var pApp uintptr
		_, err = SafeArrayGetElement(unsafe.Pointer(psafeArrayPtr), i, unsafe.Pointer(&pApp))
		if err != nil {
			return
		}
		ass := NewAssemblyFromPtr(pApp)
		var asss string
		asss, err = ass.GetFullName()
		if err != nil {
			return
		}
		assemblies = append(assemblies, asss)
	}
	return
}

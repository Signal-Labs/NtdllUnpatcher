# NtdllUnpatcher
Example code for EDR bypassing, please use this for testing blue team detection capabilities against this type of malware that will bypass EDR's userland hooks. Code is a bit spaghetti-like at the moment and serves only as a PoC. Not for malicious use.

# How To Use
NtdllUnpatcher: This may be compiled as a .lib or .dll and does the heavy work of loading an unhooked copy of NTDLL into memory and patching the current hooked functions to redirect to their unhooked counterparts, to enable the bypass with any code you already have simply compile with this .lib and call the InitializeHooks() routine. Otherwise this may be compiled as a .dll and injected into a closed-source program through the use of a loader. Note that the current project configurations are only setup for the x64 release build.

NtdllUnpatcher_Injector: This is a loader that will inject a DLL into a PID. This may be used to load the NtdllUnpatcher.dll into a closed-source program to enable NTDLL hook bypasses for the targeted application. Usage is: NtdllUnpatcher_Injector <path/to/dll> <pid>
  


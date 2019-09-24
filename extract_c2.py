from winappdbg.win32 import *
from winappdbg import Debug, EventHandler, HexDump, Process
import pefile
import threading, time, struct, binascii, sys, os, shutil, json, re
# import rpc_client
# from util import *

c2_list = []
cfg = {}
rsa_pub_key = ''

# A copy of WinAppdbg
def pattern(token):
    """
    Convert an hexadecimal search pattern into a POSIX regular expression.
    For example, the following pattern::
        "B8 0? ?0 ?? ??"
    Would match the following data::
        "B8 0D F0 AD BA"    # mov eax, 0xBAADF00D
    @type  token: str
    @param token: String to parse.
    @rtype:  str
    @return: Parsed string value.
    """
    token = ''.join([ c for c in token if c == '?' or c.isalnum() ])
    if len(token) % 2 != 0:
        raise ValueError("Missing characters in hex data")
    regexp = ''
    for i in range(0, len(token), 2):
        x = token[i:i+2]
        if x == '??':
            regexp += '.'
        elif x[0] == '?':
            f = '\\x%%.1x%s' % x[1]
            x = ''.join([ f % c for c in range(0, 0x10) ])
            regexp = '%s[%s]' % (regexp, x)
        elif x[1] == '?':
            f = '\\x%s%%.1x' % x[0]
            x = ''.join([ f % c for c in range(0, 0x10) ])
            regexp = '%s[%s]' % (regexp, x)
        else:
            regexp = '%s\\x%s' % (regexp, x)
    return regexp


def search(data, sig):

    addr = None
    pt = pattern(sig)
    ret = re.search(pt.encode(), data)
    if ret:
        offset = ret.end()
        addr = offset
    
    return addr


def extract_ioc(dump_path, base):

    print('extract ioc from:{}'.format(dump_path))
    
    pe = pefile.PE(dump_path)
    data = pe.get_memory_mapped_image()

    rsa_pub_key = ''
    c2_list = []

    # .text:00401FA1 68 00 80 00 00                          push    8000h
    # .text:00401FA6 6A 6A                                   push    6Ah
    # .text:00401FA8 68 D0 F8 40 00                          push    offset unk_40F8D0
    # .text:00401FAD 6A 13                                   push    13h
    # .text:00401FAF 68 01 00 01 00                          push    10001h
    # .text:00401FB4 FF 15 F4 05 41 00                       call    CryptDecodeObjectEx
    sig_rsa_pub_key = '68 00 80 00 00 6a 6a 68'
    offset = search(data, sig_rsa_pub_key)
    rsa_pub_key_offset = struct.unpack('<I', data[offset:offset+4])[0]-base
    rsa_pub_key = data[rsa_pub_key_offset:rsa_pub_key_offset+0x6a]
    rsa_pub_key = ''.join(['{:02x} '.format(ord(x)) for x in rsa_pub_key])

    # .text:004060C5 B8 C0 F3 40 00                          mov     eax, offset stru_40F3C0
    # .text:004060CA A3 E0 26 41 00                          mov     off_4126E0, eax
    # .text:004060CF A3 E4 26 41 00                          mov     off_4126E4, eax
    # .text:004060D4 33 C0                                   xor     eax, eax
    sig_c2_list = 'B8 ?? ?? ?? 00 A3 ?? ?? ?? 00 A3 ?? ?? ?? 00 33 C0'
    offset = search(data, sig_c2_list)
    c2_list_offset = struct.unpack('<I', data[offset-16:offset-16+4])[0]-base
    for idx in range(0, 200):
        item = data[c2_list_offset+idx*8:c2_list_offset+idx*8+8]
        ip = '{}.{}.{}.{}'.format(*reversed(struct.unpack('<BBBB', item[0:4])))
        port = struct.unpack('<H', item[4:6])[0]
        if item[0] == '\x00': break
        c2_list.append('{}:{}'.format(ip, port))

    return c2_list, rsa_pub_key


def action_callback_create_process( event ):
    
    print('hit break')
    global c2_list, cfg, rsa_pub_key

    process = event.get_process()
    thread  = event.get_thread()

    # Get the address of the top of the stack.
    stack   = thread.get_sp()

    # Get the return address of the call.
    ret_address = process.read_pointer( stack )
    print('caller addr:{:08x}'.format(ret_address))

    # Get the process and thread IDs.
    pid     = event.get_pid()
    tid     = event.get_tid()

    extract_done = False
    failed_reason = 'unknown'
    max_c2_counter = 400

    shell_data = 0

    sig_addr_list = []

    for address, data in process.search_hexa('68 00 80 00 00 6a 6a 68'):
        # Print a hex dump for each memory location found.
        if ret_address&0xFFFF0000 == address&0xFFFF0000:
            print('hit sig at:')
            print(HexDump.hexblock(data, address = address))
            sig_addr_list.append(address)

    memoryMap       = process.get_memory_map()
    mappedFilenames = process.get_mapped_filenames(memoryMap)

    # For each memory block in the map...
    for mbi in memoryMap:

        # Address and size of memory block.
        BaseAddress = mbi.BaseAddress
        RegionSize  = mbi.RegionSize

        for address in sig_addr_list:
            if address > BaseAddress and address < BaseAddress+RegionSize:
                print('Hit shell code block!\n{:08x}\t{:08x}'.format(BaseAddress, RegionSize))
                shell_data = process.read(BaseAddress, RegionSize)
                
    # no hit, just kill and return
    if shell_data != 0: 
        # dump shell code block
        print('dump shell code!')
        with open('shell.dump', 'wb') as fh:
            fh.write(shell_data)

        # dump final payload
        dump_pe_path = 'pe.dump'
        pe_offset = shell_data.find('\x4D\x5A\x90')
        print('dump final payload!')
        with open(dump_pe_path, 'wb') as fh:
            fh.write(shell_data[pe_offset:])

        print('\n-----------------------------')
        c2_list , rsa_pub_key = extract_ioc(dump_pe_path, 0x400000)
        print('\nc2 list:')
        for c2 in c2_list:
            print('{}'.format(c2))

        print('\nrsa key:\n{}'.format(rsa_pub_key))

    # Show a message to the user.
    message = "kernel32!CreateProcessW called from %s by thread %d at process %d"
    print message % (HexDump.address(ret_address, process.get_bits()), tid, pid)
    process.kill()


class MyEventHandler( EventHandler ):

    def load_dll( self, event ):

        # Get the new module object.
        module = event.get_module()

        # If it's kernel32.dll...
        if module.match_name("kernel32.dll"):            
            # Get the process ID.
            pid = event.get_pid()
            address_create_process = module.resolve("CreateProcessW")
            event.debug.break_at(pid, address_create_process, action_callback_create_process)


def simple_debugger( argv ):
    
    with Debug( MyEventHandler(), bKillOnExit = True ) as debug:
        try:
            # Start a new process for debugging.
            print('start', argv)
            debug.execv( argv )
            debug.loop()
        except:
            pass

    return c2_list
    
if __name__ == "__main__":

    file_path = sys.argv[1]
    simple_debugger([file_path])

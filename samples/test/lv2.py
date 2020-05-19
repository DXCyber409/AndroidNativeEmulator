import logging
import sys
from unicorn import *
from androidemu.emulator import Emulator
from androidemu.java.helpers.native_method import native_method
from androidemu.utils import memory_helpers
# Configure logging
logging.basicConfig(stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s")
logger = logging.getLogger(__name__)
@native_method
def __aeabi_memcpy(mu, dist, source, size):
    data = mu.mem_read(source, size)
    mu.mem_write(dist, bytes(data))
    print ('__aeabi_memcpy(%s)' % data)
@native_method
def __aeabi_memclr(mu, dist, size):
    print ('__aeabi_memclr(%x,%d)' % (dist, size))
    mu.mem_write(dist, bytes(size))
@native_method
def sprintf(mu, buffer, format1, data1, data2):
    f = memory_helpers.read_utf8(mu, format1)
    data1 = memory_helpers.read_utf8(mu, data1)
    result = f % (data1, data2)
    mu.mem_write(buffer, bytes((result + '\x00').encode('utf-8')))
emulator = Emulator()
emulator.modules.add_symbol_hook('__aeabi_memcpy', emulator.hooker.write_function(__aeabi_memcpy) + 1)
emulator.modules.add_symbol_hook('__aeabi_memclr', emulator.hooker.write_function(__aeabi_memclr) + 1)
emulator.modules.add_symbol_hook('sprintf', emulator.hooker.write_function(sprintf) + 1)
emulator.load_library("jnilibs/libc.so", do_init=False)
lib_module = emulator.load_library("jnilibs/libnative-jnilibs.so", do_init=False)
#dbg = udbg.UnicornDebugger(emulator.mu, udbg.UDBG_MODE_ALL)
try:
    sign = emulator.call_symbol(lib_module, 'Java_com_sec_udemo_MainActivity_sign_1lv2',
                                emulator.java_vm.jni_env.address_ptr, 0, "123")
    print (sign)
except UcError as e:
    #tracks = dbg.get_tracks()
    #pc = emulator.mu.reg_read(UC_ARM_REG_PC)
    #for addr in tracks[-100:-1]:
    #    print (hex(addr - 0xcbc66000))
    print (e)


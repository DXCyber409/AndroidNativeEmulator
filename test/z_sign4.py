import sys
import logging
from unicorn import *
from androidemu.emulator import Emulator
from UnicornTraceDebugger import udbg
from androidemu.java.helpers.native_method import native_method
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.utils import memory_helpers

logging.basicConfig(stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s")
logger = logging.getLogger(__name__)

@native_method
def __aeabi_memclr(mu, addr, size):
    print('__aeabi_memclr(%x,%d)' % (addr, size))
    mu.mem_write(addr, bytes(size))

@native_method
def __aeabi_memcpy(mu, dist, source, size):
    data = mu.mem_read(source, size)
    mu.mem_write(dist, bytes(data))
    print('__aeabi_memcpy(%x,%x,%d)' % (dist, source, size))

@native_method
def sprintf(mu, buffer, fmt, a1, a2):
    fmt1 = memory_helpers.read_utf8(mu, fmt)
    data1 = memory_helpers.read_utf8(mu, a1)
    result = fmt1 % (data1, a2)
    mu.mem_write(buffer, bytes((result + '\x00').encode('utf-8')))
    # print('sprintf(%s)' % (result))

class com_sec_udemo_MainActivity(metaclass=JavaClassDef, jvm_name="com/sec/udemo/MainActivity"):
    def __init__(self):
        pass
    @java_method_def(name='getSaltFromJava', signature='(Ljava/lang/String;)Ljava/lang/String;', native=False,
                   args_list=['jstring'])
    def getSaltFromJava(self, mu, str):
        return str.value.value + "salt.."

    @java_method_def(name='sign_lv4', signature='(Ljava/lang/String;)Ljava/lang/String;', native=True,
                     args_list=['jstring'])
    def sign_lv4(self, mu):
        pass

emulator = Emulator()

#got hook
emulator.modules.add_symbol_hook('__aeabi_memclr', emulator.hooker.write_function(__aeabi_memclr) + 1)
emulator.modules.add_symbol_hook('__aeabi_memcpy', emulator.hooker.write_function(__aeabi_memcpy) + 1)
emulator.modules.add_symbol_hook('sprintf', emulator.hooker.write_function(sprintf) + 1)

emulator.java_classloader.add_class(com_sec_udemo_MainActivity)

libc = emulator.load_library('jnilibs/libc.so', do_init=False)
libmod = emulator.load_library('jnilibs/libnative-lib.so', do_init=True)

try:
    dbg = udbg.UnicornDebugger(emulator.mu)
    obj = com_sec_udemo_MainActivity()

    emulator.mu.mem_write(0xcbc66000 + 0xAA02, b'\xC0\x46\xC0\x46')
    emulator.mu.mem_write(0xcbc66000 + 0xAA06, b'\xC0\x46\xC0\x46')

    emulator.call_symbol(libmod, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0)
    result = obj.sign_lv4(emulator, '123')
    print(result)
except UcError as e:
    list_tracks = dbg.get_tracks()
    for addr in list_tracks[-100:-1]:
        print(hex(addr - 0xcbc66000))
    print (e)

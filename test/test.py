import sys
import logging
from unicorn import *
from unicorn.arm_const import *
from androidemu.emulator import Emulator
from UnicornTraceDebugger import udbg
from androidemu.java.classes.String import java_lang_String
from androidemu.java.helpers.native_method import native_method
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

emulator = Emulator()

# data segment
data_base = 0xa00000
data_size = 0x10000 * 3
emulator.mu.mem_map(data_base, data_size)

#got hook
emulator.modules.add_symbol_hook('__aeabi_memclr', emulator.hooker.write_function(__aeabi_memclr) + 1)
emulator.modules.add_symbol_hook('__aeabi_memcpy', emulator.hooker.write_function(__aeabi_memcpy) + 1)
emulator.modules.add_symbol_hook('sprintf', emulator.hooker.write_function(sprintf) + 1)

libc = emulator.load_library('jnilibs/libc.so', do_init=False)
libmod = emulator.load_library('jnilibs/libencrypt.so', do_init=True)

try:
    dbg = udbg.UnicornDebugger(emulator.mu)

    p1 = java_lang_String('EDDC681644C64942A22C3ABFFDD7976F0B7D37407FB17685885B401A0D03E48DD05B324AB42B2270EDE432E39492031BE4B6623BE22A59AE56BBBA81BBDC9B9D29B5FBE873F3965170DA9D9E0A2530FCDAE7537B5F8204772F90677F4CF82C206C9D87D0102621FC1556ACD735D8584BAEE2229BEEBE53217CA996676DB0C655E76A4D4E58A93E736FB65F99264EEFB441B4E9D922893AD6C840DD9C98AC06279E78AAE3C2A9E2502C7F22CB0E82E48AF7CD831649E94A49C57B96E332F0F0723B29B72A9171715D36BF826ED0258BE6677F9DB301A92F4A1C2EA585E4B0CC688B72B598C1ADD8DA85AC2F92505338B525A8831479F6FAC3452DC7B898C6FC9B061F2999A41B93ED80849FE426694662B4DF6F5DEBAF5519821690E99A6F5991966D66386E5A069890AE4334D46C4794E8EADD6D6242ADD0509EC87628C308D87B43327C8C715A8003FC6D273CEA56A00EE220E2F224BF06B660C17B4D941C22519472BEF50312A2E5E377C80D4075D06F786AA9C033754E264E180C48C06939AAF8D0CF8E57FF31D5059877BE3CD2FCEF043EA5493098C33FEBA79EE80871B4C1EBE13C245C8412C9E18B23C2A02C11B9755C0B356D0384577E80A40A298AB2D36088179D5C4AA14BA1F321CE1F10BF0A40E7A05B8EF0EE99AF777ADA138D52F52A3DCAB3755C406FB990A6475E6FF27E34C3AA56C54720BBD2079790CB26DCD1D84C1133CF29ED95E8E9B9843B2B284AC5008DA12213781BF965FD6394236090A3160FB8EB90BBDAE0572633091B2851EBFA9064102EC1FEFEA5F4D72C22DD156F1E2E914AB660C6A55C41F1D3631C37B5F3FB7ECBEF69E743ADF59C2816A170EC5A23C11B6F458BBDEC3CBA39968802B5C703D7E583E98CDFFAD35B3695910199FA92C1107B0C85A9E4A2DF9FC4AAB8ECF4C2D58186AFB8ADFD6F1EE1A9E31EEEF648E93E031FC6A55C41F1D3631C2F349A9ED80362C254972DC5058998730C26E48FCDE26B60B40C75D3521A6DE1DC62950A4BB7CBC541512B57D3D7B1C25C06439A5BD82061A8FAEC849D57DEB10BE062F20E680E63695FECDDC364E8DD2A75E6A9F3E16CB30998DA72479C11B4886ACC86E6994EB4D48F89B0EBFA07F3679C5EB4FE516229')
    p2 = java_lang_String('USER_INFO')
    s = emulator.call_symbol_by_native(libmod, 0xcbc66000 + 0xC5C0 + 1,
                         emulator.java_vm.jni_env.address_ptr, p1, p2)
    print(s)
except UcError as e:
    list_tracks = dbg.get_tracks()
    for addr in list_tracks[-100:-1]:
        print(hex(addr - 0xcbc66000))
    print (e)

import sys
import logging
from unicorn import *
from androidemu.emulator import Emulator

logging.basicConfig(stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s")
logger = logging.getLogger(__name__)

emulator = Emulator()
emulator.load_library('jnilibs/libc.so', do_init=False)
libmod = emulator.load_library('jnilibs/libnative-jnilibs.so', do_init=False)

try:
    s = emulator.call_symbol(libmod, 'Java_com_sec_udemo_MainActivity_sign_1lv2',
                         emulator.java_vm.jni_env.address_ptr, 0, "123")
    print(s)

except UcError as e:
    print (e)

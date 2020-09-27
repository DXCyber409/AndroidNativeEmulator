import sys
import logging
from unicorn import *
from unicorn.arm_const import *
from androidemu.emulator import Emulator
from UnicornTraceDebugger import udbg

logging.basicConfig(stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s")
logger = logging.getLogger(__name__)

emulator = Emulator()

libc = emulator.load_library('jnilibs/libc.so', do_init=False)
libso = emulator.load_library('jnilibs/libso.so', do_init=False)
main = emulator.load_library('jnilibs/main', do_init=False)

try:
    dbg = udbg.UnicornDebugger(emulator.mu)
    addr_start = 0xcbc6b000 + 0x4B0 + 1
    addr_end = 0xcbc6b000 + 0x4D2
    emulator.mu.emu_start(addr_start, addr_end)
    ret = emulator.mu.reg_read(UC_ARM_REG_R0)
    print(ret)
except UcError as e:
    list_tracks = dbg.get_tracks()
    for addr in list_tracks[-100:-1]:
        print(hex(addr - 0xcbc66000))
    print (e)

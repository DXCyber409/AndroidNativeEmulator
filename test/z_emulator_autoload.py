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
libso = emulator.load_library('jnilibs/libnative-lib.so', do_init=False)

# data segment
data_base = 0xa00000
data_size = 0x10000 * 3
emulator.mu.mem_map(data_base, data_size)
emulator.mu.mem_write(data_base, b'123')
emulator.mu.reg_write(UC_ARM_REG_R0, data_base)

try:
    dbg = udbg.UnicornDebugger(emulator.mu)
    addr_start = 0xcbc66000 + 0x9B68 + 1
    addr_end = 0xcbc66000 + 0x9C2C
    emulator.mu.emu_start(addr_start, addr_end)
    r2 = emulator.mu.reg_read(UC_ARM_REG_R2)
    result = emulator.mu.mem_read(r2, 16)
    print(result.hex())
except UcError as e:
    list_tracks = dbg.get_tracks()
    for addr in list_tracks[-100:-1]:
        print(hex(addr - 0xcbc66000))
    print (e)

# 手动纯算法调用
import binascii

from unicorn import *
from unicorn.arm_const import *

from UnicornTraceDebugger import udbg


def hook_code(uc, address, size, userdata):
    print (">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))

def hook_memory(uc, access, address, size,value, userdata):
    pc = uc.reg_read(UC_ARM_REG_PC)
    print ("memory error: pc:%x address:%x size:%x" % (pc, address, size))

a1 = b'123'
mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
#image
image_base = 0x0
image_size = 0x10000 * 8
mu.mem_map(image_base, image_size)
binary = open('jnilibs/libnative-lib.so','rb').read()
mu.mem_write(image_base, binary) ### 非常简陋的加载方法

# stack
stack_base = 0xa0000
stack_size = 0x10000 * 3
stack_top = stack_base - stack_size
mu.mem_map(stack_base, stack_size)
mu.reg_write(UC_ARM_REG_SP, stack_top)

# data segment
data_base = 0xf0000
data_size = 0x10000 * 3
mu.mem_map(data_base, data_size)
mu.mem_write(data_base, a1)
mu.reg_write(UC_ARM_REG_R0, data_base)

#fix got
mu.mem_write(0x1EDB0, b'\xD9\x98\x00\x00')

#set hook
#mu.hook_add(UC_HOOK_CODE, hook_code, 0)
#mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_code, 0)

target = image_base + 0x9B68
target_end = image_base + 0x9C2C

#start
try:
    dbg = udbg.UnicornDebugger(mu)
    mu.emu_start(target + 1, target_end)
    r2 = mu.reg_read(UC_ARM_REG_R2)
    result = mu.mem_read(r2, 16)
    print(binascii.b2a_hex(result))
except UcError as e:
    list_tracks = dbg.get_tracks()
    for addr in list_tracks:
        print(hex(addr))
    print(e)

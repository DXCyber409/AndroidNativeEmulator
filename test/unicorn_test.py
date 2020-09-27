from unicorn import *
from unicorn.arm_const import *

# ARM binary code:
ARM_CODE = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0"

# Is equal to assembly code:
# mov r0, #0x37;
# sub r1, r2, r3

# Callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))

def test_arm():
    print("Emulate ARM code")
    try:
        # Initialize emulator in ARM Thunm mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        # set execution start address
        ADDRESS = 0x1000

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 1024 * 1024 * 2)
        mu.mem_write(ADDRESS, ARM_CODE)

        mu.reg_write(UC_ARM_REG_R0, 0x1234)
        mu.reg_write(UC_ARM_REG_R2, 0x6789)
        mu.reg_write(UC_ARM_REG_R3, 0x3333)

        mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(ARM_CODE))
        r0 = mu.reg_read(UC_ARM_REG_R0)
        r1 = mu.reg_read(UC_ARM_REG_R1)
        print(">>> R0 = 0x%x" % r0)
        print(">>> R1 = 0x%x" % r1)
    except UcError as e:
        print("ERROR: %s" % e)

if (__name__ == '__main__'):
    test_arm()
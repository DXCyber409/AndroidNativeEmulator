from capstone import *

ARM_CODE = b'\xD9\x98\x00\00'

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
for i in md.disasm(ARM_CODE, 0x1000):
    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

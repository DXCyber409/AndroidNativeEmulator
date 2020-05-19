#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2016-08-20 09:37:02
# @Author  : PiaoYun (piaoyunsoft@163.com)
# @Link    : http://www.dllhook.com
# @Comment : keystone汇编引擎测试

from __future__ import print_function
from keystone import *


def keystone_test(arch, mode, code, syntax=0):
    ks = Ks(arch, mode)
    if syntax != 0:
        ks.syntax = syntax

    encoding, count = ks.asm(code)
    print("%s = [ " % code, end='')
    for i in encoding:
        print("%02x " % i, end='')
    print("]")


def test():
    # X86
    keystone_test(KS_ARCH_X86, KS_MODE_16, b"add eax, ecx")
    keystone_test(KS_ARCH_X86, KS_MODE_32, b"add eax, ecx")
    keystone_test(KS_ARCH_X86, KS_MODE_64, b"add rax, rcx")
    keystone_test(
        KS_ARCH_X86, KS_MODE_32, b"add %ecx, %eax", KS_OPT_SYNTAX_ATT)
    keystone_test(
        KS_ARCH_X86, KS_MODE_64, b"add %rcx, %rax", KS_OPT_SYNTAX_ATT)

    # ARM
    keystone_test(KS_ARCH_ARM, KS_MODE_ARM, b"sub r1, r2, r5")
    keystone_test(
        KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_BIG_ENDIAN, b"sub r1, r2, r5")
    keystone_test(KS_ARCH_ARM, KS_MODE_THUMB, b"movs r4, #0xf0")
    keystone_test(
        KS_ARCH_ARM, KS_MODE_THUMB + KS_MODE_BIG_ENDIAN, b"movs r4, #0xf0")

    # ARM64
    keystone_test(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, b"ldr w1, [sp, #0x8]")

    # Hexagon
    keystone_test(
        KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN, b"v23.w=vavg(v11.w,v2.w):rnd")

    # Mips
    keystone_test(KS_ARCH_MIPS, KS_MODE_MIPS32, b"and $9, $6, $7")
    keystone_test(
        KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN, b"and $9, $6, $7")
    keystone_test(KS_ARCH_MIPS, KS_MODE_MIPS64, b"and $9, $6, $7")
    keystone_test(
        KS_ARCH_MIPS, KS_MODE_MIPS64 + KS_MODE_BIG_ENDIAN, b"and $9, $6, $7")

    # PowerPC
    keystone_test(
        KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN, b"add 1, 2, 3")
    keystone_test(KS_ARCH_PPC, KS_MODE_PPC64, b"add 1, 2, 3")
    keystone_test(
        KS_ARCH_PPC, KS_MODE_PPC64 + KS_MODE_BIG_ENDIAN, b"add 1, 2, 3")

    # Sparc
    keystone_test(
        KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_LITTLE_ENDIAN, b"add %g1, %g2, %g3")
    keystone_test(
        KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_BIG_ENDIAN, b"add %g1, %g2, %g3")

    # SystemZ
    keystone_test(KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN, b"a %r0, 4095(%r15,%r1)")


if __name__ == '__main__':
    test()
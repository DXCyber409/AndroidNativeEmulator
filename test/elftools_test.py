import msvcrt
from elftools.common import *
from elftools.elf.elffile import ELFFile

with open('jnilibs/libnative-lib.so', 'rb') as f:
    elf = ELFFile(f)

    print(type(elf))
    for seg in elf.iter_segments():
        print(seg['p_type'], hex(seg['p_offset']), hex(seg['p_vaddr']), hex(seg['p_paddr']))
    exit()

    sec_num = elf.num_sections()
    print('sec_num:' + str(sec_num))
    seg_num = elf.num_segments()
    print('seg_num:' + str(seg_num))
    
    for i in range(0, sec_num, 1):
        section = elf.get_section(i)
        print(section);print(type(section))
        print(section.data_alignment, section.data_size, str(section.data(), encoding='ISO-8859-1'))
        msvcrt.getch()

    # for i in range(0, seg_num, 1):
    #     segment = elf.get_segment(i)
    #     print(str(segment.data(), encoding='ISO-8859-1'))
        # print(segment)
        # print(segment.data_alignment, section.data_size, str(section.data(), encoding='ISO-8859-1'))
        # msvcrt.getch()
        

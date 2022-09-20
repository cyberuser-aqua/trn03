import sys


def main(*args):
    symbol = args[1]
    kallsyms = open('/proc/kallsyms', 'r')
    for line in kallsyms.readlines():
        addr, type, name, *_ = line.split()
        if name == symbol:
            print(f'0x{hex(addr)}')
            return


if __name__ == '__main__':
    main(*sys.argv)

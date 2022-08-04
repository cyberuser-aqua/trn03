import ctypes as c


class llist_node(c.Structure):
    pass


llist_node._fields_ = [
    ('next', c.POINTER(llist_node))
]


class __call_single_node(c.Structure):
    _fields_ = [
        ('llist', llist_node),
        ('u_flags', c.c_uint32)
    ]


class atomic_t(c.Structure):
    _fields_ = [
        ('counter', c.c_int32)
    ]


class refcount_struct(c.Structure):
    _fields_ = [
        ('refs', atomic_t)
    ]


class task_struct(c.Structure):
    pass


task_struct._fields_ = [
    ('__state', c.c_uint32),
    ('stack', c.c_void_p),
    ('usage', refcount_struct),
    ('flags', c.c_uint32),
    ('ptrace', c.c_uint32),
    ('on_cpu', c.c_int32),
    ('wake_entry', __call_single_node),
    ('wakee_flips', c.c_uint32),
    ('wakee_flip_decay_ts', c.c_uint32),
    ('last_wakee', c.POINTER(task_struct)),
    ('recent_used_cpu', c.c_int32),
    ('wake_cpu', c.c_int32),
    ('on_rq', c.c_int32),
    ('prio', c.c_int32),
    ('static_prio', c.c_int32),
    ('normal_prio', c.c_int32),
    ('rt_priority', c.c_uint32),
    ('sched_class', c.c_void_p),
    ('')
]

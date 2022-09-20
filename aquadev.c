#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fdtable.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include "asm/pgtable.h"

unsigned char a[10] = "Hello!";

static int aqua_open(struct inode *inode, struct file *file)
{
    printk("AQUA: Device open\n");
    file->f_mode |= FMODE_UNSIGNED_OFFSET;
    return 0;
}

loff_t aqua_llseek(struct file *file, loff_t offset, int whence)
{
    printk("AQUA: Device seek to %llx \n", offset);
    file->f_pos = offset;
    return offset;
}

static ssize_t aqua_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
    printk("AQUA: Device read at %x \n", (unsigned int)file->f_pos);

    if (copy_to_user(buf, (void *)file->f_pos, count))
    {
        printk("WARN: Partial data was written. Rest was padded with zeros.");
        return -EFAULT;
    }

    return count;
}

static ssize_t aqua_write(struct file *file, const char __user *buf, size_t count, loff_t *offset)
{
    printk("AQUA: Device write at %llx\n", file->f_pos);
    if (copy_from_user((void *)file->f_pos, buf, count))
        return EFAULT;

    return 0;
}

static int aqua_release(struct inode *inode, struct file *file)
{
    printk("AQUA: Device close\n");

    return 0;
}

// static int get_ttbr1(void)
// {
//     asm volatile(
//         "mrc	p15, 0, r0, c2, c0, 1		@ read TTBR1");
//     register int r0 asm("r0");
//     return r0;
// }

static long aqua_ioctl(struct file *file, unsigned int cmd, unsigned long data)
{
    printk("AQUA: ioctl\n");
    switch (cmd)
    {
    case 0x1337:
        printk("private_data: %x=%x",
               (unsigned int)current->files->fdt->fd[3]->private_data, *(unsigned int *)current->files->fdt->fd[3]->private_data);
        return (long)current;
    default:
        break;
    }
    return 0;
}

static const struct file_operations aqua_fops = {
    .owner = THIS_MODULE,
    .open = aqua_open,
    .release = aqua_release,
    .read = aqua_read,
    .write = aqua_write,
    .llseek = aqua_llseek,
    .unlocked_ioctl = aqua_ioctl};

// global storage for device Major number
static int dev_major = 0;

struct cdev cdev;

// sysfs class structure
static struct class *aqua_class = NULL;

static int aqua_uevent(struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

void init_char(void)
{
    int err;
    dev_t dev;

    // allocate chardev region and assign Major number
    err = alloc_chrdev_region(&dev, 0, 1, "aqua"); // TODO: ERROR

    dev_major = MAJOR(dev);

    // create sysfs class
    aqua_class = class_create(THIS_MODULE, "aqua");
    aqua_class->dev_uevent = aqua_uevent;
    // init new device
    cdev_init(&cdev, &aqua_fops);
    cdev.owner = THIS_MODULE;

    // add device to the system where "i" is a Minor number of the new device
    cdev_add(&cdev, MKDEV(dev_major, 0), 1);

    // create device node /dev/mychardev-x where "x" is "i", equal to the Minor number
    device_create(aqua_class, NULL, MKDEV(dev_major, 0), NULL, "aqua");
}

void destroy_char(void)
{
    device_destroy(aqua_class, MKDEV(dev_major, 0));
    class_unregister(aqua_class);
    class_destroy(aqua_class);
    unregister_chrdev_region(MKDEV(dev_major, 0), MINORMASK);
}

static int aqua_init(void)
{
    init_char();
    printk("Loaded aquadev\n");
    // printk("a=%px, task size=%d, comm offset=%d next offset=%d pid offset=%d\n",
    //        &a, sizeof(struct task_struct), (long)(&init_task.comm) - (long)(&init_task), (long)(&init_task.tasks.next) - (long)(&init_task), (long)(&init_task.pid) - (long)(&init_task));
    return 0;
}

static void aqua_exit(void)
{
    destroy_char();
    printk("%s\n", "Unloaded aquadev");
    return;
}

module_init(aqua_init);
module_exit(aqua_exit);
MODULE_LICENSE("GPL");

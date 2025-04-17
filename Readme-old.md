LPNS Artifact Evaluation README
============

## 1. LPNS Artifact Overview
The artifact of LPNS is a full virtualization solution for NVMe storage. So all the implementations of LPNS can be included in a Linux kernel source code directory. For the artifact evaluation of our LPNS paper, we rename the source code directory into **LPNS-kernel** (also referred as ``$KERNEL_SRC`` in the following texts).

<!-- ### 1. Main Architecture -->

LPNS design is based on mediated pass-through (by using vfio-mdev support of Linux), so we implement a kernel module (**nvme-mdev.ko**) to provide virtualized storage with full NVMe features to guest VMs, and it can coexist and cooperate with the original nvme.ko module (the NVMe driver) to
support the hybrid deployment of host processes, containers, VMs on each single NVMe SSD. 

The main functions of LPNS are in ``$KERNEL_SRC/drivers/nvme/`` directory：
* Some modification are in the ``$KERNEL_SRC/drivers/nvme/host/`` directory, including the modification to ``$KERNEL_SRC/drivers/nvme/host/pci.c``, ``$KERNEL_SRC/drivers/nvme/host/core.c`` and ``$KERNEL_SRC/drivers/nvme/host/nvme.h``. These code modifications are aimed to extend some functions of the original NVMe driver to export interfaces for the virtualized NVMe storage devices created by mediated-pass-through virtualization.
* A new dirctory ``$KERNEL_SRC/drivers/nvme/mdev`` are created for bulding a new kernel module **nvme-mdev.ko**. We briefly introduce the main functions of these source codes. For example, ``$KERNEL_SRC/drivers/nvme/mdev/adm.c`` is for admin queue resource management. ``$KERNEL_SRC/drivers/nvme/mdev/vsq.c`` and ``$KERNEL_SRC/drivers/nvme/mdev/vcq.c`` are for the I/O queue resouce management. ``$KERNEL_SRC/drivers/nvme/mdev/(instance.c, vns.c, pci.c, vctrl.c)`` are used for virtual device creation and management. ``$KERNEL_SRC/drivers/nvme/mdev/host.c`` are used for the NVMe hardware management, the vfio-mdev support, and the entire nvme-mdev creation and management. ``$KERNEL_SRC/drivers/nvme/mdev/io.c`` contains the polling mechanism for performance detection, optimization, and I/O throttling, etc.
* There are some other small modifications in ``$KERNEL_SRC//include/linux/vfio.h``, ``$KERNEL_SRC//include/linux/vfio.h``, and ``$KERNEL_SRC//include/linux/mdev.h``. 


As we described in the paper, LPNS designs a performance detector, a queue scheduler, and a command scheduler for predictable latency enhancement, and it provides a flexible polling mechanism for better virtualization scalability. These functions are mainly in ``$KERNEL_SRC/drivers/nvme/mdev/(vsq.c, vcq.c, vctrl.c, host.c, io.c)``.

## 2. Building LPNS System

* Please enter the **LPNS-kernel** directory, for example:
```
$ cd ./LPNS-AE/LPNS-kernel/
```
* Please change the kernel configuration file ``.config`` file. Please turn on the CONFIG_VFIO_MDEV, CONFIG_NVME_MDEV. On the SR-IOV-capable Samsung PM1735 SSD, Please make sure that CONFIG_NVME_MULTIPATH=n so we can run LPNS on the SSD.

```
$ make menuconfig
```
P.S. We provide a template file config-5.0.0ADLP+ with the necessary Kconfig for LPNS, which can be used by ``cp config-5.0.0ADLP+ .config`` before using ``make menuconfig``.

* Please compile and install the kernel, update grub, and reboot the server:
```
$ make -j 100
$ sudo su
# make modules_install -j 100
# make install
# vim /etc/default/grub
# update-grub
# reboot
```

* Please check the kernel version of LPNS:
```
$ uname -r
$ 5.0.0ADLP+
```

## 3. Using LPNS for virtualized devices.

First of all, we use the following example shell commands to show how we can set up a qemu/kvm virtual machine and attach the LPNS-virtualized NVMe device to it.

```
# 首先得删掉这个 mod
$ rmmod nvme-mdev
$ rmmod nvme
# Please load the nvme pci driver with $TOTAL_QUEUES$ (in the case, 8) I/O queues into the hardware queue pool, and configure the $Omega$ parameter (in the case, 280)
$ modprobe nvme-mdev mdev_device_num=8 total_threshold=280  # load the nvme-mdev driver
$ modprobe nvme mdev_queues=8

# Please use the real NVMe device BDF
$ PCI_DEVICE=/sys/bus/pci/devices/0000:XX:00.0 

# Please generate random UUID for each mediated device
$ UUID=$(uuidgen) 
$ MDEV_DEVICE=/sys/bus/mdev/devices/$UUID

# Please create the mediated device using N (in the case, N=2) I/O queues from the hardware queue pool,and LPNS hyervisor can allocate, schedule, and re-arrange the $TOTAL_QUEUES$  I/O queues to provide queues for each virtual device.
$ echo $UUID > $PCI_DEVICE/mdev_supported_types/nvme-2Q_V1/create 


# Please attach partition X (in the case, X=1) of namespace Y (in the case, Y=1) to a free virtual namespace
# We provide a scripts/LP_partition.sh script file to generate several partitions on one SSD for multiple VM experiments.
$ echo n1p1 > $MDEV_DEVICE/namespaces/add_namespace

# Please bind the polling thread to cpu core X (in the case, 40)
$ echo 40> $MDEV_DEVICE/settings/iothread_cpu

# Please configure if the VM is a latency-predictable VM (N=2, else N=0);
echo 2 > ${MDEV_DEVICE_1}/settings/qos

# Please add these configuration to qemu script, and boot the VM
#  -device vfio-pci,sysfsdev=/sys/bus/mdev/devices/$UUID
```

We provide **scripts/start_vm_N_Q_C.sh** as an example to create several VMs on LPNS. Since the maximum size of the attachment file is 600MB, we cannot provide the VM rootfs img for evaluation. Please create the qcow2 img for each VM and install a linux kernel for the VM. The VM needs no kernel changes and builds.

## 4. Running the experiments in our Paper

For comparison with K2, MQFQ, and D2FQ, we provide the **LPNS-AE/spdk** directory and **LPNS-AE/k2-scheduler** directory. We also provide a **LPNS-AE/mqfq-patch** and a **LPNS-AE/d2fq-patch** based on the original source of D2FQ (https://github.com/skkucsl/d2fq). We also provide a modified **d2fq-fio** directory for D2FQ experiments.

In the **LPNS-AE/evaluation** directory, we provide the experiment script.

### Micro Benchmark

In **LPNS-AE/evaluation-scripts** directory， we provide one **lat.fio** script, which can be used in the latency-predicable VM, and one **inten.fio** script for the VM without latency-predicable QoS. Please change the **numjobs** and **iodepth** parameter of **inten.fio** script for different test cases.

We also provide a **LPNS-AE/spdk** directory where we have set up the vhost configuration files (for example, **vhost.01** to **vhost.08**), which can be used to virtualize NVMe devices for multiple VMs.


### Application Benchmark

* For virtualized devices

In **LPNS-AE/evaluation-scripts** directory，we provide the application benchmark environments. Please copy the **inside-vm** directory into each test VM.

In **run_workloads** directory, there are the benchmark scripts for different storage virtualization and QoS-control systems.

Please run the following scripts for evaluation reproduction.

```
$ cd LPNS-AE/evaluation-scripts/run_workloads
$ sudo ./adlp_benchmark.sh LP  # collecting LPNS results
$ sudo mdev-sriov_benchmark.sh SRIOV #collecting SRIOV results (on PM1735)
```
* For native comparison experiments:

In **LPNS-AE/evaluation-scripts/k2**, **LPNS-AE/evaluation-scripts/d2fq**, **LPNS-AE/evaluation-scripts/mqfq**, we can run the following scripts:

```
$ ./K2_benchmarks.sh
$ ./D2FQ_benchmarks.sh
$ ./MQFQ_benchmarks.sh
```
These scripts use hard code for the number of VMs. Please change the parameters if necessary.


编译驱动模块：
```bash
make M=drivers/nvme
```

编译全部模块：
```
sudo su

make -j 100
make INSTALL_MOD_STRIP=1 modules_install -j 100
make install
update-grub
```


```
dmesg -T --follow | grep nvme > ./nvme.log
```



```
qemu-system-x86_64   -hda focal-server-cloudimg-amd64-01.img   -m 4G   -smp 4   -M pc   -cpu host -enable-kvm -machine kernel_irqchip=on   -boot c   -net nic   -net user,hostfwd=tcp::2222-:22   -vnc :1   -name "MyVM1"   -device vfio-pci,sysfsdev=/sys/bus/mdev/devices/5ebb9deb-e018-4b8a-a3a0-d4a89f591e53

/usr/local/qemu-7.2.0/bin/qemu-system-x86_64 \
  -hda /home/zzq/Downloads/LPNS/ubuntu-20.04-server-cloudimg-amd64-01.img \
  -m 4G \
  -smp 4 \
  -M pc \
  -cpu host \
  -enable-kvm \
  -machine kernel_irqchip=on \
  -boot c\
  -net nic \
  -net user,hostfwd=tcp::2222-:22 \
  -vnc :1 \
  -name "MyVM1" \
  -drive file=/home/zzq/Downloads/LPNS/config.img,format=raw,if=virtio




rmmod nvme-mdev
rmmod nvme
modprobe nvme-mdev mdev_device_num=8 total_threshold=280 
modprobe nvme mdev_queues=8
PCI_DEVICE=/sys/bus/pci/devices/0000:08:00.0
UUID=$(uuidgen)
MDEV_DEVICE=/sys/bus/mdev/devices/$UUID
echo $UUID > $PCI_DEVICE/mdev_supported_types/nvme-2Q_V1/create
echo n1p5 > $MDEV_DEVICE/namespaces/add_namespace
echo 8> $MDEV_DEVICE/settings/iothread_cpu
echo 2 > ${MDEV_DEVICE}/settings/qos



/usr/local/qemu-7.2.0/bin/qemu-system-x86_64 \
  -hda /home/zzq/Downloads/LPNS/ubuntu-20.04-server-cloudimg-amd64-01.img \
  -m 4G \
  -smp 4 \
  -M pc \
  -cpu host \
  -enable-kvm \
  -machine kernel_irqchip=on \
  -boot c \
  -net nic \
  -net user,hostfwd=tcp::2222-:22 \
  -vnc :1 \
  -name "MyVM1" \
  -device vfio-pci,sysfsdev=/sys/bus/mdev/devices/ec92bea0-8561-4429-8033-adaf7a089914 \
  -drive file=/home/zzq/Downloads/LPNS/seed.img,format=raw,if=virtio
```
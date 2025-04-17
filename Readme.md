

编译驱动模块：
```bash
make M=drivers/nvme
```

编译全部模块：
```
sudo su

make -j 100
make modules_install -j 100
make install
update-grub
```



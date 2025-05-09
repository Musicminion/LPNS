# /bin/bash

sudo su
cd ./linux-5.15.173

make -j 100
make INSTALL_MOD_STRIP=1 modules_install -j 100
make install
update-grub




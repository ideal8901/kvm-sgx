make -j 8
sudo make install
sudo make modules_install SUBDIR=arch/x86/kvm -j 8
#sudo make modules_install SUBDIR=arch/x86/kernel -j 8
sudo rmmod kvm_intel
sudo rmmod kvm  
sudo insmod arch/x86/kvm/kvm.ko
sudo insmod arch/x86/kvm/kvm-intel.ko

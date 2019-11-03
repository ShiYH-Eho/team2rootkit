# 进程隐藏
在不高于4.6的内核上测试功能没问题，将pid=1的进程即systemed隐藏。

编译
'''
make
'''
首先查看pid最小的前几个进程
'''
ps -e | head -4
'''
导入pshidko.ko
'''
sudo insmod pshidko.ko
'''
再次查看pid最小的前几个进程，pid=1的systemed已经被隐藏
'''
ps -e | head -4
'''
卸载lkm
'''
sudo rmmod pshidko
'''

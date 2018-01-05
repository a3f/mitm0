obj-m := uman.o
MY_CFLAGS += -g -DDEBUG
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules EXTRA_CFLAGS="$(MY_CFLAGS)"
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
insmod:
	sudo insmod $(obj-m:.o=.ko)

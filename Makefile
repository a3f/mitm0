obj-m := uman.o
MY_CFLAGS += -g -DDEBUG
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

SLAVE_IF ?= enp0s9

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules EXTRA_CFLAGS="$(MY_CFLAGS)"
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
insmod:
	sudo insmod $(obj-m:.o=.ko)
rmmod:
	sudo rmmod $(obj-m:.o=)
enslave:
	sudo sh -c 'printf $(SLAVE_IF) > /sys/kernel/debug/uman0/slave'
get_slave:
	sudo cat /sys/kernel/debug/uman0/slave

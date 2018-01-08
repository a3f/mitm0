obj-m := uman.o
MY_CFLAGS += -g -DDEBUG
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

SLAVE_IF ?= enp0s8

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules EXTRA_CFLAGS="$(MY_CFLAGS)"
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
insmod:
	sudo insmod $(obj-m:.o=.ko)
	dmesg -wH
rmmod:
	sudo rmmod $(obj-m:.o=)
	dmesg -wH
probe:
	@lsmod | grep $(obj-m:.o=) || echo Module not loaded.
slave_up:
	sudo ifconfig $(SLAVE_IF) up
	sudo dhclient $(SLAVE_IF)
	nc -l $(shell ifconfig uman0 | grep "inet " | awk -F'[: ]+' '{ print $$4 }') 1337

nc:
	nc -l $(shell ifconfig uman0 | grep "inet " | awk -F'[: ]+' '{ print $$4 }') 1337

slave_down:
	sudo ifconfig $(SLAVE_IF) down

enslave:
	sudo sh -c 'printf $(SLAVE_IF) > /sys/kernel/debug/uman0/slave'
release:
	sudo sh -c 'echo > /sys/kernel/debug/uman0/slave'
get_slave:
	sudo cat /sys/kernel/debug/uman0/slave
flush_slave_ip:
	sudo ip addr flush dev $(SLAVE_IF)

dmesg:
	dmesg -wH

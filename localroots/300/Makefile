
KERNEL_DIR := /lib/modules/$(shell uname -r)/build

obj-m := vuln_kmod.o                                                                                    
PWD := $(shell pwd)                                                                                        
default:                                                           
	make -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules
clean:                                                                                                     
	make -C $(KERNEL_DIR) SUBDIRS=$(PWD) clean                                                 

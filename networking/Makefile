
KERNEL_DIR := /lib/modules/$(shell uname -r)/build

obj-m := fw.o                                                                                    
PWD := $(shell pwd)                                                                                        
#ccflags-y := -O0                                                                                          
default:                                                                                                   
	make -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules
clean:                                                                                                     
	make -C $(KERNEL_DIR) SUBDIRS=$(PWD) clean                                                 

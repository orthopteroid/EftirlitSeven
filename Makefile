# eftirlit7 (gpl3) - orthopteroid@gmail.com
# forked from douane-lkms (gpl3) - zedtux@zedroot.org

MODULE_NAME=eftirlit7
MODULE_VERSION=0.1
MODULE_AUTHOR=orthopteroid@gmail.com

MOD_DEFINES=-DMOD_NAME=\"$(MODULE_NAME)\" -DMOD_VERSION=\"$(MODULE_VERSION)\" -DMOD_AUTHOR=\"$(MODULE_AUTHOR)\"

#EXTRA_CFLAGS=-g $(MOD_DEFINES)
EXTRA_CFLAGS=-g $(MOD_DEFINES) -DDEBUG

# obj-m, <something>-y and <something>-objs inform the make and kbuild module
# machinery what is being built. multifile modules appear to need to be located
# in a subfolder otherwise module initializers are clobbered.
# related - https://stackoverflow.com/a/13642063
obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-objs += src/module.o src/douane.o src/ksc.o src/rules.o src/netlink.o src/asc.o src/prot_udp.o src/prot_tcp.o

PRJ_ROOT=$(shell pwd)
DKMS_ROOT=/usr/src/$(MODULE_NAME)-$(MODULE_VERSION)
BOOT_MODULES=/etc/modules
CHECK_LOADED=$(shell lsmod | grep $(MODULE_NAME))

# ensure current path is set
ifeq ($(M),)
M=.
endif

# ensure kernel version is set
ifeq ($(KERNEL_VERSION),)
KERNEL_VERSION=$(shell uname -r)
endif

### development

all:
	$(MAKE) -C /lib/modules/$(KERNEL_VERSION)/build M=$(PRJ_ROOT) modules

clean:
	@rm -f dkms.conf
	$(MAKE) -C /lib/modules/$(KERNEL_VERSION)/build M=$(PRJ_ROOT) clean

install:
	@echo "Installing Douane Linux kernel module..."
	@insmod $(MODULE_NAME).ko

uninstall:
	@echo "Uninstalling Douane Linux kernel module..."
	@rmmod $(MODULE_NAME).ko

reinstall:
	$(MAKE) uninstall
	$(MAKE) install

### DKMS

dkms:
	@echo "Installing kernel module version $(MODULE_VERSION)..."
	@mkdir -p $(DKMS_ROOT)
	@mkdir -p $(DKMS_ROOT)/src
	@rm -f $(DKMS_ROOT)/dkms.conf
	@echo "PACKAGE_NAME=\"$(MODULE_NAME)\"" >> $(DKMS_ROOT)/dkms.conf
	@echo "PACKAGE_VERSION=\"$(MODULE_VERSION)\"" >> $(DKMS_ROOT)/dkms.conf
	@echo "BUILT_MODULE_NAME[0]=\"$(MODULE_NAME)\"" >> $(DKMS_ROOT)/dkms.conf
	@echo "DEST_MODULE_LOCATION[0]=\"/kernel/net/$(MODULE_NAME)/\"" >> $(DKMS_ROOT)/dkms.conf
	@echo "STRIP[0]=\"no\"" >> $(DKMS_ROOT)/dkms.conf
	@echo "AUTOINSTALL=\"yes\"" >> $(DKMS_ROOT)/dkms.conf
	@cp $(PRJ_ROOT)/src/* $(DKMS_ROOT)/src
	@cp $(PRJ_ROOT)/Makefile $(DKMS_ROOT)
	@dkms add -m $(MODULE_NAME) -v $(MODULE_VERSION)
	@dkms build -m $(MODULE_NAME) -v $(MODULE_VERSION)
	@dkms install --force -m $(MODULE_NAME) -v $(MODULE_VERSION)
	@echo "Loading kernel module..."
	@modprobe $(MODULE_NAME)
	@echo "Adding kernel module to the $(BOOT_MODULES) file ..."
	@echo "$(MODULE_NAME)" >> $(BOOT_MODULES)

cleandkms:
	@if [ ! -z "$(CHECK_LOADED)" ]; then \
		echo "Uninstalling kernel module...";\
		rmmod $(MODULE_NAME);\
	fi
	@sed -i s'/^douane$$//' $(BOOT_MODULES)
	@echo "Removing kernel module..."
	@dkms remove -m $(MODULE_NAME) -v $(MODULE_VERSION) --all
	@rm -rf $(DKMS_ROOT)

rebuilddkms:
	$(MAKE) cleandkms; \
	$(MAKE) dkms

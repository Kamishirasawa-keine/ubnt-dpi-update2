.PHONY: all clean

CROSS ?= mipsel-linux-musl

all: package.deb

clean:
	rm -f data.tar.gz control.tar.gz debian-binary package.deb usr/sbin/tdts-dpi-dump

usr/sbin/tdts-dpi-dump: src/tdts-dpi-dump.c src/tdts_shell_ioctl.h
	mkdir -p usr/sbin
	$(CROSS)-gcc -Os -Wall -march=mips32r2 -static -o $@ src/tdts-dpi-dump.c
	$(CROSS)-strip $@

data.tar.gz: etc opt usr/sbin/tdts-dpi-dump
	tar --owner=root:0 --group root:0 -czf $@ etc opt usr

control.tar.gz: control
	tar --owner=root:0 --group root:0 -czf $@ control

debian-binary:
	echo 2.0 > $@

package.deb: debian-binary control.tar.gz data.tar.gz
	rm -f $@
	ar -rcs $@ $^
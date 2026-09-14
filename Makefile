.PHONY: all clean

all: package.deb

clean:
	rm -f data.tar.gz control.tar.gz debian-binary package.deb

data.tar.gz: etc opt usr
	tar --owner=root:0 --group root:0 -czf $@ etc opt usr

control.tar.gz: control
	tar --owner=root:0 --group root:0 -czf $@ control

debian-binary:
	echo 2.0 > $@

package.deb: debian-binary control.tar.gz data.tar.gz
	rm -f $@
	ar -rcs $@ $^
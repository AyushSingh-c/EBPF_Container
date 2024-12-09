.PHONY: all clean src

ROOT_DIR ?= $(CURDIR)


all: src

src:
	rm -rf bin/sensor
	$(MAKE) -C src ROOT_DIR=$(ROOT_DIR)

clean:
	$(MAKE) -C src clean
	rm -rf $(ROOT_DIR)/bin
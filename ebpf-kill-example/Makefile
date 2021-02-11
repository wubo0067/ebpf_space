.PHONY: clean build deps test libbpf

deps:
	sudo apt update
	sudo apt install -y build-essential git make gcc clang llvm libelf-dev
	git submodule update --init

libbpf:
	$(MAKE) --directory=libbpf/src all
	DESTDIR=root $(MAKE) --directory=libbpf/src install_headers

build: libbpf
	$(MAKE) --directory=src

clean:
	$(MAKE) --directory=src clean
	$(MAKE) --directory=libbpf/src clean

test:
	./test/test.sh

.DEFAULT_GOAL := build

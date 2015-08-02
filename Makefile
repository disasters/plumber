run: build
	LD_PRELOAD=target/debug/libplumber.so strace -e connect nc localhost 79

build:
	cargo build

test:
	cargo test

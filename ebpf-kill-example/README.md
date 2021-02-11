# ebpf-kill-example

*ebpf-kill-example* is an example of an eBPF program hooking into the kill tracepoint.
This project is a Proof-of-Concept (PoC) showing the feasibility and viability of eBPF.
Furthermore, the project shows how to create and run a simple eBPF program.

## Installation

To install ebpf-kill-example, first clone this repository.

```
git clone https://github.com/niclashedam/ebpf-kill-example
```

Install dependencies needed to compile *ebpf-kill-example*.

```
make deps
```

Compile *ebpf-kill-example*.

```
make
```

## Usage

Run *ebpf-kill-example*. Super user privileges are required to load the program into the kernel.

```
sudo ./src/ebpf-kill-example
```

## Test

To test *ebpf-kill-example*, run `make test`.
This will load the eBPF program, start a looping process and kill it. It will
verify that the eBPF program was invoked when kill was called.

```
nhed@nhed-1:~/Development/ebpf-kill-example$ make test
./test/test.sh
-- Loading eBPF program.
-- Starting test process to kill.
-- PID of test process is 332996.
-- Killed. Waiting for eBPF program to terminate ..
[ OK ] -- eBPF program ran as expected.
```

## Example
![Example](/img/example.png?raw=true)

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[GPLv3](https://choosealicense.com/licenses/gpl-3.0/)

# BC-PQP in eBPF [![Build](https://github.com/ftschirpke/BC-PQP-eBPF/actions/workflows/build.yml/badge.svg)](https://github.com/ftschirpke/BC-PQP-eBPF/actions/workflows/build.yml)

The goal of this project is to implement [BC-PQP](https://doi.org/10.1145/3651890.3672267) using eBPF in XDP.

## Building

We use `make` and `bash` to run commands, so you will need to have those installed. The entire build process then happens inside docker/podman (you only need one of the two), also `tar` is used to extract some files from the image which are needed to later run this image as a VM. To compile the code and build a container which can later be used to execute the eBPF program inside a VM, run

```sh
make container
```

If you wish to compile the code on your host (and not in a container), you can run 

```sh
make build
```

This will generate 2 object files: one with logging statements enabled, one without. For a list of build dependencies, please refer to the build stage of our [Dockerfile](./Dockerfile)

## Running

We use [virt-manager](https://virt-manager.org/) to launch a VM where we can then load and test bc-pqp-ebpf. To route traffic through this VM we also set up some network interfaces on your host (for more info see the [script](./scripts/host_network_setup.sh)). For both of these things you will need to have root access to your host.

To launch the VM, run

```sh
make qemu
```

The VM will launch and attach a TTY to your terminal. Once startup is complete, you will be automatically logged in as root to the VM. All build artifacts as well as some helper scripts are located in the home directory. To load bc-pqp-ebpf into the VM, run

```sh
./load.sh # loads simple-bc-pqp-ebpf-kernel.o by default
# or
# ./load.sh sharded-bc-pqp-ebpf-kernel.o
# run the following to insert the program with logs enabled
# ./load.sh debug_simple-bc-pqp-ebpf-kernel.o
# the logs can then be viewed by running
# ./logs.sh
# To do both of these things at once, run
# ./watch.sh debug_simple-bc-pqp-ebpf-kernel.o
```

Building the code and starting the VM can also be done with one command:

```sh
make
```

## Testing

We provide some test suites to verify the behavior of bc-pqp-ebpf. These scripts use (depending on the suite) `iperf3`, `ping`, `flent` and `tcpdump`.

To get started, first build and run the VM as described above. Then run your desired test suite (from your host, not from the VM) by invoking the desired subcommand of the `./scripts/suites.sh` [script](./scripts/suites.sh).

For an overview of available suites, run

```sh
./scripts/suites.sh --help
```

## License

`SPDX-License-Identifier: GPL-2.0-or-later`

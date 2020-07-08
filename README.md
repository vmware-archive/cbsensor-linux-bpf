
# cbsensor-linux-bpf

## Overview
The cbsensor-linux-bpf project currently provides a [BCC](https://github.com/iovisor/bcc) compatibile BPF C source code for general process, file and network events.

## Try it out
Run the examples [script](examples/bcc_sample.py) on your favorite Linux distro with BCC. Just run with root-like privileges, or whatever privileges you need to load a BPF program.

```bash
sudo ./examples/bcc_sample.py ./src/bcc_sensor.c
```

### Prerequisites
* Works on 4.4 kernels and newer!
* bcc or libbpf for Ubuntu distros
* More bleeding edge kernels might require a newer version of BCC your distro provides

## Documentation

### Limitations and Known Issues
1. Endianness on ports for network events are not all host aligned yet
2. 4.4 kernels may experience some event data integrity issues
3. Filepaths have a hard limit on path components returned

### Roadmaped Enhancements
1. Basic packet dropping via `tc` BPF interface
2. Inode Delete Events
3. Retrieve files open for exec recursively

### Long Term Goals
A potential goal for this project is to eventually create a path to a libbpf + CO-RE BPF based project.

## Contributing
The cbsensor-linux-bpf project team welcomes contributions from the community. Before you start working with cbsensor-linux-bpf, please
read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).
[CONTRIBUTING.md](CONTRIBUTING.md)

## License
The cbsensor-linux-bpf licenses the BPF kernel space source code under [GNU GPL v2.0](LICENSE-GPL2.0). The example usage source code is licensed under [BSD 2](LICENSE-BSD2).

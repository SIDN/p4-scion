# P4 implementation of SCION

**This is a prototype implementation and is currently not intended for use in production.**

This is a P4 implementation of a SCION border router. It comes with several control plane applications and services.

A blog on this implementation can be found on our website: 
[Future internet at terabit speeds: SCION in P4](https://www.sidnlabs.nl/nieuws-en-blogs/future-internet-at-terabit-speeds-scion-in-p4)

## Build

Start by initialising the git submodules:
```
git submodule update --init --recursive
```

Compile the P4 code with the build script from the SDE (optionally, use `P4FLAGS="-Xp4c=--parser-bandwidth-opt"` to optimise the parser):
```
./p4_build.sh p4src/scion.p4
```

Make sure that the `PORT_CPU` constant in `scion.p4` matches with the port that will be used later to receive packets on for processing the one-hop paths in the control plane.

By default support for both IPv4 and IPv6 is enabled. This can be disable by using the flag `-DDISABLE_IPV4` or `-DDISABLE_IPV6` respectively. Note that the flags cannot be used at the same time.

Follow the instructions in `controller/README.md` to prepare the control plane applications and services.

Follow the instructions in `scion-patch/README.md` to add the functionality to the SCION code to register the generated hop fields.

## Usage

Run the P4 code as follows:
```
$SDE/run_switchd.sh -p scion
```

In `example_setup/README.md`, an explanation can be found to run the P4 implementation using the Tofino model and two VMs.

## Limitations

Currently the following features are not yet provided:
- Peering connections
- BFD support to detect link failures between border routers
- Mixing of IPv4 and IPv6
- Support to process EPIC and COLIBRI paths 

## Authors

- Joeri de Ruiter, SIDN Labs
- Caspar Schutijser, SIDN Labs

## License

This project is distributed under the 3-Clause BSD License, see [LICENSE](LICENSE).

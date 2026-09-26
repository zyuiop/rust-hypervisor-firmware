# Rust Hypervisor Firmware

This repository is forked from Cloud Hypervisor, as modified by authors of SEVeriFast in 2022.

It was adapted slightly in order to boot Hermit kernels, which are relocatable.

It has two branches:

- `sev-snp`: support for booting bzimage kernels (only Linux)
- `sev-snp-directboot`: support for booting decompressed elf kernels (Linux/Hermit)

Changes from the SEVeriFast paper:

- Linux SEV-SNP Hosts now ignore the page size argument in the GHCB MSR when trying to change private/shared status of pages. When changing page size, we therefore now need to use only 4 Kib pages.
- Hermit guests require an already existing GHCB for early boot. Therefore, we move the pre-allocated GHCB to low address space (addr. 0x3000), and map the first 2 MiB of memory using standard 4 KiB pages.
- We updated some libraries
- We skip kernel hash verification, as we only used this library for benchmarking.

**THIS IS A RESEARCH PROJECT, WHICH SHOULD NOT BE RELIED UPON FOR SECURITY. SOME SECURITY FEATURES HAVE BEEN DISABLED.**
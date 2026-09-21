use core::cmp::max;
use core::mem;
use core::mem::{size_of, MaybeUninit};
use goblin::elf64::dynamic::{Dyn, DynamicInfo};
use goblin::elf64::header::header64;
use goblin::elf64::program_header::ProgramHeader;
use goblin::elf64::{reloc, sym};
use goblin::elf64::reloc::{r_to_str, reloc64, Rela};
use goblin::elf64::section_header::SHN_UNDEF;
use goblin::elf64::sym::{sym64, Sym, STB_WEAK};
use goblin::elf::program_header;
use plain::Plain;
use x86_64::{
    instructions::port::Port,
};

use crate::{
    boot::{BootE820Entry, CCBlob, Header, SetupData, SETUP_CC_BLOB},
    ghcb::{self, Ghcb},
    loader::{
        self, Kernel, CPUID_PAGE_ADDR, CPUID_PAGE_LEN, SECRETS_PAGE_ADDR, SECRETS_PAGE_LEN,
        ZERO_PAGE_START,
    },
    mem::MemoryRegion,
    paging,
};
use sha2::Digest;
use sha2::Sha256;
use x86_64::structures::paging::{PageSize, Size2MiB};

// load the kernel at 2mib in encrypted memory
// Firecracker puts kernel at 32mib
pub const KERNEL_ADDR: u64 = 0x1000000 - 0x200000;

pub const KERNEL_LOAD_ADDR: u64 = 0x1000000;
// Max bzImage length (16MiB)

const DEBUG_PORT: u16 = 0x80;
const FW_CFG_REG: u16 = 0x81;
const FW_CFG_DATA_BASE: u64 = 0x1000000 - 0x200000;
const FW_CFG_DATA_SIZE: u64 = 0x200000;
const FW_ADDR: u64 = 0x100000;

// Debug codes
const COPY_START: u8 = 0x50;
const COPY_END: u8 = 0x51;
const INITRD_COPY_START: u8 = 0x52;
const INITRD_COPY_END: u8 = 0x53;
const HASH_START: u8 = 0x60;
const HASH_END: u8 = 0x61;
const INITRD_HASH_START: u8 = 0x62;
const INITRD_HASH_END: u8 = 0x63;


const ELF_HDR_SIZE: usize = size_of::<header64::Header>();
const ELF_PHDR_SIZE: usize = size_of::<ProgramHeader>();


enum Command {
    ///Get the type of kernel to load, should be the first command issued
    // KernelType,
    ///For a direct boot, send the ELF header
    ElfHdr,
    ///For a direct boot, get the next phdr
    PhdrData,
    ///Start reading loadable segment data
    SegData,


    ElfRela,
    ElfDynSym,
}

enum KernelType {
    BzImage,
    Elf,
}

enum Error {
    HashMismatch,
}

impl Into<u8> for Command {
    fn into(self) -> u8 {
        match self {
            // Self::KernelType => 0,
            Self::ElfHdr => 3,
            Self::PhdrData => 4,
            Self::SegData => 5,
            Self::ElfRela => 6,
            Self::ElfDynSym => 7
        }
    }
}

pub(crate) struct FwCfg {
    kernel_type: KernelType,
    cmd_reg: Port<u8>,
    bounce_buffer: MemoryRegion,
    kernel_hash: MemoryRegion,
    initrd_hash: MemoryRegion,
}

impl FwCfg {
    pub fn new() -> Self {
        let cmd_reg = Port::<u8>::new(FW_CFG_REG);
        let bounce_buffer = MemoryRegion::new(FW_CFG_DATA_BASE, FW_CFG_DATA_SIZE);
        let base = FW_ADDR - loader::HASH_SIZE_BYTES;
        let kernel_hash = MemoryRegion::new(base, loader::HASH_SIZE_BYTES);
        let initrd_hash = MemoryRegion::new(base - loader::HASH_SIZE_BYTES, loader::HASH_SIZE_BYTES);

        //bzImage default
        let mut fw_cfg = FwCfg {
            kernel_type: KernelType::BzImage,
            cmd_reg,
            bounce_buffer,
            kernel_hash,
            initrd_hash,
        };

        fw_cfg.init();

        fw_cfg
    }

    fn init(&mut self) {
        self.kernel_type = self.get_kernel_type();
    }

    fn get_kernel_type(&mut self) -> KernelType {
        KernelType::Elf
    }

    pub fn load_kernel(
        &mut self,
        initrd_plain_text_addr: u64,
        initrd_load_addr: u64,
        initrd_len: u64,
        initrd_size_aligned: u64,
    ) -> Result<(), &'static str> {
        match self.kernel_type {
            KernelType::BzImage => self.load_bzimage()?,
            KernelType::Elf => self.load_kernel_elf(
                initrd_plain_text_addr,
                initrd_load_addr,
                initrd_len,
                initrd_size_aligned,
            )?,
        };
        Ok(())
    }

    //this will copy initrd from plain text to encrypted memory
    pub fn load_initrd(
        &mut self,
        initrd_plain_text_addr: u64,
        initrd_load_addr: u64,
        initrd_len: u64,
    ) -> Result<(), &'static str> {
        let mut plain_text_region = MemoryRegion::new(initrd_plain_text_addr, initrd_len);
        let mut encrypted_region = MemoryRegion::new(initrd_load_addr, initrd_len);

        Self::debug_write(INITRD_COPY_START);
        encrypted_region
            .as_bytes()
            .copy_from_slice(&plain_text_region.as_bytes());
        Self::debug_write(INITRD_COPY_END);

        Self::debug_write(INITRD_HASH_START);
        let mut hasher = Sha256::new();
        hasher.update(encrypted_region.as_bytes());
        let hash = hasher.finalize();

        Self::validate_hash(&hash, &self.initrd_hash.as_bytes())
            .map_err(|_| "Failed to validate initrd hash")?;
        Self::debug_write(INITRD_HASH_END);

        Ok(())
    }

    pub fn load_bzimage(&mut self) -> Result<(), &'static str> {
        panic!("Not supported!");
    }

    fn load_elf_header<'h>(&mut self, hasher: &mut Sha256, header: &'h mut [u8; ELF_HDR_SIZE]) -> &'h header64::Header {
        // Get elf header
        self.do_command(Command::ElfHdr);

        // Copy elf header from bounce buffer to encrypted region on stack
        Self::debug_write(COPY_START);
        header.copy_from_slice(&self.bounce_buffer.as_bytes()[0..ELF_HDR_SIZE]);
        Self::debug_write(COPY_END);

        // Hash elf header in encrypted memory
        Self::debug_write(HASH_START);
        hasher.update(&header);
        Self::debug_write(HASH_END);

        header64::Header::from_bytes(header)
    }

    fn read_next_program_header(&mut self, hasher: &mut Sha256, header: &mut [u8; ELF_PHDR_SIZE]) -> () {
        // Get next program header
        self.do_command(Command::PhdrData);

        Self::debug_write(COPY_START);
        header.copy_from_slice(&self.bounce_buffer.as_bytes()[0..ELF_PHDR_SIZE]);
        Self::debug_write(COPY_END);

        // Hash phdr in encrypted mem
        Self::debug_write(HASH_START);
        hasher.update(&header);
        Self::debug_write(HASH_END);
    }

    fn load_segment(&mut self, load_addr: u64, phdr: &ProgramHeader, hasher: &mut Sha256) -> MemoryRegion {
        // Memory region for where the segment will be loaded
        let mut bytes_to_read = phdr.p_filesz;
        let mut seg = MemoryRegion::new(load_addr, phdr.p_memsz);
        let mut seg_offset = 0;

        // Tell hypervisor to serve first segment
        self.do_command(Command::SegData);
        loop {
            let mut read_num = FW_CFG_DATA_SIZE;
            if bytes_to_read < read_num {
                read_num = bytes_to_read;
            }
            // alias for bounce buffer region
            let src = &self.bounce_buffer.as_bytes()[0..read_num as usize];

            //Copy portion of segment from bounce buffer to encrypted region
            Self::debug_write(COPY_START);
            seg.as_bytes()[seg_offset..seg_offset + read_num as usize].copy_from_slice(&src);
            Self::debug_write(COPY_END);

            //Hash what we just copied in encrypted memory
            Self::debug_write(HASH_START);
            hasher.update(&seg.as_bytes()[seg_offset..seg_offset + read_num as usize]);
            Self::debug_write(HASH_END);


            bytes_to_read -= read_num;
            if bytes_to_read == 0 {
                break;
            } else {
                seg_offset += read_num as usize;
                //Tell hypervisor to serve next segment
                self.do_command(Command::SegData);
            }
        }

        if phdr.p_filesz < phdr.p_memsz {
            for byte in (&mut seg.as_bytes()[phdr.p_filesz as usize..]) {
                *byte = 0;
            }
        }

        seg
    }

    fn perform_relocs(&mut self, memory: &mut [u8]) {
        self.do_command(Command::ElfRela);

        let (num_sym, rest) = self.bounce_buffer.as_bytes().split_at(size_of::<u64>());
        let num_sym = u64::from_le_bytes(num_sym.try_into().unwrap()) as usize;
        let sym_size = num_sym * sym64::SIZEOF_SYM;
        let (syms, rest) = rest.split_at(sym_size);

        let (num_reloc, rest) = rest.split_at(size_of::<u64>());
        let num_reloc = u64::from_le_bytes(num_reloc.try_into().unwrap()) as usize;
        let reloc_size = num_reloc * reloc64::SIZEOF_RELA;
        let relocs = &rest[..reloc_size];

        let syms = Sym::slice_from_bytes(&syms).unwrap();
        let relocs = Rela::slice_from_bytes(relocs).unwrap();

        const ELF_ARCH: u16 = goblin::elf::header::EM_X86_64;
        const R_ABS64: u32 = goblin::elf::reloc::R_X86_64_64;
        const R_RELATIVE: u32 = goblin::elf::reloc::R_X86_64_RELATIVE;
        const R_GLOB_DAT: u32 = goblin::elf::reloc::R_X86_64_GLOB_DAT;

        for rela in relocs {
            match reloc::r_type(rela.r_info) {
                R_ABS64 => {
                    let sym = reloc::r_sym(rela.r_info) as usize;
                    let sym = &syms[sym];

                    if sym::st_bind(sym.st_info) == STB_WEAK
                        && u32::from(sym.st_shndx) == SHN_UNDEF
                    {
                        let memory = &memory[rela.r_offset as usize..][..8];
                        assert_eq!(memory, &[0; 8]);
                        continue;
                    }

                    let relocated =
                        (KERNEL_LOAD_ADDR as i64 + sym.st_value as i64 + rela.r_addend).to_ne_bytes();
                    let buf = &relocated[..];
                    memory[rela.r_offset as usize..][..mem::size_of_val(&relocated)]
                        .copy_from_slice(buf);
                }
                R_RELATIVE => {
                    let relocated = (KERNEL_LOAD_ADDR as i64 + rela.r_addend).to_ne_bytes();
                    let buf = &relocated[..];
                    memory[rela.r_offset as usize..][..mem::size_of_val(&relocated)]
                        .copy_from_slice(buf);
                }
                R_GLOB_DAT => {
                    let sym = reloc::r_sym(rela.r_info) as usize;
                    let sym = &syms[sym];

                    if sym::st_bind(sym.st_info) == STB_WEAK
                        && u32::from(sym.st_shndx) == SHN_UNDEF
                    {
                        let memory = &memory[rela.r_offset as usize..][..8];
                        assert_eq!(memory, &[0; 8]);
                        continue;
                    }

                    let relocated =
                        (KERNEL_LOAD_ADDR as i64 + sym.st_value as i64 + rela.r_addend).to_ne_bytes();
                    #[cfg(target_arch = "x86_64")]
                    assert_eq!(rela.r_addend, 0);
                    let buf = &relocated[..];
                    memory[rela.r_offset as usize..][..mem::size_of_val(&relocated)]
                        .copy_from_slice(buf);
                }
                typ => panic!("unknown relocation type {}", r_to_str(typ, ELF_ARCH)),
            }
        }
    }

    pub fn load_kernel_elf(
        &mut self,
        initrd_plain_text_addr: u64,
        initrd_load_addr: u64,
        initrd_len: u64,
        initrd_size_aligned: u64,
    ) -> Result<(), &'static str> {
        let mut hasher = Sha256::new();

        let mut header_region = MemoryRegion::new(
            ZERO_PAGE_START + 0x1f1,
            core::mem::size_of::<Header>().try_into().unwrap(),
        );
        let bootparams_header =
            unsafe { core::mem::transmute::<_, &mut Header>(header_region.as_bytes().as_ptr()) };

        let mut header = [0u8; ELF_HDR_SIZE];
        let elf_header = self.load_elf_header(&mut hasher, &mut header);

        // Is kernel relocatable?
        let is_relocatable = elf_header.e_type == header64::ET_DYN;

        if is_relocatable {
            Self::debug_write(0xCA);
        } else {
            Self::debug_write(0xCB);
        }

        Self::debug_write(0xBB);
        Self::debug_write(elf_header.e_phnum as u8);
        Self::debug_write(0xBB);

        assert!(elf_header.e_phnum <= 64, "too many headers");

        // Stack is in c bit mem so this is fine
        let mut program_headers = [0u8; ELF_PHDR_SIZE * 64];

        // Read all the program headers
        for i in 0..elf_header.e_phnum {
            let hdr = &mut program_headers[(i as usize * ELF_PHDR_SIZE)..((i as usize + 1) * ELF_PHDR_SIZE)];
            self.read_next_program_header(&mut hasher, hdr.try_into().unwrap());
        }

        let program_headers = plain::slice_from_bytes_len::<ProgramHeader>(&program_headers, elf_header.e_phnum as usize)
            .map_err(|_| "failed to parse program header")?;

        // Copy and hash loadable segments
        let mut max_addr = 0u64;
        Self::debug_write(0xF4);
        Self::debug_write(program_headers.len() as u8);
        Self::debug_write(0xF4);


        for phdr in program_headers {
            if phdr.p_filesz == 0 || phdr.p_type != program_header::PT_LOAD {
                Self::debug_write(0xF5);

                Self::debug_write((phdr.p_type >> 8) as u8);
                Self::debug_write(phdr.p_type as u8);
                Self::debug_write(0xF5);

                continue;
            }
            Self::debug_write(0xF6);

            let load_addr = if is_relocatable { KERNEL_LOAD_ADDR + phdr.p_vaddr } else { phdr.p_vaddr };
            let reg =self.load_segment(load_addr, phdr, &mut hasher);

            let end_addr = reg.base + reg.length;
            if end_addr > max_addr {
                max_addr = end_addr;
            }
        }

        // Perform relocations
        if is_relocatable {
            let mut mem_region = MemoryRegion::new(KERNEL_LOAD_ADDR, max_addr - KERNEL_LOAD_ADDR);
            self.perform_relocs(mem_region.as_bytes())
        }

        Self::debug_write(HASH_START);
        let seg_hash = hasher.finalize();
        Self::debug_write(HASH_END);

        //Verify segments hash
        // Self::validate_hash(&seg_hash, &self.kernel_hash.as_bytes()).map_err(|_| "kernel verification failed")?;

        Self::debug_write(0x90);

        //Write bootparams
        let mut kernel_params = Kernel::new();
        kernel_params.entry_point = if is_relocatable { KERNEL_LOAD_ADDR + elf_header.e_entry } else { elf_header.e_entry };

        bootparams_header.ramdisk_image = initrd_load_addr as u32;
        bootparams_header.ramdisk_size = initrd_len as u32;
        Self::debug_write(0x91);

        if bootparams_header.setup_data == 0 {
            const SETUP_DATA_LEN: u64 = core::mem::size_of::<SetupData>() as u64;
            const CCBLOB_LEN: u64 = core::mem::size_of::<CCBlob>() as u64;
            const CCBLOB_MAGIC: u32 = 0x45444d41;
            //end of the zero page
            let setup_data_addr = (ZERO_PAGE_START + CPUID_PAGE_LEN) - SETUP_DATA_LEN - CCBLOB_LEN;
            let cc_blob_addr = ((ZERO_PAGE_START + CPUID_PAGE_LEN) - CCBLOB_LEN) as u32;

            let setup_data = SetupData {
                next: 0,              //only setup data node in the list
                _type: SETUP_CC_BLOB, //CC setup data blob type
                len: 4,               //4 bytes because cc_blob_addr is u32
                cc_blob_addr,
            };

            let cc_blob = CCBlob {
                magic: CCBLOB_MAGIC,
                version: 0,
                reserved: 0,
                secrets_phys: SECRETS_PAGE_ADDR,
                secrets_len: SECRETS_PAGE_LEN as u32,
                reserved1: 0,
                cpuid_phys: CPUID_PAGE_ADDR,
                cpuid_len: 4096,
                reserved2: 0,
            };

            let mut setup_data_region =
                MemoryRegion::new(setup_data_addr as u64, SETUP_DATA_LEN as u64);

            setup_data_region
                .as_mut_slice(0, SETUP_DATA_LEN as u64)
                .copy_from_slice(&setup_data.as_slice());

            let mut cc_blob_region = MemoryRegion::new(cc_blob_addr as u64, CCBLOB_LEN as u64);

            cc_blob_region
                .as_mut_slice(0, CCBLOB_LEN as u64)
                .copy_from_slice(&cc_blob.as_slice());

            //point to the node
            bootparams_header.setup_data = setup_data_addr as u64;
        }

        Self::debug_write(0x92);


        if initrd_len > 0 {
            self.load_initrd(initrd_plain_text_addr, initrd_load_addr, initrd_len)?;
        }
        Self::debug_write(0x93);

        // //set the plain text region for the kernel and the ghcb page private
        // ghcb::page_state_change(KERNEL_ADDR, Size2MiB::SIZE, true);

        Self::debug_write(0x94);
        // //set plain text region for initrd private
        if initrd_len > 0 {
            ghcb::page_state_change(initrd_plain_text_addr, initrd_size_aligned, true);
        }
        Self::debug_write(0x95);

        //set the C-bit everywhere
        paging::setup(false, 0, 0);
        Self::debug_write(0x96);

        //re-validate the region we used for the plain text kernel
        // let entry = boot_e820_entry {
        //     addr: KERNEL_ADDR,
        //     size: Size2MiB::SIZE,
        //     type_: 1,
        // };
        // paging::pvalidate_ram(&entry, 0 as u64, 0, 0, false);

        //re-validate the region we used for the plain text initrd
        // let entry = BootE820Entry {
        //     addr: initrd_plain_text_addr,
        //     size: initrd_size_aligned,
        //     type_: 1,
        // };
        // Self::debug_write(0x97);
        // paging::pvalidate_ram(&entry, 0 as u64, 0, 0, false);

        Self::debug_write(0x99);


        Self::debug_write(((kernel_params.entry_point >> 54) & 0xff) as u8);
        Self::debug_write(((kernel_params.entry_point >> 48) & 0xff) as u8);
        Self::debug_write(((kernel_params.entry_point >> 40) & 0xff) as u8);
        Self::debug_write(((kernel_params.entry_point >> 32) & 0xff) as u8);
        Self::debug_write(((kernel_params.entry_point >> 24) & 0xff) as u8);
        Self::debug_write(((kernel_params.entry_point >> 16) & 0xff) as u8);
        Self::debug_write(((kernel_params.entry_point >> 8) & 0xff) as u8);
        Self::debug_write(((kernel_params.entry_point >> 0) & 0xff) as u8);


        Self::debug_write(0x99);
        kernel_params.boot();

        Ok(())
    }

    fn do_command(&mut self, cmd: Command) -> u8 {
        unsafe { self.cmd_reg.write(cmd.into()) };
        unsafe { self.cmd_reg.read() };

        let val = Ghcb::get_val() as u8;

        // Self::debug_write(val as u8);

        // let mut debug_port = Port::<u8>::new(DEBUG_PORT);
        // unsafe { debug_port.write(val) }

        val
        // Self::debug_write(val);
    }

    fn debug_write(val: u8) {
        let mut debug_port = Port::<u8>::new(DEBUG_PORT);
        unsafe { debug_port.write(val) }
    }

    fn validate_hash(new_hash: &[u8], old_hash: &[u8]) -> Result<(), Error> {
        for i in 0..loader::HASH_SIZE_BYTES as usize {
            if new_hash[i] != old_hash[i] {
                Self::debug_write(0xFF);
                return Err(Error::HashMismatch);
            }
        }
        Ok(())
    }
}

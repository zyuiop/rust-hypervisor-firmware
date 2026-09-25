use x86_64::structures::paging::{PageSize, Size2MiB};

use crate::mem::MemoryRegion;

pub const GHCB_ADDR: u32 = 0x3000; //48MiB
pub const GHCB_MSR: u32 = 0xC001_0130;
// pub const SEV_STATUS_MSR: u32 = 0xC001_0131;
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
//The ghcb page
pub struct Ghcb {
    reserved1: [u8; 0xcb],
    cpl: u8,
    reserved2: [u8; 0x74],
    xss: u64,
    reserved3: [u8; 0x18],
    dr7: u64,
    reserved4: [u8; 0x90],
    pub rax: u64,
    reserved5: [u8; 0x100],
    reserved6: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    reserved7: [u8; 0x70],
    pub sw_exitcode: u64,
    pub sw_exitinfo1: u64,
    pub sw_exitinfo2: u64,
    pub sw_scratch: u64,
    reserved8: [u8; 0x38],
    pub xcr0: u64,
    valid_bitmap: [u8; 0x10],
    x86_state_gpa: u64,
    reserved9: [u8; 0x3f8],
    shared_buf: [u8; 0x7f0],
    reserved10: [u8; 0x0a],
    protocol_version: u16,
    ghcb_usage: u32,
}

pub static mut GHCB_PAGE: MemoryRegion =
    MemoryRegion::new(GHCB_ADDR as u64, core::mem::size_of::<Ghcb>() as u64);

pub fn page_state_change(addr: u64, len: u64, private: bool) {
    let mut ghcb_msr = x86_64::registers::model_specific::Msr::new(GHCB_MSR);
    let mut len_aligned = if len & !0xfff > len {
        (len & !0xfff) + 0x1000
    } else {
        len
    };
    let mut addr = addr;

    let prev_value = unsafe { ghcb_msr.read() };
    while len_aligned > 0 {
        let mut value = if private { 1 << 52 } else { 2 << 52 };
        value |= addr & !0xfff;
        value |= 0x014;

        // MSR protocol implem on linux ignores page size: we HAVE to split by 4KiB
        unsafe { ghcb_msr.write(value) };

        unsafe {
            core::arch::asm!("rep; vmmcall\n\r");
        }

        len_aligned -= 0x1000;
        addr += 0x1000;
    }
    unsafe { ghcb_msr.write(prev_value) };
}

pub fn register_ghcb_page() {
    let mut ghcb_msr = x86_64::registers::model_specific::Msr::new(GHCB_MSR);

    unsafe { ghcb_msr.write(GHCB_ADDR as u64 | 0x12) };

    vmgexit();

    //TODO check response
    let _response = unsafe { ghcb_msr.read() };

    unsafe { ghcb_msr.write(GHCB_ADDR as u64) };
}

pub fn vmgexit() {
    unsafe {
        core::arch::asm!("rep; vmmcall\n\r");
    }
}

impl Ghcb {
    //Write ghcb struct to ghcb page
    pub fn port_io(port: u16, value: u8) {
        let rax: u64 = value as u64;
        let exitinfo1: u64 = ((port as u64) << 16) | 0x10;

        let rax_offset = 0x01f8 / 8;
        let rax_byte_offset = rax_offset / 8;
        let rax_bit_position = rax_offset % 8;

        let exitcode_offset: usize = 0x0390 / 8;
        let exitcode_byte_offset: usize = exitcode_offset / 8;
        let exitcode_bit_position: usize = exitcode_offset % 8;

        let exitinfo1_offset: usize = 0x0398 / 8;
        let exitinfo1_byte_offset: usize = exitinfo1_offset / 8;
        let exitinfo1_bit_position: usize = exitinfo1_offset % 8;

        let exitinfo2_offset: usize = 0x03a0 / 8;
        let exitinfo2_byte_offset: usize = exitinfo2_offset / 8;
        let exitinfo2_bit_position: usize = exitinfo2_offset % 8;

        let scratch_offset: usize = 0x03a8 / 8;
        let scratch_byte_offset: usize = scratch_offset / 8;
        let scratch_bit_position: usize = scratch_byte_offset % 8;

        let ghcb = unsafe { core::mem::transmute::<_, &mut Ghcb>(GHCB_PAGE.as_bytes().as_ptr()) };

        //rax is the value we're writing to the port
        ghcb.protocol_version = 2;
        ghcb.rax = rax;
        ghcb.sw_exitcode = 0x7b;
        ghcb.sw_exitinfo1 = exitinfo1;
        ghcb.sw_exitinfo2 = 0;
        ghcb.sw_scratch = 0;
        ghcb.valid_bitmap = [0x0u8; 16];
        ghcb.ghcb_usage = 0;

        //set valid bits
        ghcb.valid_bitmap[rax_byte_offset as usize] =
            ghcb.valid_bitmap[rax_byte_offset as usize] | (1 << rax_bit_position as usize);

        ghcb.valid_bitmap[exitcode_byte_offset as usize] = ghcb.valid_bitmap
            [exitcode_byte_offset as usize]
            | (1 << exitcode_bit_position as usize);

        ghcb.valid_bitmap[exitinfo1_byte_offset as usize] = ghcb.valid_bitmap
            [exitinfo1_byte_offset as usize]
            | (1 << exitinfo1_bit_position as usize);

        ghcb.valid_bitmap[exitinfo2_byte_offset as usize] = ghcb.valid_bitmap
            [exitinfo2_byte_offset as usize]
            | (1 << exitinfo2_bit_position as usize);

        ghcb.valid_bitmap[scratch_byte_offset as usize] =
            ghcb.valid_bitmap[scratch_byte_offset as usize] | (1 << scratch_bit_position as usize);
    }
}

// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![feature(alloc_error_handler)]
#![feature(stmt_expr_attributes)]
#![no_std]
#![no_main]
#![cfg_attr(not(feature = "log-serial"), allow(unused_variables, unused_imports))]
#![feature(abi_x86_interrupt)]
use core::panic::PanicInfo;
use x86_64::{
    instructions::{hlt, interrupts, port::Port},
    registers::{
        control::{Cr0, Cr0Flags, Cr4, Cr4Flags},
        xcontrol::{XCr0, XCr0Flags},
    },
    structures::paging::{PageSize, Size2MiB},
};

use crate::{
    boot::{BootE820Entry, Header},
    loader::{E820_ENTRIES_OFFSET, E820_TABLE_OFFSET, ZERO_PAGE_START},
    mem::MemoryRegion,
};

#[macro_use]
// #[cfg(debug_assertions)]
mod serial;

#[macro_use]
mod asm;
mod boot;
mod fw_cfg;
mod gdt;
mod ghcb;
mod idt;
mod loader;
mod mem;
mod paging;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    #[cfg(debug_assertions)]
    log!("PANIC: {}", _info);
    loop {
        hlt()
    }
}

// Enable SSE2 for XMM registers (needed for EFI calling)
fn enable_sse() {
    let mut cr0 = Cr0::read();
    cr0.remove(Cr0Flags::EMULATE_COPROCESSOR);
    cr0.remove(Cr0Flags::TASK_SWITCHED);
    cr0.insert(Cr0Flags::MONITOR_COPROCESSOR);
    cr0.insert(Cr0Flags::EXTENSION_TYPE);
    cr0.insert(Cr0Flags::ALIGNMENT_MASK);
    cr0.insert(Cr0Flags::WRITE_PROTECT);
    unsafe { Cr0::write(cr0) };
    let mut cr4 = Cr4::read();
    cr4.insert(Cr4Flags::OSFXSR);
    cr4.insert(Cr4Flags::OSXSAVE);
    cr4.insert(Cr4Flags::OSXMMEXCPT_ENABLE);
    unsafe { Cr4::write(cr4) };

    //enable AVX for sha2 crate
    let mut xcro0 = XCr0::read();
    xcro0.insert(XCr0Flags::SSE);
    xcro0.insert(XCr0Flags::AVX);
    xcro0.insert(XCr0Flags::X87);
    unsafe { XCr0::write(xcro0) };
}

#[no_mangle]
pub extern "C" fn rust64_start(kernel_len: u32, stack_start: u32) {
    main(kernel_len, stack_start)
}

fn main(kernel_len: u32, stack_start: u32) -> ! {
    let initrd_len;
    let initrd_load_addr: u64;
    //Firecracker stashes memory size and initrd_len in r14 and r15 respectively
    unsafe { core::arch::asm!("", out("r14") initrd_len) };
    unsafe { core::arch::asm!("", out("r15") initrd_load_addr) };

    //this aligns the stack
    unsafe { core::arch::asm!("push rax") };

    enable_sse();

    interrupts::enable();
    idt::init_idt();

    let align_to_pagesize = |address| address & !(0x200000 - 1);
    //plain text inird will be just before its final resting place
    let initrd_load_addr_aligned = align_to_pagesize(initrd_load_addr);
    let initrd_plain_text_addr = align_to_pagesize(initrd_load_addr_aligned - initrd_len);
    //initrd_plain_text_addr should already be 2mb aligned
    let initrd_size_aligned = if (initrd_len & !Size2MiB::SIZE) != 0 {
        (initrd_len & !(Size2MiB::SIZE - 1)) + Size2MiB::SIZE
    } else {
        initrd_len
    };
    //set up paging so we can have encrypted memory
    paging::setup(true, initrd_plain_text_addr, initrd_size_aligned);

    //set up ghcb so we can do writes to ports
    ghcb::register_ghcb_page();

    //signal firmware start, although a bit late this is the earliest we can do it
    let mut debug_port = Port::<u8>::new(0x80);
    unsafe {
        debug_port.write(0x00);
    };

    //read the e820 entries so we know what memory to validate
    let e820_entries_reg = MemoryRegion::new(ZERO_PAGE_START + E820_ENTRIES_OFFSET, 1);
    let num_e820_entries = e820_entries_reg.read_u8(0);

    let mut e820_table_reg = MemoryRegion::new(
        ZERO_PAGE_START + E820_TABLE_OFFSET,
        num_e820_entries as u64 * core::mem::size_of::<BootE820Entry>() as u64,
    );

    let mut header_region = MemoryRegion::new(
        ZERO_PAGE_START + 0x1f1,
        core::mem::size_of::<Header>().try_into().unwrap(),
    );

    let bootparams_header =
        unsafe { core::mem::transmute::<_, &mut Header>(header_region.as_bytes().as_ptr()) };

    unsafe {
        debug_port.write(bootparams_header.boot_flag as u8);
        debug_port.write((bootparams_header.boot_flag >> 8) as u8);
    };

    let e820_entries =
        unsafe { core::mem::transmute::<_, &mut [BootE820Entry]>(e820_table_reg.as_bytes()) };

    for i in 0..num_e820_entries as usize {
        //if its a ram entry validate checking for overlaps
        if e820_entries[i].type_ == 1 {
            paging::pvalidate_ram(
                &e820_entries[i],
                stack_start as u64,
                initrd_plain_text_addr,
                initrd_size_aligned,
                true,
            );
        }
    }

    let mut loader = fw_cfg::FwCfg::new();

    loader
        .load_kernel(
            initrd_plain_text_addr,
            initrd_load_addr,
            initrd_len,
            initrd_size_aligned,
        )
        .unwrap();

    panic!("Shouldn't reach here")
}

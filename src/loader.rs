use x86_64::instructions::port::Port;
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
use crate::boot::Header;

pub const ZERO_PAGE_START: u64 = 0x7000;
pub const HASH_SIZE_BYTES: u64 = 32;
pub const E820_ENTRIES_OFFSET: u64 = 0x1e8;
pub const E820_TABLE_OFFSET: u64 = 0x2d0;
pub const CPUID_PAGE_ADDR: u64 = 0x1000;
pub const CPUID_PAGE_LEN: u64 = 0x1000;
pub const SECRETS_PAGE_ADDR: u64 = 0x2000;
pub const SECRETS_PAGE_LEN: u64 = 0x1000;

pub struct Kernel {
    pub hdr: Header,
    pub entry_point: u64,
}

impl Kernel {
    pub fn new() -> Self {
        let kernel = Self {
            hdr: Header::default(),
            entry_point: 0,
        };
        kernel
    }

    pub fn boot(&mut self) {
        let jump_address = self.entry_point;

        let mut debug_port = Port::<u8>::new(0x80);
        let ct = jump_address as *const u8;

        unsafe { debug_port.write(0xa0) }
        unsafe {
            debug_port.write(*ct);
            debug_port.write(*ct.add(1));
            debug_port.write(*ct.add(2));
            debug_port.write(*ct.add(3));
            debug_port.write(*ct.add(4));
            debug_port.write(*ct.add(5));
        }

        // Rely on x86 C calling convention where second argument is put into %rsi register
        let ptr = jump_address as *const ();
        let code: extern "C" fn(u64, u64) = unsafe { core::mem::transmute(ptr) };

        unsafe { debug_port.write(0xa0) }

        (code)(0 /* dummy value */, ZERO_PAGE_START);
    }
}

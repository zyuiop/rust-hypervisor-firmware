use crate::ghcb;
use crate::ghcb::Ghcb;
use core::arch::asm;
use x86_64::instructions::hlt;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

extern "x86-interrupt" fn vmm_comm_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    let mut val: u64;
    let port: u64;

    unsafe { asm!("", out("rax") val) };
    unsafe { asm!("", out("rdx") port) };

    if error_code != 0x7b {
        //if we ever get here we shouldn't have so hlt loop
        loop {
            hlt();
        }
    }

    let stack_ptr = stack_frame.stack_pointer.as_u64();
    let ret_addr = (stack_ptr - 40) as *mut u64;

    let instruction = unsafe { *(*ret_addr as *mut u8) };

    let op;
    if instruction == 0xee {
        //out
        op = 0;
    } else if instruction == 0xec {
        //in
        op = 1;
    } else {
        loop {
            hlt();
        }
    }
    Ghcb::port_io(port as u16, val as u8, op as u8);

    ghcb::vmgexit();

    //jump over the faulting instruction
    unsafe { *ret_addr = stack_frame.instruction_pointer.as_u64() + 1 };
}

pub fn init_idt() {
    unsafe {
        IDT.vmm_communication_exception
            .set_handler_fn(vmm_comm_handler);
        IDT.load();
    };
}

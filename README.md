This is a bootloader for loading an arm9bin from SD, and for loading FIRM. The default SD filepaths for those are: "/3dshax_arm9.bin" and "/firm.bin".  

The arm9bin starts with an u32 for the load-address, the rest of the binary is loaded to this address. See main.c for the blacklisted memory ranges(MPU is disabled while this loader is running and when jumping to the arm9bin). The filesize must be at least 0x8-bytes, and the filesize must be 4-byte aligned. When DISABLE_BINVERIFY isn't used, the filesize must be at least 0x2c-bytes: the last 0x24-bytes are a footer. The first u32 in that footer is the footertype, this must match little-endian value 0x60788d1e for SHA256. The following data in the footer is a SHA256 hash over the rest of the file(this footer is loaded into memory seperate from the loadaddr).

See also the build_hashedbin.sh script, for building hashed binaries for this. "build_hashedbin.sh <inputbin> <outputbin>"

Prior to jumping to the arm9bin, it will handle booting the ARM11. This requires running the built arm11bin on the ARM11, by the loader which loaded this codebase.

The FIRM section hashes are verified, however the FIRM header signature is not verified.

# Building
"make" can be used with the following options:
* "ENABLE_RETURNFROMCRT0=1" When an error occurs, return from the crt0 to the LR from the time of loader entry, instead executing an infinite loop.
* "UNPROTBOOT9_LIBPATH={path}" This should be used to specify the path for the unprotboot9_sdmmc library, aka the path for that repo.
* "ARM9BIN_FILEPATH={sd filepath}" Override the default filepath for the arm9bin. For example: "ARM9BIN_FILEPATH=/3dshax_boot.bin".
* "FIRM_FILEPATH={sd filepath}" This is the FIRM version of the above option.
* "FIRMLOAD_DISABLE={retaddr}" Disable all FIRM-loading code. The retaddr is the address which LR will be set to, when jumping to the arm9bin(this must be the original FIRM arm9-entrypoint, if there's FIRM already loaded in memory).
* "BINLOAD_DISABLE=1" Disable loading the arm9bin. FIRMLOAD_DISABLE and BINLOAD_DISABLE must not be used at the same time.
* "DISABLE_BINVERIFY=1" Disable using/verifying the SHA256 hash in the arm9bin(see above), with this the additional filesize requirement is disabled too.
* "DISABLE_ARM11=1" Disable the code for booting the ARM11, from the arm9-code.


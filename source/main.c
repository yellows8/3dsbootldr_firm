#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <3ds.h>

#include <unprotboot9_sdmmc.h>

#ifndef USE_RAWDEVICE
#include "ff.h"
#else
typedef unsigned short TCHAR;
#endif

#ifndef ARM9BIN_FILEPATH
#define ARM9BIN_FILEPATH L"/3dshax_arm9.bin"
#endif

#ifndef FIRM_FILEPATH
#define FIRM_FILEPATH L"/firm.bin"
#endif

#ifdef FIRMLOAD_DISABLE
#ifdef BINLOAD_DISABLE
#error FIRMLOAD_DISABLE and BINLOAD_DISABLE must not be used at the same time.
#endif
#endif

#ifdef USE_RAWDEVICE
#ifndef BINLOAD_DISABLE
#error "BINLOAD_DISABLE must be used when USE_RAWDEVICE is enabled."
#endif

#ifndef RAWDEVICE_STARTSECTOR
#error "RAWDEVICE_STARTSECTOR must be specified when USE_RAWDEVICE is enabled."
#endif

#ifndef RAWDEVICE_NUMSECTORS
#error "RAWDEVICE_NUMSECTORS must be specified when USE_RAWDEVICE is enabled."
#endif
#endif

#ifdef USEDEVICE_NAND
#ifndef USE_RAWDEVICE
#error "USEDEVICE_NAND can only be used when USE_RAWDEVICE is enabled."
#endif
#endif

extern u32 _start, __end__;

void jump_to_arm9bin(u32 jumpaddr, u32 retaddr);

typedef s32 (*read_funcptr)(u32, u32, u32*);//params: u32 sector, u32 numsectors, u32 *out

typedef struct {
	u32 offset;
	u32 address;
	u32 size;
	u32 type;
	u32 hash[0x20>>2];
} firm_sectionhdr;

#ifndef USE_RAWDEVICE
#ifndef FIRMLOAD_DISABLE
FIL firm_fil;
#endif
#endif

void sha256hw_calchash_codebin(u32 *outhash, u32 *buf, u32 buf_wordsize, u32 *loadaddr, u32 *footertype)
{
	u32 pos;
	vu32 *SHA_CNT = (vu32*)0x1000a000;
	vu32 *SHA_HASH = (vu32*)0x1000a040;
	vu32 *SHA_INFIFO = (vu32*)0x1000a080;

	*SHA_CNT = 0x9;

	if(loadaddr)
	{
		while((*SHA_CNT) & 0x1);
		*SHA_INFIFO = *loadaddr;
	}

	pos = 0;
	do {
		while((*SHA_CNT) & 0x1);
		*SHA_INFIFO = buf[pos];
		pos++;
	} while(pos<buf_wordsize);

	if(footertype)
	{
		while((*SHA_CNT) & 0x1);
		*SHA_INFIFO = *footertype;
	}

	*SHA_CNT = 0xa;
	while((*SHA_CNT) & 0x2);
	while((*SHA_CNT) & 0x1);

	for(pos=0; pos<(0x20>>2); pos++)outhash[pos] = SHA_HASH[pos];
}

s32 verify_binarymemrange(u32 loadaddr, u32 binsize)
{
	s32 ret = 0;
	u32 checkaddr=0;
	u32 pos;

	u32 firmsections_memrangeblacklist[6][2] = {//Blacklist all memory which gets used / etc.
	{0x080030fc, 0x080038fc},
	{_start, __end__},
	{0x08100000-0x3000, 0x08100000},//stack
	{0x08000000, 0x08000040},
	{0xfff00000, 0xfff04000},
	{0x3800, 0x7470}//Masked ITCM addrs, resulting in offsets within ITCM.
	};

	if((loadaddr + binsize) < loadaddr)return 0x50;

	ret = 0;
	for(pos=0; pos<6; pos++)
	{
		checkaddr = loadaddr;
		if(pos==5)
		{
			if(checkaddr >= 0x08000000)break;
			checkaddr &= 0x7fff;
		}

		if(checkaddr >= firmsections_memrangeblacklist[pos][0] && checkaddr < firmsections_memrangeblacklist[pos][1])
		{
			ret = 0x51;
			break;
		}

		if((checkaddr+binsize) >= firmsections_memrangeblacklist[pos][0] && (checkaddr+binsize) < firmsections_memrangeblacklist[pos][1])
		{
			ret = 0x52;
			break;
		}

		if(checkaddr < firmsections_memrangeblacklist[pos][0] && (checkaddr+binsize) > firmsections_memrangeblacklist[pos][0])
		{
			ret = 0x53;
			break;
		}
	}

	return ret;
}

#ifndef BINLOAD_DISABLE
s32 load_binary(TCHAR *path, s32 *errortable, u32 **loadaddrptr)
{
	FRESULT res;
	FIL fil;
	UINT totalread=0;
	DWORD filesize=0;

	u32 minfilesize = 8;
	u32 extra_binsize = 4;
	u32 binsize = 0;
	u32 *bufptr;

	u32 pos;
	s32 ret;

	#ifndef DISABLE_BINVERIFY
	u32 calchash[0x20>>2];
	u32 footerdata[0x24>>2];

	minfilesize+= 0x24;
	extra_binsize+= 0x24;
	#endif

	res = f_open(&fil, path, FA_READ);
	errortable[0] = res;
	if(res!=FR_OK)return res;

	filesize = f_size(&fil);
	ret = 0;
	if((filesize < minfilesize) || (filesize>>31) || (filesize & 0x3))ret = 0x40;
	errortable[1] = ret;
	if(ret)
	{
		f_close(&fil);
		return ret;
	}

	binsize = ((u32)filesize) - extra_binsize;

	totalread=0;
	res = f_read(&fil, loadaddrptr, 4, &totalread);
	errortable[2] = res;
	if(res!=FR_OK)
	{
		f_close(&fil);
		return res;
	}

	errortable[3] = 0;
	if(totalread!=4)
	{
		f_close(&fil);
		ret = 0x41;
		errortable[3] = ret;
		return ret;
	}

	ret = verify_binarymemrange((u32)*loadaddrptr, binsize);
	errortable[4] = ret;
	if(ret)
	{
		f_close(&fil);
		return ret;
	}

	errortable[5] = 0;
	totalread=0;
	res = f_read(&fil, (u32*)*loadaddrptr, binsize, &totalread);

	ret = 0;

	if(res!=FR_OK)
	{
		errortable[5] = res;
		ret = res;
	}
	else if(totalread != binsize)
	{
		ret = 0x41;
		errortable[5] = ret;
	}

	#ifndef DISABLE_BINVERIFY
	if(ret==0)
	{
		errortable[6] = 0;
		totalread=0;
		res = f_read(&fil, footerdata, sizeof(footerdata), &totalread);

		if(res!=FR_OK)
		{
			errortable[6] = res;
			ret = res;
		}
		else if(totalread != sizeof(footerdata))
		{
			ret = 0x41;
			errortable[6] = ret;
		}

		if(ret==0)
		{
			if(footerdata[0] != 0x60788d1e)ret = 0x42;//Validate the footertype.
			errortable[7] = ret;

			if(ret==0)
			{
				sha256hw_calchash_codebin(calchash, *loadaddrptr, binsize>>2, (u32*)loadaddrptr, footerdata);

				for(pos=0; pos<(0x20>>2); pos++)
				{
					if(calchash[pos] != footerdata[1+pos])ret = 0x43;
				}

				errortable[7] = ret;
			}
		}
	}
	#endif

	f_close(&fil);

	if(ret)//Clear the memory for the binary load-addr range when reading the actual binary fails, or when verifying the hash fails.
	{
		bufptr = *loadaddrptr;
		for(pos=0; pos<(binsize>>2); pos++)bufptr[pos] = 0;
	}

	return ret;
}
#endif

#ifndef FIRMLOAD_DISABLE
s32 load_firm(s32 *errorptr, read_funcptr read_data, u32 basesector, u32 maxsectors, u32 *arm9_entrypoint, u32 *arm11_entrypoint)
{
	s32 ret = 0, imagefound = 0;
	u32 pos, cursector, firmsector, firmindex, sectionaddr, sectionsize;
	u32 sector0, sector1;

	u32 entrypoint9_firmsection_found, entrypoint11_firmsection_found;

	u32 firmhdr[0x200>>2];

	firm_sectionhdr *section_headers = (firm_sectionhdr*)&firmhdr[0x40>>2];

	u32 calchash[0x20>>2];

	for(pos=0; pos<5; pos++)errorptr[pos] = 0x44444444;

	for(cursector=0; cursector<maxsectors; cursector++)//Find+load the FIRM image.
	{
		firmsector = basesector+cursector;

		for(pos=0; pos<(0x200>>2); pos++)firmhdr[pos] = 0;

		ret = read_data(firmsector, 1, firmhdr);
		if(ret!=0)
		{
			errorptr[0] = ret;
			continue;
		}

		if(firmhdr[0] != 0x4d524946)continue;//Verify the FIRM magicnum.

		if(firmhdr[2]==0 || firmhdr[3]==0)
		{
			errorptr[0] = 0x12;
			continue;//Verify that the arm9 and arm11 FIRM entrypoints are non-zero.
		}

		*arm9_entrypoint = firmhdr[3];
		*arm11_entrypoint = firmhdr[2];

		errorptr[0] = 0;
		ret = 0;

		entrypoint9_firmsection_found = 0;//Verify that the arm9-entrypoint and arm11-entrypoint is within one of the sections.
		entrypoint11_firmsection_found = 0;
		for(firmindex=0; firmindex<4; firmindex++)
		{
			sectionaddr = section_headers[firmindex].address;
			
			if(sectionaddr <= (*arm9_entrypoint) && (*arm9_entrypoint) < sectionaddr+section_headers[firmindex].size)
			{
				entrypoint9_firmsection_found = 1;
				if((sectionaddr + section_headers[firmindex].size) < sectionaddr)
				{
					ret = 0x15;//Check for integer overflow with sectionaddr+sectionsize, for the section where the arm9entrypoint is located.
					break;
				}
			}

			if(sectionaddr <= (*arm11_entrypoint) && (*arm11_entrypoint) < sectionaddr+section_headers[firmindex].size)
			{
				entrypoint11_firmsection_found = 1;
				if((sectionaddr + section_headers[firmindex].size) < sectionaddr)
				{
					ret = 0x15;//Check for integer overflow with sectionaddr+sectionsize, for the section where the arm11entrypoint is located.
					break;
				}
			}
		}

		if(!entrypoint9_firmsection_found || !entrypoint11_firmsection_found || ret!=0)
		{
			if(ret==0)ret = 0x14;
			errorptr[0] = ret;
			continue;
		}

		for(firmindex=0; firmindex<4; firmindex++)
		{
			sectionsize = section_headers[firmindex].size;

			if(sectionsize==0)continue;

			sectionaddr = section_headers[firmindex].address;

			if((section_headers[firmindex].offset & 0x1ff) || (sectionsize & 0x1ff) || (sectionaddr & 0x3))//Check for alignment.
			{
				ret = 0x20;
				break;
			}

			sector0 = firmsector + (section_headers[firmindex].offset>>9);
			sector1 = sector0 + (sectionsize>>9);

			if((sector0 < firmsector) || (sector1 < firmsector))//Check for integer overflow when the sector values are added together.
			{
				ret = 0x21;
				break;
			}

			if((sector0 >= basesector+maxsectors) || (sector1 > basesector+maxsectors))//The section sector values must not go out of bounds with the input params sectors range.
			{
				ret = 0x22;
				break;
			}

			if((sectionaddr + sectionsize) < sectionaddr)//Check for integer overflow with sectionaddr+sectionsize.
			{
				ret = 0x23;
				break;
			}

			ret = verify_binarymemrange(sectionaddr, sectionsize);
			if(ret!=0)break;

			ret = read_data(sector0, (sectionsize>>9), (u32*)sectionaddr);

			if(ret==0)
			{
				sha256hw_calchash_codebin(calchash, (u32*)sectionaddr, sectionsize>>2, NULL, NULL);

				for(pos=0; pos<(0x20>>2); pos++)
				{
					if(calchash[pos] != section_headers[firmindex].hash[pos])ret = 0x25;
				}
			}

			errorptr[1+firmindex] = ret;

			if(ret!=0)//Clear the loaded section when either reading it failed, or the hash is invalid.
			{
				for(pos=0; pos<(sectionsize>>2); pos++)((u32*)sectionaddr)[pos] = 0;
			}

			if(ret!=0)break;
		}

		if(ret!=0)
		{
			errorptr[1+firmindex] = ret;
			continue;
		}

		imagefound = 1;
		break;
	}

	if(imagefound==0)return 0x10;

	return 0;
}

#ifndef USE_RAWDEVICE
s32 read_firm_data(u32 sector, u32 numsectors, u32 *out)
{
	FRESULT res;
	UINT totalread=0;

	s32 ret = 0;

	res = f_lseek(&firm_fil, sector<<9);
	if(res!=FR_OK)
	{
		return res;
	}

	res = f_read(&firm_fil, out, numsectors<<9, &totalread);

	if(res!=FR_OK)
	{
		ret = res;
	}
	else if(totalread != (numsectors<<9))
	{
		ret = 0x50;
	}

	return ret;
}
#endif

s32 launch_firm(s32 *errorptr, u32 *arm9_entrypoint, u32 *arm11_entrypoint, TCHAR *path)
{
	#ifndef USE_RAWDEVICE
	FRESULT res;
	DWORD filesize=0;

	s32 ret;

	res = f_open(&firm_fil, path, FA_READ);
	errorptr[0] = res;
	if(res!=FR_OK)return res;

	filesize = f_size(&firm_fil);
	ret = 0;
	if((filesize < 0x200) || (filesize>>31) || (filesize & 0x1ff))ret = 0x40;
	errorptr[1] = ret;
	if(ret)
	{
		f_close(&firm_fil);
		return ret;
	}

	ret = load_firm(&errorptr[0x40>>2], read_firm_data, 0, filesize>>9, arm9_entrypoint, arm11_entrypoint);

	f_close(&firm_fil);

	return ret;
	#else
	return load_firm(&errorptr[0x40>>2], unprotboot9_sdmmc_readrawsectors, RAWDEVICE_STARTSECTOR, RAWDEVICE_NUMSECTORS, arm9_entrypoint, arm11_entrypoint);
	#endif
}
#endif

#ifndef USE_RAWDEVICE
void wchar2tchar(wchar_t *in, TCHAR *out, u32 outsize)
{
	u32 pos;
	for(pos=0; pos<outsize; pos++)out[pos] = 0;

	while(outsize>1 && *in)
	{
		*out = *in;
		in++;
		out++;
		outsize--;
	}
}
#endif

s32 load_binaries(u32 **loadaddr9, u32 *firmentrypoint9, u32 *firmentrypoint11)
{
	s32 ret;
	s32 *errortable = (s32*)0x01ffcf00;

	#ifndef USE_RAWDEVICE
	FRESULT res;
	FATFS fs;
	#endif

	unprotboot9_sdmmc_deviceid deviceid = unprotboot9_sdmmc_deviceid_sd;

	u32 is_new3ds = 0;
	u32 pos;
	u32 *firmlaunch_params = (u32*)0x20000000;

	#ifndef BINLOAD_DISABLE
	u32 *ptr;
	#endif

	TCHAR tmpstr[32];

	#ifdef FIRMLOAD_DISABLE
	*firmentrypoint9 = FIRMLOAD_DISABLE;
	#endif

	*((u32*)0x10000200) = 1;
	if(*((u32*)0x10000FFC) != 1)is_new3ds = 1;
	is_new3ds<<= 30;

	for(pos=0; pos<(0x1000>>2); pos++)firmlaunch_params[pos] = 0;//Clear the FIRM-launch params in FCRAM.

	ret = unprotboot9_sdmmc_initialize();
	errortable[0] = (u32)ret;
	if(ret)return ret;

	#ifdef USEDEVICE_NAND
	deviceid = unprotboot9_sdmmc_deviceid_nand;
	#endif

	ret = unprotboot9_sdmmc_initdevice(deviceid);
	errortable[1] = (u32)ret;
	if(ret)return ret;

	tmpstr[0] = 0;

	#ifndef USE_RAWDEVICE
	res = f_mount(&fs, tmpstr, 1);//Mount the FS.
	errortable[2] = res;
	if(res!=FR_OK)return res;
	#endif

	#ifndef BINLOAD_DISABLE
	#ifndef USE_RAWDEVICE
	wchar2tchar(ARM9BIN_FILEPATH, tmpstr, 32);
	#endif

	ret = load_binary(tmpstr, &errortable[4], loadaddr9);//Load the arm9 binary.
	if(ret)
	{
		#ifndef USE_RAWDEVICE
		tmpstr[0] = 0;
		f_mount(NULL, tmpstr, 1);
		#endif
		return ret;
	}

	ptr = *loadaddr9;
	if(ptr[1] == 0x4d415250)//Check for the PRAM magicnum @ loaded-bin+4.
	{
		ptr[2] = 3;//FIRMLAUNCH_RUNNINGTYPE
		ptr[3] = (1<<31) | is_new3ds | (0x020200) | 50;//RUNNINGFWVER (hard-coded for v9.6 FIRM for now)
	}
	#endif

	#ifndef FIRMLOAD_DISABLE
	#ifndef USE_RAWDEVICE
	wchar2tchar(FIRM_FILEPATH, tmpstr, 32);
	#endif

	ret = launch_firm(&errortable[0x40>>2], firmentrypoint9, firmentrypoint11, tmpstr);
	if(ret)
	{
		#ifndef USE_RAWDEVICE
		tmpstr[0] = 0;
		f_mount(NULL, tmpstr, 1);
		#endif
		return ret;
	}

	#ifdef BINLOAD_DISABLE
	*loadaddr9 = (u32*)*firmentrypoint9;
	#endif
	#endif

	#ifndef USE_RAWDEVICE
	tmpstr[0] = 0;
	res = f_mount(NULL, tmpstr, 1);//Unmount
	errortable[3] = res;
	if(res!=FR_OK)return res;
	#endif

	return 0;
}

s32 main_()
{
	s32 ret = 0;

	u32 firmentrypoint11 = 0;

	u32 *loadaddr9 = 0;
	u32 firmentrypoint9 = 0;

	#ifndef DISABLE_ARM11
	vu32 *arm11boot_ptr = (u32*)0x1ffffff8;
	#endif

	ret = load_binaries(&loadaddr9, &firmentrypoint9, &firmentrypoint11);
	if(ret)
	{
		#ifndef DISABLE_ARM11
		#ifndef DISABLE_ARM11ABORT
		arm11boot_ptr[0] = 0x54524241;//Tell the ARM11 to abort FIRM-boot, since an error occured.
		#endif
		#endif
		return ret;
	}

	#ifndef DISABLE_ARM11
	//Have the ARM11 jump to the FIRM entrypoint.
	arm11boot_ptr[1] = firmentrypoint11;
	arm11boot_ptr[0] = 0x544f4f42;//"BOOT"
	while(arm11boot_ptr[0] == 0x544f4f42);//Wait for the arm11 to write to this field, which is done before/after calling the payload.
	#endif

	jump_to_arm9bin((u32)loadaddr9, firmentrypoint9);
	while(1);
}


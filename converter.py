import hashlib
import binascii

"""
struct fw_header {
	uint32_t	version;	/* 0x00: header version */ 4bytes 
	char		fw_version[48]; /* 0x04: fw version string */ 48byte
	uint32_t	hw_id;		/* 0x34: hardware id */ 4byte
	uint32_t	hw_rev;		/* 0x38: FIXME: hardware revision? */ 4byte
	uint32_t	unk1;	        /* 0x3c: 0x00000000 */ 4byte
	uint8_t		md5sum1[MD5SUM_LEN]; /* 0x40 */ 16byte
	uint32_t	unk2;		/* 0x50: 0x00000000 */ 4byte
	uint8_t		md5sum2[MD5SUM_LEN]; /* 0x54 */ 16byte
	uint32_t	unk3;		/* 0x64: 0xffffffff */

	uint32_t	kernel_la;	/* 0x68: kernel load address */
	uint32_t	kernel_ep;	/* 0x6c: kernel entry point */
	uint32_t	fw_length;	/* 0x70: total length of the image */
	uint32_t	kernel_ofs;	/* 0x74: kernel data offset */
	uint32_t	kernel_len;	/* 0x78: kernel data length */
	uint32_t	rootfs_ofs;	/* 0x7c: rootfs data offset */
	uint32_t	rootfs_len;	/* 0x80: rootfs data length */
	uint32_t	boot_ofs;	/* 0x84: FIXME: seems to be unused */
	uint32_t	boot_len;	/* 0x88: FIXME: seems to be unused */
	uint16_t	unk4;		/* 0x8c: 0x55aa */
	uint8_t		sver_hi;	/* 0x8e */
	uint8_t		sver_lo;	/* 0x8f */
	uint8_t		unk5;		/* 0x90: magic: 0xa5 */
	uint8_t		ver_hi;         /* 0x91 */
	uint8_t		ver_mid;        /* 0x92 */
	uint8_t		ver_lo;         /* 0x93 */
	uint8_t		pad[364];
} __attribute__ ((packed));

char md5salt_normal[MD5SUM_LEN] = {
        0xdc, 0xd7, 0x3a, 0xa5, 0xc3, 0x95, 0x98, 0xfb,
        0xdd, 0xf9, 0xe7, 0xf4, 0x0e, 0xae, 0x47, 0x38,
};

char md5salt_boot[MD5SUM_LEN] = {
        0x8c, 0xef, 0x33, 0x5b, 0xd5, 0xc5, 0xce, 0xfa,
        0xa7, 0x9c, 0x28, 0xda, 0xb2, 0xe9, 0x0f, 0x42,
};
"""
md5salt_normal = bytes.fromhex("dcd73aa5c39598fbddf9e7f40eae4738")
md5salt_boot = bytes.fromhex("8cef335bd5c5cefaa79c28dab2e90f42")

def extractInfor(dataFirm: bytes) -> bytes:
    countryCode = dataFirm[0x120:0x132]
    MD5hash = binascii.hexlify(dataFirm[0x4C:0x5C])
    hwid = binascii.hexlify(dataFirm[0x40:0x44])
    return (countryCode, MD5hash, hwid)

def hashMD5(data: bytes) ->bytes:
    md5_hash = hashlib.md5()
    md5_hash.update(data)
    md5_value_bytes = bytes(md5_hash.hexdigest(), encoding='utf8')
    return md5_value_bytes

def patchCountryCode_MD5Salt(targetFirmData: bytes, newCountryCode: bytes, md5salt: bytes) -> bytes:

    newTargetFirm = bytearray(targetFirmData)
    newTargetFirm[0x4C:0x5C] = md5salt
    newTargetFirm[0x120:0x132] = newCountryCode
    
    newTargetFirmPatched = bytes(newTargetFirm)

    return newTargetFirmPatched

def patchMD5Value(targetFirmDataPatched: bytes, newMD5Hash: bytes) ->bytes:

    newTargetFirmPatched = bytearray(targetFirmDataPatched)

    newTargetFirmPatched[0x4C:0x5C] = newMD5Hash

    newTargetFirmData = bytes(newTargetFirmPatched)
    return newTargetFirmData

def CheckOriginFirmware(originFname: str):
    #This firmware has current region code or flashable firmware
    originF = open(originFname, "rb")
    originData = originF.read()

    #clone originData
    originData2 = originData[:]

    (curCountryCode, curMD5, curHwid) = extractInfor(originData)

    #test md5salt_normal:
    originData2Arr = bytearray(originData2)
    originData2Arr[0x4C:0x5C] = md5salt_normal
    originData2Test_normal = bytes(originData2Arr)
    if(hashMD5(originData2Test_normal) == curMD5):
        return (curCountryCode, md5salt_normal, curHwid)
    
    #test md5salt_boot:
    originData2Arr = bytearray(originData2)
    originData2Arr[0x4C:0x5C] = md5salt_boot
    originData2Test_normal = bytes(originData2Arr)
    if(hashMD5(originData2Test_normal) == curMD5):
        return (curCountryCode, md5salt_boot, curHwid)

    return (None, None, None)


def PatchTargetFirmware(targetFname: str, newCountryCode: bytes, md5salt: bytes) -> bytes:
    #This firmware cant flash into router because 18005 error (Region Locked)

    targetF = open(targetFname, "rb")
    targetData = targetF.read()

    targetData2 = targetData[:]

    tempTargetFirmPatched = patchCountryCode_MD5Salt(targetData2, newCountryCode, md5salt)

    newMD5TarHash = binascii.unhexlify(hashMD5(tempTargetFirmPatched))

    newTargetFirmDataPatched = patchMD5Value(tempTargetFirmPatched, newMD5TarHash)

    return newTargetFirmDataPatched



def main():
    (curCountryCode, md5salt, curHwid) = CheckOriginFirmware("wr940nv6_vn.bin")

    if(curCountryCode == None):
        return

    print(curCountryCode)
    print(md5salt)
    print(curHwid)

    newTargetFirmDataPatched = PatchTargetFirmware("wr940nv6_eu.bin", curCountryCode, md5salt)

    f = open("wr940nv6_eu_patched.bin", "wb")
    f.write(newTargetFirmDataPatched)
    f.close()
    return


main()
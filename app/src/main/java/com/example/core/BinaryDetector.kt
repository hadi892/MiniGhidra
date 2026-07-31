package com.example.core

/**
 * Enumeration of binary file formats detected by MiniGhidra.
 */
enum class BinaryFormat(val extension: String, val description: String) {
    ELF("elf", "Executable and Linkable Format (ELF / .so)"),
    APK("apk", "Android Package (APK / ZIP)"),
    DEX("dex", "Dalvik Executable"),
    ODEX("odex", "Optimized Dalvik Executable (ELF/OAT wrapped)"),
    VDEX("vdex", "Verified Dalvik Executable"),
    JAR("jar", "Java Archive (ZIP)"),
    ZIP("zip", "ZIP Archive"),
    MBN("mbn", "Qualcomm Modem/Firmware Boot Image (.mbn)"),
    MDT("mdt", "Qualcomm Split Metadata (.mdt)"),
    IMG("img", "Android Partition/Firmware Image (.img)"),
    BIN("bin", "Raw Binary Firmware (.bin)"),
    AR("a", "Static Library Archive (.a)"),
    OBJ("o", "Relocatable Object File (.o)"),
    UNKNOWN("bin", "Unknown / Raw Binary")
}

/**
 * Detects file formats using magic byte headers, file extensions, and structural heuristics.
 * Supports ARM64 ELF shared libraries, Qualcomm MBN/MDT firmware, Hexagon DSP images, APK/DEX, and archives.
 */
object BinaryDetector {

    /**
     * Identifies the binary format of an opened FileLoader.
     */
    fun detect(loader: FileLoader): BinaryFormat {
        if (loader.fileSize < 4) return BinaryFormat.UNKNOWN

        val magic4 = loader.readBytes(0, 4)
        if (magic4.size < 4) return BinaryFormat.UNKNOWN

        // Check magic headers first
        // ELF: 0x7F 'E' 'L' 'F' -> [0x7F, 0x45, 0x4C, 0x46]
        if (magic4[0] == 0x7F.toByte() && magic4[1] == 0x45.toByte() &&
            magic4[2] == 0x4C.toByte() && magic4[3] == 0x46.toByte()
        ) {
            return BinaryFormat.ELF
        }

        // DEX: "dex\n" -> [0x64, 0x65, 0x78, 0x0A]
        if (magic4[0] == 0x64.toByte() && magic4[1] == 0x65.toByte() &&
            magic4[2] == 0x78.toByte() && magic4[3] == 0x0A.toByte()
        ) {
            return BinaryFormat.DEX
        }

        // VDEX: "vdex" -> [0x76, 0x64, 0x65, 0x78]
        if (magic4[0] == 0x76.toByte() && magic4[1] == 0x64.toByte() &&
            magic4[2] == 0x65.toByte() && magic4[3] == 0x78.toByte()
        ) {
            return BinaryFormat.VDEX
        }

        // ZIP / APK / JAR: "PK\x03\x04" -> [0x50, 0x4B, 0x03, 0x04]
        if (magic4[0] == 0x50.toByte() && magic4[1] == 0x4B.toByte() &&
            magic4[2] == 0x03.toByte() && magic4[3] == 0x04.toByte()
        ) {
            val name = loader.filePath.lowercase()
            return when {
                name.endsWith(".apk") -> BinaryFormat.APK
                name.endsWith(".jar") -> BinaryFormat.JAR
                else -> BinaryFormat.ZIP
            }
        }

        // Static Archive (.a): "!<arch>\n" -> magic size 8
        if (loader.fileSize >= 8) {
            val magic8 = loader.readBytes(0, 8)
            val archStr = String(magic8, Charsets.US_ASCII)
            if (archStr == "!<arch>\n") {
                return BinaryFormat.AR
            }
        }

        // Check Qualcomm MBN header signatures (often start with ELF or Qualcomm partition tables)
        // Check file extensions as fallback for firmware images
        val fileName = loader.filePath.lowercase()
        return when {
            fileName.endsWith(".so") || fileName.endsWith(".elf") || fileName.endsWith(".o") -> BinaryFormat.ELF
            fileName.endsWith(".mbn") -> BinaryFormat.MBN
            fileName.endsWith(".mdt") -> BinaryFormat.MDT
            fileName.endsWith(".img") -> BinaryFormat.IMG
            fileName.endsWith(".odex") || fileName.endsWith(".oat") -> BinaryFormat.ODEX
            fileName.endsWith(".vdex") -> BinaryFormat.VDEX
            fileName.endsWith(".apk") -> BinaryFormat.APK
            fileName.endsWith(".dex") -> BinaryFormat.DEX
            fileName.endsWith(".a") -> BinaryFormat.AR
            fileName.endsWith(".bin") -> BinaryFormat.BIN
            else -> BinaryFormat.UNKNOWN
        }
    }
}

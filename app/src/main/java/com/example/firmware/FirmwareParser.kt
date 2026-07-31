package com.example.firmware

import com.example.core.FileLoader
import com.example.core.Logger
import com.example.elf.ELFParser

/**
 * Firmware image type detected.
 */
enum class FirmwareType(val label: String) {
    QCOM_MBN("Qualcomm MBN Firmware"),
    QCOM_MDT("Qualcomm Split MDT Header"),
    ANDROID_BOOT_IMG("Android Boot/Recovery Partition Image (.img)"),
    RAW_BIN("Raw Binary Firmware (.bin)"),
    ELF_FIRMWARE("ELF-wrapped DSP/TrustZone Firmware")
}

/**
 * Firmware segment entry from partition headers or ELF segments.
 */
data class FirmwareSegment(
    val index: Int,
    val name: String,
    val fileOffset: Long,
    val loadAddress: Long,
    val size: Long,
    val isExecutable: Boolean,
    val isCompressed: Boolean,
    val compressionType: String = "NONE"
)

/**
 * Summary of detected cryptographic checksums and signatures in a firmware image.
 */
data class FirmwareSecurityInfo(
    val hasCrc32: Boolean,
    val hasMd5: Boolean,
    val hasSha1: Boolean,
    val hasSha256: Boolean,
    val hasRsaSignature: Boolean,
    val certificateChainOffset: Long? = null,
    val trustZoneSecured: Boolean
)

/**
 * Full firmware analysis result.
 */
data class FirmwareAnalysisReport(
    val filePath: String,
    val type: FirmwareType,
    val headerInfo: String,
    val entryPoint: Long,
    val segments: List<FirmwareSegment>,
    val securityInfo: FirmwareSecurityInfo,
    val dspSubsystems: List<String>
)

/**
 * Comprehensive Firmware header and segment parser supporting MBN, MDT, IMG, and ELF firmware images.
 */
object FirmwareParser {

    fun analyze(loader: FileLoader): FirmwareAnalysisReport {
        val start = System.currentTimeMillis()
        val fileSize = loader.fileSize
        var type = FirmwareType.RAW_BIN
        var entryPoint = 0L
        val segments = mutableListOf<FirmwareSegment>()
        var headerInfo = "Raw Binary Image (${fileSize} bytes)"

        // 1. Check for ELF-wrapped firmware (standard for Qualcomm ADSP / SLPI / CDSP / Modem MBNs)
        val magic4 = if (fileSize >= 4) loader.readBytes(0, 4) else ByteArray(0)
        if (magic4.size == 4 && magic4[0] == 0x7F.toByte() && magic4[1] == 0x45.toByte() &&
            magic4[2] == 0x4C.toByte() && magic4[3] == 0x46.toByte()
        ) {
            type = if (loader.filePath.endsWith(".mbn", true)) FirmwareType.QCOM_MBN
            else if (loader.filePath.endsWith(".mdt", true)) FirmwareType.QCOM_MDT
            else FirmwareType.ELF_FIRMWARE

            val elfFile = ELFParser.parse(loader)
            if (elfFile != null) {
                entryPoint = elfFile.header.entryPoint
                headerInfo = "ELF-wrapped Firmware: ${elfFile.header.machine.label} (${elfFile.header.type.label})"
                for ((idx, ph) in elfFile.programHeaders.withIndex()) {
                    val comp = detectSegmentCompression(loader, ph.offset)
                    segments.add(
                        FirmwareSegment(
                            index = idx,
                            name = "SEG_$idx (${ph.type.name})",
                            fileOffset = ph.offset,
                            loadAddress = ph.virtualAddress,
                            size = ph.fileSize,
                            isExecutable = ph.isExecutable,
                            isCompressed = comp != "NONE",
                            compressionType = comp
                        )
                    )
                }
            }
        } else if (magic4.size == 4 && String(magic4, Charsets.US_ASCII) == "ANDROID!") {
            // 2. Android boot.img / vendor_boot.img header (magic: "ANDROID!")
            type = FirmwareType.ANDROID_BOOT_IMG
            val kernelAddr = loader.readU32(12)
            val ramdiskAddr = loader.readU32(20)
            entryPoint = kernelAddr
            headerInfo = "Android Partition Image (Kernel: 0x${kernelAddr.toString(16)}, Ramdisk: 0x${ramdiskAddr.toString(16)})"
            segments.add(FirmwareSegment(0, "KERNEL", 2048, kernelAddr, fileSize / 2, true, false))
            segments.add(FirmwareSegment(1, "RAMDISK", fileSize / 2, ramdiskAddr, fileSize / 4, false, true, "GZIP"))
        } else {
            // 3. Raw BIN / MBN check
            segments.add(
                FirmwareSegment(
                    index = 0,
                    name = "RAW_IMAGE",
                    fileOffset = 0L,
                    loadAddress = 0x80000000L,
                    size = fileSize,
                    isExecutable = true,
                    isCompressed = false
                )
            )
        }

        // Detect security signatures & certificates
        val securityInfo = scanFirmwareSecurity(loader)
        // Detect DSP subsystems referenced in strings
        val subsystems = detectDspSubsystems(loader)

        val elapsed = System.currentTimeMillis() - start
        Logger.info("FirmwareParser", "Analyzed firmware $type in ${elapsed}ms (${segments.size} segments)")

        return FirmwareAnalysisReport(
            filePath = loader.filePath,
            type = type,
            headerInfo = headerInfo,
            entryPoint = entryPoint,
            segments = segments,
            securityInfo = securityInfo,
            dspSubsystems = subsystems
        )
    }

    private fun detectSegmentCompression(loader: FileLoader, offset: Long): String {
        if (offset + 4 >= loader.fileSize) return "NONE"
        val b = loader.readBytes(offset, 4)
        if (b.size < 4) return "NONE"
        // GZIP magic: 0x1F 0x8B
        if (b[0] == 0x1F.toByte() && b[1] == 0x8B.toByte()) return "GZIP"
        // LZ4 magic: 0x04 0x22 0x4D 0x18
        if (b[0] == 0x04.toByte() && b[1] == 0x22.toByte() && b[2] == 0x4D.toByte() && b[3] == 0x18.toByte()) return "LZ4"
        // ZSTD magic: 0x28 0xB5 0x2F 0xFD
        if (b[0] == 0x28.toByte() && b[1] == 0xB5.toByte() && b[2] == 0x2F.toByte() && b[3] == 0xFD.toByte()) return "ZSTD"
        return "NONE"
    }

    private fun scanFirmwareSecurity(loader: FileLoader): FirmwareSecurityInfo {
        val sampleSize = 524288L.coerceAtMost(loader.fileSize)
        val sample = loader.readBytes(0, sampleSize.toInt())
        val ascii = String(sample, Charsets.US_ASCII)

        val hasCrc = ascii.contains("CRC32") || ascii.contains("crc_")
        val hasMd5 = ascii.contains("MD5") || ascii.contains("md5_")
        val hasSha1 = ascii.contains("SHA1") || ascii.contains("sha1_")
        val hasSha256 = ascii.contains("SHA256") || ascii.contains("sha256_")
        val hasRsa = ascii.contains("RSA") || ascii.contains("-----BEGIN CERTIFICATE-----") || ascii.contains("QSEE")
        val trustZone = ascii.contains("TrustZone") || ascii.contains("tz_") || ascii.contains("qsee_")

        var certOffset: Long? = null
        val certIdx = ascii.indexOf("-----BEGIN CERTIFICATE-----")
        if (certIdx >= 0) certOffset = certIdx.toLong()

        return FirmwareSecurityInfo(
            hasCrc32 = hasCrc,
            hasMd5 = hasMd5,
            hasSha1 = hasSha1,
            hasSha256 = hasSha256,
            hasRsaSignature = hasRsa,
            certificateChainOffset = certOffset,
            trustZoneSecured = trustZone
        )
    }

    private fun detectDspSubsystems(loader: FileLoader): List<String> {
        val sampleSize = 1048576L.coerceAtMost(loader.fileSize)
        val sample = loader.readBytes(0, sampleSize.toInt())
        val ascii = String(sample, Charsets.US_ASCII)
        val subsystems = mutableListOf<String>()

        if (ascii.contains("ADSP") || ascii.contains("adsp_")) subsystems.add("Audio DSP (ADSP)")
        if (ascii.contains("SDSP") || ascii.contains("slpi") || ascii.contains("ssc")) subsystems.add("Sensor DSP (SDSP/SLPI)")
        if (ascii.contains("CDSP") || ascii.contains("cdsp_")) subsystems.add("Compute DSP (CDSP)")
        if (ascii.contains("MPSS") || ascii.contains("modem")) subsystems.add("Modem DSP (MPSS)")
        if (ascii.contains("ICP") || ascii.contains("camera")) subsystems.add("Camera DSP (ICP)")
        if (ascii.contains("MDSP")) subsystems.add("Multimedia DSP")

        return subsystems
    }
}

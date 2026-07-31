package com.example.binary

import com.example.core.FileLoader
import com.example.core.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.zip.ZipFile

/**
 * Represents an entry inside an archive (APK, JAR, ZIP).
 */
data class ArchiveEntryInfo(
    val name: String,
    val compressedSize: Long,
    val uncompressedSize: Long,
    val isDirectory: Boolean
)

/**
 * Summary of an APK archive analysis.
 */
data class APKSummary(
    val packageName: String,
    val totalEntries: Int,
    val dexFiles: List<String>,
    val nativeLibAbis: List<String>,
    val nativeLibraries: List<String>,
    val hasAndroidManifest: Boolean
)

object APKAnalyzer {
    suspend fun analyzeApk(file: File): APKSummary? = withContext(Dispatchers.IO) {
        if (!file.exists() || !file.canRead()) return@withContext null
        try {
            val zf = ZipFile(file)
            val entries = zf.entries().asSequence().toList()
            val dexList = mutableListOf<String>()
            val abiSet = mutableSetOf<String>()
            val soList = mutableListOf<String>()
            var hasManifest = false

            for (e in entries) {
                if (e.name == "AndroidManifest.xml") hasManifest = true
                if (e.name.endsWith(".dex")) dexList.add(e.name)
                if (e.name.startsWith("lib/") && e.name.endsWith(".so")) {
                    val parts = e.name.split("/")
                    if (parts.size >= 2) {
                        abiSet.add(parts[1])
                    }
                    soList.add(e.name)
                }
            }
            zf.close()

            APKSummary(
                packageName = file.nameWithoutExtension,
                totalEntries = entries.size,
                dexFiles = dexList,
                nativeLibAbis = abiSet.toList().sorted(),
                nativeLibraries = soList.sorted(),
                hasAndroidManifest = hasManifest
            )
        } catch (e: Exception) {
            Logger.error("APKAnalyzer", "Error analyzing APK ${file.name}", e)
            null
        }
    }
}

/**
 * DEX header summary.
 */
data class DEXSummary(
    val magic: String,
    val checksum: Long,
    val stringIdsSize: Int,
    val typeIdsSize: Int,
    val protoIdsSize: Int,
    val fieldIdsSize: Int,
    val methodIdsSize: Int,
    val classDefsSize: Int
)

object DEXAnalyzer {
    fun analyze(loader: FileLoader): DEXSummary? {
        if (loader.fileSize < 112) return null
        val magicBytes = loader.readBytes(0, 8)
        val magicStr = String(magicBytes, Charsets.US_ASCII).replace("\n", "\\n").replace("\u0000", "")
        if (!magicStr.startsWith("dex")) return null

        val checksum = loader.readU32(8)
        val stringIdsSize = loader.readU32(56).toInt()
        val typeIdsSize = loader.readU32(64).toInt()
        val protoIdsSize = loader.readU32(72).toInt()
        val fieldIdsSize = loader.readU32(80).toInt()
        val methodIdsSize = loader.readU32(88).toInt()
        val classDefsSize = loader.readU32(96).toInt()

        return DEXSummary(
            magic = magicStr,
            checksum = checksum,
            stringIdsSize = stringIdsSize,
            typeIdsSize = typeIdsSize,
            protoIdsSize = protoIdsSize,
            fieldIdsSize = fieldIdsSize,
            methodIdsSize = methodIdsSize,
            classDefsSize = classDefsSize
        )
    }
}

/**
 * VDEX/ODEX header summary.
 */
data class ODEXSummary(
    val formatName: String,
    val isOat: Boolean,
    val oatVersion: String,
    val embeddedDexCount: Int
)

object ODEXAnalyzer {
    fun analyze(loader: FileLoader): ODEXSummary? {
        if (loader.fileSize < 64) return null
        val magicBytes = loader.readBytes(0, 8)
        val ascii = String(magicBytes, Charsets.US_ASCII)
        return when {
            ascii.startsWith("oat\n") -> {
                val ver = ascii.substring(4, 7)
                val dexCount = loader.readU32(20).toInt()
                ODEXSummary("ODEX/OAT", true, ver, dexCount)
            }
            ascii.startsWith("vdex") -> {
                val ver = ascii.substring(4, 7)
                ODEXSummary("VDEX", false, ver, 1)
            }
            else -> null
        }
    }
}

/**
 * ZIP / JAR Archive analyzer.
 */
object ZIPAnalyzer {
    suspend fun listEntries(file: File): List<ArchiveEntryInfo> = withContext(Dispatchers.IO) {
        if (!file.exists()) return@withContext emptyList()
        try {
            val zf = ZipFile(file)
            val list = zf.entries().asSequence().map { e ->
                ArchiveEntryInfo(
                    name = e.name,
                    compressedSize = e.compressedSize,
                    uncompressedSize = e.size,
                    isDirectory = e.isDirectory
                )
            }.toList()
            zf.close()
            list
        } catch (e: Exception) {
            Logger.error("ZIPAnalyzer", "Error reading archive ${file.name}", e)
            emptyList()
        }
    }
}

/**
 * Generates structured text and markdown analysis reports.
 */
object ReportGenerator {
    fun generateTextReport(
        title: String,
        sections: Map<String, List<String>>
    ): String = buildString {
        appendLine("=".repeat(60))
        appendLine("MINIGHIDRA ANALYSIS REPORT: $title")
        appendLine("=".repeat(60))
        appendLine()
        for ((header, lines) in sections) {
            appendLine("--- $header ---")
            for (line in lines) {
                appendLine("  * $line")
            }
            appendLine()
        }
        appendLine("=".repeat(60))
        appendLine("End of Report")
    }
}

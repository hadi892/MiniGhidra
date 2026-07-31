package com.example.binary

import com.example.core.FileLoader
import com.example.core.Logger
import com.example.elf.ELFFile
import com.example.elf.ProgramHeader
import com.example.elf.SectionHeader
import com.example.elf.Symbol
import java.io.File

/**
 * Statistical analysis of instruction opcode categories in executable sections.
 */
data class InstructionStatistics(
    val totalInstructions: Long,
    val branchInstructions: Long,
    val loadStoreInstructions: Long,
    val arithmeticInstructions: Long,
    val dspInstructions: Long,
    val supervisorCalls: Long
)

object InstructionAnalyzer {
    fun analyze(loader: FileLoader, elfFile: ELFFile): InstructionStatistics {
        var total = 0L
        var branches = 0L
        var loadStore = 0L
        var arithmetic = 0L
        var dsp = 0L
        var svc = 0L

        // Scan executable sections (.text)
        val textSection = elfFile.getSectionByName(".text") ?: return InstructionStatistics(0, 0, 0, 0, 0, 0)
        val isArm64 = elfFile.isArm64
        val isHexagon = elfFile.isHexagonDsp
        val step = 4

        val size = textSection.size.coerceAtMost(1048576L) // sample first 1MB for speed
        val bytes = loader.readBytes(textSection.offset, size.toInt())

        var i = 0
        while (i <= bytes.size - 4) {
            val op = ((bytes[i].toInt() and 0xFF)) or
                    ((bytes[i + 1].toInt() and 0xFF) shl 8) or
                    ((bytes[i + 2].toInt() and 0xFF) shl 16) or
                    ((bytes[i + 3].toInt() and 0xFF) shl 24)
            total++

            if (isArm64) {
                // Check ARM64 instruction categories
                when {
                    (op and 0x7C000000) == 0x14000000 -> branches++ // B, BL
                    (op and 0x7E000000) == 0x34000000 -> branches++ // CBZ, CBNZ
                    (op and 0x3B000000) == 0x38000000 -> loadStore++ // LDR, STR
                    (op and 0x3F000000) == 0x29000000 -> loadStore++ // STP, LDP
                    (op and 0x1F000000) == 0x0B000000 -> arithmetic++ // ADD, SUB
                    (op and 0xFFE0001F.toInt()) == 0xD4000001.toInt() -> svc++ // SVC #0
                }
            } else if (isHexagon) {
                // Check Hexagon instruction packets
                when {
                    (op and 0xE0000000.toInt()) == 0x20000000 -> branches++
                    (op and 0xE0000000.toInt()) == 0x80000000.toInt() -> loadStore++
                    (op and 0xE0000000.toInt()) == 0xC0000000.toInt() -> dsp++
                }
            }
            i += step
        }
        return InstructionStatistics(total, branches, loadStore, arithmetic, dsp, svc)
    }
}

/**
 * Discovers function prologues and epilogues in ARM64 or Hexagon machine code.
 */
data class DiscoveredFunction(
    val address: Long,
    val offset: Long,
    val estimatedSize: Long,
    val name: String,
    val hasStackFrame: Boolean
)

object FunctionAnalyzer {
    fun discoverFunctions(loader: FileLoader, elfFile: ELFFile): List<DiscoveredFunction> {
        val list = mutableListOf<DiscoveredFunction>()
        val text = elfFile.getSectionByName(".text") ?: return emptyList()

        // First add known symbol table functions
        val symFuncs = elfFile.getSymbolsByType("FUNC")
        for (sf in symFuncs) {
            val off = text.offset + (sf.value - text.address)
            list.add(
                DiscoveredFunction(
                    address = sf.value,
                    offset = off,
                    estimatedSize = sf.size.coerceAtLeast(4L),
                    name = sf.name,
                    hasStackFrame = true
                )
            )
        }

        // Now perform heuristic prologue scanning if symbol table was stripped
        if (list.isEmpty() && elfFile.isArm64) {
            val size = text.size.coerceAtMost(524288L).toInt()
            val bytes = loader.readBytes(text.offset, size)
            var i = 0
            var funcCount = 1
            while (i <= bytes.size - 4) {
                val op = ((bytes[i].toInt() and 0xFF)) or
                        ((bytes[i + 1].toInt() and 0xFF) shl 8) or
                        ((bytes[i + 2].toInt() and 0xFF) shl 16) or
                        ((bytes[i + 3].toInt() and 0xFF) shl 24)
                // ARM64 prologue: stp x29, x30, [sp, -#imm]! -> 0xA9B... / 0xA9A...
                if ((op and 0x7F800000) == 0x29800000 && (op and 0x000003FF) == 0x000003FD) {
                    val addr = text.address + i
                    list.add(
                        DiscoveredFunction(
                            address = addr,
                            offset = text.offset + i,
                            estimatedSize = 64L,
                            name = "sub_${addr.toString(16)}",
                            hasStackFrame = true
                        )
                    )
                    funcCount++
                    if (list.size > 2000) break
                }
                i += 4
            }
        }
        return list.sortedBy { it.address }
    }
}

/**
 * Maps memory segments and permissions.
 */
data class MemorySegment(
    val name: String,
    val virtualAddress: Long,
    val fileSize: Long,
    val memorySize: Long,
    val permissions: String
)

object MemoryAnalyzer {
    fun analyzeMemoryLayout(elfFile: ELFFile): List<MemorySegment> {
        val list = mutableListOf<MemorySegment>()
        for ((idx, ph) in elfFile.programHeaders.withIndex()) {
            val name = when (ph.type) {
                com.example.elf.PhdrType.PT_LOAD -> "LOAD_${idx}"
                com.example.elf.PhdrType.PT_DYNAMIC -> "DYNAMIC"
                com.example.elf.PhdrType.PT_INTERP -> "INTERP"
                com.example.elf.PhdrType.PT_GNU_RELRO -> "RELRO"
                com.example.elf.PhdrType.PT_GNU_STACK -> "STACK"
                else -> ph.type.name
            }
            list.add(
                MemorySegment(
                    name = name,
                    virtualAddress = ph.virtualAddress,
                    fileSize = ph.fileSize,
                    memorySize = ph.memorySize,
                    permissions = ph.permissionString
                )
            )
        }
        return list
    }
}

/**
 * Cross-reference (XREF) analyzer between symbols, code addresses, and strings.
 */
data class CrossReference(
    val sourceAddress: Long,
    val targetAddress: Long,
    val targetName: String,
    val type: XRefType
)

enum class XRefType {
    CALL, JUMP, DATA_READ, STRING_REF
}

object ReferenceAnalyzer {
    fun findCrossReferences(elfFile: ELFFile): List<CrossReference> {
        val xrefs = mutableListOf<CrossReference>()
        for (rel in elfFile.relocationTables.flatMap { it.relocations }) {
            if (rel.symbolName != null) {
                xrefs.add(
                    CrossReference(
                        sourceAddress = rel.offset,
                        targetAddress = rel.offset + rel.addend,
                        targetName = rel.symbolName,
                        type = XRefType.DATA_READ
                    )
                )
            }
        }
        return xrefs
    }
}

/**
 * Analyzes ELF Section properties, flags, and alignment.
 */
data class SectionSummary(
    val index: Int,
    val name: String,
    val type: String,
    val size: Long,
    val address: Long,
    val flags: String
)

object SectionAnalyzer {
    fun summarizeSections(elfFile: ELFFile): List<SectionSummary> {
        return elfFile.sectionHeaders.map { sh ->
            val flagStr = buildString {
                if (sh.isAllocated) append("A")
                if (sh.isWritable) append("W")
                if (sh.isExecutable) append("X")
            }
            SectionSummary(
                index = sh.index,
                name = sh.name,
                type = sh.type.name,
                size = sh.size,
                address = sh.address,
                flags = flagStr
            )
        }
    }
}

/**
 * Signature analyzer for compilers, cryptography suites, and vendor SDK tags.
 */
data class DetectedSignature(
    val category: String,
    val name: String,
    val confidence: String
)

object SignatureAnalyzer {
    fun detectSignatures(loader: FileLoader, elfFile: ELFFile): List<DetectedSignature> {
        val list = mutableListOf<DetectedSignature>()
        val rodata = elfFile.getSectionByName(".rodata") ?: elfFile.getSectionByName(".comment")
        val scanSize = (rodata?.size ?: 65536L).coerceAtMost(524288L).toInt()
        val offset = rodata?.offset ?: 0L
        val data = loader.readBytes(offset, scanSize)
        val ascii = String(data, Charsets.US_ASCII)

        if (ascii.contains("Android NDK") || ascii.contains("ndk-build") || ascii.contains("clang version")) {
            list.add(DetectedSignature("Compiler", "Clang/LLVM (Android NDK)", "High"))
        }
        if (ascii.contains("GCC: (GNU)")) {
            list.add(DetectedSignature("Compiler", "GCC GNU Toolchain", "High"))
        }
        if (ascii.contains("OpenSSL") || ascii.contains("BoringSSL") || ascii.contains("AES_encrypt")) {
            list.add(DetectedSignature("Cryptography", "OpenSSL / BoringSSL", "High"))
        }
        if (ascii.contains("Qualcomm Technologies") || ascii.contains("QTI") || ascii.contains("qcom,adreno")) {
            list.add(DetectedSignature("Vendor SDK", "Qualcomm Technologies Inc. (QTI)", "High"))
        }
        if (ascii.contains("libunity.so") || ascii.contains("UnityPlayer")) {
            list.add(DetectedSignature("Game Engine", "Unity 3D Engine", "High"))
        }
        return list
    }
}

/**
 * System library scanner for Android 16 /system/lib64, /system_ext/lib64, /vendor/lib64, /apex without root.
 */
data class SystemLibraryEntry(
    val name: String,
    val absolutePath: String,
    val partition: String,
    val sizeBytes: Long
)

object LibraryAnalyzer {
    private val SEARCH_DIRS = listOf(
        "/system/lib64",
        "/system_ext/lib64",
        "/vendor/lib64",
        "/product/lib64",
        "/odm/lib64",
        "/apex/com.android.runtime/lib64",
        "/apex/com.android.art/lib64"
    )

    fun listSystemLibraries(): List<SystemLibraryEntry> {
        val results = mutableListOf<SystemLibraryEntry>()
        for (dirPath in SEARCH_DIRS) {
            val dir = File(dirPath)
            if (dir.exists() && dir.isDirectory) {
                try {
                    val files = dir.listFiles()
                    if (files != null) {
                        for (f in files) {
                            if (f.isFile && (f.name.endsWith(".so") || f.name.endsWith(".elf"))) {
                                val partition = dirPath.split("/").filter { it.isNotEmpty() }.firstOrNull() ?: "system"
                                results.add(
                                    SystemLibraryEntry(
                                        name = f.name,
                                        absolutePath = f.absolutePath,
                                        partition = partition,
                                        sizeBytes = f.length()
                                    )
                                )
                            }
                        }
                    }
                } catch (e: Exception) {
                    Logger.warn("LibraryAnalyzer", "Cannot scan directory $dirPath: ${e.message}")
                }
            }
        }
        Logger.info("LibraryAnalyzer", "Discovered ${results.size} system libraries across ${SEARCH_DIRS.size} directories.")
        return results.sortedBy { it.name }
    }
}

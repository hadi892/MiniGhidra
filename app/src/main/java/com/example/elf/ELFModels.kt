package com.example.elf

import com.example.core.Endianness

/**
 * ELF architecture class (32-bit or 64-bit).
 */
enum class ElfClass(val value: Int, val label: String) {
    ELFCLASSNONE(0, "Invalid"),
    ELFCLASS32(1, "ELF32 (32-bit)"),
    ELFCLASS64(2, "ELF64 (64-bit)");

    companion object {
        fun fromValue(v: Int): ElfClass = values().firstOrNull { it.value == v } ?: ELFCLASSNONE
    }
}

/**
 * ELF data encoding (Endianness).
 */
enum class ElfEndian(val value: Int, val label: String) {
    ELFDATANONE(0, "Invalid"),
    ELFDATA2LSB(1, "2's complement, Little-Endian"),
    ELFDATA2MSB(2, "2's complement, Big-Endian");

    companion object {
        fun fromValue(v: Int): ElfEndian = values().firstOrNull { it.value == v } ?: ELFDATANONE
    }
}

/**
 * ELF file type (Shared Object, Executable, Relocatable, etc.).
 */
enum class ElfType(val value: Int, val label: String) {
    ET_NONE(0, "No file type"),
    ET_REL(1, "Relocatable object file (.o)"),
    ET_EXEC(2, "Executable file"),
    ET_DYN(3, "Shared object file (.so / PIE)"),
    ET_CORE(4, "Core dump file"),
    ET_UNKNOWN(-1, "Unknown");

    companion object {
        fun fromValue(v: Int): ElfType = values().firstOrNull { it.value == v } ?: ET_UNKNOWN
    }
}

/**
 * ELF target machine architecture (ARM, ARM64/AArch64, Hexagon, x86_64, etc.).
 */
enum class ElfMachine(val value: Int, val label: String) {
    EM_NONE(0, "No machine"),
    EM_386(3, "Intel 80386"),
    EM_ARM(40, "ARM 32-bit (ARMv7)"),
    EM_X86_64(62, "AMD x86-64"),
    EM_QDSP6(164, "Qualcomm Hexagon DSP (QDSP6)"),
    EM_AARCH64(183, "ARM AArch64 (ARM64-v8a)"),
    EM_RISCV(243, "RISC-V"),
    EM_UNKNOWN(-1, "Unknown Machine");

    companion object {
        fun fromValue(v: Int): ElfMachine = values().firstOrNull { it.value == v } ?: EM_UNKNOWN
    }
}

/**
 * ELF Program Header entry type.
 */
enum class PhdrType(val value: Long, val label: String) {
    PT_NULL(0, "NULL"),
    PT_LOAD(1, "LOAD"),
    PT_DYNAMIC(2, "DYNAMIC"),
    PT_INTERP(3, "INTERP"),
    PT_NOTE(4, "NOTE"),
    PT_SHLIB(5, "SHLIB"),
    PT_PHDR(6, "PHDR"),
    PT_TLS(7, "TLS"),
    PT_GNU_EH_FRAME(0x6474e550L, "GNU_EH_FRAME"),
    PT_GNU_STACK(0x6474e551L, "GNU_STACK"),
    PT_GNU_RELRO(0x6474e552L, "GNU_RELRO"),
    PT_GNU_PROPERTY(0x6474e553L, "GNU_PROPERTY"),
    PT_ARM_EXIDX(0x70000001L, "ARM_EXIDX"),
    PT_UNKNOWN(-1, "UNKNOWN");

    companion object {
        fun fromValue(v: Long): PhdrType = values().firstOrNull { it.value == v } ?: PT_UNKNOWN
    }
}

/**
 * ELF Section Header entry type.
 */
enum class ShdrType(val value: Long, val label: String) {
    SHT_NULL(0, "NULL"),
    SHT_PROGBITS(1, "PROGBITS"),
    SHT_SYMTAB(2, "SYMTAB"),
    SHT_STRTAB(3, "STRTAB"),
    SHT_RELA(4, "RELA"),
    SHT_HASH(5, "HASH"),
    SHT_DYNAMIC(6, "DYNAMIC"),
    SHT_NOTE(7, "NOTE"),
    SHT_NOBITS(8, "NOBITS"),
    SHT_REL(9, "REL"),
    SHT_SHLIB(10, "SHLIB"),
    SHT_DYNSYM(11, "DYNSYM"),
    SHT_INIT_ARRAY(14, "INIT_ARRAY"),
    SHT_FINI_ARRAY(15, "FINI_ARRAY"),
    SHT_PREINIT_ARRAY(16, "PREINIT_ARRAY"),
    SHT_GNU_HASH(0x6ffffef5L, "GNU_HASH"),
    SHT_GNU_verdef(0x6ffffffdL, "GNU_verdef"),
    SHT_GNU_verneed(0x6ffffffeL, "GNU_verneed"),
    SHT_GNU_versym(0x6fffffffL, "GNU_versym"),
    SHT_ARM_EXIDX(0x70000001L, "ARM_EXIDX"),
    SHT_UNKNOWN(-1, "UNKNOWN");

    companion object {
        fun fromValue(v: Long): ShdrType = values().firstOrNull { it.value == v } ?: SHT_UNKNOWN
    }
}

/**
 * Represents the main ELF Header (32-bit and 64-bit unified).
 */
data class ELFHeader(
    val elfClass: ElfClass,
    val elfEndian: ElfEndian,
    val elfVersion: Int,
    val osAbi: Int,
    val abiVersion: Int,
    val type: ElfType,
    val machine: ElfMachine,
    val version: Long,
    val entryPoint: Long,
    val programHeaderOffset: Long,
    val sectionHeaderOffset: Long,
    val flags: Long,
    val headerSize: Int,
    val programHeaderEntrySize: Int,
    val programHeaderCount: Int,
    val sectionHeaderEntrySize: Int,
    val sectionHeaderCount: Int,
    val sectionHeaderStringTableIndex: Int
)

/**
 * Represents an ELF Program Header (segment).
 */
data class ProgramHeader(
    val type: PhdrType,
    val rawType: Long,
    val flags: Long,
    val offset: Long,
    val virtualAddress: Long,
    val physicalAddress: Long,
    val fileSize: Long,
    val memorySize: Long,
    val alignment: Long
) {
    val isReadable: Boolean get() = (flags and 4L) != 0L
    val isWritable: Boolean get() = (flags and 2L) != 0L
    val isExecutable: Boolean get() = (flags and 1L) != 0L

    val permissionString: String
        get() = "${if (isReadable) "R" else "-"}${if (isWritable) "W" else "-"}${if (isExecutable) "X" else "-"}"
}

/**
 * Represents an ELF Section Header.
 */
data class SectionHeader(
    val index: Int,
    val nameIndex: Long,
    val name: String,
    val type: ShdrType,
    val rawType: Long,
    val flags: Long,
    val address: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val alignment: Long,
    val entrySize: Long
) {
    val isAllocated: Boolean get() = (flags and 0x2L) != 0L
    val isExecutable: Boolean get() = (flags and 0x4L) != 0L
    val isWritable: Boolean get() = (flags and 0x1L) != 0L
}

/**
 * ELF Dynamic Section Entry tag tags.
 */
data class DynamicEntry(
    val tag: Long,
    val value: Long,
    val description: String,
    val resolvedString: String? = null
)

/**
 * ELF Symbol table entry (SYMTAB or DYNSYM).
 */
data class Symbol(
    val index: Int,
    val nameIndex: Long,
    val name: String,
    val value: Long,
    val size: Long,
    val info: Int,
    val other: Int,
    val sectionIndex: Int
) {
    val binding: String
        get() = when (info shr 4) {
            0 -> "LOCAL"
            1 -> "GLOBAL"
            2 -> "WEAK"
            else -> "OTHER"
        }

    val typeString: String
        get() = when (info and 0xF) {
            0 -> "NOTYPE"
            1 -> "OBJECT"
            2 -> "FUNC"
            3 -> "SECTION"
            4 -> "FILE"
            6 -> "TLS"
            10 -> "GNU_IFUNC"
            else -> "UNKNOWN"
        }
}

/**
 * ELF Relocation entry (.rel or .rela).
 */
data class Relocation(
    val offset: Long,
    val info: Long,
    val addend: Long,
    val type: Int,
    val symbolIndex: Int,
    val symbolName: String? = null
)

/**
 * ELF Symbol Version Definition (.gnu.version_d).
 */
data class VersionDefinition(
    val version: Int,
    val flags: Int,
    val index: Int,
    val dependencyCount: Int,
    val name: String
)

/**
 * ELF Symbol Version Requirement / Need (.gnu.version_r).
 */
data class VersionNeed(
    val version: Int,
    val fileCount: Int,
    val fileName: String,
    val neededVersions: List<String>
)

/**
 * ELF Symbol Version index (.gnu.version).
 */
data class VersionSymbol(
    val symbolIndex: Int,
    val versionIndex: Int,
    val isHidden: Boolean,
    val label: String
)

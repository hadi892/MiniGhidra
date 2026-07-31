package com.example.elf

/**
 * Complete in-memory representation of an ELF binary parsed by MiniGhidra.
 * Supports ELF32, ELF64, ARM, ARM64, Hexagon, static and dynamic libraries/executables.
 */
data class ELFFile(
    val filePath: String,
    val header: ELFHeader,
    val programHeaders: List<ProgramHeader>,
    val sectionHeaders: List<SectionHeader>,
    val dynamicSection: List<DynamicEntry> = emptyList(),
    val symbolTables: List<SymbolTable> = emptyList(),
    val relocationTables: List<RelocationTable> = emptyList(),
    val stringTables: List<StringTable> = emptyList(),
    val hashTable: HashTable? = null,
    val gnuHash: GNUHash? = null,
    val versionDefinitions: List<VersionDefinition> = emptyList(),
    val versionNeeds: List<VersionNeed> = emptyList(),
    val versionSymbols: List<VersionSymbol> = emptyList()
) {
    /**
     * Checks whether this ELF binary is a shared library (.so).
     */
    val isSharedLibrary: Boolean
        get() = header.type == ElfType.ET_DYN

    /**
     * Checks whether this ELF binary is statically linked.
     */
    val isStaticElf: Boolean
        get() = dynamicSection.isEmpty() && programHeaders.none { it.type == PhdrType.PT_DYNAMIC }

    /**
     * Checks whether this ELF binary is Position Independent Executable (PIE).
     */
    val isPie: Boolean
        get() = header.type == ElfType.ET_DYN && dynamicSection.any { it.tag == 3L } // DT_PLTGOT or entry exists

    /**
     * Checks whether this ELF is for ARM64/AArch64.
     */
    val isArm64: Boolean
        get() = header.machine == ElfMachine.EM_AARCH64

    /**
     * Checks whether this ELF is for ARM 32-bit.
     */
    val isArm32: Boolean
        get() = header.machine == ElfMachine.EM_ARM

    /**
     * Checks whether this ELF is for Qualcomm Hexagon DSP.
     */
    val isHexagonDsp: Boolean
        get() = header.machine == ElfMachine.EM_QDSP6

    /**
     * Finds a section header by its exact section name.
     */
    fun getSectionByName(name: String): SectionHeader? =
        sectionHeaders.firstOrNull { it.name == name }

    /**
     * Retrieves all symbols of a given type (e.g. "FUNC", "OBJECT").
     */
    fun getSymbolsByType(type: String): List<Symbol> =
        symbolTables.flatMap { it.symbols }.filter { it.typeString == type }

    /**
     * Retrieves all needed shared library dependency names (DT_NEEDED).
     */
    val neededDependencies: List<String>
        get() = dynamicSection.filter { it.tag == 1L }.mapNotNull { it.resolvedString }

    /**
     * Retrieves all exported symbols from dynamic or static tables.
     */
    val allExports: List<Symbol>
        get() = symbolTables.flatMap { it.exports }

    /**
     * Retrieves all imported symbols.
     */
    val allImports: List<Symbol>
        get() = symbolTables.flatMap { it.imports }
}

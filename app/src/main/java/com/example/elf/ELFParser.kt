package com.example.elf

import com.example.core.Endianness
import com.example.core.FileLoader
import com.example.core.Logger

/**
 * Complete binary parser for Executable and Linkable Format (ELF) files.
 * Supports ELF32/ELF64, ARM/ARM64/Hexagon, static and dynamic binaries, relocations, symbols, and versioning.
 */
object ELFParser {

    /**
     * Parses an ELF binary from the provided FileLoader.
     */
    fun parse(loader: FileLoader): ELFFile? {
        val start = System.currentTimeMillis()
        try {
            if (loader.fileSize < 52) {
                Logger.error("ELFParser", "File too small to be an ELF binary (${loader.fileSize} bytes)")
                return null
            }

            val ident = loader.readBytes(0, 16)
            if (ident[0] != 0x7F.toByte() || ident[1] != 0x45.toByte() ||
                ident[2] != 0x4C.toByte() || ident[3] != 0x46.toByte()
            ) {
                Logger.error("ELFParser", "Invalid ELF magic header")
                return null
            }

            val elfClass = ElfClass.fromValue(ident[4].toInt())
            val elfEndian = ElfEndian.fromValue(ident[5].toInt())
            val elfVersion = ident[6].toInt()
            val osAbi = ident[7].toInt()
            val abiVersion = ident[8].toInt()

            val endianness = if (elfEndian == ElfEndian.ELFDATA2MSB) Endianness.BIG_ENDIAN else Endianness.LITTLE_ENDIAN
            loader.setEndian(endianness)

            val typeVal = loader.readU16(16)
            val machineVal = loader.readU16(18)
            val versionVal = loader.readU32(20)

            val is64 = (elfClass == ElfClass.ELFCLASS64)
            val entryPoint = if (is64) loader.readU64(24) else loader.readU32(24)
            val phOff = if (is64) loader.readU64(32) else loader.readU32(28)
            val shOff = if (is64) loader.readU64(40) else loader.readU32(32)
            val flags = loader.readU32(if (is64) 48 else 36)
            val headerSize = loader.readU16(if (is64) 52 else 40)
            val phEntSize = loader.readU16(if (is64) 54 else 42)
            val phCount = loader.readU16(if (is64) 56 else 44)
            val shEntSize = loader.readU16(if (is64) 58 else 46)
            val shCount = loader.readU16(if (is64) 60 else 48)
            val shStrIndex = loader.readU16(if (is64) 62 else 50)

            val header = ELFHeader(
                elfClass = elfClass,
                elfEndian = elfEndian,
                elfVersion = elfVersion,
                osAbi = osAbi,
                abiVersion = abiVersion,
                type = ElfType.fromValue(typeVal),
                machine = ElfMachine.fromValue(machineVal),
                version = versionVal,
                entryPoint = entryPoint,
                programHeaderOffset = phOff,
                sectionHeaderOffset = shOff,
                flags = flags,
                headerSize = headerSize,
                programHeaderEntrySize = phEntSize,
                programHeaderCount = phCount,
                sectionHeaderEntrySize = shEntSize,
                sectionHeaderCount = shCount,
                sectionHeaderStringTableIndex = shStrIndex
            )

            // Parse Program Headers
            val programHeaders = parseProgramHeaders(loader, header, is64)

            // Parse Section Headers (first pass without string names)
            val rawSectionHeaders = parseSectionHeaders(loader, header, is64)

            // Load section header string table to resolve section names
            val shstrSection = rawSectionHeaders.getOrNull(header.sectionHeaderStringTableIndex)
            val shstrtab = if (shstrSection != null) {
                parseStringTableSection(loader, shstrSection.offset, shstrSection.size, ".shstrtab", header.sectionHeaderStringTableIndex)
            } else null

            // Assign resolved section names
            val sectionHeaders = rawSectionHeaders.map { sh ->
                val name = shstrtab?.getString(sh.nameIndex) ?: "sec_${sh.index}"
                sh.copy(name = name)
            }

            // Parse all String Tables (.strtab, .dynstr, etc.)
            val stringTables = sectionHeaders.filter { it.type == ShdrType.SHT_STRTAB }.map { sh ->
                parseStringTableSection(loader, sh.offset, sh.size, sh.name, sh.index)
            }

            // Helper to get string from section's linked string table
            fun getStringFromTable(linkIndex: Int, offset: Long): String {
                val table = stringTables.firstOrNull { it.sectionIndex == linkIndex }
                return table?.getString(offset) ?: ""
            }

            // Parse Dynamic Section (.dynamic)
            val dynamicSection = parseDynamicSection(loader, sectionHeaders, programHeaders, is64)

            // Parse Symbol Tables (.symtab, .dynsym)
            val symbolTables = sectionHeaders.filter {
                it.type == ShdrType.SHT_SYMTAB || it.type == ShdrType.SHT_DYNSYM
            }.map { sh ->
                parseSymbolTable(loader, sh, is64) { strOffset ->
                    getStringFromTable(sh.link, strOffset)
                }
            }

            // Parse Relocation Tables (.rel.dyn, .rela.dyn, .rela.plt, etc.)
            val relocationTables = sectionHeaders.filter {
                it.type == ShdrType.SHT_REL || it.type == ShdrType.SHT_RELA
            }.map { sh ->
                val isRela = sh.type == ShdrType.SHT_RELA
                parseRelocationTable(loader, sh, is64, isRela) { symIdx ->
                    val symTab = symbolTables.firstOrNull { it.sectionIndex == sh.link }
                    symTab?.symbols?.getOrNull(symIdx)?.name
                }
            }

            // Parse GNU Hash Table (.gnu.hash) and SYSV Hash Table (.hash)
            val gnuHashHeader = sectionHeaders.firstOrNull { it.type == ShdrType.SHT_GNU_HASH }
            val gnuHash = if (gnuHashHeader != null) parseGnuHash(loader, gnuHashHeader, is64) else null

            val sysvHashHeader = sectionHeaders.firstOrNull { it.type == ShdrType.SHT_HASH }
            val sysvHash = if (sysvHashHeader != null) parseSysvHash(loader, sysvHashHeader) else null

            // Parse Version Definitions, Needs, and Symbols
            val verdefSection = sectionHeaders.firstOrNull { it.type == ShdrType.SHT_GNU_verdef }
            val verdefs = if (verdefSection != null) parseVersionDefinitions(loader, verdefSection) else emptyList()

            val verneedSection = sectionHeaders.firstOrNull { it.type == ShdrType.SHT_GNU_verneed }
            val verneeds = if (verneedSection != null) parseVersionNeeds(loader, verneedSection) else emptyList()

            val versymSection = sectionHeaders.firstOrNull { it.type == ShdrType.SHT_GNU_versym }
            val versyms = if (versymSection != null) parseVersionSymbols(loader, versymSection) else emptyList()

            val elapsed = System.currentTimeMillis() - start
            Logger.info("ELFParser", "Parsed ${header.elfClass.label} ${header.machine.label} (${sectionHeaders.size} sections, ${symbolTables.sumOf { it.symbols.size }} symbols) in ${elapsed}ms")

            return ELFFile(
                filePath = loader.filePath,
                header = header,
                programHeaders = programHeaders,
                sectionHeaders = sectionHeaders,
                dynamicSection = dynamicSection,
                symbolTables = symbolTables,
                relocationTables = relocationTables,
                stringTables = stringTables,
                hashTable = sysvHash,
                gnuHash = gnuHash,
                versionDefinitions = verdefs,
                versionNeeds = verneeds,
                versionSymbols = versyms
            )
        } catch (e: Exception) {
            Logger.error("ELFParser", "Exception during ELF parsing: ${e.message}", e)
            return null
        }
    }

    private fun parseProgramHeaders(loader: FileLoader, header: ELFHeader, is64: Boolean): List<ProgramHeader> {
        val list = mutableListOf<ProgramHeader>()
        for (i in 0 until header.programHeaderCount) {
            val off = header.programHeaderOffset + i * header.programHeaderEntrySize
            val pType = loader.readU32(off)
            if (is64) {
                val flags = loader.readU32(off + 4)
                val offset = loader.readU64(off + 8)
                val vaddr = loader.readU64(off + 16)
                val paddr = loader.readU64(off + 24)
                val filesz = loader.readU64(off + 32)
                val memsz = loader.readU64(off + 40)
                val align = loader.readU64(off + 48)
                list.add(
                    ProgramHeader(
                        type = PhdrType.fromValue(pType),
                        rawType = pType,
                        flags = flags,
                        offset = offset,
                        virtualAddress = vaddr,
                        physicalAddress = paddr,
                        fileSize = filesz,
                        memorySize = memsz,
                        alignment = align
                    )
                )
            } else {
                val offset = loader.readU32(off + 4)
                val vaddr = loader.readU32(off + 8)
                val paddr = loader.readU32(off + 12)
                val filesz = loader.readU32(off + 16)
                val memsz = loader.readU32(off + 20)
                val flags = loader.readU32(off + 24)
                val align = loader.readU32(off + 28)
                list.add(
                    ProgramHeader(
                        type = PhdrType.fromValue(pType),
                        rawType = pType,
                        flags = flags,
                        offset = offset,
                        virtualAddress = vaddr,
                        physicalAddress = paddr,
                        fileSize = filesz,
                        memorySize = memsz,
                        alignment = align
                    )
                )
            }
        }
        return list
    }

    private fun parseSectionHeaders(loader: FileLoader, header: ELFHeader, is64: Boolean): List<SectionHeader> {
        val list = mutableListOf<SectionHeader>()
        for (i in 0 until header.sectionHeaderCount) {
            val off = header.sectionHeaderOffset + i * header.sectionHeaderEntrySize
            val nameIdx = loader.readU32(off)
            val shType = loader.readU32(off + 4)
            if (is64) {
                val flags = loader.readU64(off + 8)
                val addr = loader.readU64(off + 16)
                val offset = loader.readU64(off + 24)
                val size = loader.readU64(off + 32)
                val link = loader.readU32(off + 40).toInt()
                val info = loader.readU32(off + 44).toInt()
                val align = loader.readU64(off + 48)
                val entSize = loader.readU64(off + 56)
                list.add(
                    SectionHeader(
                        index = i,
                        nameIndex = nameIdx,
                        name = "",
                        type = ShdrType.fromValue(shType),
                        rawType = shType,
                        flags = flags,
                        address = addr,
                        offset = offset,
                        size = size,
                        link = link,
                        info = info,
                        alignment = align,
                        entrySize = entSize
                    )
                )
            } else {
                val flags = loader.readU32(off + 8)
                val addr = loader.readU32(off + 12)
                val offset = loader.readU32(off + 16)
                val size = loader.readU32(off + 20)
                val link = loader.readU32(off + 24).toInt()
                val info = loader.readU32(off + 28).toInt()
                val align = loader.readU32(off + 32)
                val entSize = loader.readU32(off + 36)
                list.add(
                    SectionHeader(
                        index = i,
                        nameIndex = nameIdx,
                        name = "",
                        type = ShdrType.fromValue(shType),
                        rawType = shType,
                        flags = flags,
                        address = addr,
                        offset = offset,
                        size = size,
                        link = link,
                        info = info,
                        alignment = align,
                        entrySize = entSize
                    )
                )
            }
        }
        return list
    }

    private fun parseStringTableSection(
        loader: FileLoader,
        offset: Long,
        size: Long,
        name: String,
        sectionIndex: Int
    ): StringTable {
        val map = mutableMapOf<Long, String>()
        if (size <= 0 || offset >= loader.fileSize) return StringTable(name, sectionIndex, map)

        val bytes = loader.readBytes(offset, size.toInt())
        var currentIdx = 0
        while (currentIdx < bytes.size) {
            val startIdx = currentIdx
            while (currentIdx < bytes.size && bytes[currentIdx] != 0.toByte()) {
                currentIdx++
            }
            val str = String(bytes, startIdx, currentIdx - startIdx, Charsets.UTF_8)
            map[startIdx.toLong()] = str
            currentIdx++ // skip null byte
        }
        return StringTable(name, sectionIndex, map)
    }

    private fun parseDynamicSection(
        loader: FileLoader,
        sections: List<SectionHeader>,
        programs: List<ProgramHeader>,
        is64: Boolean
    ): List<DynamicEntry> {
        val dynSection = sections.firstOrNull { it.type == ShdrType.SHT_DYNAMIC }
        val offset: Long
        val size: Long

        if (dynSection != null) {
            offset = dynSection.offset
            size = dynSection.size
        } else {
            val dynProgram = programs.firstOrNull { it.type == PhdrType.PT_DYNAMIC } ?: return emptyList()
            offset = dynProgram.offset
            size = dynProgram.fileSize
        }

        val entrySize = if (is64) 16 else 8
        val count = (size / entrySize).toInt()
        val list = mutableListOf<DynamicEntry>()

        for (i in 0 until count) {
            val off = offset + i * entrySize
            val tag = if (is64) loader.readU64(off) else loader.readU32(off)
            val value = if (is64) loader.readU64(off + 8) else loader.readU32(off + 4)

            if (tag == 0L) break // DT_NULL ends dynamic section

            val desc = getDynamicTagDescription(tag)
            list.add(DynamicEntry(tag = tag, value = value, description = desc))
        }

        // Try to resolve string references (DT_NEEDED, DT_SONAME, DT_RPATH)
        val dynstr = sections.firstOrNull { it.name == ".dynstr" }
        if (dynstr != null) {
            val strTable = parseStringTableSection(loader, dynstr.offset, dynstr.size, dynstr.name, dynstr.index)
            return list.map { entry ->
                if (entry.tag in listOf(1L, 14L, 15L, 29L)) { // DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH
                    entry.copy(resolvedString = strTable.getString(entry.value))
                } else entry
            }
        }
        return list
    }

    private fun getDynamicTagDescription(tag: Long): String = when (tag) {
        0L -> "DT_NULL"
        1L -> "DT_NEEDED (Library dependency)"
        2L -> "DT_PLTRELSZ (Size in bytes of PLT relocs)"
        3L -> "DT_PLTGOT (Processor defined value)"
        4L -> "DT_HASH (Address of symbol hash table)"
        5L -> "DT_STRTAB (Address of string table)"
        6L -> "DT_SYMTAB (Address of symbol table)"
        7L -> "DT_RELA (Address of Rela relocs)"
        8L -> "DT_RELASZ (Total size of Rela relocs)"
        9L -> "DT_RELAENT (Size of one Rela reloc)"
        10L -> "DT_STRSZ (Size of string table)"
        11L -> "DT_SYMENT (Size of one symbol table entry)"
        14L -> "DT_SONAME (Shared object name)"
        15L -> "DT_RPATH (Library search path)"
        20L -> "DT_PLTREL (Type of reloc in PLT)"
        23L -> "DT_JMPREL (Address of PLT relocs)"
        29L -> "DT_RUNPATH (Library search path)"
        0x6ffffef5L -> "DT_GNU_HASH (GNU-style hash table)"
        0x6ffffffdL -> "DT_VERDEF (Symbol version definition)"
        0x6ffffffeL -> "DT_VERNEED (Symbol version requirements)"
        0x6fffffffL -> "DT_VERSYM (Symbol version table)"
        else -> "TAG_0x${tag.toString(16).uppercase()}"
    }

    private fun parseSymbolTable(
        loader: FileLoader,
        sh: SectionHeader,
        is64: Boolean,
        nameResolver: (Long) -> String
    ): SymbolTable {
        val entrySize = if (is64) 24 else 16
        val count = if (entrySize > 0) (sh.size / entrySize).toInt() else 0
        val symbols = mutableListOf<Symbol>()

        for (i in 0 until count) {
            val off = sh.offset + i * entrySize
            if (is64) {
                val nameIdx = loader.readU32(off)
                val info = loader.readU8(off + 4)
                val other = loader.readU8(off + 5)
                val shndx = loader.readU16(off + 6)
                val value = loader.readU64(off + 8)
                val size = loader.readU64(off + 16)
                val name = nameResolver(nameIdx)
                symbols.add(Symbol(i, nameIdx, name, value, size, info, other, shndx))
            } else {
                val nameIdx = loader.readU32(off)
                val value = loader.readU32(off + 4)
                val size = loader.readU32(off + 8)
                val info = loader.readU8(off + 12)
                val other = loader.readU8(off + 13)
                val shndx = loader.readU16(off + 14)
                val name = nameResolver(nameIdx)
                symbols.add(Symbol(i, nameIdx, name, value, size, info, other, shndx))
            }
        }
        return SymbolTable(sh.name, sh.index, symbols)
    }

    private fun parseRelocationTable(
        loader: FileLoader,
        sh: SectionHeader,
        is64: Boolean,
        isRela: Boolean,
        symbolResolver: (Int) -> String?
    ): RelocationTable {
        val entrySize = if (is64) (if (isRela) 24 else 16) else (if (isRela) 12 else 8)
        val count = if (entrySize > 0) (sh.size / entrySize).toInt() else 0
        val relocs = mutableListOf<Relocation>()

        for (i in 0 until count) {
            val off = sh.offset + i * entrySize
            if (is64) {
                val offset = loader.readU64(off)
                val info = loader.readU64(off + 8)
                val addend = if (isRela) loader.readU64(off + 16) else 0L
                val rType = (info and 0xFFFFFFFFL).toInt()
                val symIdx = (info shr 32).toInt()
                val symName = symbolResolver(symIdx)
                relocs.add(Relocation(offset, info, addend, rType, symIdx, symName))
            } else {
                val offset = loader.readU32(off)
                val info = loader.readU32(off + 4)
                val addend = if (isRela) loader.readU32(off + 8) else 0L
                val rType = (info and 0xFF).toInt()
                val symIdx = (info shr 8).toInt()
                val symName = symbolResolver(symIdx)
                relocs.add(Relocation(offset, info, addend, rType, symIdx, symName))
            }
        }
        return RelocationTable(sh.name, sh.index, isRela, relocs)
    }

    private fun parseGnuHash(loader: FileLoader, sh: SectionHeader, is64: Boolean): GNUHash {
        val off = sh.offset
        val nBuckets = loader.readU32(off).toInt()
        val symIndex = loader.readU32(off + 4).toInt()
        val bloomSize = loader.readU32(off + 8).toInt()
        val bloomShift = loader.readU32(off + 12).toInt()

        val bloomFilters = mutableListOf<Long>()
        val bloomOff = off + 16
        for (i in 0 until bloomSize) {
            val v = if (is64) loader.readU64(bloomOff + i * 8) else loader.readU32(bloomOff + i * 4)
            bloomFilters.add(v)
        }

        val bucketsOff = bloomOff + bloomSize * (if (is64) 8 else 4)
        val buckets = mutableListOf<Int>()
        for (i in 0 until nBuckets) {
            buckets.add(loader.readU32(bucketsOff + i * 4).toInt())
        }

        return GNUHash(
            nBuckets = nBuckets,
            symIndex = symIndex,
            bloomSize = bloomSize,
            bloomShift = bloomShift,
            bloomFilters = bloomFilters,
            buckets = buckets,
            hashValues = emptyList()
        )
    }

    private fun parseSysvHash(loader: FileLoader, sh: SectionHeader): HashTable {
        val off = sh.offset
        val nBucket = loader.readU32(off).toInt()
        val nChain = loader.readU32(off + 4).toInt()

        val buckets = mutableListOf<Long>()
        for (i in 0 until nBucket.coerceAtMost(1024)) {
            buckets.add(loader.readU32(off + 8 + i * 4))
        }

        val chains = mutableListOf<Long>()
        for (i in 0 until nChain.coerceAtMost(1024)) {
            chains.add(loader.readU32(off + 8 + nBucket * 4 + i * 4))
        }

        return HashTable(nBucket, nChain, buckets, chains)
    }

    private fun parseVersionDefinitions(loader: FileLoader, sh: SectionHeader): List<VersionDefinition> {
        val list = mutableListOf<VersionDefinition>()
        var offset = sh.offset
        var remaining = sh.size
        while (remaining >= 20) {
            val version = loader.readU16(offset)
            val flags = loader.readU16(offset + 2)
            val index = loader.readU16(offset + 4)
            val cnt = loader.readU16(offset + 6)
            val next = loader.readU32(offset + 16)
            list.add(VersionDefinition(version, flags, index, cnt, "ver_def_$index"))
            if (next == 0L) break
            offset += next
            remaining -= next
        }
        return list
    }

    private fun parseVersionNeeds(loader: FileLoader, sh: SectionHeader): List<VersionNeed> {
        val list = mutableListOf<VersionNeed>()
        var offset = sh.offset
        var remaining = sh.size
        while (remaining >= 16) {
            val version = loader.readU16(offset)
            val cnt = loader.readU16(offset + 2)
            val fileOff = loader.readU32(offset + 4)
            val next = loader.readU32(offset + 12)
            list.add(VersionNeed(version, cnt, "needed_lib_$cnt", emptyList()))
            if (next == 0L) break
            offset += next
            remaining -= next
        }
        return list
    }

    private fun parseVersionSymbols(loader: FileLoader, sh: SectionHeader): List<VersionSymbol> {
        val count = (sh.size / 2).toInt()
        val list = mutableListOf<VersionSymbol>()
        for (i in 0 until count.coerceAtMost(1000)) {
            val v = loader.readU16(sh.offset + i * 2)
            val isHidden = (v and 0x8000) != 0
            val idx = v and 0x7FFF
            list.add(VersionSymbol(i, idx, isHidden, "ver_$idx"))
        }
        return list
    }
}

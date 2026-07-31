package com.example.elf

/**
 * Represents a parsed ELF Symbol Table (.symtab or .dynsym).
 */
data class SymbolTable(
    val name: String,
    val sectionIndex: Int,
    val symbols: List<Symbol>
) {
    fun findSymbolByName(name: String): Symbol? =
        symbols.firstOrNull { it.name == name }

    fun findSymbolByAddress(address: Long): Symbol? =
        symbols.firstOrNull { it.value == address }

    val functions: List<Symbol>
        get() = symbols.filter { it.typeString == "FUNC" && it.name.isNotEmpty() }

    val exports: List<Symbol>
        get() = symbols.filter {
            it.binding in listOf("GLOBAL", "WEAK") &&
                    it.sectionIndex != 0 &&
                    it.name.isNotEmpty()
        }

    val imports: List<Symbol>
        get() = symbols.filter {
            it.binding in listOf("GLOBAL", "WEAK") &&
                    it.sectionIndex == 0 &&
                    it.name.isNotEmpty()
        }
}

/**
 * Represents a parsed ELF Relocation Table (.rel.dyn, .rela.plt, etc.).
 */
data class RelocationTable(
    val name: String,
    val sectionIndex: Int,
    val isRela: Boolean,
    val relocations: List<Relocation>
)

/**
 * Represents a parsed ELF String Table (.strtab, .dynstr, .shstrtab).
 */
data class StringTable(
    val name: String,
    val sectionIndex: Int,
    val strings: Map<Long, String>
) {
    fun getString(offset: Long): String = strings[offset] ?: ""
}

/**
 * Represents an ELF SYSV Hash Table (.hash).
 */
data class HashTable(
    val nBucket: Int,
    val nChain: Int,
    val buckets: List<Long>,
    val chains: List<Long>
)

/**
 * Represents a GNU Hash Table (.gnu.hash).
 */
data class GNUHash(
    val nBuckets: Int,
    val symIndex: Int,
    val bloomSize: Int,
    val bloomShift: Int,
    val bloomFilters: List<Long>,
    val buckets: List<Int>,
    val hashValues: List<Long>
)

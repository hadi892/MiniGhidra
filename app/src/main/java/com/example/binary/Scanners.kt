package com.example.binary

import com.example.elf.ELFFile
import com.example.elf.Symbol

/**
 * Scans and categorizes symbols from ELF or binary symbol tables.
 */
object SymbolScanner {
    fun scanAllSymbols(elfFile: ELFFile): List<Symbol> {
        return elfFile.symbolTables.flatMap { it.symbols }
            .filter { it.name.isNotEmpty() }
            .sortedBy { it.value }
    }

    fun findFunctionSymbols(elfFile: ELFFile): List<Symbol> {
        return elfFile.symbolTables.flatMap { it.functions }
            .sortedBy { it.value }
    }
}

/**
 * Scans external symbol imports (undefined symbols linked from shared libraries).
 */
object ImportScanner {
    fun scanImports(elfFile: ELFFile): List<Symbol> {
        return elfFile.allImports.sortedBy { it.name }
    }

    fun groupImportsByPrefix(imports: List<Symbol>): Map<String, List<Symbol>> {
        return imports.groupBy { sym ->
            val idx = sym.name.indexOf('_')
            if (idx > 0) sym.name.substring(0, idx) else "General"
        }
    }
}

/**
 * Scans public exported symbols available for external linkage.
 */
object ExportScanner {
    fun scanExports(elfFile: ELFFile): List<Symbol> {
        return elfFile.allExports.sortedBy { it.name }
    }

    fun findJniExports(elfFile: ELFFile): List<Symbol> {
        return elfFile.allExports.filter {
            it.name.startsWith("Java_") || it.name.startsWith("JNI_OnLoad")
        }
    }
}

/**
 * Scans shared library dependencies (DT_NEEDED) and library search paths (DT_RPATH, DT_RUNPATH).
 */
data class DependencyReport(
    val neededLibraries: List<String>,
    val runPaths: List<String>,
    val soname: String?
)

object DependencyScanner {
    fun scanDependencies(elfFile: ELFFile): DependencyReport {
        val needed = elfFile.dynamicSection.filter { it.tag == 1L }
            .mapNotNull { it.resolvedString }
        val rpaths = elfFile.dynamicSection.filter { it.tag in listOf(15L, 29L) }
            .mapNotNull { it.resolvedString }
        val soname = elfFile.dynamicSection.firstOrNull { it.tag == 14L }?.resolvedString
        return DependencyReport(needed, rpaths, soname)
    }
}

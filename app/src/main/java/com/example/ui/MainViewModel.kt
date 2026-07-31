package com.example.ui

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.binary.APKAnalyzer
import com.example.binary.APKSummary
import com.example.binary.EntropyAnalyzer
import com.example.binary.EntropyReport
import com.example.binary.ExtractedString
import com.example.binary.LibraryAnalyzer
import com.example.binary.ReportGenerator
import com.example.binary.StringScanner
import com.example.binary.SystemLibraryEntry
import com.example.core.BinaryDetector
import com.example.core.BinaryFormat
import com.example.core.FileLoader
import com.example.core.Logger
import com.example.elf.ELFFile
import com.example.elf.ELFParser
import com.example.elf.Symbol
import com.example.firmware.FirmwareAnalysisReport
import com.example.firmware.FirmwareParser
import com.example.hexagon.HexagonAnalyzer
import com.example.hexagon.HexagonReport
import com.example.plugins.PluginManager
import com.example.plugins.PluginResult
import com.example.qualcomm.QualcommAnalyzer
import com.example.qualcomm.QualcommReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Available navigation tabs in MiniGhidra Analyzer.
 */
enum class AnalysisTab(val label: String) {
    SUMMARY("Summary"),
    ELF_HEADER("ELF Header"),
    SECTIONS("Sections"),
    SYMBOLS("Symbols"),
    QUALCOMM_DSP("Qualcomm & DSP"),
    HEXAGON_QDSP6("Hexagon (QDSP6)"),
    STRINGS("Strings"),
    ENTROPY("Entropy"),
    SYS_LIBS("System Libs"),
    PLUGINS("Plugins & Report")
}

/**
 * UI state for MiniGhidra main screen.
 */
data class MainUiState(
    val isLoading: Boolean = false,
    val statusMessage: String = "Ready. Select a system library or load an ELF/Firmware binary.",
    val currentFilePath: String = "",
    val currentFileName: String = "",
    val fileSizeBytes: Long = 0,
    val detectedFormat: BinaryFormat = BinaryFormat.UNKNOWN,
    val activeTab: AnalysisTab = AnalysisTab.SUMMARY,
    val symbolSearchQuery: String = "",
    val stringSearchQuery: String = "",
    val elfFile: ELFFile? = null,
    val firmwareReport: FirmwareAnalysisReport? = null,
    val qualcommReport: QualcommReport? = null,
    val hexagonReport: HexagonReport? = null,
    val extractedStrings: List<ExtractedString> = emptyList(),
    val entropyReport: EntropyReport? = null,
    val systemLibraries: List<SystemLibraryEntry> = emptyList(),
    val apkSummary: APKSummary? = null,
    val pluginResults: List<PluginResult> = emptyList(),
    val generatedReportText: String = ""
)

/**
 * Main ViewModel managing reverse engineering analysis pipelines for MiniGhidra.
 */
class MainViewModel : ViewModel() {

    private val _uiState = MutableStateFlow(MainUiState())
    val uiState: StateFlow<MainUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            PluginManager.initialize()
            scanSystemLibraries()
        }
    }

    /**
     * Switches the currently displayed analysis tab.
     */
    fun selectTab(tab: AnalysisTab) {
        _uiState.value = _uiState.value.copy(activeTab = tab)
    }

    /**
     * Updates the symbol search filter query.
     */
    fun updateSymbolQuery(query: String) {
        _uiState.value = _uiState.value.copy(symbolSearchQuery = query)
    }

    /**
     * Updates the string search filter query.
     */
    fun updateStringQuery(query: String) {
        _uiState.value = _uiState.value.copy(stringSearchQuery = query)
    }

    /**
     * Scans system libraries on device (/system/lib64, etc.) without root.
     */
    fun scanSystemLibraries() {
        viewModelScope.launch(Dispatchers.IO) {
            val libs = LibraryAnalyzer.listSystemLibraries()
            _uiState.value = _uiState.value.copy(systemLibraries = libs)
            // If no file is currently loaded and we found system libraries, load the first interesting library
            if (_uiState.value.currentFilePath.isEmpty() && libs.isNotEmpty()) {
                val candidate = libs.firstOrNull { it.name == "libc.so" }
                    ?: libs.firstOrNull { it.name.startsWith("libqti") || it.name.startsWith("libad") }
                    ?: libs.first()
                loadFile(candidate.absolutePath)
            }
        }
    }

    /**
     * Loads and analyzes any ELF, Firmware (MBN/MDT), or APK binary from file path.
     */
    fun loadFile(filePath: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isLoading = true,
                statusMessage = "Loading binary: $filePath...",
                currentFilePath = filePath,
                currentFileName = File(filePath).name
            )

            val file = File(filePath)
            if (!file.exists() || !file.canRead()) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    statusMessage = "Error: File not found or unreadable: $filePath"
                )
                return@launch
            }

            val loader = FileLoader()
            if (!loader.openFile(file)) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    statusMessage = "Error: Could not open file: $filePath"
                )
                return@launch
            }
            val format = BinaryDetector.detect(loader)

            _uiState.value = _uiState.value.copy(
                fileSizeBytes = loader.fileSize,
                detectedFormat = format,
                statusMessage = "Parsing ${format.description}..."
            )

            // 1. ELF Parsing
            var elfFile: ELFFile? = null
            if (format == BinaryFormat.ELF || format == BinaryFormat.MBN) {
                elfFile = withContext(Dispatchers.Default) { ELFParser.parse(loader) }
            }

            // 2. Firmware parsing
            val firmware = withContext(Dispatchers.Default) { FirmwareParser.analyze(loader) }

            // 3. Qualcomm & DSP Analysis
            _uiState.value = _uiState.value.copy(statusMessage = "Analyzing Qualcomm FastRPC & TrustZone APIs...")
            val qualcomm = withContext(Dispatchers.Default) { QualcommAnalyzer.analyze(loader, elfFile) }

            // 4. Hexagon QDSP6 Analysis
            _uiState.value = _uiState.value.copy(statusMessage = "Disassembling Hexagon QDSP6 instructions...")
            val hexagon = withContext(Dispatchers.Default) { HexagonAnalyzer.analyze(loader, elfFile) }

            // 5. String Scanning
            _uiState.value = _uiState.value.copy(statusMessage = "Extracting ASCII & UTF-8 strings...")
            val strings = withContext(Dispatchers.Default) { StringScanner.scanAsciiAndUtf8(loader, minLength = 4, maxResults = 2500) }

            // 6. Entropy & Cryto Hash Analysis
            _uiState.value = _uiState.value.copy(statusMessage = "Computing Shannon entropy & cryptographic hashes...")
            val entropy = withContext(Dispatchers.Default) { EntropyAnalyzer.analyze(loader, numBlocks = 32) }

            // 7. APK Archive Analysis (if APK)
            val apkSummary = if (format == BinaryFormat.APK) {
                APKAnalyzer.analyzeApk(file)
            } else null

            // 8. Run Plugins
            _uiState.value = _uiState.value.copy(statusMessage = "Running automated inspection plugins...")
            val plugins = PluginManager.runApplicablePlugins(filePath, format, loader)

            // 9. Generate Text Report
            val reportText = buildSummaryReport(filePath, format, elfFile, qualcomm, hexagon, entropy, strings)

            _uiState.value = _uiState.value.copy(
                isLoading = false,
                statusMessage = "Analysis completed: ${file.name} (${format.description})",
                elfFile = elfFile,
                firmwareReport = firmware,
                qualcommReport = qualcomm,
                hexagonReport = hexagon,
                extractedStrings = strings,
                entropyReport = entropy,
                apkSummary = apkSummary,
                pluginResults = plugins,
                generatedReportText = reportText,
                activeTab = AnalysisTab.SUMMARY
            )
        }
    }

    /**
     * Copies a sample resource or raw binary from context assets if needed.
     */
    fun loadFromSystemLib(entry: SystemLibraryEntry) {
        loadFile(entry.absolutePath)
    }

    private fun buildSummaryReport(
        filePath: String,
        format: BinaryFormat,
        elf: ELFFile?,
        qualcomm: QualcommReport,
        hexagon: HexagonReport,
        entropy: EntropyReport,
        strings: List<ExtractedString>
    ): String {
        val sections = mutableMapOf<String, List<String>>()

        sections["General Info"] = listOf(
            "File: $filePath",
            "Format: ${format.description}",
            "Shannon Entropy: %.4f (Packed: ${entropy.isPackedOrEncrypted})".format(entropy.shannonEntropy),
            "SHA-256: ${entropy.sha256Hash}"
        )

        if (elf != null) {
            sections["ELF Header"] = listOf(
                "Class: ${elf.header.elfClass.label}, Endian: ${elf.header.elfEndian.label}",
                "Machine: ${elf.header.machine.label}, Type: ${elf.header.type.label}",
                "Entry Point: 0x${elf.header.entryPoint.toString(16)}",
                "Sections: ${elf.sectionHeaders.size}, Symbols: ${elf.symbolTables.sumOf { it.symbols.size }}"
            )
        }

        sections["Qualcomm Reverse Engineering"] = listOf(
            "FastRPC Handles: ${qualcomm.fastRpcHandles.size}",
            "adsprpc APIs: ${qualcomm.adspRpcApis.size}",
            "DSP Subsystems: ${qualcomm.dspSubsystemsDetected.joinToString(", ") { it.name }}",
            "TrustZone Refs: ${qualcomm.trustZoneReferences.size}",
            "Assessment: ${qualcomm.securityAssessment}"
        )

        sections["Hexagon QDSP6"] = listOf(
            "Architecture: ${hexagon.architectureVersion}",
            "Discovered Functions: ${hexagon.discoveredFunctions.size}",
            "Sample Instructions Decoded: ${hexagon.instructionSample.size}"
        )

        sections["Strings"] = listOf(
            "Extracted Strings (minLen=4): ${strings.size} strings"
        )

        return ReportGenerator.generateTextReport(File(filePath).name, sections)
    }
}

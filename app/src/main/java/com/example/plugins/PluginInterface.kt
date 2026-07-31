package com.example.plugins

import com.example.core.BinaryFormat

/**
 * Metadata describing a MiniGhidra plugin module.
 */
data class PluginMetadata(
    val id: String,
    val name: String,
    val version: String,
    val author: String,
    val description: String,
    val supportedFormats: Set<BinaryFormat>,
    val isEnabledByDefault: Boolean = true,
    val category: PluginCategory = PluginCategory.ANALYZER
)

/**
 * Categorization of plugins by functional role.
 */
enum class PluginCategory {
    ANALYZER,
    DECOMPILER_PASS,
    DISASSEMBLER_EXTENSION,
    FIRMWARE_DETECTOR,
    QUALCOMM_DSP_SCANNER,
    EXPORT_FORMATTER
}

/**
 * Execution context passed to a running plugin.
 */
data class PluginContext(
    val filePath: String,
    val format: BinaryFormat,
    val fileLoader: com.example.core.FileLoader,
    val parameters: Map<String, String> = emptyMap()
)

/**
 * Result returned by a plugin execution pass.
 */
data class PluginResult(
    val pluginId: String,
    val success: Boolean,
    val message: String,
    val findings: List<PluginFinding> = emptyList(),
    val durationMs: Long = 0L
)

/**
 * An individual finding or anomaly detected by a plugin.
 */
data class PluginFinding(
    val title: String,
    val description: String,
    val offset: Long = -1L,
    val severity: FindingSeverity = FindingSeverity.INFO,
    val metadata: Map<String, String> = emptyMap()
)

enum class FindingSeverity {
    INFO, LOW, MEDIUM, HIGH, CRITICAL
}

/**
 * Core lifecycle and execution interface for MiniGhidra plugins.
 */
interface PluginInterface {
    val metadata: PluginMetadata

    suspend fun onInit(): Boolean
    suspend fun execute(context: PluginContext): PluginResult
    suspend fun onShutdown()
}

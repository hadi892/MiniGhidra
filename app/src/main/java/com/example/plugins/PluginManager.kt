package com.example.plugins

import com.example.core.FileLoader
import com.example.core.Logger
import com.example.core.BinaryFormat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.withContext

/**
 * Orchestrates plugin discovery, execution, and lifecycle management for MiniGhidra.
 */
object PluginManager {

    /**
     * Initializes the plugin system and loads built-in analyzers.
     */
    suspend fun initialize() {
        Logger.info("PluginManager", "Initializing PluginManager...")
        PluginLoader.discoverAndLoadBuiltInPlugins()
        Logger.info("PluginManager", "Registered ${PluginRegistry.getAllPlugins().size} plugins.")
    }

    /**
     * Executes all enabled plugins that support the target file format.
     */
    suspend fun runApplicablePlugins(
        filePath: String,
        format: BinaryFormat,
        fileLoader: FileLoader,
        parameters: Map<String, String> = emptyMap()
    ): List<PluginResult> = withContext(Dispatchers.Default) {
        val applicablePlugins = PluginRegistry.getAllPlugins().filter { plugin ->
            PluginRegistry.isEnabled(plugin.metadata.id) &&
                    (plugin.metadata.supportedFormats.contains(format) ||
                            plugin.metadata.supportedFormats.contains(BinaryFormat.UNKNOWN))
        }

        Logger.info(
            "PluginManager",
            "Executing ${applicablePlugins.size} plugins for format $format on file $filePath"
        )

        val context = PluginContext(
            filePath = filePath,
            format = format,
            fileLoader = fileLoader,
            parameters = parameters
        )

        val deferredResults = applicablePlugins.map { plugin ->
            async {
                try {
                    Logger.debug("PluginManager", "Running plugin: ${plugin.metadata.name}")
                    plugin.execute(context)
                } catch (e: Exception) {
                    Logger.error("PluginManager", "Error executing plugin ${plugin.metadata.id}", e)
                    PluginResult(
                        pluginId = plugin.metadata.id,
                        success = false,
                        message = "Exception: ${e.message}"
                    )
                }
            }
        }
        deferredResults.awaitAll()
    }

    /**
     * Shuts down all registered plugins and clears the registry.
     */
    suspend fun shutdown() {
        for (plugin in PluginRegistry.getAllPlugins()) {
            try {
                plugin.onShutdown()
            } catch (e: Exception) {
                Logger.warn("PluginManager", "Error shutting down plugin ${plugin.metadata.id}: ${e.message}")
            }
        }
        PluginRegistry.clear()
    }
}

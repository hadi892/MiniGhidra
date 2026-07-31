package com.example.plugins

import java.util.concurrent.ConcurrentHashMap

/**
 * Thread-safe registry for MiniGhidra plugins.
 * Maintains plugin registrations and operational status.
 */
object PluginRegistry {
    private val plugins = ConcurrentHashMap<String, PluginInterface>()
    private val enabledStates = ConcurrentHashMap<String, Boolean>()

    fun register(plugin: PluginInterface) {
        plugins[plugin.metadata.id] = plugin
        enabledStates.putIfAbsent(plugin.metadata.id, plugin.metadata.isEnabledByDefault)
    }

    fun unregister(pluginId: String) {
        plugins.remove(pluginId)
        enabledStates.remove(pluginId)
    }

    fun getPlugin(pluginId: String): PluginInterface? = plugins[pluginId]

    fun getAllPlugins(): List<PluginInterface> = plugins.values.toList()

    fun isEnabled(pluginId: String): Boolean = enabledStates[pluginId] ?: false

    fun setEnabled(pluginId: String, enabled: Boolean) {
        if (plugins.containsKey(pluginId)) {
            enabledStates[pluginId] = enabled
        }
    }

    fun clear() {
        plugins.clear()
        enabledStates.clear()
    }
}

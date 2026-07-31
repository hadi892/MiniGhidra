package com.example.core

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "minighidra_settings")

/**
 * Disassembly syntax options.
 */
enum class DisassemblySyntax {
    ARM_UAL, // ARM Unified Assembler Language
    QUALCOMM_HEXAGON, // Qualcomm Hexagon DSP syntax
    GNU_ATT // GNU AT&T syntax
}

/**
 * Manages user preferences and analysis configuration parameters using AndroidX DataStore.
 */
class ConfigurationManager(private val context: Context) {

    companion object {
        private val KEY_DARK_MODE = booleanPreferencesKey("dark_mode_enabled")
        private val KEY_MIN_STRING_LEN = intPreferencesKey("min_string_length")
        private val KEY_MAX_FILE_READ_MB = intPreferencesKey("max_file_read_mb")
        private val KEY_DISASM_SYNTAX = stringPreferencesKey("disasm_syntax")
        private val KEY_QUALCOMM_DEEP_SCAN = booleanPreferencesKey("qualcomm_deep_scan")
        private val KEY_HEXAGON_DSP_HEURISTICS = booleanPreferencesKey("hexagon_dsp_heuristics")
    }

    val isDarkMode: Flow<Boolean> = context.dataStore.data.map { prefs ->
        prefs[KEY_DARK_MODE] ?: true
    }

    val minStringLength: Flow<Int> = context.dataStore.data.map { prefs ->
        prefs[KEY_MIN_STRING_LEN] ?: 4
    }

    val disasmSyntax: Flow<DisassemblySyntax> = context.dataStore.data.map { prefs ->
        val name = prefs[KEY_DISASM_SYNTAX] ?: DisassemblySyntax.ARM_UAL.name
        try {
            DisassemblySyntax.valueOf(name)
        } catch (e: Exception) {
            DisassemblySyntax.ARM_UAL
        }
    }

    val qualcommDeepScanEnabled: Flow<Boolean> = context.dataStore.data.map { prefs ->
        prefs[KEY_QUALCOMM_DEEP_SCAN] ?: true
    }

    val hexagonDspHeuristicsEnabled: Flow<Boolean> = context.dataStore.data.map { prefs ->
        prefs[KEY_HEXAGON_DSP_HEURISTICS] ?: true
    }

    suspend fun setDarkMode(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[KEY_DARK_MODE] = enabled
        }
    }

    suspend fun setMinStringLength(length: Int) {
        context.dataStore.edit { prefs ->
            prefs[KEY_MIN_STRING_LEN] = length.coerceIn(2, 64)
        }
    }

    suspend fun setDisasmSyntax(syntax: DisassemblySyntax) {
        context.dataStore.edit { prefs ->
            prefs[KEY_DISASM_SYNTAX] = syntax.name
        }
    }

    suspend fun setQualcommDeepScan(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[KEY_QUALCOMM_DEEP_SCAN] = enabled
        }
    }

    suspend fun setHexagonDspHeuristics(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[KEY_HEXAGON_DSP_HEURISTICS] = enabled
        }
    }
}

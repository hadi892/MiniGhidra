package com.example.core

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Log severity level for MiniGhidra analysis diagnostics.
 */
enum class LogLevel {
    DEBUG, INFO, WARN, ERROR, SUCCESS
}

/**
 * Structured log message item stored in memory for UI inspection and export.
 */
data class LogEntry(
    val timestamp: Long = System.currentTimeMillis(),
    val level: LogLevel,
    val tag: String,
    val message: String,
    val exception: Throwable? = null
) {
    val formattedTime: String
        get() = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date(timestamp))
}

/**
 * Global structured logger for MiniGhidra engine and reverse engineering modules.
 * Maintains an in-memory buffer of analysis events for display in reports and logs UI.
 */
object Logger {
    private const val MAX_LOGS = 5000
    private val logQueue = ConcurrentLinkedQueue<LogEntry>()
    private val _logsFlow = MutableStateFlow<List<LogEntry>>(emptyList())
    val logsFlow: StateFlow<List<LogEntry>> = _logsFlow.asStateFlow()

    fun debug(tag: String, message: String) = log(LogLevel.DEBUG, tag, message)
    fun info(tag: String, message: String) = log(LogLevel.INFO, tag, message)
    fun warn(tag: String, message: String) = log(LogLevel.WARN, tag, message)
    fun error(tag: String, message: String, exception: Throwable? = null) =
        log(LogLevel.ERROR, tag, message, exception)
    fun success(tag: String, message: String) = log(LogLevel.SUCCESS, tag, message)

    private fun log(level: LogLevel, tag: String, message: String, exception: Throwable? = null) {
        val entry = LogEntry(
            level = level,
            tag = tag,
            message = message,
            exception = exception
        )
        logQueue.add(entry)
        while (logQueue.size > MAX_LOGS) {
            logQueue.poll()
        }
        _logsFlow.value = logQueue.toList()

        when (level) {
            LogLevel.DEBUG -> Log.d("MiniGhidra-$tag", message)
            LogLevel.INFO -> Log.i("MiniGhidra-$tag", message)
            LogLevel.WARN -> Log.w("MiniGhidra-$tag", message)
            LogLevel.ERROR -> Log.e("MiniGhidra-$tag", message, exception)
            LogLevel.SUCCESS -> Log.i("MiniGhidra-$tag", "SUCCESS: $message")
        }
    }

    fun clear() {
        logQueue.clear()
        _logsFlow.value = emptyList()
    }
}

package com.example.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * State representing an active reverse engineering analysis session in MiniGhidra.
 */
data class SessionState(
    val sessionId: String,
    val filePath: String,
    val fileName: String,
    val format: BinaryFormat,
    val fileSize: Long,
    val isAnalyzing: Boolean = false,
    val progress: Float = 0f,
    val progressStatus: String = "Idle",
    val errorMessage: String? = null
)

/**
 * Manages the currently active analysis session across multiple screens and modules.
 */
object SessionManager {
    private val _currentSession = MutableStateFlow<SessionState?>(null)
    val currentSession: StateFlow<SessionState?> = _currentSession.asStateFlow()

    fun openSession(
        filePath: String,
        fileName: String,
        format: BinaryFormat,
        fileSize: Long
    ): SessionState {
        val session = SessionState(
            sessionId = "MG-" + System.currentTimeMillis().toString(16),
            filePath = filePath,
            fileName = fileName,
            format = format,
            fileSize = fileSize,
            isAnalyzing = false,
            progress = 0f,
            progressStatus = "Ready"
        )
        _currentSession.value = session
        Logger.info("SessionManager", "Created session ${session.sessionId} for $fileName ($format)")
        return session
    }

    fun updateProgress(progress: Float, status: String) {
        _currentSession.value = _currentSession.value?.copy(
            isAnalyzing = progress < 1f,
            progress = progress.coerceIn(0f, 1f),
            progressStatus = status,
            errorMessage = null
        )
    }

    fun setError(error: String) {
        _currentSession.value = _currentSession.value?.copy(
            isAnalyzing = false,
            errorMessage = error,
            progressStatus = "Error: $error"
        )
        Logger.error("SessionManager", error)
    }

    fun closeSession() {
        val id = _currentSession.value?.sessionId
        _currentSession.value = null
        if (id != null) {
            Logger.info("SessionManager", "Closed session $id")
        }
    }
}

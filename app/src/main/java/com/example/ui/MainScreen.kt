package com.example.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.binary.SystemLibraryEntry
import com.example.ui.theme.CodeBackground
import com.example.ui.theme.FastRpcTeal
import com.example.ui.theme.HexagonPurple

/**
 * Main reverse engineering dashboard screen for MiniGhidra.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    viewModel: MainViewModel = viewModel(),
    modifier: Modifier = Modifier
) {
    val uiState by viewModel.uiState.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Memory,
                            contentDescription = "MiniGhidra Logo",
                            tint = FastRpcTeal,
                            modifier = Modifier.size(26.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "MiniGhidra Analyzer",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = "Qualcomm & Hexagon Reverse Engineering",
                                style = MaterialTheme.typography.labelSmall,
                                color = FastRpcTeal
                            )
                        }
                    }
                },
                actions = {
                    IconButton(onClick = { viewModel.scanSystemLibraries() }) {
                        Icon(
                            imageVector = Icons.Default.Refresh,
                            contentDescription = "Rescan system libraries",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            )
        },
        modifier = modifier.fillMaxSize()
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            // Quick Selector Bar for System Libraries (.so)
            QuickLibraryBar(
                systemLibraries = uiState.systemLibraries,
                currentFileName = uiState.currentFileName,
                onSelectLibrary = { lib -> viewModel.loadFromSystemLib(lib) },
                onOpenLibsTab = { viewModel.selectTab(AnalysisTab.SYS_LIBS) }
            )

            // Status Bar & Format Badge
            Surface(
                color = CodeBackground,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = uiState.statusMessage,
                        style = MaterialTheme.typography.labelMedium,
                        fontFamily = FontFamily.Monospace,
                        color = FastRpcTeal,
                        modifier = Modifier.weight(1f)
                    )
                    FormatBadge(format = uiState.detectedFormat)
                }
            }

            // Analysis Tabs
            val tabs = AnalysisTab.values()
            val selectedTabIndex = tabs.indexOf(uiState.activeTab).coerceAtLeast(0)

            ScrollableTabRow(
                selectedTabIndex = selectedTabIndex,
                edgePadding = 16.dp,
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            ) {
                tabs.forEach { tab ->
                    Tab(
                        selected = uiState.activeTab == tab,
                        onClick = { viewModel.selectTab(tab) },
                        text = {
                            Text(
                                text = tab.label,
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = if (uiState.activeTab == tab) FontWeight.Bold else FontWeight.Normal
                            )
                        }
                    )
                }
            }

            // Main Content Body
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .weight(1f)
            ) {
                if (uiState.isLoading) {
                    Column(
                        modifier = Modifier.fillMaxSize(),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        CircularProgressIndicator(color = FastRpcTeal)
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            text = uiState.statusMessage,
                            style = MaterialTheme.typography.bodyMedium,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                } else {
                    when (uiState.activeTab) {
                        AnalysisTab.SUMMARY -> {
                            SummaryView(
                                fileName = uiState.currentFileName,
                                filePath = uiState.currentFilePath,
                                fileSize = uiState.fileSizeBytes,
                                format = uiState.detectedFormat,
                                elfFile = uiState.elfFile,
                                firmwareReport = uiState.firmwareReport,
                                qualcommReport = uiState.qualcommReport,
                                hexagonReport = uiState.hexagonReport,
                                entropyReport = uiState.entropyReport
                            )
                        }

                        AnalysisTab.ELF_HEADER -> {
                            ElfHeaderView(elfFile = uiState.elfFile)
                        }

                        AnalysisTab.SECTIONS -> {
                            SectionsView(elfFile = uiState.elfFile)
                        }

                        AnalysisTab.SYMBOLS -> {
                            SymbolsView(
                                elfFile = uiState.elfFile,
                                searchQuery = uiState.symbolSearchQuery,
                                onQueryChange = { viewModel.updateSymbolQuery(it) }
                            )
                        }

                        AnalysisTab.QUALCOMM_DSP -> {
                            QualcommView(report = uiState.qualcommReport)
                        }

                        AnalysisTab.HEXAGON_QDSP6 -> {
                            HexagonView(report = uiState.hexagonReport)
                        }

                        AnalysisTab.STRINGS -> {
                            StringsView(
                                strings = uiState.extractedStrings,
                                searchQuery = uiState.stringSearchQuery,
                                onQueryChange = { viewModel.updateStringQuery(it) }
                            )
                        }

                        AnalysisTab.ENTROPY -> {
                            EntropyView(report = uiState.entropyReport)
                        }

                        AnalysisTab.SYS_LIBS -> {
                            SystemLibsView(
                                libraries = uiState.systemLibraries,
                                onSelectLibrary = { lib ->
                                    viewModel.loadFromSystemLib(lib)
                                }
                            )
                        }

                        AnalysisTab.PLUGINS -> {
                            PluginsReportView(
                                results = uiState.pluginResults,
                                reportText = uiState.generatedReportText
                            )
                        }
                    }
                }
            }
        }
    }
}

/**
 * Quick system library selector bar at top of screen for instant reverse engineering.
 */
@Composable
fun QuickLibraryBar(
    systemLibraries: List<SystemLibraryEntry>,
    currentFileName: String,
    onSelectLibrary: (SystemLibraryEntry) -> Unit,
    onOpenLibsTab: () -> Unit
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Quick Libs:",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )

            val quickNames = listOf("libc.so", "libdl.so", "liblog.so", "libm.so", "libz.so")
            for (name in quickNames) {
                val match = systemLibraries.firstOrNull { it.name.equals(name, ignoreCase = true) }
                if (match != null) {
                    val isSelected = currentFileName.equals(name, ignoreCase = true)
                    Card(
                        onClick = { onSelectLibrary(match) },
                        colors = CardDefaults.cardColors(
                            containerColor = if (isSelected) FastRpcTeal else CodeBackground
                        ),
                        shape = RoundedCornerShape(6.dp)
                    ) {
                        Text(
                            text = name,
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.SemiBold,
                            color = if (isSelected) MaterialTheme.colorScheme.surface else MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                }
            }

            Button(
                onClick = onOpenLibsTab,
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
                contentPadding = ButtonDefaults.ContentPadding,
                shape = RoundedCornerShape(6.dp)
            ) {
                Text("Browse All (${systemLibraries.size})", style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

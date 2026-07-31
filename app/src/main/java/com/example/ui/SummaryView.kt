package com.example.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.binary.EntropyReport
import com.example.core.BinaryFormat
import com.example.elf.ELFFile
import com.example.firmware.FirmwareAnalysisReport
import com.example.hexagon.HexagonReport
import com.example.qualcomm.QualcommReport
import com.example.ui.theme.CodeBackground
import com.example.ui.theme.FastRpcTeal
import com.example.ui.theme.HexagonPurple
import com.example.ui.theme.SecurityGreen
import com.example.ui.theme.SecurityRed
import com.example.ui.theme.TrustZoneAmber

/**
 * Summary tab displaying overall binary architecture, Qualcomm DSP analysis highlights,
 * security assessment, and cryptographic checksums.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SummaryView(
    fileName: String,
    filePath: String,
    fileSize: Long,
    format: BinaryFormat,
    elfFile: ELFFile?,
    firmwareReport: FirmwareAnalysisReport?,
    qualcommReport: QualcommReport?,
    hexagonReport: HexagonReport?,
    entropyReport: EntropyReport?,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Top Banner Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column {
                        Text(
                            text = fileName.ifEmpty { "No File Selected" },
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Text(
                            text = filePath.ifEmpty { "Select a system library from the menu below" },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    FormatBadge(format = format)
                }

                Spacer(modifier = Modifier.height(12.dp))
                Divider(color = MaterialTheme.colorScheme.outlineVariant)
                Spacer(modifier = Modifier.height(12.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    SummaryStatItem(label = "File Size", value = "${fileSize / 1024} KB (${fileSize} bytes)")
                    if (elfFile != null) {
                        SummaryStatItem(label = "Architecture", value = "${elfFile.header.elfClass.label} ${elfFile.header.machine.label}")
                        SummaryStatItem(label = "Type", value = elfFile.header.type.label)
                    } else if (firmwareReport != null) {
                        SummaryStatItem(label = "Firmware Type", value = firmwareReport.type.label)
                    }
                }
            }
        }

        // Qualcomm & DSP Highlight Card
        if (qualcommReport != null) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = CodeBackground
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Memory,
                            contentDescription = "Qualcomm DSP",
                            tint = FastRpcTeal,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Qualcomm & DSP Reverse Engineering Profile",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = FastRpcTeal
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Text(
                        text = qualcommReport.securityAssessment,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (qualcommReport.fastRpcHandles.isNotEmpty()) {
                            TagChip(text = "FastRPC Remote Handles (${qualcommReport.fastRpcHandles.size})", color = FastRpcTeal)
                        }
                        if (qualcommReport.trustZoneReferences.isNotEmpty()) {
                            TagChip(text = "TrustZone TEE (${qualcommReport.trustZoneReferences.size})", color = TrustZoneAmber)
                        }
                        if (qualcommReport.binderInterfaces.isNotEmpty()) {
                            TagChip(text = "Binder IPC (${qualcommReport.binderInterfaces.size})", color = MaterialTheme.colorScheme.primary)
                        }
                        for (dsp in qualcommReport.dspSubsystemsDetected) {
                            TagChip(text = dsp.name, color = HexagonPurple)
                        }
                    }
                }
            }
        }

        // Hexagon QDSP6 Status Card
        if (hexagonReport != null && hexagonReport.isHexagonBinary) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Assessment,
                            contentDescription = "Hexagon QDSP6",
                            tint = HexagonPurple,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = hexagonReport.architectureVersion,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = HexagonPurple
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Discovered ${hexagonReport.discoveredFunctions.size} heuristic functions and decoded ${hexagonReport.instructionSample.size} sample instruction packets.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        // Entropy & Security Checksums
        if (entropyReport != null) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = if (entropyReport.isPackedOrEncrypted) Icons.Default.Warning else Icons.Default.Shield,
                            contentDescription = "Entropy",
                            tint = if (entropyReport.isPackedOrEncrypted) SecurityRed else SecurityGreen,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Shannon Entropy & Cryptographic Hashes",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        SummaryStatItem(
                            label = "Shannon Entropy Score",
                            value = "%.4f / 8.0000".format(entropyReport.shannonEntropy)
                        )
                        val packedText = if (entropyReport.isPackedOrEncrypted) "LIKELY PACKED / ENCRYPTED" else "NORMAL UNPACKED"
                        val packedColor = if (entropyReport.isPackedOrEncrypted) SecurityRed else SecurityGreen
                        Column {
                            Text(text = "Status", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(text = packedText, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold, color = packedColor)
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))
                    HashRow(label = "SHA-256", value = entropyReport.sha256Hash)
                    Spacer(modifier = Modifier.height(4.dp))
                    HashRow(label = "SHA-1", value = entropyReport.sha1Hash)
                    Spacer(modifier = Modifier.height(4.dp))
                    HashRow(label = "MD5", value = entropyReport.md5Hash)
                }
            }
        }
    }
}

@Composable
private fun SummaryStatItem(label: String, value: String) {
    Column {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}

@Composable
private fun HashRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = "$label: ",
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.width(68.dp)
        )
        Text(
            text = value.ifEmpty { "N/A" },
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}

@Composable
fun FormatBadge(format: BinaryFormat) {
    Surface(
        color = MaterialTheme.colorScheme.primaryContainer,
        shape = RoundedCornerShape(16.dp)
    ) {
        Text(
            text = format.description,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onPrimaryContainer,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
        )
    }
}

@Composable
fun TagChip(text: String, color: Color) {
    Surface(
        color = color.copy(alpha = 0.15f),
        shape = RoundedCornerShape(8.dp)
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Medium,
            color = color,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
        )
    }
}

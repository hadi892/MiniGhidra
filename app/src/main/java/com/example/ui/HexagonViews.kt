package com.example.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.Code
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.hexagon.HexagonInstruction
import com.example.hexagon.HexagonReport
import com.example.ui.theme.AddressText
import com.example.ui.theme.CodeBackground
import com.example.ui.theme.HexDumpText
import com.example.ui.theme.HexagonPurple

/**
 * Hexagon (QDSP6) tab displaying instruction packet disassembly,
 * architecture version, feature flags, and discovered heuristic functions.
 */
@Composable
fun HexagonView(
    report: HexagonReport?,
    modifier: Modifier = Modifier
) {
    if (report == null) {
        EmptyStateNotice(message = "No Hexagon (QDSP6) analysis report available.")
        return
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Assessment,
                            contentDescription = "Hexagon",
                            tint = HexagonPurple
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = report.architectureVersion,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = HexagonPurple
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Text(
                        text = "Hexagon DSP Feature Detection:",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Spacer(modifier = Modifier.height(6.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        FeatureIndicator("DSP Firmware", report.featureDetection.hasDspFirmware)
                        FeatureIndicator("HVX / Audio", report.featureDetection.hasDspAudio)
                        FeatureIndicator("Sensor DSP", report.featureDetection.hasDspSensors)
                        FeatureIndicator("Modem DSP", report.featureDetection.hasDspModem)
                    }
                }
            }
        }

        item {
            Text(
                text = "Heuristic Discovered Functions (${report.discoveredFunctions.size})",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = HexagonPurple
            )
        }

        if (report.discoveredFunctions.isEmpty()) {
            item {
                Text(
                    text = "No symbols or heuristic function prologues discovered.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            items(report.discoveredFunctions.take(15)) { fn ->
                FunctionItemCard(functionText = fn)
            }
        }

        item {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "Hexagon Instruction Packet Disassembly Sample (${report.instructionSample.size} words)",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )
        }

        if (report.instructionSample.isEmpty()) {
            item {
                Text(
                    text = "No executable .text code block found to disassemble.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            items(report.instructionSample) { inst ->
                InstructionCard(instruction = inst)
            }
        }
    }
}

@Composable
private fun FeatureIndicator(label: String, active: Boolean) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = if (active) "YES" else "NO",
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Bold,
            color = if (active) HexagonPurple else MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun FunctionItemCard(functionText: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = CodeBackground),
        shape = RoundedCornerShape(8.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.Code,
                contentDescription = "Function",
                tint = HexagonPurple
            )
            Spacer(modifier = Modifier.width(10.dp))
            Text(
                text = functionText,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurface
            )
        }
    }
}

@Composable
private fun InstructionCard(instruction: HexagonInstruction) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = CodeBackground),
        shape = RoundedCornerShape(4.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "0x${instruction.address.toString(16)}",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                color = AddressText,
                modifier = Modifier.width(90.dp)
            )
            Text(
                text = "%08x".format(instruction.rawWord),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = HexDumpText,
                modifier = Modifier.width(80.dp)
            )
            Text(
                text = instruction.fullText,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.SemiBold,
                color = if (instruction.isPacketEnd) HexagonPurple else MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

package com.example.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.SwapHoriz
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
import com.example.qualcomm.AdspRpcApi
import com.example.qualcomm.FastRpcHandle
import com.example.qualcomm.IpcInterfaceToken
import com.example.qualcomm.QualcommReport
import com.example.qualcomm.TrustZoneReference
import com.example.ui.theme.CodeBackground
import com.example.ui.theme.FastRpcTeal
import com.example.ui.theme.HexagonPurple
import com.example.ui.theme.TrustZoneAmber

/**
 * Qualcomm & DSP specialized tab displaying FastRPC remote handles, adsprpc API calls,
 * TrustZone references, shared memory heaps, and Android Binder/AIDL/HIDL IPC tokens.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun QualcommView(
    report: QualcommReport?,
    modifier: Modifier = Modifier
) {
    if (report == null) {
        EmptyStateNotice(message = "No Qualcomm reverse engineering report available.")
        return
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // DSP Subsystem Badges
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Memory,
                        contentDescription = "DSP Subsystems",
                        tint = HexagonPurple
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Detected Qualcomm DSP Subsystems",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = HexagonPurple
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))

                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    if (report.dspSubsystemsDetected.isEmpty()) {
                        TagChip(text = "No dedicated DSP subsystem signatures detected", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    } else {
                        for (dsp in report.dspSubsystemsDetected) {
                            TagChip(text = dsp.label, color = HexagonPurple)
                        }
                    }
                }
            }
        }

        // FastRPC Handles Section
        Text(
            text = "Qualcomm FastRPC Remote Handles (${report.fastRpcHandles.size})",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            color = FastRpcTeal
        )

        if (report.fastRpcHandles.isEmpty()) {
            Text(
                text = "No FastRPC remote handle invocations discovered in binary.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            for (handle in report.fastRpcHandles) {
                FastRpcCard(handle = handle)
            }
        }

        // adsprpc / CDSP API references
        Text(
            text = "adsprpc & Remote Memory APIs (${report.adspRpcApis.size})",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            color = FastRpcTeal
        )

        if (report.adspRpcApis.isEmpty()) {
            Text(
                text = "No adsprpc APIs discovered.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            for (api in report.adspRpcApis) {
                AdspRpcCard(api = api)
            }
        }

        // TrustZone / Keymaster Secure References
        Text(
            text = "Qualcomm TrustZone & Secure OS References (${report.trustZoneReferences.size})",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            color = TrustZoneAmber
        )

        if (report.trustZoneReferences.isEmpty()) {
            Text(
                text = "No TrustZone/QSEE/Keymaster secure calls detected.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            for (tz in report.trustZoneReferences) {
                TrustZoneCard(ref = tz)
            }
        }

        // Android Binder / AIDL / HIDL IPC Interfaces
        val allIpc = report.binderInterfaces + report.aidlInterfaces + report.hidlInterfaces
        Text(
            text = "Android Binder / AIDL / HIDL Interfaces (${allIpc.size})",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.primary
        )

        if (allIpc.isEmpty()) {
            Text(
                text = "No Android IPC descriptors found in string table.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            for (ipc in allIpc) {
                IpcTokenCard(ipc = ipc)
            }
        }
    }
}

@Composable
private fun FastRpcCard(handle: FastRpcHandle) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = CodeBackground),
        shape = RoundedCornerShape(8.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = handle.name,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                    color = FastRpcTeal
                )
                Text(
                    text = "ID: 0x${handle.interfaceId.toString(16)}",
                    style = MaterialTheme.typography.labelMedium,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Domain: ${handle.domain} (${if (handle.domain == 0) "ADSP" else "CDSP/SDSP"}) | Methods: ~${handle.methodCountEstimate}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun AdspRpcCard(api: AdspRpcApi) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        shape = RoundedCornerShape(8.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                text = api.symbolName,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = api.description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun TrustZoneCard(ref: TrustZoneReference) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = CodeBackground),
        shape = RoundedCornerShape(8.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.Security,
                    contentDescription = "TrustZone",
                    tint = TrustZoneAmber
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = ref.appName,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = TrustZoneAmber
                )
            }
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = ref.description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface
            )
        }
    }
}

@Composable
private fun IpcTokenCard(ipc: IpcInterfaceToken) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        shape = RoundedCornerShape(8.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = ipc.descriptor,
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            TagChip(text = ipc.type, color = MaterialTheme.colorScheme.primary)
        }
    }
}

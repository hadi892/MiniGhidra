package com.example.qualcomm

/**
 * Qualcomm DSP Subsystem target.
 */
enum class DspSubsystemType(val label: String) {
    ADSP("Audio DSP (ADSP)"),
    SDSP("Sensor DSP (SDSP/SLPI)"),
    CDSP("Compute DSP (CDSP)"),
    MDSP("Modem DSP (MPSS/MDSP)"),
    ICP("Camera DSP (ICP/Spectra)"),
    TRUSTZONE("TrustZone Secure OS (QSEE/TEE)")
}

/**
 * FastRPC handle invocation discovered in binary.
 */
data class FastRpcHandle(
    val name: String,
    val domain: Int,
    val interfaceId: Long,
    val isStaticHandle: Boolean,
    val methodCountEstimate: Int
)

/**
 * adsprpc API reference discovered in binary.
 */
data class AdspRpcApi(
    val symbolName: String,
    val category: String,
    val description: String
)

/**
 * Android IPC Interface (AIDL, HIDL, or Binder transaction).
 */
data class IpcInterfaceToken(
    val descriptor: String,
    val type: String, // "AIDL", "HIDL", "BINDER_TRANSACTION"
    val transactionCodes: List<Int> = emptyList()
)

/**
 * Qualcomm TrustZone secure app reference or QSEE RPC call.
 */
data class TrustZoneReference(
    val appName: String,
    val uuid: String?,
    val commandId: Int?,
    val description: String
)

/**
 * Shared memory region (ION buffer, DMA-BUF, ashmem, FastRPC shared heap).
 */
data class SharedMemoryRegion(
    val heapName: String,
    val allocationMethod: String,
    val isCached: Boolean,
    val flags: String
)

/**
 * DSP RPC Session token.
 */
data class DspSessionInfo(
    val domainName: String,
    val sessionUri: String,
    val maxPayloadSize: Long
)

/**
 * Complete Qualcomm reverse engineering analysis report.
 */
data class QualcommReport(
    val binaryPath: String,
    val fastRpcHandles: List<FastRpcHandle>,
    val adspRpcApis: List<AdspRpcApi>,
    val binderInterfaces: List<IpcInterfaceToken>,
    val hidlInterfaces: List<IpcInterfaceToken>,
    val aidlInterfaces: List<IpcInterfaceToken>,
    val vendorLibrariesReferenced: List<String>,
    val dspSubsystemsDetected: Set<DspSubsystemType>,
    val audioDspFeatures: List<String>,
    val sensorDspFeatures: List<String>,
    val cameraDspFeatures: List<String>,
    val modemDspFeatures: List<String>,
    val trustZoneReferences: List<TrustZoneReference>,
    val sharedMemoryRegions: List<SharedMemoryRegion>,
    val rpcSessions: List<DspSessionInfo>,
    val securityAssessment: String
)

package com.example.hexagon

/**
 * Qualcomm Hexagon (QDSP6) register category.
 */
enum class HexagonRegisterType {
    GENERAL_PURPOSE, // R0..R31
    PREDICATE, // P0..P3
    MODIFIER, // M0..M1
    CONTROL, // C0..C11, SA0, LC0, SA1, LC1, P3_0, PC, UGIM
    VECTOR // V0..V31 (HVX vector registers)
}

/**
 * An individual Hexagon (QDSP6) register definition.
 */
data class HexagonRegister(
    val id: Int,
    val name: String,
    val alias: String,
    val type: HexagonRegisterType,
    val bitWidth: Int = 32
)

/**
 * Qualcomm Hexagon instruction packet or single instruction.
 */
data class HexagonInstruction(
    val address: Long,
    val rawWord: Long,
    val mnemonic: String,
    val operands: String,
    val isPacketEnd: Boolean,
    val syntax: String
) {
    val fullText: String
        get() = if (isPacketEnd) "$mnemonic $operands }" else "  $mnemonic $operands"
}

/**
 * Hexagon DSP subsystem feature detection result.
 */
data class HexagonFeatureDetection(
    val hasDspFirmware: Boolean,
    val hasDspMemory: Boolean,
    val hasDspRpc: Boolean,
    val hasDspAudio: Boolean,
    val hasDspFm: Boolean,
    val hasDspModem: Boolean,
    val hasDspCamera: Boolean,
    val hasDspSensors: Boolean
)

/**
 * Complete Qualcomm Hexagon (QDSP6) reverse engineering report.
 */
data class HexagonReport(
    val filePath: String,
    val architectureVersion: String, // e.g. "Hexagon v66 (HVX enabled)"
    val isHexagonBinary: Boolean,
    val featureDetection: HexagonFeatureDetection,
    val discoveredFunctions: List<String>,
    val memoryRegions: List<String>,
    val crossReferences: List<String>,
    val instructionSample: List<HexagonInstruction>
)

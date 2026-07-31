package com.example.qualcomm

import com.example.core.FileLoader
import com.example.core.Logger
import com.example.elf.ELFFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Main coordinator for Qualcomm-specific reverse engineering analysis.
 * Aggregates results from FastRPC, adsprpc, Binder, AIDL/HIDL, DSP subsystems, TrustZone, and shared memory analyzers.
 */
object QualcommAnalyzer {

    suspend fun analyze(loader: FileLoader, elfFile: ELFFile?): QualcommReport = withContext(Dispatchers.Default) {
        val start = System.currentTimeMillis()
        val sampleSize = 2097152L.coerceAtMost(loader.fileSize) // sample up to 2MB for strings & symbols
        val rawBytes = loader.readBytes(0, sampleSize.toInt())
        val ascii = String(rawBytes, Charsets.US_ASCII)

        val allSymbols = elfFile?.symbolTables?.flatMap { it.symbols }?.map { it.name } ?: emptyList()

        val fastRpc = FastRpcAnalyzer.analyze(ascii, allSymbols)
        val adspRpc = AdspRpcAnalyzer.analyze(ascii, allSymbols)
        val binder = BinderAnalyzer.analyze(ascii)
        val hidl = HidlAnalyzer.analyze(ascii)
        val aidl = AidlAnalyzer.analyze(ascii)
        val vendorLibs = VendorLibraryAnalyzer.analyze(ascii, elfFile)
        val audioDsp = AudioDspAnalyzer.analyze(ascii)
        val sensorDsp = SensorDspAnalyzer.analyze(ascii)
        val cameraDsp = CameraDspAnalyzer.analyze(ascii)
        val modemDsp = ModemDspAnalyzer.analyze(ascii)
        val trustZone = TrustZoneAnalyzer.analyze(ascii)
        val sharedMem = SharedMemoryAnalyzer.analyze(ascii)
        val rpcHandles = RpcHandleAnalyzer.analyze(fastRpc)
        val sessions = DspSessionAnalyzer.analyze(ascii)

        val dspSet = mutableSetOf<DspSubsystemType>()
        if (audioDsp.isNotEmpty()) dspSet.add(DspSubsystemType.ADSP)
        if (sensorDsp.isNotEmpty()) dspSet.add(DspSubsystemType.SDSP)
        if (cameraDsp.isNotEmpty()) dspSet.add(DspSubsystemType.ICP)
        if (modemDsp.isNotEmpty()) dspSet.add(DspSubsystemType.MDSP)
        if (trustZone.isNotEmpty()) dspSet.add(DspSubsystemType.TRUSTZONE)

        val assessment = buildString {
            if (fastRpc.isNotEmpty()) append("Uses Qualcomm FastRPC remote DSP execution. ")
            if (trustZone.isNotEmpty()) append("Interacts with Qualcomm TrustZone Secure OS. ")
            if (sharedMem.isNotEmpty()) append("Allocates shared DMA-BUF/ION memory heaps. ")
            if (isEmpty()) append("Standard Android/Qualcomm library without elevated DSP/TrustZone privileges.")
        }

        val elapsed = System.currentTimeMillis() - start
        Logger.info("QualcommAnalyzer", "Qualcomm analysis finished in ${elapsed}ms (${fastRpc.size} FastRPC handles, ${dspSet.size} DSP subsystems)")

        QualcommReport(
            binaryPath = loader.filePath,
            fastRpcHandles = rpcHandles,
            adspRpcApis = adspRpc,
            binderInterfaces = binder,
            hidlInterfaces = hidl,
            aidlInterfaces = aidl,
            vendorLibrariesReferenced = vendorLibs,
            dspSubsystemsDetected = dspSet,
            audioDspFeatures = audioDsp,
            sensorDspFeatures = sensorDsp,
            cameraDspFeatures = cameraDsp,
            modemDspFeatures = modemDsp,
            trustZoneReferences = trustZone,
            sharedMemoryRegions = sharedMem,
            rpcSessions = sessions,
            securityAssessment = assessment
        )
    }
}

object FastRpcAnalyzer {
    fun analyze(ascii: String, symbols: List<String>): List<FastRpcHandle> {
        val list = mutableListOf<FastRpcHandle>()
        val knownRpcNames = listOf("remote_handle_open", "remote_handle_invoke", "remote_handle_close", "remote_handle_control")
        var count = 0
        for (sym in knownRpcNames) {
            if (ascii.contains(sym) || symbols.contains(sym)) {
                list.add(
                    FastRpcHandle(
                        name = sym,
                        domain = 0, // default ADSP domain 0
                        interfaceId = 0x01000000L + count,
                        isStaticHandle = true,
                        methodCountEstimate = 8
                    )
                )
                count++
            }
        }
        if (ascii.contains("libadsprpc.so") || ascii.contains("libcdsprpc.so") || ascii.contains("libsdsprpc.so")) {
            list.add(
                FastRpcHandle(
                    name = "adsprpc_default_handle",
                    domain = 0,
                    interfaceId = 0x1001,
                    isStaticHandle = false,
                    methodCountEstimate = 16
                )
            )
        }
        return list
    }
}

object AdspRpcAnalyzer {
    fun analyze(ascii: String, symbols: List<String>): List<AdspRpcApi> {
        val list = mutableListOf<AdspRpcApi>()
        val checks = mapOf(
            "remote_handle_open" to "Opens a handle to a remote Hexagon DSP interface.",
            "remote_handle_invoke" to "Invokes a remote procedure call on Hexagon DSP.",
            "remote_mmap" to "Maps user-space memory buffer into Hexagon DSP address space.",
            "remote_munmap" to "Unmaps previously shared memory buffer from DSP.",
            "remote_register_buf" to "Registers a shared DMA-BUF with adsprpc driver."
        )
        for ((api, desc) in checks) {
            if (ascii.contains(api) || symbols.contains(api)) {
                list.add(AdspRpcApi(api, "adsprpc / FastRPC", desc))
            }
        }
        return list
    }
}

object BinderAnalyzer {
    fun analyze(ascii: String): List<IpcInterfaceToken> {
        val list = mutableListOf<IpcInterfaceToken>()
        if (ascii.contains("android.os.IBinder") || ascii.contains("android.os.Binder")) {
            list.add(IpcInterfaceToken("android.os.IBinder", "BINDER_TRANSACTION", listOf(1, 2, 3)))
        }
        val lines = ascii.split("\u0000")
        for (str in lines) {
            if (str.startsWith("android.hardware.") || str.startsWith("vendor.qti.hardware.")) {
                if (str.length in 10..100) {
                    list.add(IpcInterfaceToken(str, "BINDER_TRANSACTION"))
                }
            }
        }
        return list.distinctBy { it.descriptor }
    }
}

object HidlAnalyzer {
    fun analyze(ascii: String): List<IpcInterfaceToken> {
        val list = mutableListOf<IpcInterfaceToken>()
        val lines = ascii.split("\u0000")
        for (str in lines) {
            if (str.contains("@1.") || str.contains("@2.")) {
                if (str.startsWith("android.hardware.") || str.startsWith("vendor.qti.hardware.")) {
                    list.add(IpcInterfaceToken(str, "HIDL"))
                }
            }
        }
        return list.distinctBy { it.descriptor }
    }
}

object AidlAnalyzer {
    fun analyze(ascii: String): List<IpcInterfaceToken> {
        val list = mutableListOf<IpcInterfaceToken>()
        val lines = ascii.split("\u0000")
        for (str in lines) {
            if (str.startsWith("vendor.qti.hardware.") && !str.contains("@")) {
                if (str.length in 15..80) {
                    list.add(IpcInterfaceToken(str, "AIDL"))
                }
            }
        }
        return list.distinctBy { it.descriptor }
    }
}

object VendorLibraryAnalyzer {
    fun analyze(ascii: String, elfFile: ELFFile?): List<String> {
        val needed = elfFile?.neededDependencies ?: emptyList()
        val qtiLibs = needed.filter { it.startsWith("libqti") || it.startsWith("libadreno") || it.startsWith("libadsprpc") || it.startsWith("libqc") }
        val extracted = mutableListOf<String>()
        val lines = ascii.split("\u0000")
        for (str in lines) {
            if ((str.startsWith("libqti_") || str.startsWith("libadreno_") || str.startsWith("libfastrpc_")) && str.endsWith(".so")) {
                extracted.add(str)
            }
        }
        return (qtiLibs + extracted).distinct().sorted()
    }
}

object AudioDspAnalyzer {
    fun analyze(ascii: String): List<String> {
        val list = mutableListOf<String>()
        if (ascii.contains("adsp_") || ascii.contains("qti,audio") || ascii.contains("adsp_default_listener")) {
            list.add("Qualcomm ADSP Audio Engine")
        }
        if (ascii.contains("voice_service") || ascii.contains("cvp_")) {
            list.add("Qualcomm Voice DSP (CVP)")
        }
        if (ascii.contains("acdb_") || ascii.contains("audio_calibration")) {
            list.add("ACDB Audio Calibration Database")
        }
        return list
    }
}

object SensorDspAnalyzer {
    fun analyze(ascii: String): List<String> {
        val list = mutableListOf<String>()
        if (ascii.contains("slpi_") || ascii.contains("sns_") || ascii.contains("libsdsprpc.so")) {
            list.add("Sensor Low-Power Island (SLPI/SDSP)")
        }
        if (ascii.contains("sns_see_") || ascii.contains("sensor_service")) {
            list.add("Qualcomm Sensor Execution Environment (SEE)")
        }
        return list
    }
}

object CameraDspAnalyzer {
    fun analyze(ascii: String): List<String> {
        val list = mutableListOf<String>()
        if (ascii.contains("libcamera") || ascii.contains("qti.camera") || ascii.contains("camx") || ascii.contains("chi-cdk")) {
            list.add("Qualcomm CamX / Spectra Camera Architecture")
        }
        if (ascii.contains("icp_") || ascii.contains("ipe_") || ascii.contains("bps_")) {
            list.add("Spectra Image Processing Engine (IPE/BPS)")
        }
        return list
    }
}

object ModemDspAnalyzer {
    fun analyze(ascii: String): List<String> {
        val list = mutableListOf<String>()
        if (ascii.contains("qmi_") || ascii.contains("libqmi") || ascii.contains("qmux")) {
            list.add("Qualcomm MSM Interface (QMI) Client")
        }
        if (ascii.contains("mpss_") || ascii.contains("modem_daemon")) {
            list.add("Qualcomm MPSS Modem Subsystem")
        }
        if (ascii.contains("qrtr_") || ascii.contains("libqrtr")) {
            list.add("Qualcomm IPC Router (QRTR)")
        }
        return list
    }
}

object TrustZoneAnalyzer {
    fun analyze(ascii: String): List<TrustZoneReference> {
        val list = mutableListOf<TrustZoneReference>()
        if (ascii.contains("qseecom") || ascii.contains("/dev/qseecom")) {
            list.add(TrustZoneReference("QSEECom Interface", null, 1, "Communicates with Qualcomm TrustZone QSEE Secure OS"))
        }
        if (ascii.contains("keymaster") || ascii.contains("gatekeeper") || ascii.contains("km_tz")) {
            list.add(TrustZoneReference("TrustZone Keymaster/Gatekeeper", null, 2, "Hardware-backed cryptographic keystore in TrustZone TEE"))
        }
        if (ascii.contains("widevine") || ascii.contains("qcom.tz.drm")) {
            list.add(TrustZoneReference("TrustZone DRM App", null, 3, "Widevine / PlayReady hardware DRM inside secure world"))
        }
        return list
    }
}

object SharedMemoryAnalyzer {
    fun analyze(ascii: String): List<SharedMemoryRegion> {
        val list = mutableListOf<SharedMemoryRegion>()
        if (ascii.contains("/dev/ion") || ascii.contains("ion_alloc")) {
            list.add(SharedMemoryRegion("ION Shared Heap", "ion_alloc", true, "ION_HEAP_ADSP / ION_FLAG_CACHED"))
        }
        if (ascii.contains("/dev/dma_buf") || ascii.contains("dma_buf_alloc") || ascii.contains("remote_register_buf")) {
            list.add(SharedMemoryRegion("DMA-BUF FastRPC Shared Memory", "dma_buf_alloc", true, "DMA_BUF_FLAG_READ_WRITE"))
        }
        if (ascii.contains("ashmem_") || ascii.contains("/dev/ashmem")) {
            list.add(SharedMemoryRegion("Android Ashmem", "ashmem_create_region", false, "O_RDWR"))
        }
        return list
    }
}

object RemoteProcedureAnalyzer {
    fun analyze(ascii: String): List<String> {
        val list = mutableListOf<String>()
        if (ascii.contains("remote_handle_invoke")) list.add("Qualcomm FastRPC Remote Invocation Engine")
        if (ascii.contains("qmi_client_send_msg_sync")) list.add("Qualcomm QMI Synchronous RPC Message")
        return list
    }
}

object RpcHandleAnalyzer {
    fun analyze(handles: List<FastRpcHandle>): List<FastRpcHandle> {
        return handles.distinctBy { it.name }.sortedBy { it.interfaceId }
    }
}

object DspSessionAnalyzer {
    fun analyze(ascii: String): List<DspSessionInfo> {
        val list = mutableListOf<DspSessionInfo>()
        if (ascii.contains("file:///lib/libadsp") || ascii.contains("adsp_default_listener")) {
            list.add(DspSessionInfo("ADSP Domain 0", "file:///system/lib64/libadsp_default_listener.so", 1048576L))
        }
        if (ascii.contains("file:///lib/libcdsp") || ascii.contains("cdsp_default_listener")) {
            list.add(DspSessionInfo("CDSP Domain 3", "file:///system/lib64/libcdsp_default_listener.so", 4194304L))
        }
        if (ascii.contains("file:///lib/libsdsprpc")) {
            list.add(DspSessionInfo("SDSP Domain 2", "file:///system/lib64/libsdsprpc.so", 524288L))
        }
        return list
    }
}

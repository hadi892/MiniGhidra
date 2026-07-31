package com.example.binary

import com.example.core.FileLoader
import com.example.core.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import kotlin.math.log2

/**
 * Result of entropy and hash analysis for a binary or segment.
 */
data class EntropyReport(
    val shannonEntropy: Double,
    val md5Hash: String,
    val sha1Hash: String,
    val sha256Hash: String,
    val isPackedOrEncrypted: Boolean,
    val blockEntropies: List<Double> = emptyList()
)

/**
 * Computes Shannon entropy (0.0 to 8.0) and cryptographic hashes (MD5, SHA-1, SHA-256)
 * across binary files and ELF sections to detect packing, compression, and obfuscation.
 */
object EntropyAnalyzer {

    /**
     * Analyzes overall file entropy and computes cryptographic hashes.
     */
    suspend fun analyze(loader: FileLoader, numBlocks: Int = 32): EntropyReport = withContext(Dispatchers.Default) {
        val fileSize = loader.fileSize
        if (fileSize <= 0) {
            return@withContext EntropyReport(
                shannonEntropy = 0.0,
                md5Hash = "",
                sha1Hash = "",
                sha256Hash = "",
                isPackedOrEncrypted = false
            )
        }

        val md5 = MessageDigest.getInstance("MD5")
        val sha1 = MessageDigest.getInstance("SHA-1")
        val sha256 = MessageDigest.getInstance("SHA-256")

        val byteCounts = LongArray(256)
        val chunkSize = 524288L // 512 KB
        var current = 0L

        // For block entropy visualization
        val blockEntropies = mutableListOf<Double>()
        val blockSize = (fileSize / numBlocks.toLong()).coerceAtLeast(1024L)
        var currentBlockCounts = LongArray(256)
        var currentBlockBytes = 0L
        var blockTarget = blockSize

        while (current < fileSize) {
            val toRead = (fileSize - current).coerceAtMost(chunkSize).toInt()
            val data = loader.readBytes(current, toRead)

            md5.update(data)
            sha1.update(data)
            sha256.update(data)

            for (b in data) {
                val idx = b.toInt() and 0xFF
                byteCounts[idx]++
                currentBlockCounts[idx]++
                currentBlockBytes++

                if (currentBlockBytes >= blockTarget && blockEntropies.size < numBlocks) {
                    blockEntropies.add(computeShannonEntropy(currentBlockCounts, currentBlockBytes))
                    currentBlockCounts = LongArray(256)
                    currentBlockBytes = 0L
                }
            }
            current += toRead
        }

        if (currentBlockBytes > 0 && blockEntropies.size < numBlocks) {
            blockEntropies.add(computeShannonEntropy(currentBlockCounts, currentBlockBytes))
        }

        val totalEntropy = computeShannonEntropy(byteCounts, fileSize)
        val isPacked = totalEntropy >= 7.2

        val md5Str = md5.digest().joinToString("") { "%02x".format(it) }
        val sha1Str = sha1.digest().joinToString("") { "%02x".format(it) }
        val sha256Str = sha256.digest().joinToString("") { "%02x".format(it) }

        Logger.info("EntropyAnalyzer", "Shannon entropy: %.4f (Packed=$isPacked), SHA-256: ${sha256Str.take(12)}...".format(totalEntropy))

        EntropyReport(
            shannonEntropy = totalEntropy,
            md5Hash = md5Str,
            sha1Hash = sha1Str,
            sha256Hash = sha256Str,
            isPackedOrEncrypted = isPacked,
            blockEntropies = blockEntropies
        )
    }

    private fun computeShannonEntropy(counts: LongArray, totalBytes: Long): Double {
        if (totalBytes == 0L) return 0.0
        var entropy = 0.0
        val n = totalBytes.toDouble()
        for (c in counts) {
            if (c > 0) {
                val p = c.toDouble() / n
                entropy -= p * log2(p)
            }
        }
        return entropy
    }
}

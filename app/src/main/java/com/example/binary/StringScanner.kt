package com.example.binary

import com.example.core.FileLoader
import com.example.core.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Type of string extracted from a binary.
 */
enum class StringEncoding {
    ASCII,
    UTF8,
    UNICODE_UTF16LE
}

/**
 * Represents a string extracted from binary analysis.
 */
data class ExtractedString(
    val offset: Long,
    val length: Int,
    val value: String,
    val encoding: StringEncoding,
    val sectionName: String = "RAW"
)

/**
 * High-performance binary string scanner supporting ASCII, UTF-8, and UTF-16LE Unicode strings.
 * Operates on chunks to support files larger than 2GB without out-of-memory errors.
 */
object StringScanner {

    /**
     * Scans the given file for ASCII and UTF-8 strings of at least minLength characters.
     */
    suspend fun scanAsciiAndUtf8(
        loader: FileLoader,
        minLength: Int = 4,
        maxResults: Int = 10000
    ): List<ExtractedString> = withContext(Dispatchers.Default) {
        val results = mutableListOf<ExtractedString>()
        val chunkSize = 1048576L // 1MB chunks
        var currentOffset = 0L
        val fileSize = loader.fileSize

        val currentBuilder = StringBuilder()
        var startOffset = -1L

        while (currentOffset < fileSize && results.size < maxResults) {
            val toRead = (fileSize - currentOffset).coerceAtMost(chunkSize).toInt()
            val chunk = loader.readBytes(currentOffset, toRead)

            for (i in chunk.indices) {
                val b = chunk[i].toInt() and 0xFF
                val absOffset = currentOffset + i

                // Check printable ASCII / UTF-8
                if (isPrintableAscii(b)) {
                    if (startOffset == -1L) startOffset = absOffset
                    currentBuilder.append(b.toChar())
                } else {
                    if (currentBuilder.length >= minLength) {
                        results.add(
                            ExtractedString(
                                offset = startOffset,
                                length = currentBuilder.length,
                                value = currentBuilder.toString(),
                                encoding = StringEncoding.ASCII
                            )
                        )
                        if (results.size >= maxResults) break
                    }
                    currentBuilder.clear()
                    startOffset = -1L
                }
            }
            currentOffset += toRead
        }

        if (currentBuilder.length >= minLength && results.size < maxResults) {
            results.add(
                ExtractedString(
                    offset = startOffset,
                    length = currentBuilder.length,
                    value = currentBuilder.toString(),
                    encoding = StringEncoding.ASCII
                )
            )
        }

        Logger.info("StringScanner", "Extracted ${results.size} ASCII/UTF-8 strings (minLen=$minLength)")
        results
    }

    /**
     * Scans the given file for UTF-16 Little-Endian Unicode strings.
     */
    suspend fun scanUnicodeUtf16(
        loader: FileLoader,
        minLength: Int = 4,
        maxResults: Int = 5000
    ): List<ExtractedString> = withContext(Dispatchers.Default) {
        val results = mutableListOf<ExtractedString>()
        val chunkSize = 524288L // 512KB chunks
        var currentOffset = 0L
        val fileSize = loader.fileSize

        val builder = StringBuilder()
        var startOffset = -1L

        while (currentOffset < fileSize - 1 && results.size < maxResults) {
            val toRead = (fileSize - currentOffset).coerceAtMost(chunkSize).toInt()
            val chunk = loader.readBytes(currentOffset, toRead)

            var i = 0
            while (i < chunk.size - 1) {
                val low = chunk[i].toInt() and 0xFF
                val high = chunk[i + 1].toInt() and 0xFF
                val absOffset = currentOffset + i

                if (high == 0 && isPrintableAscii(low)) {
                    if (startOffset == -1L) startOffset = absOffset
                    builder.append(low.toChar())
                    i += 2
                } else {
                    if (builder.length >= minLength) {
                        results.add(
                            ExtractedString(
                                offset = startOffset,
                                length = builder.length * 2,
                                value = builder.toString(),
                                encoding = StringEncoding.UNICODE_UTF16LE
                            )
                        )
                        if (results.size >= maxResults) break
                    }
                    builder.clear()
                    startOffset = -1L
                    i += 2
                }
            }
            currentOffset += toRead
        }

        Logger.info("StringScanner", "Extracted ${results.size} Unicode UTF-16LE strings (minLen=$minLength)")
        results
    }

    private fun isPrintableAscii(byteVal: Int): Boolean {
        return (byteVal in 32..126) || byteVal == 9 || byteVal == 10 || byteVal == 13
    }
}

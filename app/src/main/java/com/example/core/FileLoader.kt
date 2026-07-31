package com.example.core

import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import java.io.File
import java.io.FileInputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel

/**
 * Endianness specification for binary parsing.
 */
enum class Endianness {
    LITTLE_ENDIAN,
    BIG_ENDIAN;

    val byteOrder: ByteOrder
        get() = when (this) {
            LITTLE_ENDIAN -> ByteOrder.LITTLE_ENDIAN
            BIG_ENDIAN -> ByteOrder.BIG_ENDIAN
        }
}

/**
 * Handles high-performance, buffered, and memory-mapped file access for binaries up to and exceeding 2 GB.
 * Supports standard POSIX files (e.g. /system/lib64, /vendor/lib64) and Android Scoped Storage (Uri).
 */
class FileLoader : AutoCloseable {

    private var randomAccessFile: RandomAccessFile? = null
    private var fileChannel: FileChannel? = null
    private var parcelFileDescriptor: ParcelFileDescriptor? = null
    private var mappedBuffer: ByteBuffer? = null

    var filePath: String = ""
        private set
    var fileUri: Uri? = null
        private set
    var fileSize: Long = 0L
        private set
    var endianness: Endianness = Endianness.LITTLE_ENDIAN
        private set

    /**
     * Opens a file from a direct filesystem path (e.g. /system/lib64/libc.so, /vendor/lib64/libadreno_utils.so, or user storage).
     */
    fun openFile(file: File, endian: Endianness = Endianness.LITTLE_ENDIAN): Boolean {
        close()
        return try {
            if (!file.exists() || !file.canRead()) {
                Logger.error("FileLoader", "File not readable: ${file.absolutePath}")
                return false
            }
            filePath = file.absolutePath
            fileSize = file.length()
            endianness = endian
            randomAccessFile = RandomAccessFile(file, "r")
            fileChannel = randomAccessFile?.channel
            tryMapOrBuffer()
            Logger.info("FileLoader", "Opened file: $filePath (${fileSize} bytes, $endianness)")
            true
        } catch (e: Exception) {
            Logger.error("FileLoader", "Failed to open file: ${file.absolutePath}", e)
            false
        }
    }

    /**
     * Opens a file from a Storage Access Framework Uri using Context contentResolver.
     */
    fun openUri(context: Context, uri: Uri, endian: Endianness = Endianness.LITTLE_ENDIAN): Boolean {
        close()
        return try {
            val pfd = context.contentResolver.openFileDescriptor(uri, "r")
                ?: throw IllegalStateException("Unable to open ParcelFileDescriptor for $uri")
            parcelFileDescriptor = pfd
            fileUri = uri
            fileSize = pfd.statSize
            endianness = endian

            val fis = FileInputStream(pfd.fileDescriptor)
            fileChannel = fis.channel
            tryMapOrBuffer()
            Logger.info("FileLoader", "Opened URI: $uri (${fileSize} bytes, $endianness)")
            true
        } catch (e: Exception) {
            Logger.error("FileLoader", "Failed to open URI: $uri", e)
            false
        }
    }

    /**
     * Attempts to memory-map files under 1 GB for near-instant access.
     * Falls back to standard FileChannel seeks for larger binaries (>2GB safe).
     */
    private fun tryMapOrBuffer() {
        val channel = fileChannel ?: return
        if (fileSize in 1..1_073_741_824L) { // map up to 1GB
            try {
                mappedBuffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, fileSize).apply {
                    order(endianness.byteOrder)
                }
            } catch (e: Exception) {
                Logger.warn("FileLoader", "MMap failed ($fileSize bytes), falling back to channel reads: ${e.message}")
                mappedBuffer = null
            }
        }
    }

    fun setEndian(endian: Endianness) {
        endianness = endian
        mappedBuffer?.order(endian.byteOrder)
    }

    /**
     * Reads a slice of bytes at the specified offset into a ByteArray.
     */
    fun readBytes(offset: Long, length: Int): ByteArray {
        if (offset < 0 || offset >= fileSize || length <= 0) return ByteArray(0)
        val actualLength = ((fileSize - offset).coerceAtMost(length.toLong())).toInt()
        val result = ByteArray(actualLength)

        val buffer = mappedBuffer
        if (buffer != null && offset + actualLength <= buffer.capacity()) {
            val dup = buffer.duplicate().apply { order(endianness.byteOrder) }
            dup.position(offset.toInt())
            dup.get(result)
            return result
        }

        val channel = fileChannel ?: return ByteArray(0)
        synchronized(channel) {
            channel.position(offset)
            val byteBuf = ByteBuffer.wrap(result)
            var totalRead = 0
            while (totalRead < actualLength) {
                val r = channel.read(byteBuf)
                if (r <= 0) break
                totalRead += r
            }
        }
        return result
    }

    /**
     * Reads an unsigned 8-bit integer (byte).
     */
    fun readU8(offset: Long): Int {
        val bytes = readBytes(offset, 1)
        if (bytes.isEmpty()) return 0
        return bytes[0].toInt() and 0xFF
    }

    /**
     * Reads an unsigned 16-bit integer (2 bytes).
     */
    fun readU16(offset: Long): Int {
        val bytes = readBytes(offset, 2)
        if (bytes.size < 2) return 0
        val buf = ByteBuffer.wrap(bytes).apply { order(endianness.byteOrder) }
        return buf.short.toInt() and 0xFFFF
    }

    /**
     * Reads an unsigned 32-bit integer (4 bytes).
     */
    fun readU32(offset: Long): Long {
        val bytes = readBytes(offset, 4)
        if (bytes.size < 4) return 0L
        val buf = ByteBuffer.wrap(bytes).apply { order(endianness.byteOrder) }
        return buf.int.toLong() and 0xFFFFFFFFL
    }

    /**
     * Reads a signed 64-bit integer (8 bytes).
     */
    fun readU64(offset: Long): Long {
        val bytes = readBytes(offset, 8)
        if (bytes.size < 8) return 0L
        val buf = ByteBuffer.wrap(bytes).apply { order(endianness.byteOrder) }
        return buf.long
    }

    /**
     * Reads a null-terminated ASCII/UTF-8 string starting at the offset, up to maxLength.
     */
    fun readNullTerminatedString(offset: Long, maxLength: Int = 1024): String {
        if (offset < 0 || offset >= fileSize) return ""
        val bytes = readBytes(offset, maxLength)
        val index = bytes.indexOfFirst { it == 0.toByte() }
        val validBytes = if (index >= 0) bytes.sliceArray(0 until index) else bytes
        return String(validBytes, Charsets.UTF_8)
    }

    override fun close() {
        try {
            mappedBuffer = null
            fileChannel?.close()
            randomAccessFile?.close()
            parcelFileDescriptor?.close()
        } catch (e: Exception) {
            Logger.warn("FileLoader", "Error while closing resources: ${e.message}")
        } finally {
            fileChannel = null
            randomAccessFile = null
            parcelFileDescriptor = null
        }
    }
}

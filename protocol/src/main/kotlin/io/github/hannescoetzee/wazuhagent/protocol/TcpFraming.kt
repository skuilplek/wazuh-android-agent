package io.github.hannescoetzee.wazuhagent.protocol

import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream

/**
 * `OS_SendSecureTCP()` / `OS_RecvSecureTCP()`: every frame is a 4-byte little-endian
 * length followed by the payload.
 */
object TcpFraming {
    fun write(out: OutputStream, payload: ByteArray) {
        val size = payload.size
        val frame = ByteArray(4 + size)
        frame[0] = size.toByte()
        frame[1] = (size ushr 8).toByte()
        frame[2] = (size ushr 16).toByte()
        frame[3] = (size ushr 24).toByte()
        payload.copyInto(frame, 4)
        out.write(frame)
        out.flush()
    }

    /** Returns null when the peer closed the connection cleanly between frames. */
    fun read(input: InputStream, maxSize: Int = MessageCodec.MAX_FRAME_SIZE): ByteArray? {
        val header = ByteArray(4)
        val first = readFully(input, header, allowEofAtStart = true) ?: return null
        check(first == 4)
        val size = (header[0].toInt() and 0xff) or
            ((header[1].toInt() and 0xff) shl 8) or
            ((header[2].toInt() and 0xff) shl 16) or
            ((header[3].toInt() and 0xff) shl 24)
        if (size < 0 || size > maxSize) throw ProtocolException("Frame size $size exceeds limit")
        val payload = ByteArray(size)
        readFully(input, payload, allowEofAtStart = false)
        return payload
    }

    private fun readFully(input: InputStream, buf: ByteArray, allowEofAtStart: Boolean): Int? {
        var read = 0
        while (read < buf.size) {
            val n = input.read(buf, read, buf.size - read)
            if (n < 0) {
                if (read == 0 && allowEofAtStart) return null
                throw EOFException("Connection closed mid-frame")
            }
            read += n
        }
        return read
    }
}

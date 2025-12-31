package org.example
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString

@Serializable
data class GetStatusResponse(
    val attn: String,
    val type: Int,
    val length: Int,
    val result: Int,
    val serialNumber: String,
    val mode: Int,
    val transRecordStatus: Int,
    val logEntries: Int,
    val versions: Versions,
    val firmwareVersion: String,
    val crc: String
)

@Serializable
data class Versions(
    val bootloaders: List<String>,
    val cil: List<String>,
    val cfg: String
)

object ProtocolParser {
    private val json = Json { prettyPrint = false }

    fun parse(data: ByteArray): String {
        if (data.size < 64) return "{\"error\": \"Invalid data length: ${data.size}\"}"
        // 校验包头
        if ((data[0].toInt() and 0xFF) != 0xA5) return "{\"error\": \"Invalid Attn byte\"}"
        // 辅助方法：读取 2 字节（大端序）并转为十六进制或整数
        fun readShort(offset: Int) = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
        fun toHex(start: Int, len: Int) = data.sliceArray(start until start + len).joinToString("") { "%02X".format(it) }
        fun toAscii(start: Int, len: Int): String {
            val sb = StringBuilder()
            for (i in start until start + len) {
                // 过滤掉不可见字符 (0x00 或 0xFF)
                val b = data[i].toInt() and 0xFF
                if (b in 32..126) {
                    sb.append(b.toChar())
                }
            }
            return sb.toString().trim()
        }
        val response = GetStatusResponse(
            attn = "0x%02X".format(data[0]),
            type = data[1].toInt() and 0xFF,
            length = readShort(2),
            result = data[4].toInt() and 0xFF,
            serialNumber = toAscii(5, 32),
            mode = data[37].toInt() and 0xFF,
            transRecordStatus = data[38].toInt() and 0xFF,
            logEntries = readShort(39),
            versions = Versions(
                bootloaders = listOf(toHex(41, 2), toHex(43, 2), toHex(45, 2), toHex(47, 2)),
                cil = listOf(toHex(49, 2), toHex(51, 2), toHex(53, 2), toHex(55, 2)),
                cfg = toHex(57, 2)
            ),
            // 59-61 字节为固件版本
            firmwareVersion = "${data[59].toInt() and 0xFF}.${data[60].toInt() and 0xFF}.${data[61].toInt() and 0xFF}",
            crc = toHex(62, 2)
        )

        return json.encodeToString(response)
    }

    // CRC 校验（通常为 CRC16-CCITT 或 XMODEM，需根据硬件文档调整算法）
    fun verifyCrc(data: ByteArray): Boolean {
        // TODO: 根据你的硬件说明书实现具体 CRC 算法
        return true
    }

}
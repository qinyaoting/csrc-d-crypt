package org.example

import com.fazecast.jSerialComm.SerialPort
import java.lang.Thread.sleep
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec


fun main() {
    val comPort = SerialPort.getCommPorts().find {
        it.systemPortName.contains("ttyUSB") || it.systemPortName.contains("ttyACM")
    } ?: run {
        println("未发现 USB 串口设备")
        return
    }
    comPort.baudRate = 115200
    comPort.numDataBits = 8
    comPort.numStopBits = SerialPort.ONE_STOP_BIT
    comPort.parity = SerialPort.NO_PARITY
    comPort.setComPortTimeouts(SerialPort.TIMEOUT_READ_BLOCKING, 1000, 0)

    if (comPort.openPort()) {
        println("串口已打开 (同步模式)")
        repeat(5) { i ->
            val cmd = getAuthLogin1Cmd()
            val cmdHexStr = cmd.toHexString()
            val reCmd = cmd.sliceArray(5 until 21).reversedArray()
            println("${i + 1}  Ts Challenge:\t ${cmdHexStr.substring(10, 42)} \t\t  re:${reCmd.toHexString()}")
            val bytesWritten = comPort.writeBytes(cmd, cmd.size)
            if (bytesWritten > 0) {
                val buffer = ByteArray(64)
                val bytesRead = comPort.readBytes(buffer, buffer.size)
                if (bytesRead > 0) {
                    val login1RspHex = buffer.toHexString()
                    println("Login1 Rsp:\t $login1RspHex")
                    val readerChallenge = buffer.sliceArray(21 until 37)
                    //val authKey = buffer.sliceArray(5 until 21)  //ByteArray(16)
                    val rsRsp = generateTsResponse(readerChallenge, ByteArray(32));
                    val cmd2 = getAuthLogin2Cmd(rsRsp);
                    val bytesWritten2 = comPort.writeBytes(cmd2, cmd2.size)
                    if (bytesWritten2 > 0) {
                        val buffer2 = ByteArray(64)
                        val bytesRead2= comPort.readBytes(buffer2, buffer2.size)
                        if (bytesRead2 > 0) {
                            val login2RspHex = buffer2.toHexString()
                            println("Login2 \tres: ${login2RspHex.substring(8,10)}\t\t rsp: $login2RspHex")
                        }
                    }
                }
            }
            sleep(2000)
        }
        comPort.closePort()
        println("串口已关闭")
    } else {
        println("无法打开串口，请检查权限。")
    }
}

fun sendCmdParseRsp(comPort: SerialPort, cmd:ByteArray) :String? {
    val bytesWritten = comPort.writeBytes(cmd, cmd.size)
    if (bytesWritten > 0) {
        //println("${i + 1} 成功发送 $bytesWritten 字节，正在等待回复...")
        val buffer = ByteArray(64)
        val bytesRead = comPort.readBytes(buffer, buffer.size)
        if (bytesRead > 0) {
            if (ProtocolParser.verifyCrc(buffer)) {
                //val jsonResult = ProtocolParser.parse(buffer)
                //println("收到回复：\n$jsonResult")
                val rspHexStr = buffer.toHexString()
                val readerRsp = rspHexStr.substring(10,42);
                println("AuthLogin1:${rspHexStr.substring(8,10)} \t\t  hexStr:$rspHexStr ");
                println("Reader Rsp:\t\t ${rspHexStr.substring(10, 42)} \t\t  Reader Challenge: ${rspHexStr.substring(42,74)}");
                return readerRsp
            } else {
                println("CRC 校验失败")
            }
        } else {
            println("读取超时或回复数据不足 ($bytesRead 字节)")
        }
    } else {
        println(" 发送失败")
    }
    return null;
}


fun getStatusCmd() : ByteArray {
    val packet = ByteArray(6)
    packet[0] = 0xA5.toByte()
    packet[1] = 0x00.toByte()
    packet[2] = 0x00.toByte()
    packet[3] = 0x06.toByte()
    val dataForCrc = packet.copyOf(4)
    val crcValue = calculateCrc(dataForCrc)
    packet[4] = (crcValue shr 8).toByte() // 高位字节
    packet[5] = (crcValue and 0xFF).toByte() // 低位字节
    return packet
}
fun getAuthLogin1Cmd() : ByteArray {
    val packet = ByteArray(23)
    packet[0] = 0xA5.toByte()
    packet[1] = 0x10.toByte()
    packet[2] = 0x00.toByte()
    packet[3] = 0x17.toByte()
    packet[4] = 0x01.toByte()
    // 将传入的16字节质询复制到数据包中
    val tsChallenge = ByteArray(16)
    SecureRandom().nextBytes(tsChallenge)
    System.arraycopy(tsChallenge, 0, packet, 5, 16)
    val dataForCrc = packet.copyOf(21)
    val crcValue = calculateCrc(dataForCrc)
    packet[21] = (crcValue shr 8).toByte() // 高位字节
    packet[22] = (crcValue and 0xFF).toByte() // 低位字节
    return packet
}

fun getAuthLogin2Cmd(tsResponse:ByteArray) : ByteArray {
    val packet = ByteArray(22)
    packet[0] = 0xA5.toByte()
    packet[1] = 0x11.toByte()
    packet[2] = 0x00.toByte()
    packet[3] = 0x16.toByte()
    // 将传入的16字节响应复制到数据包中
    System.arraycopy(tsResponse, 0, packet, 4, 16)
    // CRC 是对前面所有字节（0-19）进行计算
    val dataForCrc = packet.copyOf(20)
    val crcValue = calculateCrc(dataForCrc)
    packet[20] = (crcValue shr 8).toByte() // 高位字节
    packet[21] = (crcValue and 0xFF).toByte() // 低位字节
    return packet
}


fun verifyReaderResponse(tsChallengeHex: String, readerRspHex: String, keyBytes: ByteArray): Boolean {
    val tsBytes = tsChallengeHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    val tsLittleEndian = tsBytes.reversedArray()
    val secretKey = SecretKeySpec(keyBytes, "AES")
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    val encryptedResult = cipher.doFinal(tsLittleEndian)
    val calculatedRsp = encryptedResult.joinToString("") { "%02X".format(it) }
    val isValid = calculatedRsp.equals(readerRspHex, ignoreCase = true)
    println("计算出的 Rsp: $calculatedRsp\t\t  收到的 Rsp:   $readerRspHex")
    return isValid
}

fun generateTsResponse(readerChallenge: ByteArray, keyBytes: ByteArray): ByteArray {
    val tsLittleEndian = readerChallenge.reversedArray()
    println("challenge:${readerChallenge.toHexString()} \tchallenge reserved:${tsLittleEndian.toHexString()}  \tkey:${keyBytes.toHexString()} ")
    val secretKey = SecretKeySpec(keyBytes, "AES")
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    val encryptedResult = cipher.doFinal(tsLittleEndian)
    val calculatedRsp = encryptedResult.toHexString()
    println("TsRsp:\t\t $calculatedRsp")
    return encryptedResult
}


fun ByteArray.toHexString(separator: String = ""): String {
    return this.joinToString(separator) { byte ->
        // %02X 表示：16进制，不少于2位，不足补0，大写
        "%02X".format(byte)
    }
}
fun ByteArray.toHexString(separator: String = "", upperCase: Boolean = true): String {
    val format = if (upperCase) "%02X" else "%02x"
    return this.joinToString(separator) { format.format(it) }
}
private fun calculateCrc(data: ByteArray): Int {
    var crc = 0xFFFF // 初始值
    val polynomial = 0x1021

    for (b in data) {
        for (i in 0..7) {
            val bit = ((b.toInt() shr (7 - i) and 1) == 1)
            val c15 = ((crc shr 15 and 1) == 1)
            crc = crc shl 1
            if (c15 xor bit) {
                crc = crc xor polynomial
            }
        }
    }
    return crc and 0xFFFF
}

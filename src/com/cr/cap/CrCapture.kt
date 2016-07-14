package com.cr.cap

import net.sourceforge.jpcap.capture.PacketCapture
import net.sourceforge.jpcap.net.IPPacket
import net.sourceforge.jpcap.net.TCPPacket
import net.sourceforge.jpcap.net.UDPPacket
import net.sourceforge.jpcap.util.ArrayHelper
import net.sourceforge.jpcap.util.HexHelper
import java.text.SimpleDateFormat
import java.util.*

/**
 * Created by wangbo on 7/13/16.
 */
val info =  """
战斗中用的是udp,有一个序号,收到的一方会回发序号表示收到,没有序号会一直发送同一个包
发送 : 10个字节的包头,每场战斗不同 | 00 | 两字节序号 | 三字节消息码(服务器8e d6 02,客户端a8 c9 01) | 一字节 后面的长度 | 消息内容
反馈 : 10个字节的包头,每场战斗不同 | 两字节序号
server和client各自有自己的序号,会有一个重发机制

摆放单位的时候消息很大,平时消息很小

只有两种消息号,client和server的
有一个针对某一个序号返回消息的机制



"""


val INFINITE: Int = -1
val PACKET_COUNT: Int = 1000

val GAME_PORT: Int = 9339

val FILTER: String = "proto TCP or proto UDP and port 9339"

var pcap: PacketCapture = PacketCapture();

val TIME_FORMAT: String = "HH:mm:ss:SSS"

val df: SimpleDateFormat = SimpleDateFormat(TIME_FORMAT)

fun run() {
    println(" --- start --- ")

    var device: String = pcap.findDevice()
    pcap.open("en0", true)
    pcap.setFilter(FILTER, true)

    pcap.addPacketListener {

        when (it) {

            is UDPPacket -> {
                var time = it.timeval.seconds * 1000 + it.timeval.microSeconds / 1000
                printMessageInfo(it.destinationPort, it.data, true, time, it)
            }
            is TCPPacket -> {
                var time = it.timeval.seconds * 1000 + it.timeval.microSeconds / 1000
                printMessageInfo(it.destinationPort, it.data, false, time, it)
            }
            else -> {
                println("NOT TCP Packet $it")
            }
        }
    }


    pcap.addRawPacketListener {
        var count: Int = 0
//        println("Packet ${count.inc()} \n data \n")
    }

    pcap.capture(INFINITE)

}


fun printMessageInfo(desPort: Int, data: ByteArray, isTCP: Boolean, time: Long, packet: IPPacket) {
    var sb: StringBuilder = StringBuilder()

    sb.append("${df.format(Date(time))}")
    if (desPort == GAME_PORT) {
        sb.append("\tCLIENT : ")
    } else {
        sb.append("\tSERVER : ")
    }
//            println("[${HexHelper.toString(it.data)}]")
    if (data.size > 5) {
        try {
            var msgId: Int = ArrayHelper.extractInteger(data, 0, 2)
            var msgLength = ArrayHelper.extractInteger(data, 2, 3)

            var msgName: String? = MsgType.types[msgId]
            msgName?.run {
                sb.append(" $msgName\t$msgId \t ${packet.toColoredString(true)}")
            } ?: kotlin.run {
                sb.append(" unknown msg $msgId \t ${packet.toColoredString(true)} ${HexHelper.toString(packet.data)}")
            }
            if (sb.contains("KeepAlive") || sb.contains("KeepAliveOk")) {
                //ignore
            } else {
                println(sb)
            }
        } catch(e: Exception) {
            e.printStackTrace()
        }
    } else {
//                println("!!!!!!! small msg !!!!!! ${it.isAck} ${it.isFin} ${it.isSyn} $it")
    }
}

fun main(args: Array<String>) {
    try {
        run()
    } catch (e: Exception) {
        e.printStackTrace()
    }

}
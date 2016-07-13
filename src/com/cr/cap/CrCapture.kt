package com.cr.cap

import net.sourceforge.jpcap.capture.PacketCapture
import net.sourceforge.jpcap.net.TCPPacket
import net.sourceforge.jpcap.util.ArrayHelper
import net.sourceforge.jpcap.util.HexHelper
import java.text.SimpleDateFormat
import java.util.*

/**
 * Created by wangbo on 7/13/16.
 */
val INFINITE: Int = -1
val PACKET_COUNT: Int = 1000

val FILTER: String = "proto TCP and port 9339"

var pcap: PacketCapture = PacketCapture();

val TIME_FORMAT: String = "HH:mm:ss:SSS"

val df: SimpleDateFormat = SimpleDateFormat(TIME_FORMAT)

fun main(args: Array<String>) {
    println(" --- start --- ")

    var device: String = pcap.findDevice()
    pcap.open("en0", true)
    pcap.setFilter(FILTER, true)
    pcap.capture(PACKET_COUNT)

    pcap.addPacketListener {
        if (it is TCPPacket) {
            var time = it.timeval.seconds * 1000 + it.timeval.microSeconds / 1000
            print("${df.format(Date(time))}    ")
            print("${it.sourceAddress} to ${it.destinationAddress}")
            println(" l = ${it.data.size}")
            println(HexHelper.toString(it.data))
            if (it.data.size > 5) {
                try {
                    var msgId: Int = ArrayHelper.extractInteger(it.data, 0, 2)
                    var msgLength = ArrayHelper.extractInteger(it.data, 2, 3)

                    println(" msg id = $msgId")
                    println(" msg length = $msgLength")

                    var msgName: String? = MsgType.types[msgId]
                    msgName?.run {
                        println(" get $msgId : $msgName ")
                    }
                } catch(e: Exception) {
                    e.printStackTrace()
                }
            }

        }
    }

    pcap.addRawPacketListener {
        var count: Int = 0
        println("Packet ${count.inc()} \n data \n")
    }

}
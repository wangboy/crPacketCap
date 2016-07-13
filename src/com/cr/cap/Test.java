// $Id: Example1.java,v 1.3 2002/02/18 15:33:00 pcharles Exp $

/***************************************************************************
 * Copyright (C) 2001, Patrick Charles and Jonas Lehmann                   *
 * Distributed under the Mozilla Public License                            *
 * http://www.mozilla.org/NPL/MPL-1.1.txt                                *
 ***************************************************************************/

package com.cr.cap;

import net.sourceforge.jpcap.capture.*;
import net.sourceforge.jpcap.net.*;
import net.sourceforge.jpcap.util.ArrayHelper;
import net.sourceforge.jpcap.util.HexHelper;

import java.nio.ByteBuffer;
import java.rmi.server.ExportException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;


/**
 * jpcap Tutorial - Example 1
 *
 * @author Jonas Lehmann and Patrick Charles
 * @version $Revision: 1.3 $
 * @lastModifiedBy $Author: pcharles $
 * @lastModifiedAt $Date: 2002/02/18 15:33:00 $
 */
public class Test {
	private static final int INFINITE = -1;
	private static final int PACKET_COUNT = 1000;

	// BPF filter for capturing any packet
	private static final String FILTER = "proto TCP and port 9339";

	private PacketCapture m_pcap;
	private String m_device;

	public Test() throws Exception {
		// Step 1:  Instantiate Capturing Engine
		m_pcap = new PacketCapture();

		// Step 2:  Check for devices
		m_device = m_pcap.findDevice();

		// Step 3:  Open Device for Capturing (requires root)
		m_pcap.open("en0", true);

		// Step 4:  Add a BPF Filter (see tcpdump documentation)
		m_pcap.setFilter(FILTER, true);

		// Step 5:  Register a Listener for Raw Packets
//		m_pcap.addRawPacketListener(new RawPacketHandler());

		m_pcap.addPacketListener(p -> {
			if (p instanceof TCPPacket) {
				TCPPacket tcpPacket = (TCPPacket) p;

				String TIME_FORMAT = "HH:mm:ss:SSS";
				SimpleDateFormat df = new SimpleDateFormat(TIME_FORMAT);

				long time = tcpPacket.getTimeval().getSeconds() * 1000 + tcpPacket.getTimeval().getMicroSeconds() / 1000;
				System.out.print(df.format(new Date(time)) + "   ");

				System.out.print(tcpPacket.getSourceAddress() + " to " + tcpPacket.getDestinationAddress());

				System.out.println(" l = " + tcpPacket.getData().length);
				System.out.println(HexHelper.toString(tcpPacket.getData()));


				/////////////
				byte[] data = tcpPacket.getData();
				if (data.length > 5) {

					try {

						byte[] msgID = new byte[2];
						msgID[0] = data[1];
						msgID[1] = data[0];
						byte[] msglength = new byte[3];
						msglength[0] = data[4];
						msglength[1] = data[3];
						msglength[2] = data[2];

						int msgId = ArrayHelper.extractInteger(data, 0, 2);
						int msgl = ArrayHelper.extractInteger(data, 2, 3);

						System.out.println("msg id = " + ArrayHelper.extractInteger(data, 0, 2));
						System.out.println("msg length = " + ArrayHelper.extractInteger(data, 2, 3));

//				ByteBuffer buf = ByteBuffer.allocate(1024);
//				buf.put(data);
//				buf.flip();

//					System.out.println("msg id = " + ArrayHelper.extractInteger(msgID, 0, 2));
//					System.out.println("msg length = " + ArrayHelper.extractInteger(msglength, 0, 3));
						System.out.println(MsgType.Companion.getTypes());
						String msgName = MsgType.Companion.getTypes().get(msgId);
						System.out.println(" get " + msgId + " : " + msgName);

					} catch (Exception e) {
						e.printStackTrace();
					}


				}
				//////////


				System.out.println();
			}
		});

		// Step 6:  Capture Data (max. PACKET_COUNT packets)
		m_pcap.capture(PACKET_COUNT);
	}

	public static void main(String[] args) {
		try {
			Test test = new Test();
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}
}


class RawPacketHandler implements RawPacketListener {
	private static int m_counter = 0;

	public void rawPacketArrived(RawPacket data) {
		String TIME_FORMAT = "HH:mm:ss:SSS";
		SimpleDateFormat df = new SimpleDateFormat(TIME_FORMAT);

		long time = data.getTimeval().getSeconds() * 1000 + data.getTimeval().getMicroSeconds() / 1000;
		System.out.print(df.format(new Date(time)) + "   ");

		System.out.println("l = " + data.getData().length + " of " + data.getDroplen());
		System.out.println(HexHelper.toString(data.getData()));

		m_counter++;
//		System.out.println("Packet " + m_counter + "\n" + data + "\n");
	}
}

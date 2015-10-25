package org.agrs.jcuda;

/**
 * Created by vascofg on 25-10-2015.
 */

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class Analyze {

    /**
     * Main startup method
     *
     * @param args ignored
     */

    public static void main(String[] args) {
        /***************************************************************************
         * First we setup error buffer and name for our file
         **************************************************************************/
        final StringBuilder errbuf = new StringBuilder(); // For any error msgs
        final String file = "tests/http.pcap";

        System.out.printf("Opening file for reading: %s%n", file);

        /***************************************************************************
         * Second we open up the selected file using openOffline call
         **************************************************************************/
        Pcap pcap = Pcap.openOffline(file, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }

        /***************************************************************************
         * Third we create a packet handler which will receive packets from the
         * libpcap loop.
         **************************************************************************/
        PcapPacketHandler<List<PcapPacket>> jpacketHandler = new PcapPacketHandler<List<PcapPacket>>() {

            public void nextPacket(PcapPacket packet, List<PcapPacket> httpPackets) { //user param
                //packets.add(packet);
                //byteCounts.add(packet.getPacketWirelen());
                /*System.out.printf("Received at %s caplen=%-4d len=%-4d %s%n",
                        new Date(packet.getCaptureHeader().timestampInMillis()),
                        packet.getCaptureHeader().caplen(), // Length actually captured
                        packet.getCaptureHeader().wirelen(), // Original length
                        user // User supplied object
                );*/
                packet.scan(JProtocol.ETHERNET_ID);

                Ip4 ip = new Ip4();
                Tcp tcp = new Tcp();
                Http http = new Http();

                if (packet.hasHeader(ip) && packet.hasHeader(tcp) && packet.hasHeader(http)) {
                    /*System.out.printf("HTTP PACKET: %s:%d->%s:%d%n", FormatUtils.ip(ip.source()), tcp.source(),
                            FormatUtils.ip(ip.destination()), tcp.destination());*/
                    httpPackets.add(packet);
                }
            }
        };

        /***************************************************************************
         * Fourth we enter the loop and tell it to capture * packets. The loop
         * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
         * is needed by JScanner. The scanner scans the packet buffer and decodes
         * the headers. The mapping is done automatically, although a variation on
         * the loop method exists that allows the programmer to sepecify exactly
         * which protocol ID to use as the data link type for this pcap interface.
         **************************************************************************/
        try {
            List<PcapPacket> httpPackets = new LinkedList<>();
            pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, httpPackets);
            System.out.printf("Found %d HTTP packets%n", httpPackets.size());
        } finally {
            /***************************************************************************
             * Last thing to do is close the pcap handle
             **************************************************************************/
            pcap.close();
        }
    }

    private static int[] convertIntegers(List<Integer> integers) {
        int[] ret = new int[integers.size()];
        Iterator<Integer> iterator = integers.iterator();
        for (int i = 0; i < ret.length; i++) {
            ret[i] = iterator.next().intValue();
        }
        return ret;
    }
}
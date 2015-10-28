package org.agrs.jcuda;

/**
 * Created by vascofg on 25-10-2015.
 */

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.network.Ip4;

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
        PcapPacketHandler<List<PcapPacket>> deepPacketHandler = new PcapPacketHandler<List<PcapPacket>>() {

            public void nextPacket(PcapPacket packet, List<PcapPacket> packets) { //user param

                int i = 0, state = 0;
                Boolean isHTTP = null;
                try {
                    while (isHTTP == null) {
                        switch (state) {
                            case 0:
                                if (packet.getByte(i) == 'G' && packet.getByte(i + 1) == 'E' &&
                                        packet.getByte(i + 2) == 'T' && packet.getByte(i + 3) == ' ') {
                                    state++;
                                    i += 3;
                                }
                                break;
                            case 1:
                                if (packet.getByte(i) == ' ')
                                    state++;
                                break;
                            case 2:
                                if (packet.getByte(i) == 'H' && packet.getByte(i + 1) == 'T' &&
                                        packet.getByte(i + 2) == 'T' && packet.getByte(i + 3) == 'P' &&
                                        packet.getByte(i + 4) == '/' && packet.getByte(i + 6) == '.')
                                    isHTTP = true;
                                else
                                    isHTTP = false;
                                break;
                        }
                        i++;
                    }
                } catch (java.nio.BufferUnderflowException e) {
                    isHTTP = false;
                }

                if (isHTTP) {
                    packets.add(packet);
                }
            }
        };

        final PcapPacketHandler<List<PcapPacket>> ipPacketHandler = new PcapPacketHandler<List<PcapPacket>>() {

            public void nextPacket(PcapPacket packet, List<PcapPacket> packets) { //user param
                packet.scan(JProtocol.ETHERNET_ID);

                Ip4 ip = new Ip4();

                if (packet.hasHeader(ip)) {
                    packets.add(packet);
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
            long time0 = System.nanoTime();
            pcap.loop(Pcap.LOOP_INFINITE, deepPacketHandler, httpPackets);
            long time1 = System.nanoTime();
            System.out.printf("Found %d HTTP packets in %5.3fms%n", httpPackets.size(), (time1 - time0) / 1e6);

            /*
            List<PcapPacket> ipPackets = new LinkedList<>();
            time0 = System.nanoTime();
            pcap.loop(Pcap.LOOP_INFINITE, ipPacketHandler, ipPackets);
            time1 = System.nanoTime();
            System.out.printf("Found %d IP packets in %5.3fms%n", ipPackets.size(), (time1-time0) / 1e6);

            long byteCount = 0;

            for(PcapPacket p : ipPackets)
                byteCount+=p.getPacketWirelen();

            System.out.printf("Total byte count: %d%n",byteCount);*/

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
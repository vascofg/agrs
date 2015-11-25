package org.agrs.jcuda;

/**
 * Created by vascofg on 25-10-2015.
 */

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.AbstractMessageHeader;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;

import java.io.IOException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class Analyze {

    /**
     * Main startup method
     *
     * @param args ignored
     */

    static long numPackets = 0;

    public static void main(String[] args) {

        final StringBuilder errbuf = new StringBuilder(); // For any error msgs
        final String file = "tests/http.pcap";

        System.out.printf("Opening file for reading: %s%n", file);

        Pcap pcap = Pcap.openOffline(file, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }

        long time0 = System.nanoTime();
        long result = analyzeDPICUDA(pcap);
        long time1 = System.nanoTime();

        System.out.printf("Found %d packets in %5.3fms%n", result, (time1-time0) / 1e6);

        pcap.close();
    }

    private static List<PcapPacket> analyzeDPI(Pcap pcap) {
        final PcapPacketHandler<List<PcapPacket>> DPIHandler = new PcapPacketHandler<List<PcapPacket>>() {

            public void nextPacket(PcapPacket packet, List<PcapPacket> packets) { //user param
                numPackets++;
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

        List<PcapPacket> httpPackets = new LinkedList<>();
        pcap.loop(Pcap.LOOP_INFINITE, DPIHandler, httpPackets);

        return httpPackets;
    }

    private static List<PcapPacket> analyzeIpPackets(Pcap pcap) {
        final PcapPacketHandler<List<PcapPacket>> ipPacketHandler = new PcapPacketHandler<List<PcapPacket>>() {

            public void nextPacket(PcapPacket packet, List<PcapPacket> packets) { //user param
                packet.scan(JProtocol.ETHERNET_ID);

                Ip4 ip = new Ip4();

                if (packet.hasHeader(ip)) {
                    packets.add(packet);
                }
            }
        };

        List<PcapPacket> ipPackets = new LinkedList<>();
        pcap.loop(Pcap.LOOP_INFINITE, ipPacketHandler, ipPackets);
        return ipPackets;
    }

    private static List<PcapPacket> analyzeHttpPackets(Pcap pcap) {
        final PcapPacketHandler<List<PcapPacket>> httpPacketHandler = new PcapPacketHandler<List<PcapPacket>>() {

            public void nextPacket(PcapPacket packet, List<PcapPacket> packets) { //user param
                numPackets++;
                packet.scan(JProtocol.ETHERNET_ID);

                Http http = new Http();

                if (packet.hasHeader(http)) {
                    if (http.getMessageType() == AbstractMessageHeader.MessageType.REQUEST)
                        if (http.fieldValue(Http.Request.RequestMethod).equals("GET"))
                            packets.add(packet);
                }
            }
        };

        List<PcapPacket> httpPackets = new LinkedList<>();
        pcap.loop(Pcap.LOOP_INFINITE, httpPacketHandler, httpPackets);
        return httpPackets;
    }

    private static long analyzeDPICUDA(Pcap pcap) {
        final PcapPacketHandler<List<String>> packetStringListHandler = new PcapPacketHandler<List<String>>() {

            public void nextPacket(PcapPacket packet, List<String> stringList) { //user param
                stringList.add(packet.getUTF8String(0, packet.size()));
            }
        };

        List<String> packetStrings = new LinkedList<>();
        pcap.loop(Pcap.LOOP_INFINITE, packetStringListHandler, packetStrings);

        long numHTTPPackets = 0;

        try {
            CudaAnalyzer.init();
            numHTTPPackets = CudaAnalyzer.processMultiplePointersCountPackets(packetStrings);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return numHTTPPackets;
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
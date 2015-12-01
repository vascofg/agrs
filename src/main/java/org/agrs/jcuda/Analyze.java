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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.concurrent.atomic.AtomicLong;

public class Analyze {

    /**
     * Main startup method
     *
     * @param args ignored
     */

    public static void main(String[] args) {

        final StringBuilder errbuf = new StringBuilder(); // For any error msgs
        final String file = "/run/media/vascofg/DATA/teste.pcap";

        System.out.printf("OPENING FILE FOR READING: %s%n", file);

        Pcap pcap = Pcap.openOffline(file, errbuf);

        if (pcap == null) {
            System.err.printf("ERROR OPENING FILE: "
                    + errbuf.toString());
            return;
        }

        long time0 = System.nanoTime();
        long result = analyzeDPICUDA(pcap);
        long time1 = System.nanoTime();

        System.out.printf("FOUND %d HTTP PACKETS IN %5.3fms%n", result, (time1 - time0) / 1e6);

        pcap.close();
    }

    private static long analyzeDPI(Pcap pcap) {

        final PcapPacketHandler<AtomicLong> DPIHandler = new PcapPacketHandler<AtomicLong>() {

            public void nextPacket(PcapPacket packet, AtomicLong sum) { //user param
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
                    sum.getAndIncrement();
                }
            }
        };

        AtomicLong numPackets = new AtomicLong(0);
        pcap.loop(Pcap.LOOP_INFINITE, DPIHandler, numPackets);

        return numPackets.longValue();
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

        final Pcap superPcap = pcap;

        final int MAX_LENGTH = 67108864; /*64MiB*/

        final List<Integer> packetIndices = new LinkedList<>();

        final PcapPacketHandler<ByteArrayOutputStream> packetHandler = new PcapPacketHandler<ByteArrayOutputStream>() {

            public void nextPacket(PcapPacket packet, ByteArrayOutputStream stream) { //user param
                try {
                    packetIndices.add(stream.size());
                    stream.write(packet.getByteArray(0, packet.size()));

                    if (stream.size() > MAX_LENGTH)
                        superPcap.breakloop();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        };

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        boolean finished = false;
        long numPackets = 0, numHTTPPackets = 0;

        try {
            CudaAnalyzer.init();
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }

        while (!finished) {
            System.out.printf("%nSPLITTING PACKETS... ");

            stream.reset();
            packetIndices.clear();

            long time0 = System.nanoTime();

            int statusCode = pcap.loop(Pcap.LOOP_INFINITE, packetHandler, stream);

            long time1 = System.nanoTime();

            System.out.printf("%5.3fms%n", (time1 - time0) / 1e6);

            if (statusCode == Pcap.OK) //FINISHED
                finished = true;

        /* add final buffer size*/
            packetIndices.add(stream.size());

            int packetIndicesArray[] = new int[packetIndices.size()];
            ListIterator<Integer> itr = packetIndices.listIterator();
            int i = 0;
            while (itr.hasNext()) {
                packetIndicesArray[i++] = itr.next();
            }

            numPackets += (i - 1);
            System.out.printf("SENDING %d PACKETS (%d MiB) TO CUDA%n", (i - 1), stream.size()/1024/1024);
            numHTTPPackets += CudaAnalyzer.processSinglePointer(stream.toByteArray(), packetIndicesArray, i - 1);
        }
        System.out.printf("%nDONE PROCESSING %d PACKETS%n", numPackets);
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
package org.agrs.jcuda;

/**
 * Created by vascofg on 25-10-2015.
 */

import org.jnetpcap.ByteBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.packet.AbstractMessageHeader;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.tcpip.Http;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
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
        final String file = "/run/media/vascofg/DATA/1G.pcap";

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

        final ByteBufferHandler<AtomicLong> DPIHandler = new ByteBufferHandler<AtomicLong>() {

            @Override
            public void nextPacket(PcapHeader pcapHeader, ByteBuffer packet, AtomicLong sum) {
                int i = 0, state = 0;
                Boolean isHTTP = null;
                try {
                    while (isHTTP == null) {
                        switch (state) {
                            case 0:
                                if (packet.get(i) == 'G' && packet.get(i + 1) == 'E' &&
                                        packet.get(i + 2) == 'T' && packet.get(i + 3) == ' ') {
                                    state++;
                                    i += 3;
                                }
                                break;
                            case 1:
                                if (packet.get(i) == ' ')
                                    state++;
                                break;
                            case 2:
                                if (packet.get(i) == 'H' && packet.get(i + 1) == 'T' &&
                                        packet.get(i + 2) == 'T' && packet.get(i + 3) == 'P' &&
                                        packet.get(i + 4) == '/' && packet.get(i + 6) == '.')
                                    isHTTP = true;
                                else
                                    isHTTP = false;
                                break;
                        }
                        i++;
                    }
                } catch (IndexOutOfBoundsException e) {
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


    private static long analyzeJnetpcap(Pcap pcap) {
        final PcapPacketHandler<AtomicLong> httpPacketHandler = new PcapPacketHandler<AtomicLong>() {

            public void nextPacket(PcapPacket packet, AtomicLong sum) { //user param
                packet.scan(JProtocol.ETHERNET_ID);

                Http http = new Http();

                if (packet.hasHeader(http)) {
                    if (http.getMessageType() == AbstractMessageHeader.MessageType.REQUEST)
                        if (http.fieldValue(Http.Request.RequestMethod).equals("GET"))
                            sum.getAndIncrement();
                }
            }
        };

        AtomicLong numPackets = new AtomicLong(0);
        pcap.loop(Pcap.LOOP_INFINITE, httpPacketHandler, numPackets);
        return numPackets.longValue();
    }

    private static long analyzeDPICUDA(Pcap pcap) {

        final Pcap superPcap = pcap;

        final int MAX_LENGTH = 67108864; /*64MiB*/

        final IntBuffer packetIndices = IntBuffer.allocate(MAX_LENGTH/64); //min packet size should be 64 bytes

        final ByteBufferHandler<ByteBuffer> byteBufferHandler = new ByteBufferHandler<ByteBuffer>() {
            @Override
            public void nextPacket(PcapHeader pcapHeader, ByteBuffer packetBuffer, ByteBuffer buffer) {
                packetIndices.put(buffer.position());
                buffer.put(packetBuffer);

                if (buffer.position() >= MAX_LENGTH)
                    superPcap.breakloop();
            }
        };

        ByteBuffer packetBuffer = ByteBuffer.allocate(MAX_LENGTH+(1024*1024)); //Allocate extra 1MB for possible extra packet
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

            packetBuffer.clear();
            packetIndices.clear();

            long time0 = System.nanoTime();

            int statusCode = pcap.loop(Pcap.LOOP_INFINITE, byteBufferHandler, packetBuffer);

            long time1 = System.nanoTime();

            System.out.printf("%5.3fms%n", (time1 - time0) / 1e6);

            if (statusCode == Pcap.OK) //FINISHED
                finished = true;

            /* add final buffer size*/
            packetIndices.put(packetBuffer.position());

            int iterNumPackets = packetIndices.position() - 1; //remove extra buffer size

            numPackets += iterNumPackets;
            System.out.printf("SENDING %d PACKETS (%d MiB) TO CUDA%n", iterNumPackets, packetBuffer.position()/1024/1024);
            numHTTPPackets += CudaAnalyzer.processSinglePointer(packetBuffer.array(), packetIndices.array(), iterNumPackets);
        }
        System.out.printf("%nDONE PROCESSING %d PACKETS%n", numPackets);
        return numHTTPPackets;
    }
}
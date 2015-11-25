package org.agrs.jcuda;

import jcuda.Pointer;
import jcuda.Sizeof;
import jcuda.driver.*;

import java.io.IOException;
import java.util.List;

import static jcuda.driver.JCudaDriver.*;
import static jcuda.driver.JCudaDriver.cuMemFree;
import static jcuda.driver.JCudaDriver.cuMemcpyDtoH;

/**
 * Created by vascofg on 25-11-2015.
 */
public class CudaAnalyzer {

    private static CUfunction stringPacketKernel;

    public static void init() throws IOException
    {
        System.out.println("[CUDA] INITIALIZING");
        // Enable exceptions and omit all subsequent error checks
        JCudaDriver.setExceptionsEnabled(true);

        // Initialize the driver and create a context for the first device.
        cuInit(0);
        CUdevice device = new CUdevice();
        cuDeviceGet(device, 0);
        CUcontext context = new CUcontext();
        cuCtxCreate(context, 0, device);

        // Load the ptx file.
        CUmodule module = new CUmodule();
        cuModuleLoad(module, "./target/kernels/JCudaStringPacketKernel.ptx");

        stringPacketKernel = new CUfunction();
        cuModuleGetFunction(stringPacketKernel, module, "stringPacketKernel");
    }

    public static long processMultiplePointersCountPackets(List<String> packetList)
    {
        int numPackets = packetList.size();

        // Allocate and fill arrays on the device:
        // - One one for each input word, which is filled
        //   with the byte data for the respective word

        long time0 = System.nanoTime();

        System.out.println("[CUDA] ALLOCATING AND COPYING");

        CUdeviceptr dPacketInputPointers[] = new CUdeviceptr[numPackets];
        int packetLengths[] = new int[numPackets];
        for(int i = 0; i < numPackets; i++)
        {
            String packet = packetList.get(i);
            byte hostPacketData[] = packet.getBytes();
            packetLengths[i] = hostPacketData.length;

            dPacketInputPointers[i] = new CUdeviceptr();
            cuMemAlloc(dPacketInputPointers[i], packetLengths[i] * Sizeof.BYTE);
            cuMemcpyHtoD(dPacketInputPointers[i],
                    Pointer.to(hostPacketData), packetLengths[i] * Sizeof.BYTE);
        }

        // Allocate device memory for the array of pointers
        // that point to the individual input words, and copy
        // the input word pointers from the host to the device.
        CUdeviceptr dPacketInputPointersArray = new CUdeviceptr();
        cuMemAlloc(dPacketInputPointersArray, numPackets * Sizeof.POINTER);
        cuMemcpyHtoD(dPacketInputPointersArray,
                Pointer.to(dPacketInputPointers),
                numPackets * Sizeof.POINTER);

        // Allocate and fill the device array for the word lengths
        CUdeviceptr dPacketLengths = new CUdeviceptr();
        cuMemAlloc(dPacketLengths, numPackets * Sizeof.INT);
        cuMemcpyHtoD(dPacketLengths, Pointer.to(packetLengths),
                numPackets * Sizeof.INT);

        CUdeviceptr dNumHTTPPackets = new CUdeviceptr();
        cuMemAlloc(dNumHTTPPackets, numPackets * Sizeof.BYTE);

        // Set up the kernel parameters
        Pointer kernelParams = Pointer.to(
                Pointer.to(new int[]{numPackets}),
                Pointer.to(dPacketInputPointersArray),
                Pointer.to(dPacketLengths),
                Pointer.to(dNumHTTPPackets)
        );

        long time1 = System.nanoTime();

        System.out.printf("[CUDA] %5.3fms%n", (time1-time0) / 1e6);

        System.out.println("[CUDA] COMPUTING");

        // Call the kernel function.
        int blockDimX = 256;
        int gridDimX = (int)Math.ceil((double)numPackets/blockDimX);

        time0 = System.nanoTime();
        cuLaunchKernel(stringPacketKernel,
                gridDimX, 1, 1,    // Grid dimension
                blockDimX, 1, 1,   // Block dimension
                0, null,           // Shared memory size and stream
                kernelParams, null // Kernel- and extra parameters
        );
        cuCtxSynchronize();
        time1 = System.nanoTime();
        System.out.printf("[CUDA] %5.3fms%n", (time1-time0) / 1e6);

        byte[] numHTTPPackets = new byte[numPackets];

        System.out.println("[CUDA] GATHERING RESULTS");

        cuMemcpyDtoH(Pointer.to(numHTTPPackets), dNumHTTPPackets, numPackets
                * Sizeof.BYTE);

        long sum = 0;

        // Clean up.
        for(int i = 0; i < numPackets; i++)
        {
            cuMemFree(dPacketInputPointers[i]);
            if(numHTTPPackets[i]>0)
                sum++;
        }
        cuMemFree(dPacketInputPointersArray);
        cuMemFree(dNumHTTPPackets);
        cuMemFree(dPacketLengths);

        System.out.println("[CUDA] ALL DONE");

        return sum;
    }
}

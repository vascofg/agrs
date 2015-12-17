package org.agrs.jcuda;

import jcuda.Pointer;
import jcuda.Sizeof;
import jcuda.driver.*;

import java.io.IOException;

import static jcuda.driver.JCudaDriver.*;

public class CudaAnalyzer {

    private static CUfunction bytePacketKernel;

    private static CUdeviceptr dNumRepeats;
    private static CUdeviceptr dPacketInputPointer;
    private static CUdeviceptr dPacketIndices;
    private static CUdeviceptr dNumHTTPPackets;

    private static long totalComputeTime;
    private static long totalAllocTime;

    public static void init() throws IOException {
        System.out.println("[CUDA] INITIALIZING");

        totalComputeTime = 0;
        totalAllocTime = 0;

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
        cuModuleLoad(module, "./target/kernels/JCudaPacketKernel.ptx");

        bytePacketKernel = new CUfunction();
        cuModuleGetFunction(bytePacketKernel, module, "bytePacketKernel");

        dNumRepeats = new CUdeviceptr();
        dPacketInputPointer = new CUdeviceptr();
        dPacketIndices = new CUdeviceptr();
        dNumHTTPPackets = new CUdeviceptr();

        cuModuleGetGlobal(dNumRepeats, new long[1], module,
                "numRepeats");

        cuMemAlloc(dPacketInputPointer, Analyze.ABSOLUTE_MAXLEN * Sizeof.BYTE);
        cuMemAlloc(dPacketIndices, Analyze.ABSOLUTE_MAXLEN * Sizeof.INT);
        cuMemAlloc(dNumHTTPPackets, Analyze.ABSOLUTE_MAXLEN * Sizeof.BYTE);

        cuMemcpyHtoD(dNumRepeats, Pointer.to(new int[]{Analyze.NUM_REPEATS}), Sizeof.INT);
    }

    public static long processSinglePointer(byte[] packets, int[] indices, int numPackets) {
        long time0 = System.nanoTime();

        System.out.print("[CUDA] ALLOCATING AND COPYING... ");


        cuMemcpyHtoD(dPacketInputPointer,
                Pointer.to(packets),
                packets.length * Sizeof.BYTE);

        cuMemcpyHtoD(dPacketIndices, Pointer.to(indices),
                indices.length * Sizeof.INT);

        // Set up the kernel parameters
        Pointer kernelParams = Pointer.to(
                Pointer.to(new int[]{numPackets}),
                Pointer.to(dPacketInputPointer),
                Pointer.to(dPacketIndices),
                Pointer.to(dNumHTTPPackets)
        );

        long time1 = System.nanoTime();

        totalAllocTime += (time1 - time0);
        System.out.printf("%5.3fms%n", (time1 - time0) / 1e6);

        System.out.print("[CUDA] COMPUTING... ");

        // Call the kernel function.
        int blockDimX = 256;
        int gridDimX = (int) Math.ceil((double) numPackets / blockDimX);

        time0 = System.nanoTime();
        cuLaunchKernel(bytePacketKernel,
                gridDimX, 1, 1,    // Grid dimension
                blockDimX, 1, 1,   // Block dimension
                0, null,           // Shared memory size and stream
                kernelParams, null // Kernel- and extra parameters
        );
        cuCtxSynchronize();
        time1 = System.nanoTime();
        totalComputeTime += (time1 - time0);
        System.out.printf("%5.3fms%n", (time1 - time0) / 1e6);

        byte[] numHTTPPackets = new byte[numPackets];

        System.out.print("[CUDA] GATHERING RESULTS... ");

        time0 = System.nanoTime();
        cuMemcpyDtoH(Pointer.to(numHTTPPackets), dNumHTTPPackets, numPackets
                * Sizeof.BYTE);
        time1 = System.nanoTime();
        System.out.printf("%5.3fms%n", (time1 - time0) / 1e6);

        long sum = 0;

        for (int i = 0; i < numPackets; i++) {
            if (numHTTPPackets[i] > 0)
                sum++;
        }

        return sum;
    }

    public static void close() {
        System.out.println("[CUDA] CLOSING");

        cuMemFree(dPacketInputPointer);
        cuMemFree(dNumHTTPPackets);
        cuMemFree(dPacketIndices);

        System.out.printf("[CUDA] TOTAL ALLOCATION TIME: %5.3fms%n", totalAllocTime / 1e6);
        System.out.printf("[CUDA] TOTAL COMPUTE TIME: %5.3fms%n", totalComputeTime / 1e6);
    }
}

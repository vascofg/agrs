/*
 * JCuda - Java bindings for NVIDIA CUDA driver and runtime API
 * http://www.jcuda.org
 *
 * Copyright 2011 Marco Hutter - http://www.jcuda.org
 */

package org.mystic.cuda.samples;

import static jcuda.driver.JCudaDriver.*;

import java.io.*;

import jcuda.*;
import jcuda.driver.*;

/**
 * This is a sample class demonstrating how to use the JCuda driver
 * bindings to load and execute a CUDA vector addition kernel.
 * The sample reads a CUDA file, compiles it to a PTX file
 * using NVCC, loads the PTX file as a module and executes
 * the kernel function. <br />
 */
public class JCudaVectorAdd
{
    /**
     * Entry point of this sample
     *
     * @param args Not used
     * @throws IOException If an IO error occurs
     */

    public static void main(String args[]) throws IOException
    {
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
        cuModuleLoad(module, "./target/kernels/JCudaVectorAddKernel.ptx");

        // Obtain a function pointer to the "add" function.
        CUfunction function = new CUfunction();
        cuModuleGetFunction(function, module, "add");

        int numElements = 10000000;

        // Allocate and fill the host input data
        float hostInputA[] = new float[numElements];
        float hostInputB[] = new float[numElements];
        for(int i = 0; i < numElements; i++)
        {
            hostInputA[i] = (float)i;
            hostInputB[i] = (float)i;
        }

        System.out.printf("[Vector addition of %d elements]%n", numElements);

        // Allocate the device input data, and copy the
        // host input data to the device
        System.out.println("Copy input data from the host memory to the CUDA device");
        CUdeviceptr deviceInputA = new CUdeviceptr();
        cuMemAlloc(deviceInputA, numElements * Sizeof.FLOAT);
        cuMemcpyHtoD(deviceInputA, Pointer.to(hostInputA),
            numElements * Sizeof.FLOAT);
        CUdeviceptr deviceInputB = new CUdeviceptr();
        cuMemAlloc(deviceInputB, numElements * Sizeof.FLOAT);
        cuMemcpyHtoD(deviceInputB, Pointer.to(hostInputB),
            numElements * Sizeof.FLOAT);

        // Allocate device output memory
        CUdeviceptr deviceOutput = new CUdeviceptr();
        cuMemAlloc(deviceOutput, numElements * Sizeof.FLOAT);

        // Set up the kernel parameters: A pointer to an array
        // of pointers which point to the actual values.
        Pointer kernelParameters = Pointer.to(
            Pointer.to(new int[]{numElements}),
            Pointer.to(deviceInputA),
            Pointer.to(deviceInputB),
            Pointer.to(deviceOutput)
        );

        // Launch the Vector Add CUDA Kernel
        int threadsPerBlock = 256;
        int blocksPerGrid = (numElements + threadsPerBlock - 1) / threadsPerBlock;

        System.out.printf("CUDA kernel launch with %d blocks of %d threads%n",blocksPerGrid, threadsPerBlock);

        long time0 = System.nanoTime();
        cuLaunchKernel(function,
            blocksPerGrid,  1, 1,      // Grid dimension
            threadsPerBlock, 1, 1,      // Block dimension
            0, null,               // Shared memory size and stream
            kernelParameters, null // Kernel- and extra parameters
        );
        cuCtxSynchronize();

        long time1 = System.nanoTime();
        System.out.printf("%5.3fms%n", (time1-time0) / 1e6);
        // Allocate host output memory and copy the device output
        // to the host.
        System.out.println("Copy output data from the CUDA device to the host memory");
        float hostOutput[] = new float[numElements];
        cuMemcpyDtoH(Pointer.to(hostOutput), deviceOutput,
            numElements * Sizeof.FLOAT);

        // Verify the result
        System.out.println("Verifying the result on CPU");
        time0 = System.nanoTime();
        boolean passed = true;
        for(int i = 0; i < numElements; i++)
        {
            float expected = i+i;
            if (Math.abs(hostOutput[i] - expected) > 1e-5)
            {
                System.out.println(
                    "At index "+i+ " found "+hostOutput[i]+
                    " but expected "+expected);
                passed = false;
                break;
            }
        }
        time1 = System.nanoTime();
        System.out.printf("%5.3fms%n", (time1-time0) / 1e6);
        System.out.println("Test "+(passed?"PASSED":"FAILED"));

        // Clean up.
        cuMemFree(deviceInputA);
        cuMemFree(deviceInputB);
        cuMemFree(deviceOutput);
    }

    /**
     * Fully reads the given InputStream and returns it as a byte array
     *
     * @param inputStream The input stream to read
     * @return The byte array containing the data from the input stream
     * @throws IOException If an I/O error occurs
     */
    private static byte[] toByteArray(InputStream inputStream)
        throws IOException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte buffer[] = new byte[8192];
        while (true)
        {
            int read = inputStream.read(buffer);
            if (read == -1)
            {
                break;
            }
            baos.write(buffer, 0, read);
        }
        return baos.toByteArray();
    }


}

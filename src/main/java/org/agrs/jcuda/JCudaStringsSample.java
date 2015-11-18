package org.agrs.jcuda;
 
import static jcuda.driver.JCudaDriver.*;
 
import java.io.*;
import java.util.*;
 
import jcuda.*;
import jcuda.driver.*;
 
/**
 * A sample demonstrating two different ways of passing strings
 * to a kernel:
 * - As an array of pointers, where each pointer points to
 *   a single word
 * - As a single data block, where all words are concatenated
 *   and the word boundaries are given explicitly
 */
public class JCudaStringsSample
{
    /**
     * The kernel function using multiple pointers
     * (i.e. an array of pointers)
     */
    private static CUfunction multiplePointersKernel = null;
   
    /**
     * The kernel function using a single pointer to
     * a memory block containing the concatenated words
     */
    private static CUfunction singlePointerKernel = null;

    private static CUfunction multiplePointersSumLetterKernel = null;
   
    /**
     * Entry point of this sample
     *
     * @param args Not used
     * @throws IOException If an IO error occurs
     */
    public static void main(String args[]) throws IOException
    {
        // Perform the CUDA initialization
        init();
 
        // Fill a list with dummy words
        List<String> wordList = new ArrayList<String>();
        /*int numWords = 100;
        for (int i=0; i<numWords; i++)
        {
            wordList.add("string"+i);
        }
       
        // Process the word list in several ways
        List<String> result0 = processMultiplePointers(wordList);
        List<String> result1 = processSinglePointer(wordList);
        List<String> resultRef = processHost(wordList);
 
        // Verify the result
        boolean passed = true;
        for (int i=0; i<wordList.size(); i++)
        {
            String word = wordList.get(i);
            String word0 = result0.get(i);
            String word1 = result1.get(i);
            String wordRef = resultRef.get(i);
            passed &= word0.equals(wordRef);
            passed &= word1.equals(wordRef);
            if (i < 10)
            {
                System.out.printf(
                    "Input: %-10s Reference: %-10s Multi: %-10s Single: %-10s\n",
                    word, wordRef, word0, word1);
            }
        }
        System.out.println("Test "+(passed ? "PASSED" : "FAILED"));*/
        wordList.add("LOCURAS");
        wordList.add("ADRENALINA");
        int[] numLetters = processMultiplePointersSumLetters(wordList);

        for(int n : numLetters) {
            System.out.println(n);
        }
    }
   
    /**
     * Host implementation of what is done in the kernel: It will
     * only add 1 to the ASCII code of each character, and return
     * the resulting strings
     *
     * @param wordList The word list
     * @return The new word list
     */
    private static List<String> processHost(List<String> wordList)
    {
        List<String> result = new ArrayList<String>();
        for (String word : wordList)
        {
            byte hostWordData[] = word.getBytes();
            for (int i=0; i<hostWordData.length; i++)
            {
                hostWordData[i] += 1;
            }
            String resultWord = new String(hostWordData);
            result.add(resultWord);
        }
        return result;
    }
   
    /**
     * Process the word list by creating one pointer for each word,
     * and passing these to the kernel as an array of pointers.
     *
     * @param wordList The word list
     * @return The new word list
     */
    private static List<String> processMultiplePointers(List<String> wordList)
    {
        int numWords = wordList.size();
       
        // Allocate and fill arrays on the device:
        // - One one for each input word, which is filled
        //   with the byte data for the respective word
        // - One for each output word
        CUdeviceptr dWordInputPointers[] = new CUdeviceptr[numWords];
        CUdeviceptr dWordOutputPointers[] = new CUdeviceptr[numWords];
        int wordLengths[] = new int[numWords];
        for(int i = 0; i < numWords; i++)
        {
            String word = wordList.get(i);
            byte hostWordData[] = word.getBytes();
            wordLengths[i] = hostWordData.length;
           
            dWordInputPointers[i] = new CUdeviceptr();
            cuMemAlloc(dWordInputPointers[i], wordLengths[i] * Sizeof.BYTE);
            cuMemcpyHtoD(dWordInputPointers[i],
                Pointer.to(hostWordData), wordLengths[i] * Sizeof.BYTE);
           
            dWordOutputPointers[i] = new CUdeviceptr();
            cuMemAlloc(dWordOutputPointers[i], wordLengths[i] * Sizeof.BYTE);
        }
       
        // Allocate device memory for the array of pointers
        // that point to the individual input words, and copy
        // the input word pointers from the host to the device.
        CUdeviceptr dWordInputPointersArray = new CUdeviceptr();
        cuMemAlloc(dWordInputPointersArray, numWords * Sizeof.POINTER);
        cuMemcpyHtoD(dWordInputPointersArray,
            Pointer.to(dWordInputPointers),
            numWords * Sizeof.POINTER);
       
        // Allocate device memory for the array of pointers
        // that point to the individual output words, and copy
        // the output word pointers from the host to the device.
        CUdeviceptr dWordOutputPointersArray = new CUdeviceptr();
        cuMemAlloc(dWordOutputPointersArray, numWords * Sizeof.POINTER);
        cuMemcpyHtoD(dWordOutputPointersArray,
            Pointer.to(dWordOutputPointers),
            numWords * Sizeof.POINTER);
       
        // Allocate and fill the device array for the word lengths
        CUdeviceptr dWordLengths = new CUdeviceptr();
        cuMemAlloc(dWordLengths, numWords * Sizeof.INT);
        cuMemcpyHtoD(dWordLengths, Pointer.to(wordLengths),
            numWords * Sizeof.INT);
       
        // Set up the kernel parameters
        Pointer kernelParams = Pointer.to(
            Pointer.to(new int[]{numWords}),
            Pointer.to(dWordInputPointersArray),
            Pointer.to(dWordLengths),
            Pointer.to(dWordOutputPointersArray)
        );
       
        // Call the kernel function.
        int blockDimX = 256;
        int gridDimX = (int)Math.ceil((double)numWords/blockDimX);
        cuLaunchKernel(multiplePointersKernel,
            gridDimX, 1, 1,    // Grid dimension
            blockDimX, 1, 1,   // Block dimension
            0, null,           // Shared memory size and stream
            kernelParams, null // Kernel- and extra parameters
        );
        cuCtxSynchronize();
 
        // Copy the contents of each output pointer of the
        // device back into a host array, create a string
        // from each array and store it in the result list
        List<String> result = new ArrayList<String>();
        for(int i = 0; i < numWords; i++)
        {
            byte hostWordData[] = new byte[wordLengths[i]];
            cuMemcpyDtoH(Pointer.to(hostWordData), dWordOutputPointers[i],
                wordLengths[i] * Sizeof.BYTE);
            String word = new String(hostWordData);
            result.add(word);
        }
 
        // Clean up.
        for(int i = 0; i < numWords; i++)
        {
            cuMemFree(dWordInputPointers[i]);
            cuMemFree(dWordOutputPointers[i]);
        }
        cuMemFree(dWordInputPointersArray);
        cuMemFree(dWordOutputPointersArray);
        cuMemFree(dWordLengths);
       
        return result;
    }

    private static int[] processMultiplePointersSumLetters(List<String> wordList)
    {
        int numWords = wordList.size();

        // Allocate and fill arrays on the device:
        // - One one for each input word, which is filled
        //   with the byte data for the respective word
        CUdeviceptr dWordInputPointers[] = new CUdeviceptr[numWords];
        int wordLengths[] = new int[numWords];
        for(int i = 0; i < numWords; i++)
        {
            String word = wordList.get(i);
            byte hostWordData[] = word.getBytes();
            wordLengths[i] = hostWordData.length;

            dWordInputPointers[i] = new CUdeviceptr();
            cuMemAlloc(dWordInputPointers[i], wordLengths[i] * Sizeof.BYTE);
            cuMemcpyHtoD(dWordInputPointers[i],
                    Pointer.to(hostWordData), wordLengths[i] * Sizeof.BYTE);
        }

        // Allocate device memory for the array of pointers
        // that point to the individual input words, and copy
        // the input word pointers from the host to the device.
        CUdeviceptr dWordInputPointersArray = new CUdeviceptr();
        cuMemAlloc(dWordInputPointersArray, numWords * Sizeof.POINTER);
        cuMemcpyHtoD(dWordInputPointersArray,
                Pointer.to(dWordInputPointers),
                numWords * Sizeof.POINTER);

        // Allocate and fill the device array for the word lengths
        CUdeviceptr dWordLengths = new CUdeviceptr();
        cuMemAlloc(dWordLengths, numWords * Sizeof.INT);
        cuMemcpyHtoD(dWordLengths, Pointer.to(wordLengths),
                numWords * Sizeof.INT);

        CUdeviceptr dNumLetters = new CUdeviceptr();
        cuMemAlloc(dNumLetters, numWords * Sizeof.INT);

        // Set up the kernel parameters
        Pointer kernelParams = Pointer.to(
                Pointer.to(new int[]{numWords}),
                Pointer.to(dWordInputPointersArray),
                Pointer.to(dWordLengths),
                Pointer.to(dNumLetters)
        );

        // Call the kernel function.
        int blockDimX = 256;
        int gridDimX = (int)Math.ceil((double)numWords/blockDimX);
        cuLaunchKernel(multiplePointersSumLetterKernel,
                gridDimX, 1, 1,    // Grid dimension
                blockDimX, 1, 1,   // Block dimension
                0, null,           // Shared memory size and stream
                kernelParams, null // Kernel- and extra parameters
        );
        cuCtxSynchronize();

        int[] numLetters = new int[numWords];

        cuMemcpyDtoH(Pointer.to(numLetters), dNumLetters,
                numWords * Sizeof.INT);

        // Clean up.
        for(int i = 0; i < numWords; i++)
        {
            cuMemFree(dWordInputPointers[i]);
        }
        cuMemFree(dWordInputPointersArray);
        cuMemFree(dNumLetters);
        cuMemFree(dWordLengths);

        return numLetters;
    }
   
    /**
     * Process the word list by creating one large memory block
     * that contains all words, and pass this to the kernel
     * together with additional information about the word
     * boundaries
     *
     * @param wordList The word list
     * @return The new word list
     */
    private static List<String> processSinglePointer(List<String> wordList)
    {
        int numWords = wordList.size();
 
        // Compute the word lengths and the index
        // that the end of each word will have
        // in a large, combined array
        int wordLengths[] = new int[numWords];
        int wordEndIndices[] = new int[numWords];
        int offset = 0;
        for(int i = 0; i < numWords; i++)
        {
            String word = wordList.get(i);
            wordLengths[i] = word.length();
            offset += word.length();
            wordEndIndices[i] = offset;
        }
        int totalLength = offset;
       
       
        // Allocate and fill the device array for the word lengths
        CUdeviceptr dWordLengths = new CUdeviceptr();
        cuMemAlloc(dWordLengths, numWords * Sizeof.INT);
        cuMemcpyHtoD(dWordLengths, Pointer.to(wordLengths),
            numWords * Sizeof.INT);
       
        // Allocate and fill the device array for the word end indices
        CUdeviceptr dWordEndIndices = new CUdeviceptr();
        cuMemAlloc(dWordEndIndices, numWords * Sizeof.INT);
        cuMemcpyHtoD(dWordEndIndices, Pointer.to(wordEndIndices),
            numWords * Sizeof.INT);
       
        // Allocate and fill the device memory for the actual
        // input- and output word data
        CUdeviceptr dInputWords = new CUdeviceptr();
        cuMemAlloc(dInputWords, totalLength * Sizeof.BYTE);
        offset = 0;
        for(int i = 0; i < numWords; i++)
        {
            String word = wordList.get(i);
            byte hostWordData[] = word.getBytes();
            CUdeviceptr d = dInputWords.withByteOffset(offset * Sizeof.BYTE);
            cuMemcpyHtoD(d, Pointer.to(hostWordData),
                wordLengths[i] * Sizeof.BYTE);
            offset += wordLengths[i];
        }
        CUdeviceptr dOutputWords = new CUdeviceptr();
        cuMemAlloc(dOutputWords, totalLength * Sizeof.BYTE);
 
        // Set up the kernel parameters
        Pointer kernelParams = Pointer.to(
            Pointer.to(new int[]{numWords}),
            Pointer.to(dInputWords),
            Pointer.to(dWordEndIndices),
            Pointer.to(dWordLengths),
            Pointer.to(dOutputWords)
        );
       
        // Call the kernel function.
        int blockDimX = 256;
        int gridDimX = (int)Math.ceil((double)numWords/blockDimX);
        cuLaunchKernel(singlePointerKernel,
            gridDimX, 1, 1,    // Grid dimension
            blockDimX, 1, 1,   // Block dimension
            0, null,           // Shared memory size and stream
            kernelParams, null // Kernel- and extra parameters
        );
        cuCtxSynchronize();
 
        // Copy the each word from the output device pointer
        // device back into a host array, create a string  
        // from each array, and put it into the result list
        List<String> result = new ArrayList<String>();
        offset = 0;
        for(int i = 0; i < numWords; i++)
        {
            byte wordHostData[] = new byte[wordLengths[i]];
            CUdeviceptr d = dOutputWords.withByteOffset(offset * Sizeof.BYTE);
            cuMemcpyDtoH(Pointer.to(wordHostData), d,
                wordLengths[i] * Sizeof.BYTE);
            String word = new String(wordHostData);
            result.add(word);
            offset += wordLengths[i];
        }
 
        // Clean up.
        cuMemFree(dInputWords);
        cuMemFree(dOutputWords);
        cuMemFree(dWordLengths);
        cuMemFree(dWordEndIndices);
       
        return result;
    }
   
   
    private static void init() throws IOException
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
        cuModuleLoad(module, "./target/kernels/JCudaStringsSampleKernel.ptx");
 
        // Obtain function pointers to the kernel functions.
        multiplePointersKernel = new CUfunction();
        cuModuleGetFunction(multiplePointersKernel, module, "multiplePointers");
 
        singlePointerKernel = new CUfunction();
        cuModuleGetFunction(singlePointerKernel, module, "singlePointer");

        multiplePointersSumLetterKernel = new CUfunction();
        cuModuleGetFunction(multiplePointersSumLetterKernel, module, "multiplePointersSumLetter");
    }
}
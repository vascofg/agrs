extern "C"
__global__ void multiplePointers(
    int numWords,
    char** inputWords,
    int* wordLengths,
    char** outputWords)
{
    const unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid < numWords)
    {
        char *inputWord = inputWords[tid];
        char *outputWord = outputWords[tid];
        int wordLength = wordLengths[tid];
        for (int i=0; i<wordLength; i++)
        {
            // Dummy: Just copy input to output and add 1 to
            // the ASCII code of each character
            outputWord[i] = inputWord[i] + 1;
        }
    }
}

extern "C"
__global__ void multiplePointersSumLetter(
    int numWords,
    char** inputWords,
    int* wordLengths,
    int* numLetters)
{
    const unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid < numWords)
    {
        char *inputWord = inputWords[tid];
        int wordLength = wordLengths[tid];
        numLetters[tid]=0;
        for (int i=0; i<wordLength; i++)
        {
            if(inputWord[i]=='A')
                numLetters[tid]++;
        }
    }
}

extern "C"
__global__ void singlePointer(
    int numWords,
    char* inputWords,
    int* wordEndIndices,
    int* wordLengths,
    char* outputWords)
{
    const unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid < numWords)
    {
        int offset = 0;
        if (tid > 0)
        {
            offset = wordEndIndices[tid-1];
        }
        char *inputWord = inputWords + offset;
        char *outputWord = outputWords + offset;
        int wordLength = wordLengths[tid];
        for (int i=0; i<wordLength; i++)
        {
            // Dummy: Just copy input to output and add 1 to
            // the ASCII code of each character
            outputWord[i] = inputWord[i] + 1;
        }
    }
}
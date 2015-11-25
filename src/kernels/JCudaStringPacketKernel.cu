extern "C"
__global__ void stringPacketKernel(
    int numPackets,
    char** inputPackets,
    int* packetLengths,
    char* numHTTPPackets)
{
    const unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid < numPackets)
    {
        char *inputPacket = inputPackets[tid];
        int packetLength = packetLengths[tid];
        numHTTPPackets[tid]=0;
        int state = 0;
        for (int i=0; i<packetLength; i++)
        {
            switch (state) {
                case 0:
                    if (inputPacket[i] == 'G' && inputPacket[i + 1] == 'E' &&
                            inputPacket[i + 2] == 'T' && inputPacket[i + 3] == ' ') {
                        state++;
                        i+=3;
                    }
                    break;
                case 1:
                    if (inputPacket[i] == ' ')
                        state++;
                    break;
                case 2:
                    if (inputPacket[i] == 'H' && inputPacket[i + 1] == 'T' &&
                            inputPacket[i + 2] == 'T' && inputPacket[i + 3] == 'P' &&
                            inputPacket[i + 4] == '/' && inputPacket[i + 6] == '.')
                        numHTTPPackets[tid]=1;
                    i=packetLength; //EXIT LOOP
                    break;
            }
        }
    }
}
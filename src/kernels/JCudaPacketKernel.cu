extern "C"
__global__ void bytePacketKernel(
    int numPackets,
    char* inputPackets,
    int* packetIndices,
    char* numHTTPPackets)
{
    const unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid < numPackets)
    {
        int packetStart = packetIndices[tid];
        int nextPacket = packetIndices[tid+1];
        numHTTPPackets[tid]=0;
        int state = 0;
        for (int i=packetStart; i<nextPacket; i++)
        {
            switch (state) {
                case 0:
                    if (inputPackets[i] == 'G' && inputPackets[i + 1] == 'E' &&
                            inputPackets[i + 2] == 'T' && inputPackets[i + 3] == ' ') {
                        state++;
                        i+=3;
                    }
                    break;
                case 1:
                    if (inputPackets[i] == ' ')
                        state++;
                    break;
                case 2:
                    if (inputPackets[i] == 'H' && inputPackets[i + 1] == 'T' &&
                            inputPackets[i + 2] == 'T' && inputPackets[i + 3] == 'P' &&
                            inputPackets[i + 4] == '/' && inputPackets[i + 6] == '.')
                        numHTTPPackets[tid]=1;
                    i=nextPacket; //EXIT LOOP
                    break;
            }
        }
    }
}
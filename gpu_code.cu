 #include <cuda_runtime.h>

#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include <map>

#include "petya.h"

#define SHL(x, s) ((uint32_t) ((x) << ((s) & 31)))
#define SHR(x, s) ((uint32_t) ((x) >> (32 - ((s) & 31))))
#define ROTL(x, s) ((uint32_t) (SHL((x), (s)) | SHR((x), (s))))

#define NR_THREADS 1024
#define NR_BLOCKS 1

#define NR_KEYS (long)(NR_THREADS*NR_BLOCKS)

using namespace std;


// -- 16 Byte Key funtions...

void calculate16ByteKeyFromIndex(unsigned long index, char*key) {
	// cc??cc??cc??cc??
	
	char keyChars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	// char key[17];
	
	memset(key, 'x', 16);
	  
	int posToKey[] = {13,12,9,8,5,4,1,0};
	  
	for (int i=0; i<8; i++) {
		int characterNumber = index % (26*2+10);
		key[posToKey[i]] = keyChars[characterNumber];					
		index /= (26*2+10);
	}
		
	// key[16] = 0;
	
	//char * result = (char *)malloc(17);
	//printf("Key calculated from index is: %s\r\n", &key[0]);
	// memcpy(result, key, 17);
	//return result;
} 

void nextKey16Byte(char *key) {
	char keyChars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	map<char, int> keyToIndexMap;
	
	
	for (int i=0; i<sizeof(keyChars); i++) {
		keyToIndexMap[keyChars[i]]=i;
	}		
	
	int posToKey[] = {13,12,9,8,5,4,1,0};
	
	for (int i=0; i<8; i++) {
		int idx = keyToIndexMap[key[posToKey[i]]];		
		idx++;
		idx %=sizeof(keyChars);
		key[posToKey[i]] = keyChars[idx];
		
		if (idx!=0) break;
	}
	
	printf("Next key of is %s\r\n",key);
}


__global__ void gpu_crypt_and_validate(uint8_t *keys,
                           
                            uint8_t nonce[8],
                            uint32_t si,
                            uint8_t *buf,
                            uint32_t buflen,
                            bool *isValid,
							int nrTotal,
							unsigned long nrKeysToCalculatePerThread)
{
  // This is initialized here to save time to calculate next key later, todo: Calculate outside and provide with parameters...
  char keyChars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    
  int keyToIndexMap[256];
  for (int i=0; i<sizeof(keyChars);i++) {
	  for (int j=0; j<256;j++) {
		  if (keyChars[i]==(char)j) {
			  keyToIndexMap[(char)j]=i;
		  }
	  }
  }

  int threadNr = blockDim.x * blockIdx.x + threadIdx.x;

  if (threadNr>=nrTotal) return;

  uint8_t *key = keys + (threadNr*(KEY_SIZE));   
  
  while (nrKeysToCalculatePerThread>0) {
	  (isValid)[threadNr] = false;

	  uint8_t keystream[64];
	  uint8_t n[16] = { 0 };
	  uint32_t i;

	  for (i = 0; i < 8; ++i)
		n[i] = nonce[i];

	  if (si % 64 != 0) {
		// s20_rev_littleendian(n+8, si / 64);
		(n+8)[0] = (si / 64);
		(n+8)[1] = (si / 64)>>8;
		(n+8)[2] = (si / 64)>>16;
		(n+8)[3] = (si / 64)>>24;

		// --------------------------------
		// s20_expand16(key, n, keystream);
		// --------------------------------

		  int i, j;
	  uint8_t t[4][4] = {
		{ 'e', 'x', 'p', 'a' },
		{ 'n', 'd', ' ', '1' },
		{ '6', '-', 'b', 'y' },
		{ 't', 'e', ' ', 'k' }
	  };

	  for (i = 0; i < 64; i += 20)
		for (j = 0; j < 4; ++j)
		  keystream[i + j] = t[i / 20][j];
	
	  for (i = 0; i < 16; ++i) {
		keystream[4+i]  = key[i];
		keystream[44+i] = key[i];
		keystream[24+i] = n[i];
	  }

	  // ____________________
	  // s20_hash(keystream);
	  // --------------------

	//    int i;
	  uint32_t x[16];
	  uint32_t z[16];
	
	  for (i = 0; i < 16; ++i) {

		// s20_littleendian
		uint8_t* result = keystream + (4 * i);
		x[i] = z[i] = (int16_t)(result[0]+(result[1]<<8)); //  s20_littleendian(seq + (4 * i));
	  }
	
	  for (i = 0; i < 10; ++i) {
	//    s20_doubleround(z);

	  // ColumnRound
	  // s20_quarterround(&x[0], &x[4], &x[8], &x[12]);

	  z[4] =  z[4]  ^ ROTL(z[0]  + z[12], 7);
	  z[8] =  z[8]  ^ ROTL(z[4]  + z[0], 9);
	  z[12] = z[12] ^ ROTL(z[8]  + z[4], 13);
	  z[0] =  z[0]  ^ ROTL(z[12] + z[8], 18);

	  // s20_quarterround(&x[5], &x[9], &x[13], &x[1]);
	  z[9] =  z[9]  ^ ROTL(z[5]  + z[1], 7);
	  z[13] = z[13] ^ ROTL(z[9]  + z[5], 9);
	  z[1] =  z[1]  ^ ROTL(z[13] + z[9], 13);
	  z[5] =  z[5]  ^ ROTL(z[1]  + z[13], 18);

	  // s20_quarterround(&x[10], &x[14], &x[2], &x[6]);
	  z[14]=  z[14] ^ ROTL(z[10] + z[6], 7);
	  z[2] =  z[2]  ^ ROTL(z[14] + z[10], 9);
	  z[6] =  z[6]  ^ ROTL(z[2]  + z[14], 13);
	  z[10] = z[10] ^ ROTL(z[6]  + z[2], 18);

	  // s20_quarterround(&x[15], &x[3], &x[7], &x[11]);
	  z[3] =  z[3]  ^ ROTL(z[15] + z[11], 7);
	  z[7] =  z[7]  ^ ROTL(z[3]  + z[15], 9);
	  z[11] = z[11] ^ ROTL(z[7]  + z[3], 13);
	  z[15] = z[15] ^ ROTL(z[11] + z[7], 18);

	  // Rowround
	  // s20_quarterround(&y[0], &y[1], &y[2], &y[3]);
	  z[1] = z[1] ^ ROTL(z[0]+  z[3], 7);
	  z[2] = z[2] ^ ROTL(z[1] + z[0], 9);
	  z[3] = z[3] ^ ROTL(z[2] + z[1], 13);
	  z[0] = z[0] ^ ROTL(z[3] + z[2], 18);

	  // s20_quarterround(&y[5], &y[6], &y[7], &y[4]);
	  z[6] = z[6] ^ ROTL(z[5] + z[4], 7);
	  z[7] = z[7] ^ ROTL(z[6] + z[5], 9);
	  z[4] = z[4] ^ ROTL(z[7] + z[6], 13);
	  z[5] = z[5] ^ ROTL(z[4] + z[7], 18);

	  // s20_quarterround(&y[10], &y[11], &y[8], &y[9]);
	  z[11] = z[11] ^ ROTL(z[10] + z[9], 7);
	  z[8] =  z[8]  ^ ROTL(z[11] + z[10], 9);
	  z[9] =  z[9]  ^ ROTL(z[8] +  z[11], 13);
	  z[10] = z[10] ^ ROTL(z[9] +  z[8], 18);
	  
	  // s20_quarterround(&y[15], &y[12], &y[12], &y[14]);
	  z[12] = z[12] ^ ROTL(z[15] + z[14], 7);
	  z[12] = z[12] ^ ROTL(z[12] + z[15], 9);
	  z[14] = z[14] ^ ROTL(z[12] + z[12], 13);
	  z[15] = z[15] ^ ROTL(z[14] + z[12], 18);
	  }
	
	  for (i = 0; i < 16; ++i) {
		z[i] += x[i];
		// s20_rev_littleendian(seq + (4 * i), z[i]);
		  (keystream + (4 * i))[0] = z[i];
		  (keystream + (4 * i))[1] = z[i] >> 8;
		  (keystream + (4 * i))[2] = z[i] >> 16;
		  (keystream + (4 * i))[3] = z[i] >> 24;
	  }
	  


	  }

	  for (int bufPos = 0; bufPos < buflen; ++bufPos) {
		if ((si + bufPos) % 64 == 0) {
		  //s20_rev_littleendian(n+8, ((si + i) / 64));
		  (n+8)[0] = ((si + bufPos) / 64);
		  (n+8)[1] = ((si + bufPos) / 64)>>8;
		  (n+8)[2] = ((si + bufPos) / 64)>>16;
		  (n+8)[3] = ((si + bufPos) / 64)>>24;

		  // s20_expand16(key, n, keystream);

		  int i, j;
		  uint8_t t[4][4] = {
			{ 'e', 'x', 'p', 'a' },
			{ 'n', 'd', ' ', '1' },
			{ '6', '-', 'b', 'y' },
			{ 't', 'e', ' ', 'k' }
		  };

		  for (i = 0; i < 64; i += 20)
			for (j = 0; j < 4; ++j)
			  keystream[i + j] = t[i / 20][j];

		  for (i = 0; i < 16; ++i) {
			keystream[4+i]  = key[i];
			keystream[44+i] = key[i];
			keystream[24+i] = n[i];
		  }

	  // ____________________
	  // s20_hash(keystream);
	  // --------------------

		//    int i;
		  uint32_t x[16];
		  uint32_t z[16];

		  for (i = 0; i < 16; ++i) {

			// s20_littleendian
			uint8_t* result = keystream + (4 * i);
			x[i] = z[i] = (int16_t)(result[0]+(result[1]<<8)); //  s20_littleendian(seq + (4 * i));
		  }

		  for (i = 0; i < 10; ++i) {
				//    s20_doubleround(z);

				  // ColumnRound
				  // s20_quarterround(&x[0], &x[4], &x[8], &x[12]);

				  z[4] =  z[4]  ^ ROTL(z[0]  + z[12], 7);
				  z[8] =  z[8]  ^ ROTL(z[4]  + z[0], 9);
				  z[12] = z[12] ^ ROTL(z[8]  + z[4], 13);
				  z[0] =  z[0]  ^ ROTL(z[12] + z[8], 18);

				  // s20_quarterround(&x[5], &x[9], &x[13], &x[1]);
				  z[9] =  z[9]  ^ ROTL(z[5]  + z[1], 7);
				  z[13] = z[13] ^ ROTL(z[9]  + z[5], 9);
				  z[1] =  z[1]  ^ ROTL(z[13] + z[9], 13);
				  z[5] =  z[5]  ^ ROTL(z[1]  + z[13], 18);

				  // s20_quarterround(&x[10], &x[14], &x[2], &x[6]);
				  z[14]=  z[14] ^ ROTL(z[10] + z[6], 7);
				  z[2] =  z[2]  ^ ROTL(z[14] + z[10], 9);
				  z[6] =  z[6]  ^ ROTL(z[2]  + z[14], 13);
				  z[10] = z[10] ^ ROTL(z[6]  + z[2], 18);

				  // s20_quarterround(&x[15], &x[3], &x[7], &x[11]);
				  z[3] =  z[3]  ^ ROTL(z[15] + z[11], 7);
				  z[7] =  z[7]  ^ ROTL(z[3]  + z[15], 9);
				  z[11] = z[11] ^ ROTL(z[7]  + z[3], 13);
				  z[15] = z[15] ^ ROTL(z[11] + z[7], 18);

				  // Rowround
				  // s20_quarterround(&y[0], &y[1], &y[2], &y[3]);
				  z[1] = z[1] ^ ROTL(z[0]+  z[3], 7);
				  z[2] = z[2] ^ ROTL(z[1] + z[0], 9);
				  z[3] = z[3] ^ ROTL(z[2] + z[1], 13);
				  z[0] = z[0] ^ ROTL(z[3] + z[2], 18);

				  // s20_quarterround(&y[5], &y[6], &y[7], &y[4]);
				  z[6] = z[6] ^ ROTL(z[5] + z[4], 7);
				  z[7] = z[7] ^ ROTL(z[6] + z[5], 9);
				  z[4] = z[4] ^ ROTL(z[7] + z[6], 13);
				  z[5] = z[5] ^ ROTL(z[4] + z[7], 18);

				  // s20_quarterround(&y[10], &y[11], &y[8], &y[9]);
				  z[11] = z[11] ^ ROTL(z[10] + z[9], 7);
				  z[8] =  z[8]  ^ ROTL(z[11] + z[10], 9);
				  z[9] =  z[9]  ^ ROTL(z[8] +  z[11], 13);
				  z[10] = z[10] ^ ROTL(z[9] +  z[8], 18);

				  // s20_quarterround(&y[15], &y[12], &y[12], &y[14]);
				  z[12] = z[12] ^ ROTL(z[15] + z[14], 7);
				  z[12] = z[12] ^ ROTL(z[12] + z[15], 9);
				  z[14] = z[14] ^ ROTL(z[12] + z[12], 13);
				  z[15] = z[15] ^ ROTL(z[14] + z[12], 18);
			  }

			  for (i = 0; i < 16; ++i) {
				z[i] += x[i];
				// s20_rev_littleendian(seq + (4 * i), z[i]);
				  (keystream + (4 * i))[0] = z[i];
				  (keystream + (4 * i))[1] = z[i] >> 8;
				  (keystream + (4 * i))[2] = z[i] >> 16;
				  (keystream + (4 * i))[3] = z[i] >> 24;
			  }

			}
			buf[bufPos] ^= keystream[(si + bufPos) % 64];
		  }

	  	  (isValid)[threadNr] = true; // Assume we found the key

		  // Validate Crypto Result
		  for (size_t bufPos = 0; bufPos < VERIBUF_SIZE; bufPos++) {
			 if (buf[bufPos] != VERIFICATION_CHAR) {
				(isValid)[threadNr] = false; // We didn't

				// Calculate next key to try...
				int posToKey[] = {13,12,9,8,5,4,1,0};

				for (int i=0; i<8; i++) {
					int idx = keyToIndexMap[key[posToKey[i]]];
					idx++;
					idx %=sizeof(keyChars);
					key[posToKey[i]] = keyChars[idx];

					if (idx!=0) break;
				}
				break;
			}
		  }

		  nrKeysToCalculatePerThread--;
  	  }

}


void stub(char *x){
	x[0]=5;
}

void initializeAndCalculate(uint8_t nonce_hc[8],  char *verificationBuffer_hc) {

    int n=2048*2048;

    char p_key[(KEY_SIZE)*NR_KEYS];
    char *key = p_key;             
    
    for (unsigned long i=0; i<NR_KEYS;i++){
    	calculate16ByteKeyFromIndex(0, key+i*NR_KEYS);
    }

    cudaError_t err = cudaSuccess;
    
    uint8_t *verifbuf_test_dc = NULL;
    char veribuf_test_local[VERIBUF_SIZE];
         
    err = cudaMalloc((void **)&verifbuf_test_dc, VERIBUF_SIZE);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device memory (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }


    err = cudaMemcpy(verifbuf_test_dc, verificationBuffer_hc, VERIBUF_SIZE, cudaMemcpyHostToDevice);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to copy verification buffer from host to gpu (error code %s)!\n",      cudaGetErrorString(err));
        exit(EXIT_FAILURE);

    }
    
    
                    
    uint32_t si_hc;
    uint8_t *buf_hc;
    uint32_t buflen_hc;
    
    uint8_t *key_dc;                       
    uint8_t *nonce_dc;
    uint32_t si_dc = 0;
    uint8_t *buf_dc;
    uint32_t buflen_dc;
    
    
    err = cudaMalloc((void **)&key_dc, (KEY_SIZE)*NR_KEYS);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device memory for key (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }


    err = cudaMalloc((void **)&nonce_dc, 8);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device memory for nonce (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    
    

    
    
    err = cudaMemcpy(nonce_dc, nonce_hc, 8, cudaMemcpyHostToDevice);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to copy nonce from host to gpu (error code %s)!\n",      cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    bool result_hc[NR_KEYS];
    bool *result_dc;
    
    err = cudaMalloc((void **)&result_dc, sizeof(bool)*NR_KEYS);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device memory for isValid Result (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }


    bool keyFound = false;
    
    unsigned long nrOfKeysPerThreadAndCall = 1; // pow(2*26+10,8)/NR_THREADS
    
    do {
        
        err = cudaMemcpy(key_dc, (uint8_t *) key, (KEY_SIZE)*NR_KEYS, cudaMemcpyHostToDevice);        
        if (err != cudaSuccess)
        {
            fprintf(stderr, "Failed to copy key from host to gpu (error code %s)!\n",      cudaGetErrorString(err));
            exit(EXIT_FAILURE);
        }
                                
        gpu_crypt_and_validate<<<NR_BLOCKS, NR_THREADS>>>(key_dc, 
                                         nonce_dc, 
                                         si_dc, 
                                         verifbuf_test_dc, 
                                         VERIBUF_SIZE, 
                                         result_dc,n, 
										 nrOfKeysPerThreadAndCall										 
        								  );
        
        
        
        err = cudaGetLastError();    
        if (err != cudaSuccess)
        {
            fprintf(stderr, "error starting thread on gpu (error code %s)!\n",      cudaGetErrorString(err));
            exit(EXIT_FAILURE);
        }
    
        
        err = cudaMemcpy(&result_hc, 
                         result_dc, 
                         sizeof(bool)*NR_KEYS, 
                         cudaMemcpyDeviceToHost);   
        if (err != cudaSuccess)
        {
            fprintf(stderr, "Failed to copy memory from device to host (error code %s)!\n",      cudaGetErrorString(err));
            exit(EXIT_FAILURE);
        }

        
        err = cudaMemcpy((uint8_t *) key, key_dc, (KEY_SIZE)*NR_KEYS, cudaMemcpyDeviceToHost);        
        if (err != cudaSuccess)
        {
            fprintf(stderr, "Failed to copy key from host to gpu (error code %s)!\n",      cudaGetErrorString(err));
            exit(EXIT_FAILURE);
        }
        
        
        for (int i=0; i<NR_KEYS;i++) {
            if (result_hc[i]) {
                printf("Key found:\r\n");
                for (int j=0; j<KEY_SIZE; j++) {
                    printf("%c", key[(KEY_SIZE)*i+j]);
                }
                printf("\r\n");
                keyFound = true;
            }
        }

        printf("Next round\r\n");

        // Calculate next keys for next round...
        for (unsigned long i=0;i<(KEY_SIZE)*NR_KEYS;i++) {
        	char *currentKey = (key+i*KEY_SIZE); 
        	nextKey16Byte(currentKey);
        }
        
        
        
    } while (!keyFound);
    
    
    
    

    // Free device global memory
     err = cudaFree(result_dc);
    
    
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to free device memory (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }


    
    
    err = cudaFree(verifbuf_test_dc);
    
    
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to free device memory (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    
}







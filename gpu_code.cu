 #include <cuda_runtime.h>

#include<stdio.h>
#include<stdlib.h>


#include "petya.h"
#include "keyCandidateDistributor.h"

#include <boost/thread.hpp>
#include <boost/container/vector.hpp>

#include "globals.h"

#define NR_THREADS 1024
#define NR_BLOCKS 1
#define NR_OF_KEYS_CALCULATED_BEFORE_THREAD_RETURNS (unsigned long)10000
#define NR_KEYS_PER_GPU_CALL (unsigned long)(NR_THREADS*NR_BLOCKS)


// Define this to turn on error checking
#define CUDA_ERROR_CHECK

#define CudaSafeCall( err ) __cudaSafeCall( err, __FILE__, __LINE__ )
#define CudaCheckError()    __cudaCheckError( __FILE__, __LINE__ )

inline void __cudaSafeCall( cudaError err, const char *file, const int line )
{
#ifdef CUDA_ERROR_CHECK
    if ( cudaSuccess != err )
    {
        fprintf( stderr, "cudaSafeCall() failed at %s:%i : %s\n",
                 file, line, cudaGetErrorString( err ) );
        exit( -1 );
    }
#endif

    return;
}

inline void __cudaCheckError( const char *file, const int line )
{
#ifdef CUDA_ERROR_CHECK
    cudaError err = cudaGetLastError();
    if ( cudaSuccess != err )
    {
        fprintf( stderr, "cudaCheckError() failed at %s:%i : %s\n",
                 file, line, cudaGetErrorString( err ) );
        exit( -1 );
    }

    // More careful checking. However, this will affect performance.
    // Comment away if needed.
    err = cudaDeviceSynchronize();
    if( cudaSuccess != err )
    {
        fprintf( stderr, "cudaCheckError() with sync failed at %s:%i : %s\n",
                 file, line, cudaGetErrorString( err ) );
        exit( -1 );
    }
#endif

    return;
}


using namespace std;




__global__ void gpu_crypt_and_validate(uint8_t *keys,
                           
                            uint8_t nonce[8],
                            uint32_t si,
                            uint8_t *buf,
                            uint32_t buflen,
                            bool *isValid,
							int nrTotal,
							unsigned long nrKeysToCalculatePerThreadBeforeReturn,
							char *keyChars,
							int *keyToIndexMap
							)
{


  int threadNr = blockDim.x * blockIdx.x + threadIdx.x;

  if (threadNr>=nrTotal) return;
  
  bool keyFound = false;

  uint8_t *key = keys + (threadNr*(KEY_SIZE));   
  
  while (nrKeysToCalculatePerThreadBeforeReturn>0 && !keyFound) {
	  (isValid)[threadNr] = false;

	  uint8_t keystream[64];
	  uint8_t n[16] = { 0 };
	  uint32_t i;

	  for (i = 0; i < 8; ++i)
		n[i] = nonce[i];

	  /*
	    legacyCode();
	  */

	  uint8_t *validationBuffer;
	  
	  validationBuffer = buf + (threadNr*(KEY_SIZE));
	  
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

				  // s20_quarterround(&y[15], &y[12], &y[13], &y[14]);
				  z[12] = z[12] ^ ROTL(z[15] + z[14], 7);
				  z[13] = z[13] ^ ROTL(z[12] + z[15], 9);
				  z[14] = z[14] ^ ROTL(z[12] + z[13], 13);
				  z[15] = z[15] ^ ROTL(z[14] + z[13], 18);
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
				validationBuffer[bufPos] ^= keystream[(si + bufPos) % 64];
		  }

	  	  (isValid)[threadNr] = true; // Assume we found the key

	  	  
		  // Validate Crypto Result
		  for (size_t bufPos = 0; bufPos < VERIBUF_SIZE; bufPos++) {
			 if (validationBuffer[bufPos] != VERIFICATION_CHAR) {
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
		  
		  if ((isValid)[threadNr]==true) keyFound = true;
		  nrKeysToCalculatePerThreadBeforeReturn--;
  	  }
}



void initializeAndCalculate(uint8_t nonce_hc[8],  char *verificationBuffer) {

    char p_key[(KEY_SIZE)*NR_KEYS_PER_GPU_CALL];
    char *key = p_key;  
    
    /*

	key[0] = 'n';
	key[1] = 'G';
	key[2] = 'u';
	key[3] = 'J';
	key[4] = 'G';
	key[5] = 'b';
	key[6] = 'm';
	key[7] = 'D';
	key[8] = 'u';
	key[9] = 'V';
	key[10] = 'N';
	key[11] = '9';
	key[12] = 'X';
	key[13] = 'm';
	key[14] = 'L';
	key[15] = 'a';
	
	*/

    // int n=2048*2048;

    uint8_t *verificationBuffer_hc;
    verificationBuffer_hc = (uint8_t *) malloc(VERIBUF_SIZE*NR_KEYS_PER_GPU_CALL);
    
    // Fill verificationBuffer for each thread...
    for (unsigned long i=0; i<NR_KEYS_PER_GPU_CALL; i++) {
    	memcpy(verificationBuffer_hc+i*KEY_SIZE, verificationBuffer, VERIBUF_SIZE);
    }
           
    
    unsigned long keyBlocks = pow(26*2+10,8)/(NR_THREADS*NR_BLOCKS);
    
    
    for (unsigned long i=0; i<NR_KEYS_PER_GPU_CALL;i++){
    	calculate16ByteKeyFromIndex(0+i*keyBlocks, key+i*KEY_SIZE);
    }
    

    
    uint8_t *verifbuf_test_dc = NULL;
         
    CudaSafeCall(cudaMalloc((void **)&verifbuf_test_dc, (VERIBUF_SIZE*NR_KEYS_PER_GPU_CALL)));
    CudaSafeCall(cudaMemcpy(verifbuf_test_dc, verificationBuffer_hc, (VERIBUF_SIZE*NR_KEYS_PER_GPU_CALL), cudaMemcpyHostToDevice));
    
    
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
                        
    
    uint8_t *key_dc;                       
    uint8_t *nonce_dc;
    uint32_t si_dc = 0;
    
    char *keyChars_dc;
    int *keyToIndexMap_dc;
    

    CudaSafeCall(cudaMalloc((void **)&keyChars_dc, sizeof(keyChars)));
    CudaSafeCall(cudaMemcpy(keyChars_dc, keyChars, sizeof(keyChars), cudaMemcpyHostToDevice));
    CudaSafeCall(cudaMalloc((void **)&keyToIndexMap_dc, 256));
    CudaSafeCall(cudaMemcpy(keyToIndexMap_dc, keyToIndexMap, 256, cudaMemcpyHostToDevice));
    CudaSafeCall(cudaMalloc((void **)&key_dc, (KEY_SIZE)*NR_KEYS_PER_GPU_CALL));
    CudaSafeCall(cudaMalloc((void **)&nonce_dc, 8));
    CudaSafeCall(cudaMemcpy(nonce_dc, nonce_hc, 8, cudaMemcpyHostToDevice));

    bool result_hc[NR_KEYS_PER_GPU_CALL];
    bool *result_dc;
    
    CudaSafeCall(cudaMalloc((void **)&result_dc, sizeof(bool)*NR_KEYS_PER_GPU_CALL));


    bool keyFound = false;
    unsigned long keysCalculated = 0;
    
    boost::posix_time::time_duration duration;
    boost::posix_time::ptime beginTs = boost::posix_time::second_clock::local_time();

    //int debugCalls =1;
    
    do {
        
    	CudaSafeCall(cudaMemcpy(key_dc, (uint8_t *) key, (KEY_SIZE)*NR_KEYS_PER_GPU_CALL, cudaMemcpyHostToDevice));


        gpu_crypt_and_validate<<<NR_BLOCKS, NR_THREADS>>>(key_dc, 
                                         nonce_dc, 
                                         si_dc, 
                                         verifbuf_test_dc, 
                                         VERIBUF_SIZE, 
                                         result_dc,NR_KEYS_PER_GPU_CALL, 
										 NR_OF_KEYS_CALCULATED_BEFORE_THREAD_RETURNS,
										 keyChars_dc,
										 keyToIndexMap_dc
        								  );
        CudaCheckError();
        
        
    


        CudaSafeCall(cudaMemcpy(&result_hc, result_dc, sizeof(bool)*NR_KEYS_PER_GPU_CALL, cudaMemcpyDeviceToHost));        
        CudaSafeCall(cudaMemcpy((uint8_t *) key, key_dc, (KEY_SIZE)*NR_KEYS_PER_GPU_CALL, cudaMemcpyDeviceToHost));
        
        
        for (int i=0; i<NR_KEYS_PER_GPU_CALL;i++) {
            if (result_hc[i]) {
                printf("Key found:\r\n");
                for (int j=0; j<KEY_SIZE; j++) {
                    printf("%c", key[(KEY_SIZE)*i+j]);
                }
                printf("\r\n");
                keyFound = true;
            }
        }

        //printf("Next round\r\n");

        // Calculate next keys for next round...
        for (unsigned long i=0;i<NR_KEYS_PER_GPU_CALL;i++) {
        	char *currentKey = (key+i*KEY_SIZE); 
        	nextKey16Byte(currentKey);
        }
        
        keysCalculated += NR_THREADS*NR_BLOCKS*NR_OF_KEYS_CALCULATED_BEFORE_THREAD_RETURNS;
        
        if (keysCalculated%1000000 == 0) {
        	unsigned long divider = 1000000;
        	// Print estimated time...
            boost::posix_time::ptime now = boost::posix_time::second_clock::local_time();  
            duration = (now-beginTs);
            std::cout << "Diff:" << duration.total_seconds() << endl;
            std::cout << "Based upon this performance all keys will be calculated in " << endl;
            
            unsigned long years = pow(2*26+10,8)/divider*duration.total_seconds() /60/60/24/365;
            unsigned long days = (pow(2*26+10,8)/divider*duration.total_seconds() /60/60/24)-years*365;
            unsigned long hours = (pow(2*26+10,8)/divider*duration.total_seconds() /60/60)-(years*365*24+days*24);
            unsigned long minutes = (pow(2*26+10,8)/divider*duration.total_seconds() /60)-(years*365*24*60+days*24*60+hours*60);
            
            std::cout << years << " years" << endl;
            std::cout << days << " days" << endl;
            std::cout << hours << " hours" << endl;
            std::cout << minutes << " minutes" << endl;

            beginTs = boost::posix_time::second_clock::local_time();         
        }
        
//        debugCalls--;
//        if (debugCalls<=0) break;
    } while (!keyFound);
    
    free(verificationBuffer_hc);
    
    CudaSafeCall(cudaFree(keyChars_dc));
    CudaSafeCall(cudaFree(keyToIndexMap_dc));

    // Free device global memory
    CudaSafeCall(cudaFree(result_dc));    
    CudaSafeCall(cudaFree(verifbuf_test_dc));
    
    
}





/*
__device__ void calculateSingleShot(uint8_t *keys,
        
        uint8_t nonce[8],
        uint8_t *buf,
        uint32_t buflen,
        bool *isValid,
		int nrTotal) {
	
}*/

__global__ void gpu_decryptSingleShot(uint8_t *keys,
                           
                            uint8_t nonce[8],
                            uint8_t *buf,
                            uint32_t buflen,
                            bool *isValid,
							int nrTotal)
{
	
  int threadNr = blockDim.x * blockIdx.x + threadIdx.x;

  if (threadNr>=nrTotal) return;
  
  uint8_t *key = keys + (threadNr*(KEY_SIZE));   
  
  (isValid)[threadNr] = false;

  uint8_t keystream[64];
  uint8_t n[16] = { 0 };
  uint32_t i;

  for (i = 0; i < 8; ++i)
	n[i] = nonce[i];

  uint8_t *validationBuffer;
  
  validationBuffer = buf + (threadNr*(KEY_SIZE));
  
  for (int bufPos = 0; bufPos < buflen; ++bufPos) {
	  
	  
	if (bufPos % 64 == 0) {
	  //s20_rev_littleendian(n+8, ((si + i) / 64));
	  (n+8)[0] = (bufPos / 64);
	  (n+8)[1] = (bufPos / 64)>>8;
	  (n+8)[2] = (bufPos / 64)>>16;
	  (n+8)[3] = (bufPos / 64)>>24;

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

			  // s20_quarterround(&y[15], &y[12], &y[13], &y[14]);
			  z[12] = z[12] ^ ROTL(z[15] + z[14], 7);
			  z[13] = z[13] ^ ROTL(z[12] + z[15], 9);
			  z[14] = z[14] ^ ROTL(z[12] + z[13], 13);
			  z[15] = z[15] ^ ROTL(z[14] + z[13], 18);
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
			validationBuffer[bufPos] ^= keystream[ bufPos % 64];
	  }

	  (isValid)[threadNr] = true; // Assume we found the key

	  
	  // Validate Crypto Result
	  for (size_t bufPos = 0; bufPos < VERIBUF_SIZE; bufPos++) {
		 if (validationBuffer[bufPos] != VERIFICATION_CHAR) {
			(isValid)[threadNr] = false; // We didn't								
			break;
		}
		
	  }
	  
  }



__global__ void gpu_decryptMultiShot(uint8_t *keys,                           
                            uint8_t nonce[8],
                            uint8_t *buf,
                            uint32_t buflen,
                            bool *isValid,
							int nrTotal,
							unsigned long nrKeysToCalculatePerThreadBeforeReturn,
							char *keyChars,
							int *keyToIndexMap)
{
	  int threadNr = blockDim.x * blockIdx.x + threadIdx.x;
	  
	  if (threadNr>=nrTotal) return;
	  
	  
	  bool keyFound = false;

	  uint8_t *key = keys + (threadNr*(KEY_SIZE));   
	  
	  while (nrKeysToCalculatePerThreadBeforeReturn>0 && !keyFound) 
	  {
		  (isValid)[threadNr+1] = false;

		  
		  uint8_t keystream[64];
		  uint8_t n[16] = { 0 };
		  uint32_t i;

		  for (i = 0; i < 8; ++i)
			n[i] = nonce[i];


		  uint8_t *validationBuffer;
		  
		  validationBuffer = buf + (threadNr*(KEY_SIZE));
	
	//		if (bufPos % 64 == 0) {
			  //s20_rev_littleendian(n+8, ((si + i) / 64));
			  (n+8)[0] = 0;// (bufPos / 64);
			  (n+8)[1] = 0;//(bufPos / 64)>>8;
			  (n+8)[2] = 0;//(bufPos / 64)>>16;
			  (n+8)[3] = 0;//(bufPos / 64)>>24;

			  // s20_expand16(key, n, keystream);

			  //int i; 
			  int j;
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

					  // s20_quarterround(&y[15], &y[12], &y[13], &y[14]);
					  z[12] = z[12] ^ ROTL(z[15] + z[14], 7);
					  z[13] = z[13] ^ ROTL(z[12] + z[15], 9);
					  z[14] = z[14] ^ ROTL(z[12] + z[13], 13);
					  z[15] = z[15] ^ ROTL(z[14] + z[13], 18);
				  }

				  for (i = 0; i < 16; ++i) {
					z[i] += x[i];
					// s20_rev_littleendian(seq + (4 * i), z[i]);
					  (keystream + (4 * i))[0] = z[i];
					  (keystream + (4 * i))[1] = z[i] >> 8;
					  (keystream + (4 * i))[2] = z[i] >> 16;
					  (keystream + (4 * i))[3] = z[i] >> 24;
				  }

//				}

		  
	  	  (isValid)[threadNr+1] = true; // Assume we found the key

	 
		  for (int bufPos = 0; bufPos < buflen; ++bufPos) {
			  
			  
					char c = validationBuffer[bufPos];
					c ^= keystream[ bufPos % 64];
					if (c!=VERIFICATION_CHAR) {
						(isValid)[threadNr+1] = false;
						
						// Calculate next key to try...
						int posToKey[] = {13,12,9,8,5,4,1,0};

						for (int i=0; i<8; i++) {
							int idx = keyToIndexMap[(char)key[posToKey[i]]];
							idx++;
							idx %=sizeof(keyChars);
							key[posToKey[i]] = keyChars[idx];

							if (idx!=0) break;
						}				
						break;
					}
			  }
		  
		  	  
	
		  /*
		  	  (isValid)[threadNr+1] = true; // Assume we found the key

		  	  
			  // Validate Crypto Result
			  for (size_t bufPos = 0; bufPos < VERIBUF_SIZE; bufPos++) {
				 if (validationBuffer[bufPos] != VERIFICATION_CHAR) {
					(isValid)[threadNr+1] = false; // We didn't	
					
					
					// Calculate next key to try...
					int posToKey[] = {13,12,9,8,5,4,1,0};

					for (int i=0; i<8; i++) {
						int idx = keyToIndexMap[(char)key[posToKey[i]]];
						idx++;
						idx %=sizeof(keyChars);
						key[posToKey[i]] = keyChars[idx];

						if (idx!=0) break;
					}				
					
					break;
					
				}
				
			  }
			  */
			  if ((isValid)[threadNr+1]==true) {
				  keyFound = true;
				  (isValid)[0] = true; // set first index to true to inducate key was found in one of the threads 
			  }
			  
			  
			  
			  nrKeysToCalculatePerThreadBeforeReturn--;
	  	  }
	  	  
	  	  

}


void tryKeysGPUSingleShot(unsigned int nrBlocks,
		        unsigned int nrThreads,
				uint8_t nonce_hc[8],  
		        char *verificationBuffer, 
				char*keys, 
				unsigned long nrKeys, 
				bool *result) {
    
    uint8_t *verificationBuffer_hc;
    uint8_t *verifbuf_test_dc = NULL;
    uint8_t *keys_dc;                       
    uint8_t *nonce_dc;
    bool *result_dc;
    
    verificationBuffer_hc = (uint8_t *) malloc(VERIBUF_SIZE*nrKeys);
    
    // Fill verificationBuffer for each thread...
    for (unsigned long i=0; i<nrKeys; i++) {
    	memcpy(verificationBuffer_hc+i*KEY_SIZE, verificationBuffer, VERIBUF_SIZE);
    }
                    
    CudaSafeCall(cudaMalloc((void **)&verifbuf_test_dc, (VERIBUF_SIZE*nrKeys)));
    CudaSafeCall(cudaMemcpy(verifbuf_test_dc, verificationBuffer_hc, (VERIBUF_SIZE*nrKeys), cudaMemcpyHostToDevice));
    CudaSafeCall(cudaMalloc((void **)&keys_dc, (KEY_SIZE)*nrKeys));
    CudaSafeCall(cudaMalloc((void **)&nonce_dc, 8));
    CudaSafeCall(cudaMemcpy(nonce_dc, nonce_hc, 8, cudaMemcpyHostToDevice));
    CudaSafeCall(cudaMalloc((void **)&result_dc, sizeof(bool)*nrKeys));
    

        
    CudaSafeCall(cudaMemcpy(keys_dc, (uint8_t *) keys, (KEY_SIZE)*nrKeys, cudaMemcpyHostToDevice));

    gpu_decryptSingleShot<<<nrBlocks, nrThreads>>>(keys_dc, 
                                         nonce_dc, 
                                         verifbuf_test_dc, 
                                         VERIBUF_SIZE, 
                                         result_dc,nrKeys);
    CudaCheckError();
        
    CudaSafeCall(cudaMemcpy(result, result_dc, sizeof(bool)*nrKeys, cudaMemcpyDeviceToHost));        
    CudaSafeCall(cudaMemcpy((uint8_t *) keys, keys_dc, (KEY_SIZE)*nrKeys, cudaMemcpyDeviceToHost));
        
       
	free(verificationBuffer_hc);

	// Free device global memory
	CudaSafeCall(cudaFree(result_dc));    
	CudaSafeCall(cudaFree(verifbuf_test_dc));    
}


void tryKeysGPUMultiShot(unsigned int nrBlocks,
		        unsigned int nrThreads,
				uint8_t nonce_hc[8],  
		        char *verificationBuffer, 
				char*keys, 
				unsigned long nrKeys,
				unsigned long keysBeforeContextSwitch,
				unsigned long keysInTotalToCalculate) {
    
	unsigned long nrTotalKeys = pow(26*2+10,8);
	
    uint8_t *verificationBuffer_hc;
    uint8_t *verifbuf_test_dc = NULL;
    uint8_t *keys_dc;                       
    uint8_t *nonce_dc;
    bool *result_dc;
    
    char *keyChars_dc;
    int *keyToIndexMap_dc;

    bool *result = (bool *)malloc(sizeof(bool)*(nrKeys+1)); //+1 as 0 Index stores information if key was found by one thread at all
    
    memset(result, 0, sizeof(bool)*(nrKeys+1));

    
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
              
    
    verificationBuffer_hc = (uint8_t *) malloc(VERIBUF_SIZE*nrKeys);
    
    // Fill verificationBuffer for each thread...
    for (unsigned long i=0; i<nrKeys; i++) {
    	memcpy(verificationBuffer_hc+i*KEY_SIZE, verificationBuffer, VERIBUF_SIZE);
    }
                    
    CudaSafeCall(cudaMalloc((void **)&verifbuf_test_dc, (VERIBUF_SIZE*nrKeys)));
    CudaSafeCall(cudaMemcpy(verifbuf_test_dc, verificationBuffer_hc, (VERIBUF_SIZE*nrKeys), cudaMemcpyHostToDevice));
    CudaSafeCall(cudaMalloc((void **)&keys_dc, (KEY_SIZE)*nrKeys));
    CudaSafeCall(cudaMalloc((void **)&nonce_dc, 8));
    CudaSafeCall(cudaMemcpy(nonce_dc, nonce_hc, 8, cudaMemcpyHostToDevice));
    CudaSafeCall(cudaMalloc((void **)&result_dc, sizeof(bool)*(nrKeys+1))); // +1 as 0 Index stores information if key was found by one thread at all
    CudaSafeCall(cudaMemcpy(result_dc, result, sizeof(bool)*(nrKeys+1), cudaMemcpyHostToDevice));
    

    CudaSafeCall(cudaMalloc((void **)&keyChars_dc, sizeof(keyChars)));
    CudaSafeCall(cudaMemcpy(keyChars_dc, keyChars, sizeof(keyChars), cudaMemcpyHostToDevice));
    CudaSafeCall(cudaMalloc((void **)&keyToIndexMap_dc, 256));
    CudaSafeCall(cudaMemcpy(keyToIndexMap_dc, keyToIndexMap, 256, cudaMemcpyHostToDevice));

    
    bool keyFound = false;
    unsigned long keysCalculated = 0;
    
    boost::posix_time::time_duration duration;
    boost::posix_time::ptime beginTs = boost::posix_time::second_clock::local_time();

    CudaSafeCall(cudaMemcpy(keys_dc, (uint8_t *) keys, (KEY_SIZE)*nrKeys, cudaMemcpyHostToDevice));

    /*
    for (int i=0; i<(KEY_SIZE)*nrKeys; i++) {
    	printf("%c",keys[i]);
    }
    cout << endl;
    */
    
    do {
    
		gpu_decryptMultiShot<<<nrBlocks, nrThreads>>>(keys_dc, 
											 nonce_dc, 
											 verifbuf_test_dc, 
											 VERIBUF_SIZE, 
											 result_dc,nrKeys,
											 keysBeforeContextSwitch,
											 keyChars,
											 keyToIndexMap);
		CudaCheckError();
			
		CudaSafeCall(cudaMemcpy(result, result_dc, sizeof(bool)*(nrKeys+1), cudaMemcpyDeviceToHost));        
	
		if (result[0]==true) { // If key was found at all...
			CudaSafeCall(cudaMemcpy((uint8_t *) keys, keys_dc, (KEY_SIZE)*nrKeys, cudaMemcpyDeviceToHost));
			

			for (int i=1; i<nrKeys+1;i++) {
				if (result[i]) {
					printf("Key found:\r\n");
					for (int j=0; j<KEY_SIZE; j++) {
						printf("%c", keys[(KEY_SIZE)*(i-1)+j]); // -1 as 0 index is reserved to store if result was found at all
					}
					printf("\r\n");
					keyFound = true;
				}
			}
		}
	
		// Keys for next round should have been already calculated on GPU
		
		// Calculate next keys for next round...
		// for (unsigned long i=0;i<NR_KEYS_PER_GPU_CALL;i++) {
		//	char *currentKey = (key+i*KEY_SIZE); 
		//	nextKey16Byte(currentKey);
		// }
		
		keysCalculated += nrThreads*nrBlocks*keysBeforeContextSwitch;
		
		if (keysCalculated%1000000 == 0) {
			cout << (keysCalculated*100/keysInTotalToCalculate) << "% of Job calculated, that's " << keysCalculated*100/nrTotalKeys << " Percent of the whole key range"<< endl;
		}
		    
    } while (!keyFound &&  keysCalculated<keysInTotalToCalculate);

       
	// Free device global memory

	CudaSafeCall(cudaFree(keyChars_dc));
	CudaSafeCall(cudaFree(keyToIndexMap_dc));    

	
	CudaSafeCall(cudaFree(keys_dc));
	CudaSafeCall(cudaFree(result_dc));    
	CudaSafeCall(cudaFree(nonce_dc));    
	CudaSafeCall(cudaFree(verifbuf_test_dc));  

	free(verificationBuffer_hc);
    free(verificationBuffer);
    free(keys);
	free(result);
}


void measureGPUPerformance(unsigned int nrBlocks,
		        unsigned int nrThreads, 
				unsigned long keysBeforeContextSwitch, 
				unsigned long *nrKeysCalculatedResult,
				unsigned long *nrOfSecondsInTotalMeasured,
				int nrSecondsToMeasure = 30) {
    
    uint8_t *verificationBuffer_hc;
    uint8_t *verifbuf_test_dc = NULL;
    uint8_t *keys_dc;                       
    uint8_t *nonce_dc;
    bool *result_dc;
    
    char *keyChars_dc;
    int *keyToIndexMap_dc;

    
    unsigned long nrKeys = nrThreads * nrBlocks;
    bool *result = (bool *)malloc(sizeof(bool)*(nrKeys+1));
    char*keys = (char*) malloc(sizeof(char)*nrKeys*KEY_SIZE);
    
    memset(result, 0, sizeof(bool)*(nrKeys+1));
    
    	
    unsigned long keysCalculated = 0;

	uint8_t nonce_hc[8];
    char *verificationBuffer = (char *)malloc(VERIBUF_SIZE);
	
	
	nonce_hc[0] = 0x07;
	nonce_hc[1] = 0x0c;
	nonce_hc[2] = 0x12;
	nonce_hc[3] = 0xf6;
	nonce_hc[4] = 0x79;
	nonce_hc[5] = 0x28;
	nonce_hc[6] = 0x73;
	nonce_hc[7] = 0xcb;

	verificationBuffer[0] = 0x34;
	verificationBuffer[1] = 0x80;
	verificationBuffer[2] = 0x15;
	verificationBuffer[3] = 0x1a;
	verificationBuffer[4] = 0xd1;
	verificationBuffer[5] = 0x76;
	verificationBuffer[6] = 0x5c;
	verificationBuffer[7] = 0x7b;
	verificationBuffer[8] = 0x60;
	verificationBuffer[9] = 0x2b;
	verificationBuffer[10] = 0xe3;
	verificationBuffer[11] = 0xd0;
	verificationBuffer[12] = 0xd0;
	verificationBuffer[13] = 0xae;
	verificationBuffer[14] = 0xf8;
	verificationBuffer[15] = 0xc2;
	
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

    verificationBuffer_hc = (uint8_t *) malloc(VERIBUF_SIZE*nrKeys);
   
    
	
    // Fill verificationBuffer for each thread...
    for (unsigned long i=0; i<nrKeys; i++) {
    	memcpy(verificationBuffer_hc+i*KEY_SIZE, verificationBuffer, VERIBUF_SIZE);
    }
    
    
	// memset(keys,'0', nrKeys*KEY_SIZE);
    unsigned long keyBlocks = pow(26*2+10,8)/(nrKeys);
    
    char *currentKey = keys;
    for (unsigned long i=0; i<nrKeys;i++){
    	calculate16ByteKeyFromIndex(0+i*keyBlocks, currentKey);
    	currentKey+=KEY_SIZE;
    }
    

    /*
    for (int i=0; i<nrKeys;i++) {
    	cout << keys[i];
    }
    cout << endl;
    */
    

    
    CudaSafeCall(cudaMalloc((void **)&verifbuf_test_dc, (VERIBUF_SIZE*nrKeys)));
    CudaSafeCall(cudaMemcpy(verifbuf_test_dc, verificationBuffer_hc, (VERIBUF_SIZE*nrKeys), cudaMemcpyHostToDevice));
    CudaSafeCall(cudaMalloc((void **)&nonce_dc, 8));
    CudaSafeCall(cudaMemcpy(nonce_dc, nonce_hc, 8, cudaMemcpyHostToDevice));
    CudaSafeCall(cudaMalloc((void **)&result_dc, sizeof(bool)*(nrKeys+1)));
    CudaSafeCall(cudaMemcpy(result_dc, result, sizeof(bool)*(nrKeys+1), cudaMemcpyHostToDevice));
    CudaSafeCall(cudaMalloc((void **)&keys_dc, sizeof(uint8_t)*(KEY_SIZE)*nrKeys));

    CudaSafeCall(cudaMalloc((void **)&keyChars_dc, sizeof(keyChars)));
    CudaSafeCall(cudaMemcpy(keyChars_dc, keyChars, sizeof(keyChars), cudaMemcpyHostToDevice));
    CudaSafeCall(cudaMalloc((void **)&keyToIndexMap_dc, 256));
    CudaSafeCall(cudaMemcpy(keyToIndexMap_dc, keyToIndexMap, 256, cudaMemcpyHostToDevice));



	
    boost::posix_time::time_duration duration;
    boost::posix_time::ptime beginTs = boost::posix_time::second_clock::local_time();


	CudaSafeCall(cudaMemcpy(keys_dc, (uint8_t *) keys, (KEY_SIZE)*nrKeys, cudaMemcpyHostToDevice));

	do {


		
	

		
		gpu_decryptMultiShot<<<nrBlocks, nrThreads>>>(keys_dc, 
											 nonce_dc, 
											 verifbuf_test_dc, 
											 VERIBUF_SIZE, 
											 result_dc,
											 nrKeys,
											 keysBeforeContextSwitch,
											 keyChars_dc,
											 keyToIndexMap_dc);
		
		CudaCheckError();
		
			
		CudaSafeCall(cudaMemcpy(result, result_dc, sizeof(bool)*(nrKeys+1), cudaMemcpyDeviceToHost));        


		
		if (result[0]==true) {
			
			CudaSafeCall(cudaMemcpy((uint8_t *) keys, keys_dc, (KEY_SIZE)*nrKeys, cudaMemcpyDeviceToHost));
			
			cout << endl;
			for (int i=1; i<nrKeys+1;i++) {
				if (result[i]) {
					printf("Key found:\r\n");
					for (int j=0; j<KEY_SIZE; j++) {
						printf("%c", keys[(KEY_SIZE)*(i-1)+j]);
					}
					printf("\r\n");
				}
			}
			
		}
	
		
		keysCalculated += nrThreads*nrBlocks*keysBeforeContextSwitch;
		

    
		
		boost::posix_time::ptime now = boost::posix_time::second_clock::local_time();  
		duration = (now-beginTs);

    } while (!(duration.total_seconds()>nrSecondsToMeasure));

		
	
						
	// Print estimated time...
	// std::cout << "Diff:" << duration.total_seconds() << endl;

	
	
	
	// Free device global memory

	CudaSafeCall(cudaFree(keyChars_dc));
	CudaSafeCall(cudaFree(keyToIndexMap_dc));    

	
	CudaSafeCall(cudaFree(keys_dc));
	CudaSafeCall(cudaFree(result_dc));    
	CudaSafeCall(cudaFree(nonce_dc));    
	CudaSafeCall(cudaFree(verifbuf_test_dc));  

	free(verificationBuffer_hc);
    free(verificationBuffer);
    free(keys);
	free(result);

	*nrOfSecondsInTotalMeasured = duration.total_seconds();
	*nrKeysCalculatedResult = keysCalculated;
}



/*
void legacyCode() {
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
	  
	  // s20_quarterround(&y[15], &y[12], &y[13], &y[14]);
	  z[12] = z[12] ^ ROTL(z[15] + z[14], 7);
	  z[13] = z[13] ^ ROTL(z[12] + z[15], 9);
	  z[14] = z[14] ^ ROTL(z[12] + z[13], 13);
	  z[15] = z[15] ^ ROTL(z[14] + z[13], 18);
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
}
*/





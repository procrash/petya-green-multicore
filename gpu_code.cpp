#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include <map>

#include "petya.h"

#include <boost/thread.hpp>
#include <boost/container/vector.hpp>

#define SHL(x, s) ((uint32_t) ((x) << ((s) & 31)))
#define SHR(x, s) ((uint32_t) ((x) >> (32 - ((s) & 31))))
#define ROTL(x, s) ((uint32_t) (SHL((x), (s)) | SHR((x), (s))))

// #define ROTL rotl

#define NR_THREADS 1024
#define NR_BLOCKS 1
#define NR_OF_KEYS_CALCULATED_BEFORE_THREAD_RETURNS (unsigned long)1
#define NR_KEYS (unsigned long)(NR_THREADS*NR_BLOCKS)


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
	
	/*
	char oldKeyDebug[KEY_SIZE+1];
	memcpy(oldKeyDebug, key, KEY_SIZE);
	oldKeyDebug[KEY_SIZE] = 0;
	*/
	
	for (int i=0; i<(2*26+10); i++) {
		keyToIndexMap[keyChars[i]]=i;
	}		
	
	int posToKey[] = {13,12,9,8,5,4,1,0};
	
	for (int i=0; i<8; i++) {
		int idx = keyToIndexMap[key[posToKey[i]]];		
		idx++;
		idx %=(2*26+10);
		key[posToKey[i]] = keyChars[idx];
		
		if (idx!=0) break;
	}
	
	/*
	char keyDebug[KEY_SIZE+1];
	memcpy(keyDebug, key, KEY_SIZE);
	keyDebug[KEY_SIZE] = 0;
	printf("Next key of %s is %s\r\n",oldKeyDebug, keyDebug);
	*/
}

int firstTime = 0;

void gpu_crypt_and_validate(uint8_t *keys,
                           
                            uint8_t nonce[8],
                            uint32_t si,
                            uint8_t *buf,
                            uint32_t buflen,
                            bool *isValid,
							int nrTotal,
							unsigned long nrKeysToCalculatePerThread,
							char *keyChars,
							int *keyToIndexMap
							)
{

  int threadNr = 0;



  uint8_t *key = keys + (threadNr*(KEY_SIZE));   

  /*
  char debugKey[17];
  memcpy(debugKey, key, 16);
  debugKey[16] = 0;
  printf("Key is %s\r\n", key);
  */


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

	  memset(keystream,0,64);
	  // printf("Keystream is:\r\n");
	  //hexdump((char*)keystream, 64);

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
				  z[4] =  z[4] ^ ROTL(z[0]  + z[12], 7);
				  z[8] =  z[8] ^ ROTL(z[4]  + z[0], 9);
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
					idx %=(2*26+10);
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


void initializeAndCalculate(uint8_t nonce_hc[8],  char *verificationBuffer_hc, char *keys, unsigned long nrKeysPerGPUCall) {

    //  p_key[(KEY_SIZE)*nrKeysPerGPUCall];
    // char *keys = p_key;
    
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
	
    int n=2048*2048;


    unsigned long keyBlocks = pow(26*2+10,8)/(NR_THREADS*NR_BLOCKS);
    

    for (unsigned long i=0; i<nrKeysPerGPUCall;i++){
    	calculate16ByteKeyFromIndex(0+i*keyBlocks, keys+i*KEY_SIZE);
    }

    uint8_t *verifbuf_test_dc = NULL;
         
    verifbuf_test_dc = (uint8_t *)malloc(VERIBUF_SIZE);
    memcpy(verifbuf_test_dc, verificationBuffer_hc, VERIBUF_SIZE);
    
    
    // This is initialized here to save time to calculate next key later, todo: Calculate outside and provide with parameters...
    char keyChars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
      
    int keyToIndexMap[256];
    for (int i=0; i<(2*26+10);i++) {
  	  for (int j=0; j<256;j++) {
  		  if (keyChars[i]==(char)j) {
  			  keyToIndexMap[(char)j]=i;
  		  }
  	  }
    }
                        
    uint8_t *keys_dc;
    uint8_t *nonce_dc;
    uint32_t si_dc = 0;
    
    char *keyChars_dc;
    int *keyToIndexMap_dc;
    

    keyChars_dc = (char *)malloc(sizeof(keyChars));
    memcpy(keyChars_dc, keyChars, sizeof(keyChars));
    keyToIndexMap_dc = (int*)malloc(256);
    memcpy(keyToIndexMap_dc, keyToIndexMap, 256);
    keys_dc = (uint8_t *)malloc(KEY_SIZE*nrKeysPerGPUCall);
    nonce_dc = (uint8_t *)malloc(8);
    memcpy(nonce_dc, nonce_hc, 8);

    bool result_hc[nrKeysPerGPUCall];
    bool *result_dc;
    
    result_dc = (bool*)malloc(sizeof(bool)*nrKeysPerGPUCall);


    bool keyFound = false;
    
    
    unsigned long keysCalculated = 0;
    
    boost::posix_time::time_duration duration;
    boost::posix_time::ptime beginTs = boost::posix_time::second_clock::local_time();

    // int debugCalls =1;
    
    do {
        
    	memcpy(keys_dc, (uint8_t *) keys, (KEY_SIZE)*nrKeysPerGPUCall);
                                
        gpu_crypt_and_validate(keys_dc,
                                         nonce_dc, 
                                         si_dc, 
                                         verifbuf_test_dc, 
                                         VERIBUF_SIZE, 
                                         result_dc,n, 
										 NR_OF_KEYS_CALCULATED_BEFORE_THREAD_RETURNS,
										 keyChars_dc,
										 keyToIndexMap_dc
        								  );
        
        
    
        
        memcpy(&result_hc, result_dc, sizeof(bool)*nrKeysPerGPUCall);
        memcpy((uint8_t *) keys, keys_dc, (KEY_SIZE)*nrKeysPerGPUCall);
        
        
        for (int i=0; i<nrKeysPerGPUCall;i++) {
            if (result_hc[i]) {
                printf("Key found:\r\n");
                for (int j=0; j<KEY_SIZE; j++) {
                    printf("%c", keys[(KEY_SIZE)*i+j]);
                }
                printf("\r\n");
                keyFound = true;
            }
        }

        //printf("Next round\r\n");

        // Calculate next keys for next round...
        for (unsigned long i=0;i<nrKeysPerGPUCall;i++) {
        	char *currentKey = (keys+i*KEY_SIZE);
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
        
        // debugCalls--;
        // if (debugCalls<=0) break;
    } while (!keyFound);
    
    
    
    free(keyChars_dc);
    free(keyToIndexMap_dc);

    // Free device global memory
    free(result_dc);
    free(verifbuf_test_dc);
    
    
}







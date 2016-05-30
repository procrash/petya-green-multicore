#include<stdio.h>
#include<stdlib.h>
#include <iostream>
#include <boost/thread.hpp>
#include <boost/container/vector.hpp>
#include "keyCandidateDistributor.h"
#include "salsa20.h"
#include "globals.h"

#include "petya.h"
using namespace std;

static unsigned long long keysCalculated = 0;


void tryKeyRandom(int i, char *nonce, char*veribuf) {

	bool shutdownRequested = false;

		keysCalculated=0;
	    // remove static keyword and you're doomed as the TS doesn't seem to be updated
	    static boost::posix_time::ptime beginTs = boost::posix_time::second_clock::local_time();
        boost::posix_time::time_duration duration;

        char veribuf_test[VERIBUF_SIZE];

        char p_key[KEY_SIZE+1];
        char *key = p_key;

        bool veribufIsValid = false;
        bool keyFound = false;
        //cout << "Trying random key on CPU Thread "<< i << endl;

        do {
            memcpy(veribuf_test, veribuf, VERIBUF_SIZE);
            keyFound = false;

            make_random_key(key);

            if (s20_crypt((uint8_t *) key, S20_KEYLEN_128, (uint8_t *) nonce, 0, (uint8_t *) veribuf_test, VERIBUF_SIZE) == S20_FAILURE) {
                puts("Error: encryption failed");
                return;
            }

            veribufIsValid = is_valid(veribuf_test);

            if (veribufIsValid) {
                printf("\ndecoded data:\n");
                hexdump(veribuf_test, VERIBUF_SIZE);
                keyFound = true;
                break;
            }

            keysCalculated++;


        } while (!(veribufIsValid || keyFound) && !shutdownRequested);

        if (keyFound) {
            printf("[+] %s is a valid key!\n", key);
            return;
        } else {
            printf("[-] %s is NOT a valid key!\n", key);
        }
}


bool threadShutdownRequested = false;
void tryKey(unsigned int threadNr,
		    char*nonce,
			char*buf,
		    char *keys,
			unsigned long long nrOfKeys,
		    char *keyChars,
		    int *keyToIndexMap,
		    bool *isValid,
			unsigned long long *threadKeysCalculated) {

//	char veribuf_test[VERIBUF_SIZE];

    char *currentKey = keys+threadNr*KEY_SIZE;

    unsigned long long thisThreadKeysCalculated=0;
    bool keyFound = false;

	  uint8_t *key = ((uint8_t *)keys) + (threadNr*(KEY_SIZE));

  while (!keyFound && !threadShutdownRequested)
  {
	  (isValid)[threadNr+1] = false;


	  uint8_t keystream[64];
	  uint8_t n[16] = { 0 };
	  uint32_t i;

	  for (i = 0; i < 8; ++i)
		n[i] = nonce[i];


	  uint8_t *validationBuffer;

	  validationBuffer = ((uint8_t *)buf) + (threadNr*(KEY_SIZE));

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


	  for (int bufPos = 0; bufPos < VERIBUF_SIZE; ++bufPos) {


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




		  if ((isValid)[threadNr+1]==true) {
			  keyFound = true;
			  (isValid)[0] = true; // set first index to true to inducate key was found in one of the threads
		  }



		  thisThreadKeysCalculated++;
	  }


    threadKeysCalculated[threadNr] = thisThreadKeysCalculated;
}



void measureCPUPerformance(unsigned long long nrOfThreads,
									unsigned long long *nrKeysCalculatedResult,
									unsigned long long *nrOfSecondsInTotalMeasured,
									unsigned long long nrSecondsToMeasure = 30) {


	keysCalculated = 0;
    // remove static keyword and you're doomed as the TS doesn't seem to be updated
    static boost::posix_time::ptime beginTs = boost::posix_time::second_clock::local_time();

    boost::posix_time::time_duration duration;

    char veribuf[VERIBUF_SIZE];
    char nonce[8];

    nonce[0] = 0x07;
    nonce[1] = 0x0c;
    nonce[2] = 0x12;
    nonce[3] = 0xf6;
    nonce[4] = 0x79;
    nonce[5] = 0x28;
    nonce[6] = 0x73;
    nonce[7] = 0xcb;

    veribuf[0] = 0x34;
    veribuf[1] = 0x80;
    veribuf[2] = 0x15;
    veribuf[3] = 0x1a;
    veribuf[4] = 0xd1;
    veribuf[5] = 0x76;
    veribuf[6] = 0x5c;
    veribuf[7] = 0x7b;
    veribuf[8] = 0x60;
    veribuf[9] = 0x2b;
    veribuf[10] = 0xe3;
    veribuf[11] = 0xd0;
    veribuf[12] = 0xd0;
    veribuf[13] = 0xae;
    veribuf[14] = 0xf8;
    veribuf[15] = 0xc2;

    unsigned long long nrOfKeys = nrOfThreads;

    char *keys = (char*)malloc(sizeof(char)*KEY_SIZE*nrOfKeys);

    bool veribufIsValid = false;
    bool matches = false;

    unsigned long long keyBlocks = pow(26*2+10,8)/(nrOfKeys);

    char *currentKey = keys;
    for (unsigned long long i=0; i<nrOfKeys;i++){
    	calculate16ByteKeyFromIndex(0+i*keyBlocks, currentKey);
    	currentKey+=KEY_SIZE;
    }

    unsigned long long *threadKeysCalculated = (unsigned long long *)malloc(sizeof(unsigned long long)*nrOfThreads);
    memset(threadKeysCalculated,0, sizeof(unsigned long long)*nrOfThreads);

	vector<boost::thread> threadList;

	bool *result = (bool*)malloc(sizeof(bool)*(nrOfThreads+1));
    memset(result, 0, sizeof(bool)*(nrOfThreads+1));



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

	threadShutdownRequested = false;
	for (unsigned int i=0; i<nrOfThreads; i++) {
		threadList.push_back(boost::thread(tryKey, i, nonce, veribuf, keys,
				nrOfKeys, keyChars,
				keyToIndexMap,
				result,
				threadKeysCalculated));
	}


    do {

        boost::posix_time::ptime now = boost::posix_time::second_clock::local_time();
		duration = (now-beginTs);

		boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
	} while (!(duration.total_seconds()>nrSecondsToMeasure));

    threadShutdownRequested = true;

	for (unsigned int i=0; i<threadList.size(); i++) {
		threadList[i].join();
	}

    keysCalculated = 0;
    for (int i=0; i<nrOfThreads;i++) {
    	keysCalculated+=threadKeysCalculated[i];
    }
    free(threadKeysCalculated);
    free(keys);
    free(result);

	*nrKeysCalculatedResult = keysCalculated;
	*nrOfSecondsInTotalMeasured = duration.total_seconds();

}

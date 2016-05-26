#include <boost/thread.hpp>
#include <boost/container/vector.hpp>
#include "gpu_code.h"

#include <stdio.h>
#include <string.h>

#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */

#include "salsa20.h"
#include "petya.h"

#define VERBOSE 0


#include <iostream>

using namespace std;



void make_random_key(char* key)
{
    size_t charset_len = strlen(KEY_CHARSET);

    memset(key, 'x', KEY_SIZE);

    for (int i = 0; i < KEY_SIZE; i+=4) {
        size_t rand_i1 = rand() % charset_len;
        size_t rand_i2 = rand() % charset_len;
        key[i] = KEY_CHARSET[rand_i1];
        key[i+1] = KEY_CHARSET[rand_i2];
    }
    key[KEY_SIZE] = 0;
}

long nrOfKeysSearched = 0;
char* veribuf;
char* nonce;

bool keyFound = false;

void tryKey(char *key) {
      bool veribufIsValid = false;
      char veribuf_test[VERIBUF_SIZE];
      
    memcpy(veribuf_test, veribuf, VERIBUF_SIZE);


  	nonce[0] = 0x07;
  	nonce[1] = 0x0c;
  	nonce[2] = 0x12;
  	nonce[3] = 0xf6;
  	nonce[4] = 0x79;
  	nonce[5] = 0x28;
  	nonce[6] = 0x73;
  	nonce[7] = 0xcb;

  	veribuf_test[0] = 0x34;
  	veribuf_test[1] = 0x80;
  	veribuf_test[2] = 0x15;
  	veribuf_test[3] = 0x1a;
  	veribuf_test[4] = 0xd1;
  	veribuf_test[5] = 0x76;
  	veribuf_test[6] = 0x5c;
  	veribuf_test[7] = 0x7b;
  	veribuf_test[8] = 0x60;
  	veribuf_test[9] = 0x2b;
  	veribuf_test[10] = 0xe3;
  	veribuf_test[11] = 0xd0;
  	veribuf_test[12] = 0xd0;
  	veribuf_test[13] = 0xae;
  	veribuf_test[14] = 0xf8;
  	veribuf_test[15] = 0xc2;

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







      
      if (s20_crypt((uint8_t *) key, S20_KEYLEN_128, (uint8_t *) nonce, 0, (uint8_t *) veribuf_test, VERIBUF_SIZE) == S20_FAILURE) {
          puts("Error: encryption failed");
          return;
      }
      veribufIsValid = is_valid(veribuf_test);
      
      if (veribufIsValid) {
        printf("[+] %s is a valid key!\n", key);
        return;
      } else {
        printf("[-] %s is NOT a valid key!\n", key);
      }
}


void tryKeyRandom() {

        boost::posix_time::time_duration duration;
        boost::posix_time::ptime beginTs = boost::posix_time::second_clock::local_time();
        

        char veribuf_test[VERIBUF_SIZE];

        char p_key[KEY_SIZE+1];
        char *key = p_key;
        
        bool veribufIsValid = false;
        bool matches = false;
          
        do {
                    
            
            memcpy(veribuf_test, veribuf, VERIBUF_SIZE);
            matches = false;
            
            make_random_key(key);
    

            if (s20_crypt((uint8_t *) key, S20_KEYLEN_128, (uint8_t *) nonce, 0, (uint8_t *) veribuf_test, VERIBUF_SIZE) == S20_FAILURE) {
                puts("Error: encryption failed");
                return;
            }
            
            veribufIsValid = is_valid(veribuf_test);
            
            if (veribufIsValid) {
                printf("\ndecoded data:\n");
                hexdump(veribuf_test, VERIBUF_SIZE);
                matches = true;
                keyFound = true;
                break;
            }
            
            nrOfKeysSearched++;
                        
            if (nrOfKeysSearched%50000000 ==0) {
                boost::posix_time::ptime now = boost::posix_time::second_clock::local_time();  
                duration = (now-beginTs);
                std::cout << "Diff:" << duration.total_seconds() << endl;
                beginTs = boost::posix_time::second_clock::local_time();         
            }
        
        } while (!(veribufIsValid || keyFound)); 
        
        if (matches) {
            printf("[+] %s is a valid key!\n", key);
            return;
        } else {
            printf("[-] %s is NOT a valid key!\n", key);
        }        
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Supply the disk dump as a parameter!\n");
        return -1;
    }
    char* filename = argv[1];
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        printf("Cannot open file %s\n", filename);
        return -1;
    }

    if (is_infected(fp)) {
        printf("[+] Petya FOUND on the disk!\n");
    } else {
        printf("[-] Petya not found on the disk!\n");
        return -1;
    }
    veribuf = fetch_veribuf(fp);
    nonce = fetch_nonce(fp);
    
    if (!nonce || !veribuf) {
        printf("Cannot fetch nonce or veribuf!\n");
        return -1;
    }
    printf("---\n");
    printf("verification data:\n");
    hexdump(veribuf, VERIBUF_SIZE);

    printf("nonce:\n");
    hexdump(nonce,NONCE_SIZE);
    printf("---\n");

    char p_key[KEY_SIZE+1];
    char *key = p_key;
    bool make_random = false;

    



    if (argc >= 3) {
        key = argv[2];
        tryKey(key);
    } else {
        printf("The key will be random!\n");
        srand(time(NULL));
        printf("Please wait, searching key is in progress...\n");
    }
    
    bool GPU = true;
    
    if (GPU) {
        initializeAndCalculate((uint8_t *)nonce,  veribuf);
        return 0;
    } else { // CPU
    
    
        vector<boost::thread> threadList;
    
        for (int i=0; i<10; i++) {
            threadList.push_back(boost::thread(tryKeyRandom));
        }
        
        for (unsigned int i=0; i<threadList.size(); i++) {
            threadList[i].join();
        }
    }

    return -1;
}


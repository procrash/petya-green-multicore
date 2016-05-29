#include <boost/thread.hpp>
#include <boost/container/vector.hpp>
#include <boost/program_options/cmdline.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/filesystem.hpp>
#include <boost/date_time/posix_time/posix_time.hpp> //include all types plus i/o

#include "keyCandidateDistributor.h"

#include <boost/asio.hpp>
#include <csignal>

#include "OptionPrinter.h"

#include "gpu_code.h"

#include <stdio.h>
#include <string.h>

#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */

#include "salsa20.h"
#include "petya.h"

#define VERBOSE 0


#include <iostream>

namespace po = boost::program_options;
using namespace std;



bool shutdownRequested = false;

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

unsigned long nrOfKeysSearched = 0;
char* veribuf;
char* nonce;

bool keyFound = false;

bool tryKey(char *key) {
      bool veribufIsValid = false;
      char veribuf_test[VERIBUF_SIZE];
      
    memcpy(veribuf_test, veribuf, VERIBUF_SIZE);
      
      if (s20_crypt((uint8_t *) key, S20_KEYLEN_128, (uint8_t *) nonce, 0, (uint8_t *) veribuf_test, VERIBUF_SIZE) == S20_FAILURE) {
          puts("Error: encryption failed");
          return false;
      }
      veribufIsValid = is_valid(veribuf_test);
      
      if (veribufIsValid) {
        return true;
      } else {
        return false;
      }
}


void tryKeyRandom(int i) {

	    // remove static keyword and you're doomed as the TS doesn't seem to be updated
	    static boost::posix_time::ptime beginTs = boost::posix_time::second_clock::local_time();
        boost::posix_time::time_duration duration;
        

        char veribuf_test[VERIBUF_SIZE];

        char p_key[KEY_SIZE+1];
        char *key = p_key;
        
        bool veribufIsValid = false;
        bool matches = false;
          
        //cout << "Trying random key on CPU Thread "<< i << endl;

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
            	unsigned long divider = 50000000;
            	// Print estimated time...
                boost::posix_time::ptime now = boost::posix_time::second_clock::local_time();  
                duration = (now-beginTs);
                std:cout << endl;
                std::cout << "Diff:" << duration.total_seconds() << " startTime:" << boost::posix_time::to_simple_string(beginTs) << " endTime:" << boost::posix_time::to_simple_string(now) <<  endl;
                std::cout << "Based upon this performance all keys will be calculated in " << endl;

                unsigned long years = pow(2*26+10,8)/divider*duration.total_seconds() /60/60/24/365;
                unsigned long days = (pow(2*26+10,8)/divider*duration.total_seconds() /60/60/24)-years*365;
                unsigned long hours = (pow(2*26+10,8)/divider*duration.total_seconds() /60/60)-(years*365*24+days*24);
                unsigned long minutes = (pow(2*26+10,8)/divider*duration.total_seconds() /60)-(years*365*24*60+days*24*60+hours*60);

                std::cout << years << " years" << endl;
                std::cout << days << " days" << endl;
                std::cout << hours << " hours" << endl;
                std::cout << minutes << " minutes" << endl;

                beginTs = boost::posix_time::second_clock::local_time();;

                cout << "Updated to: " << boost::posix_time::to_simple_string(beginTs)  << endl;
            }
        

        } while (!(veribufIsValid || keyFound) && !shutdownRequested);
        
        if (matches) {
            printf("[+] %s is a valid key!\n", key);
            return;
        } else {
            printf("[-] %s is NOT a valid key!\n", key);
        }        
}



boost::asio::io_service io_service;
boost::asio::signal_set signals(io_service, SIGINT, SIGTERM);
void handler(
    const boost::system::error_code& error,
    int signal_number)
{

  // cout << "Signal handler" <<endl;

  if (!error)
  {
    // A signal occurred.
	  switch (signal_number) {
	  case SIGTERM:   shutdownRequested = true;
	  	  	  	  	  //cout << "SIGTERM received" << endl;
	  	  	  	  	  break;
	  case SIGINT:   shutdownRequested = true;
	  	  	  	  	  // ctr+c pressed
	  	  	  	  	  //cout << "SIGINT received" << endl;
	  	  	  	  	  break;
	  default:       signals.async_wait(handler);
		  	  	     break;
	  }

//	  cout << "Signal occured" <<endl;
  }

}

void setupSignalHandler() {

	// io_service.poll();

	// Construct a signal set registered for process termination.
	// Start an asynchronous wait for one of the signals to occur.
	//boost::bind(&handler, this);
	signals.async_wait(handler);
	io_service.run();
    // io_service.poll();

}


int main(int argc, char *argv[])
{


	std::string appName = boost::filesystem::basename(argv[0]);

	bool enableCPU;
	bool enableGPU;

	po::options_description commandLineOptions;

	po::options_description generic("Options");
	generic.add_options()
	    ("help,h", "display help message")
		("version,v", "output the version number")
	    ("file", po::value<string>()->required(), "filename which contains disk dump of crypted harddrive (does only need to be the first 57 sectors)")
	    ("gpu", po::bool_switch(&enableGPU)->default_value(false), "keys are calculated on gpu (notice if you specify both option gpu and cpu is used to calculute the keys)")
	    ("cpu", po::bool_switch(&enableCPU)->default_value(true), "keys are calculated on cpu")

		("resume", "resume previous calculation")
		("random,rnd", "use a random key instead of brute force mothod, notice this doesn't allow a resume as wrong keys are not stored")
	    ("key,k", po::value<string>(), "try a specific key")
	    ("selftest,st", "check if algorithms work")
	    ("performance", "provide information about performance")

	;

	po::options_description optionalGPU("Optional GPU Arguments");
	optionalGPU.add_options()
		("gpu_threads", po::value<unsigned int>()->default_value(1024), "number of threads to use on GPU")
	    ("gpu_blocks", po::value<unsigned int>()->default_value(1), "number of blocks to use on GPU")
	    ("gpu_keysCtxSwitch", po::value<unsigned long>()->default_value(10000), "number keys which are calculated on a the gpu before the context switches back to host")
	;

	po::options_description optionalCPU("Optional GPU Arguments");
	optionalCPU.add_options()
	    ("cpu_threads", po::value<unsigned int>()->default_value(10), "nr of threads to use on CPU for CPU calculation")
	;

	po::positional_options_description positionalOptions;
	positionalOptions.add("file", 1);

	commandLineOptions.add(generic).add(optionalCPU).add(optionalGPU);


	po::variables_map vm;

	try {
		// po::store(po::parse_command_line(argc, argv, commandLineOptions), vm);
		po::store(po::command_line_parser(argc, argv).options(commandLineOptions)
		            .positional(positionalOptions).run(), vm);

		po::notify(vm);

		if (vm.count("help")) {
			rad::OptionPrinter::printStandardAppDesc(appName,
															 std::cout,
															 commandLineOptions,
															 &positionalOptions);
			return 1;
		}

		if (vm.count("version")) {
			cout << appName << " Version 1.0" << endl;
			return 0;
		}

		if (vm.count("performance")) {
			cout << "There are " << pow(26*2+10,8) << " candidates to try." << endl;
			cout << "All keys together stored on the harddrive would take " << (unsigned int)((pow(26*2+10,8)*8)/1024/1024/1024/1024) << " terabytes of data [(2*26+10)^8*8)/1 TB]"<< endl;
			cout << "The odds to find the key by guessing is 1 in 218340105584896" << endl << endl;

			cout << "However based upon your current selected configuration and hardware I try to do a rough time estimation for a brute force attack" << endl;

			unsigned long ctxSwitchKeys = vm["gpu_keysCtxSwitch"].as<unsigned long>();
			unsigned long nrThreads = vm["gpu_threads"].as<unsigned int>();
			unsigned long nrBlocks = vm["gpu_blocks"].as<unsigned int>();


			measureGPUPerformance(nrBlocks,
			        nrThreads,
					ctxSwitchKeys);

			return 0;
		}

		char p_key[KEY_SIZE+1];
		char *key = p_key;


		bool selftest = false;

		if (vm.count("selftest")) {
			selftest = true;

			nonce = (char *)malloc(8);
			veribuf = (char *)malloc(VERIBUF_SIZE);

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

			p_key[0] = 'n';
			p_key[1] = 'G';
			p_key[2] = 'u';
			p_key[3] = 'J';
			p_key[4] = 'G';
			p_key[5] = 'b';
			p_key[6] = 'm';
			p_key[7] = 'D';
			p_key[8] = 'u';
			p_key[9] = 'V';
			p_key[10] = 'N';
			p_key[11] = '9';
			p_key[12] = 'X';
			p_key[13] = 'm';
			p_key[14] = 'L';
			p_key[15] = 'a';
			p_key[16] = 0;


			printf("verification data:\n");
			hexdump(veribuf, VERIBUF_SIZE);

			printf("nonce:\n");
			hexdump(nonce,NONCE_SIZE);
			printf("---\n");

			printf("Performing CPU test.....");

			bool verifbusIsValid = tryKey(p_key);
			if (verifbusIsValid) printf(" passed\r\n");
			else printf(" failed\r\n");

			printf("Performing GPU test.....");

			unsigned int gpuThreads = vm["gpu_threads"].as<unsigned int>();;
			unsigned int gpuBlocks = vm["gpu_blocks"].as<unsigned int>();;

			unsigned int nrKeys = gpuThreads*gpuBlocks;
			char *keys = (char *) malloc(nrKeys*sizeof(char)*KEY_SIZE);
			bool *result = (bool *) malloc(nrKeys*sizeof(bool)*KEY_SIZE);

			bool gpuPassed = true;
			for (int i=0; i<nrKeys; i++) {
				memset(keys, 0, nrKeys*sizeof(char)*KEY_SIZE);
				memcpy(keys+i*KEY_SIZE, p_key, KEY_SIZE);
				tryKeysGPUSingleShot(gpuBlocks, gpuThreads, (uint8_t *)nonce, veribuf, keys, nrKeys, result);

				for (int j=0; j<nrKeys;j++) {
					if (j!=i && (result[j]==true)) {
						gpuPassed = false;
						break;
					}
					if (j==i && (result[j]==false)) {
						gpuPassed = false;
						break;
					}
				}
			}

			if (gpuPassed) printf(" passed\r\n"); else printf(" failed\r\n");


			printf("Checking key generator...");
			srand(time(NULL));

			unsigned long randomKeyIndex;
			unsigned long resultKeyIndex;

			bool checkOk = true;
			for (unsigned long i=0; i<10000; i++) {
				char key[17];
				randomKeyIndex = rand() % (unsigned long)(pow(2*26+10,8));

				calculate16ByteKeyFromIndex(randomKeyIndex, key);
				resultKeyIndex = calculateIndexFrom16ByteKey(key);

				if (resultKeyIndex!=randomKeyIndex) {
					checkOk = false;
					break;
				}
			}

			char keyZeroed[17];
			memset(keyZeroed,0,17);
			memcpy(keyZeroed, key, 16);

			if (checkOk) cout << "passed\r\n"; else cout << "failed" << endl; // , random key was "<<keyZeroed << " keyIndex is "<<randomKeyIndex << " result is " <<resultKeyIndex << endl;


			free(nonce);
			free(veribuf);

			return 0;
		}


		if (!vm.count("file")) {
			rad::OptionPrinter::printStandardAppDesc(appName,
															 std::cout,
															 commandLineOptions,
															 NULL /*&positionalOptions*/);

			return -1;
		}



		string filenameStr = vm["file"].as<string>();


		const char* filename = filenameStr.c_str(); // argv[1];
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




		if (vm.count("key")) {
			string keyStr = vm["key"].as<string>();
			key = (char *)keyStr.c_str();
			bool veribufIsValid = tryKey(key);

   		    if (veribufIsValid) {
			  printf("[+] %s is a valid key!\n", key);
		    } else {
			  printf("[-] %s is NOT a valid key!\n", key);
		    }

			return 0;
		}


		boost::thread signalHUPThread(setupSignalHandler);

		if (vm.count("random")) {
			srand(time(NULL));
		}


		if (enableCPU && enableGPU) {

			return 0;
		}
		else
		if (enableCPU) {
			vector<boost::thread> threadList;

			unsigned int nrCPUThreads = vm["cpu_threads"].as<unsigned int>();

			for (unsigned int i=0; i<nrCPUThreads; i++) {
		        cout << "Trying random key on CPU Thread "<< (i+1) << endl;
				threadList.push_back(boost::thread(tryKeyRandom, i));
				//boost::this_thread::sleep(boost::posix_time::milliseconds(10));
			}


			for (unsigned int i=0; i<threadList.size(); i++) {
				threadList[i].join();
			}

			return 0;
		}
		else
		if (enableGPU) {
			initializeAndCalculate((uint8_t *)nonce,  veribuf);
			return 0;
		}


		 //<< vm["file"].as<string>() << ".\n";


	}
	catch (std::exception& ex) {

		rad::OptionPrinter::printStandardAppDesc(appName,
		                                                 std::cout,
		                                                 commandLineOptions,
		                                                 NULL ); // &positionalOptions
	}

	return -1;




}


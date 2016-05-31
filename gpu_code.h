#pragma once
void initializeAndCalculate(uint8_t nonce_hc[8],  char *verificationBuffer_hc);
void tryKeysGPUSingleShot(unsigned int nrBlocks,
		        unsigned int nrThreads,
				uint8_t nonce_hc[8],
		        char *verificationBuffer,
				char *keys,
				unsigned long long nrKeys,
				bool *result);

bool tryKeysGPUMultiShot(unsigned int nrBlocks,
		        unsigned int nrThreads,
				uint8_t nonce_hc[8],
		        char *verificationBuffer,
				char*keys,
				unsigned long long nrKeys,
				unsigned long long keysBeforeContextSwitch,
				unsigned long long keysInTotalToCalculate,
				bool supressOutput, 
				bool* shutdownRequested);


void measureGPUPerformance(unsigned int nrBlocks,
		        unsigned int nrThreads,
				unsigned long long keysBeforeContextSwitch,
				unsigned long long *nrKeysCalculatedResult,
				unsigned long long *nrOfSecondsInTotalMeasured,
				bool* shutdownRequested,
				int nrSecondsToMeasure = 30);

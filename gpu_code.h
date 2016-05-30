#pragma once
void initializeAndCalculate(uint8_t nonce_hc[8],  char *verificationBuffer_hc);
void tryKeysGPUSingleShot(unsigned int nrBlocks,
		        unsigned int nrThreads,
				uint8_t nonce_hc[8],
		        char *verificationBuffer,
				char *keys,
				unsigned long long nrKeys,
				bool *result);

void tryKeysGPUMultiShot(unsigned int nrBlocks,
		        unsigned int nrThreads,
				uint8_t nonce_hc[8],
		        char *verificationBuffer,
				char*keys,
				unsigned long long nrKeys,
				unsigned long long keysBeforeContextSwitch,
				unsigned long long keysInTotalToCalculate);

void measureGPUPerformance(unsigned int nrBlocks,
		        unsigned int nrThreads,
				unsigned long long keysBeforeContextSwitch,
				unsigned long long *nrKeysCalculatedResult,
				unsigned long long *nrOfSecondsInTotalMeasured,
				int nrSecondsToMeasure = 30);

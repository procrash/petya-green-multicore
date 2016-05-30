#pragma once
void initializeAndCalculate(uint8_t nonce_hc[8],  char *verificationBuffer_hc);
void tryKeysGPUSingleShot(unsigned int nrBlocks,
		        unsigned int nrThreads,
				uint8_t nonce_hc[8],
		        char *verificationBuffer,
				char *keys,
				unsigned long nrKeys,
				bool *result);

void tryKeysGPUMultiShot(unsigned int nrBlocks,
		        unsigned int nrThreads,
				uint8_t nonce_hc[8],
		        char *verificationBuffer,
				char*keys,
				unsigned long nrKeys,
				unsigned long keysBeforeContextSwitch,
				unsigned long keysInTotalToCalculate);

void measureGPUPerformance(unsigned int nrBlocks,
		        unsigned int nrThreads,
				unsigned long keysBeforeContextSwitch,
				unsigned long *nrKeysCalculatedResult,
				unsigned long *nrOfSecondsInTotalMeasured,
				int nrSecondsToMeasure = 30);

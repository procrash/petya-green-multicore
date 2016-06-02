#pragma once

void queryDeviceInfo();

// void initializeAndCalculate(uint8_t nonce_hc[8],  char *verificationBuffer_hc);
void tryKeysGPUSingleShot(unsigned int nrBlocks,
		        unsigned int nrThreads,
				uint8_t nonce_hc[8],
		        char *verificationBuffer,
				char *keys,
				uint64_t nrKeys,
				bool *result);

bool tryKeysGPUMultiShot(unsigned int nrBlocks,
		        unsigned int nrThreads,
				uint8_t nonce_hc[8],
		        char *verificationBuffer,
				char*keys,
				uint64_t nrKeys,
				uint64_t keysBeforeContextSwitch,
				uint64_t keysInTotalToCalculate,
				bool supressOutput, 
				bool* shutdownRequested);


void measureGPUPerformance(unsigned int nrBlocks,
		        unsigned int nrThreads,
				uint64_t keysBeforeContextSwitch,
				uint64_t *nrKeysCalculatedResult,
				uint64_t *nrOfSecondsInTotalMeasured,
				bool* shutdownRequested,
				int nrSecondsToMeasure = 30);

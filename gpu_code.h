#pragma once

struct GPUMultiShotArguments{
	uint64_t nrBlocks;
	uint64_t nrThreads;
	uint8_t nonce_hc[8];
	char *verificationBuffer;
	char*keys;
	uint64_t nrKeys;
	uint64_t keysBeforeContextSwitch;
	uint64_t keysInTotalToCalculate;
	bool supressOutput;
	bool* shutdownRequested;
};

void queryDeviceInfo(uint64_t* nrOfBlocks, uint64_t* nrThreads);

// void initializeAndCalculate(uint8_t nonce_hc[8],  char *verificationBuffer_hc);
void tryKeysGPUSingleShot(uint64_t nrBlocks,
				uint64_t nrThreads,
				uint8_t nonce_hc[8],
		        char *verificationBuffer,
				char *keys,
				uint64_t nrKeys,
				bool *result);

bool tryKeysGPUMultiShot(const GPUMultiShotArguments &argument);

bool tryKeysGPUMultiShot(uint64_t nrBlocks,
				uint64_t nrThreads,
				uint8_t nonce_hc[8],
		        char *verificationBuffer,
				char*keys,
				uint64_t nrKeys,
				uint64_t keysBeforeContextSwitch,
				uint64_t keysInTotalToCalculate,
				bool supressOutput, 
				bool* shutdownRequested);



void measureGPUPerformance(uint64_t nrBlocks,
				uint64_t nrThreads,
				uint64_t keysBeforeContextSwitch,
				uint64_t *nrKeysCalculatedResult,
				uint64_t *nrOfSecondsInTotalMeasured,
				bool* shutdownRequested,
				int nrSecondsToMeasure);

#pragma once

void tryKeyRandom(int i, char *nonce, char*veribuf);
void measureCPUPerformance(uint64_t nrOfThreads,
						   uint64_t *nrKeysCalculatedResult,
						   uint64_t *nrOfSecondsInTotalMeasured,
						   bool* shutdownRequested,
						   uint64_t nrSecondsToMeasure = 30);

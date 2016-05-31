#pragma once

void tryKeyRandom(int i, char *nonce, char*veribuf);
void measureCPUPerformance(unsigned long long nrOfThreads,
						   unsigned long long *nrKeysCalculatedResult,
						   unsigned long long *nrOfSecondsInTotalMeasured,
						   bool* shutdownRequested,
						   unsigned long long nrSecondsToMeasure = 30);

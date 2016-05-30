#pragma once

void tryKeyRandom(int i, char *nonce, char*veribuf);
void measureCPUPerformance(unsigned long nrOfThreads,
						   unsigned long *nrKeysCalculatedResult,
						   unsigned long *nrOfSecondsInTotalMeasured,
						   unsigned long nrSecondsToMeasure = 30);

#pragma once

#include <map>
#include<math.h>
#include <iostream>
#include "petya.h"

// -- 16 Byte Key funtions...

inline void calculate16ByteKeyFromIndex(unsigned long index, char*key) {
	// cc??cc??cc??cc??

	char keyChars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	// char key[17];

	memset(key, 'x', 16);

	int posToKey[] = {13,12,9,8,5,4,1,0};

	for (int i=0; i<8; i++) {
		int characterNumber = index % (26*2+10);
		key[posToKey[i]] = keyChars[characterNumber];
		//std::cout << "remainder: " <<  index % (26*2+10) << index << std::endl;
		index /= (26*2+10);
	}

	// key[16] = 0;

	//char * result = (char *)malloc(17);
	//printf("Key calculated from index is: %s\r\n", &key[0]);
	// memcpy(result, key, 17);
	//return result;
}


inline unsigned long calculateIndexFrom16ByteKey(char*key) {
	// cc??cc??cc??cc??

	unsigned long resultIndex = 0;

	char keyChars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	//                           1123456789213456789312345678941234567895123456789612
	std::map<char, int> charToKeyCharsIndex;


	for (int i=0; i<255;i++) {
		charToKeyCharsIndex[i] = 0;
		for (int j=0; j<sizeof(keyChars); j++) {
			if (keyChars[j]==(char)i) charToKeyCharsIndex[(char)i] = j;
		}
	}

	int posToKey[] = {13,12,9,8,5,4,1,0};



	for (int i=0; i<8; i++) {
		char c = key[posToKey[i]];
		unsigned long idx = charToKeyCharsIndex[c];

		unsigned long tmp = idx*pow((2*26+10),i);;

		// std::cout << idx << " " << tmp << std::endl;
		resultIndex +=  tmp;
	}
	return resultIndex;
}


inline void nextKey16Byte(char *key) {
	char keyChars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	std::map<char, int> keyToIndexMap;

	/*
	char oldKeyDebug[KEY_SIZE+1];
	memcpy(oldKeyDebug, key, KEY_SIZE);
	oldKeyDebug[KEY_SIZE] = 0;
	*/

	for (int i=0; i<sizeof(keyChars); i++) {
		keyToIndexMap[keyChars[i]]=i;
	}

	int posToKey[] = {13,12,9,8,5,4,1,0};

	for (int i=0; i<8; i++) {
		int idx = keyToIndexMap[key[posToKey[i]]];
		idx++;
		idx %=sizeof(keyChars);
		key[posToKey[i]] = keyChars[idx];

		if (idx!=0) break;
	}

	/*
	char keyDebug[KEY_SIZE+1];
	memcpy(keyDebug, key, KEY_SIZE);
	keyDebug[KEY_SIZE] = 0;
	printf("Next key of %s is %s\r\n",oldKeyDebug, keyDebug);
	*/
}

inline void make_random_key(char* key)
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


#ifndef RNENCRYPTOR_H
#define RNENCRYPTOR_H

#include "rncryptor.h"

#include <iostream>
using std::string;

class RNEncryptor : public RNCryptor {
	string generateRandomString(int length);
	string addPKCS7Padding(string plaintext, int blockSize);
	public:
		string encrypt(string plaintext, string password, RNCryptorSchema schemaVersion = SCHEMA_2);
};

#endif

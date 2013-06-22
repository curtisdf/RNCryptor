
#include "rnencryptor.h"

#include <iostream>
using std::cout;
using std::endl;

#include <sstream>
using std::stringstream;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CTR_Mode;

#include "cryptopp/filters.h"
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

string RNEncryptor::encrypt(string plaintext, string password, RNCryptorSchema schemaVersion)
{
	this->configureSettings(schemaVersion);

	RNCryptorPayloadComponents components;
	components.schema = (char)schemaVersion;
	components.options = (char)this->options;
	components.salt = this->generateRandomString(this->saltLength);
	components.hmacSalt = this->generateRandomString(this->saltLength);
	components.iv = this->generateRandomString(this->ivLength);

	/*
	cout << endl;
	cout << "--- " << __func__ << " Components ---" << endl;
	cout << "Schema:     " << this->hex_encode(components.schema) << endl;
	cout << "Options:    " << this->hex_encode(components.options) << endl;
	cout << "Salt:       " << this->hex_encode(components.salt) << endl;
	cout << "HMAC Salt:  " << this->hex_encode(components.hmacSalt) << endl;
	cout << "IV:         " << this->hex_encode(components.iv) << endl;
	*/

	SecByteBlock key = this->generateKey(components.salt, password);

	switch (this->aesMode) {
		case MODE_CTR: {
			components.ciphertext = this->aesCtrLittleEndianCrypt(plaintext, key, components.iv);
			break;
		}
		case MODE_CBC: {

			string paddedPlaintext = this->addPKCS7Padding(plaintext, components.iv.length());
//cout << "Padded plaintext length: " << paddedPlaintext.length() << endl;

			CBC_Mode<AES>::Encryption encryptor;
			encryptor.SetKeyWithIV(key.BytePtr(), key.size(), (const byte *)components.iv.data());

			StringSource(paddedPlaintext, true,
				// StreamTransformationFilter adds padding as required.
				new StreamTransformationFilter(encryptor,
					new StringSink(components.ciphertext),
					StreamTransformationFilter::NO_PADDING
				)
			);

			break;
		}
	}

	stringstream binaryData;
	binaryData << components.schema;
	binaryData << components.options;
	binaryData << components.salt;
	binaryData << components.hmacSalt;
	binaryData << components.iv;
	binaryData << components.ciphertext;

	//cout << "Hex encoded: " << this->hex_encode(binaryData.str()) << endl;

	components.hmac = this->generateHmac(components, password);

	binaryData << components.hmac;

	//cout << "Ciphertext: " << this->hex_encode(components.ciphertext) << endl;
	//cout << "HMAC:       " << this->hex_encode(components.hmac) << endl;
	//cout << endl;

	return this->base64_encode(binaryData.str());
}

string RNEncryptor::addPKCS7Padding(string plaintext, int blockSize)
{
	string paddedPlaintext;
	paddedPlaintext.assign(plaintext.begin(), plaintext.end());

	int padSize = blockSize - plaintext.length() % blockSize;

	stringstream padStream;
	for (int i = 0; i < padSize; i++) {
		padStream << (char)padSize;
	}
	paddedPlaintext.append(padStream.str());

	return paddedPlaintext;
}

string RNEncryptor::generateRandomString(int length)
{
	//cout << __func__ << "(" << length << ")" << endl;

	AutoSeededRandomPool prng;

	SecByteBlock randomBytes(length);
	prng.GenerateBlock(randomBytes, randomBytes.size());

	byte * randomData = randomBytes.BytePtr();
	stringstream randomStream;
	for (int i = 0; i < (int)randomBytes.size(); i++) {
		randomStream << randomData[i];
	}
	return randomStream.str();
}


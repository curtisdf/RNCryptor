#include "encrypt.h"

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

	SecByteBlock key = this->generateKey(components.salt, password);

	switch (this->aesMode) {
		case MODE_CTR: {
			components.ciphertext = this->aesCtrLittleEndianCrypt(plaintext, key, components.iv);
			break;
		}
		case MODE_CBC: {

			string paddedPlaintext = this->addPKCS7Padding(plaintext, components.iv.length());

			CBC_Mode<AES>::Encryption encryptor;
			encryptor.SetKeyWithIV(key.BytePtr(), key.size(), (const byte *)components.iv.data());

			StringSource(paddedPlaintext, true,
				new StreamTransformationFilter(
					encryptor,
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

	components.hmac = this->generateHmac(components, password);

	binaryData << components.hmac;

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


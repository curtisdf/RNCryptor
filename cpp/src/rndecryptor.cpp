#include "rndecryptor.h"

#include <iostream>
using std::cout;
using std::endl;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CTR_Mode;

#include "cryptopp/filters.h"
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;


string RNDecryptor::decrypt(string encryptedBase64, string password)
{
	RNCryptorPayloadComponents components = this->unpackEncryptedBase64Data(encryptedBase64);

	/*
	cout << endl;
	cout << "--- " << __func__ << " Components (as parsed from encrypted input) ---" << endl;
	cout << "Schema:     " << this->hex_encode(components.schema) << endl;
	cout << "Options:    " << this->hex_encode(components.options) << endl;
	cout << "Salt:       " << this->hex_encode(components.salt) << endl;
	cout << "HMAC Salt:  " << this->hex_encode(components.hmacSalt) << endl;
	cout << "IV:         " << this->hex_encode(components.iv) << endl;
	cout << "Ciphertext: " << this->hex_encode(components.ciphertext) << endl;
	cout << "HMAC:       " << this->hex_encode(components.hmac) << endl;
	cout << endl;
	*/

	if (!this->hmacIsValid(components, password)) {
		//cout << "HMAC mismatch" << endl;
		return "";
	}

	SecByteBlock key = this->generateKey(components.salt, password);

	string encrypted = components.ciphertext;
	string plaintext = "";

	switch (this->aesMode) {
		case MODE_CTR: {
			plaintext = this->aesCtrLittleEndianCrypt(encrypted, key, components.iv);
			break;
		}
		case MODE_CBC: {

			CBC_Mode<AES>::Decryption decryptor;
			decryptor.SetKeyWithIV((const byte *)key.data(), key.size(), (const byte *)components.iv.data());

			StringSource(components.ciphertext, true,
				// StreamTransformationFilter removes padding as required
				new StreamTransformationFilter(decryptor,
					new StringSink(plaintext),
					StreamTransformationFilter::PKCS_PADDING
				)
			);

			break;
		}
	}
//cout << "Decrypted: " << plaintext << endl;

	return plaintext;
}

RNCryptorPayloadComponents RNDecryptor::unpackEncryptedBase64Data(string encryptedBase64)
{
	string binaryData = RNCryptor::base64_decode(encryptedBase64);

	RNCryptorPayloadComponents components;
	int offset = 0;

	components.schema = binaryData[0];
	//components.schema = (RNCryptorSchema)binaryData[0];
	offset++;

	this->configureSettings((RNCryptorSchema)binaryData[0]);

	components.options = binaryData[1];
	//components.options = (RNCryptorOptions)binaryData[1];
	offset++;

	components.salt = binaryData.substr(offset, this->saltLength);
	offset += this->saltLength;

	components.hmacSalt = binaryData.substr(offset, this->saltLength);
	offset += this->saltLength;

	components.iv = binaryData.substr(offset, this->ivLength);
	offset += this->ivLength;

	components.header_length = offset;

	components.ciphertext = binaryData.substr(components.header_length, binaryData.length() - this->hmac_length - components.header_length);
	components.hmac = binaryData.substr(binaryData.length() - this->hmac_length);

	return components;
}

bool RNDecryptor::hmacIsValid(RNCryptorPayloadComponents components, string password)
{
	return (components.hmac == this->generateHmac(components, password));
}

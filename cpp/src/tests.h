#include <string>
using std::string;

#include "base.h"

class RNCryptorTests {
	int completedTests;
	int failedTests;
	int nonImplementedTests;
	int passedTests;

	void performSymmetricTest(string functionName, string plaintext, string password);
	void performSymmetricTestWithExplicitSchema(string functionName, string plaintext, string password, RNCryptorSchema schemaVersion);

	void performDecryptionTest(string functionName, string encrypted, string expected, string password);

	void performEncryptionTest(string functionName, string plaintext, string password);
	void performEncryptionTestWithExplicitSchema(string functionName, string plaintext, string password, RNCryptorSchema schemaVersion);
	void performEncryptionTestWithSchemaCheck(string functionName, string plaintext, string password, RNCryptorSchema schemaVersion);

	void reportSuccess(string functionName, bool success);
	void reportStatus(string functionName, string status);
	void reportStatusNotImplemented(string functionName);

	// RNCryptor Tests
	void testCanDecryptSelfEncryptedDefaultVersion();
	void testCanDecryptSelfEncryptedStringEqualToBlockSizeMultiple();
	void testCanDecryptSelfEncryptedVersion0();
	void testCanDecryptSelfEncryptedVersion1();
	void testCanDecryptSelfEncryptedVersion2();
	void testCanDecryptLongText();
	void testCannotUseWithUnsupportedSchemaVersions();

	// RNDecryptor Tests
	void testCanDecryptIosEncryptedVersion0WithPlaintextLengthLessThanOneBlock();
	void testCanDecryptIosEncryptedVersion0WithPlaintextReallyLong();
	void testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyOneBlock();
	void testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyTwoBlocks();
	void testCanDecryptIosEncryptedVersion0WithPlaintextLengthNotOnBlockInterval();
	void testCanDecryptIosEncryptedVersion1WithPlaintextReallyLong();
	void testCanDecryptIosEncryptedVersion1WithPlaintextLengthExactlyOneBlock();
	void testCanDecryptIosEncryptedVersion1WithPlaintextLengthNotOnBlockInterval();
	void testCanDecryptIosEncryptedVersion2WithPlaintextReallyLong();
	void testCanDecryptIosEncryptedVersion2WithPlaintextLengthExactlyOneBlock();
	void testCanDecryptIosEncryptedVersion2WithPlaintextLengthNotOnBlockInterval();
	void testDecryptingWithBadPasswordFails();

	// RNEncryptor Tests
	void testCanEncryptWithDefaultVersion();
	void testCanEncryptWithVersion0();
	void testCanEncryptWithVersion1();
	void testCanEncryptWithVersion2();
	void testSelfEncryptedVersion0VectorIsVersion0();
	void testSelfEncryptedVersion1VectorIsVersion1();
	void testSelfEncryptedVersion2VectorIsVersion2();

	public:
		RNCryptorTests();
		void run();
};

using System;

namespace RNCryptor
{
	public class TestRunner
	{
		private int completedTests = 0;
		private int failedTests = 0;
		private int nonImplementedTests = 0;
		private int passedTests = 0;

		public void run ()
		{
			// RNCryptor Tests
			this.testCanDecryptSelfEncryptedDefaultVersion();
			this.testCanDecryptSelfEncryptedStringEqualToBlockSizeMultiple();
			this.testCanDecryptSelfEncryptedVersion0();
			this.testCanDecryptSelfEncryptedVersion1();
			this.testCanDecryptSelfEncryptedVersion2();
			this.testCanDecryptLongText();
			this.testCannotUseWithUnsupportedSchemaVersions();
			
			// Decryptor Tests
			this.testCanDecryptIosEncryptedVersion0WithPlaintextLengthLessThanOneBlock();
			this.testCanDecryptIosEncryptedVersion0WithPlaintextReallyLong();
			this.testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyOneBlock();
			this.testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyTwoBlocks();
			this.testCanDecryptIosEncryptedVersion0WithPlaintextLengthNotOnBlockInterval();
			this.testCanDecryptIosEncryptedVersion1WithPlaintextReallyLong();
			this.testCanDecryptIosEncryptedVersion1WithPlaintextLengthExactlyOneBlock();
			this.testCanDecryptIosEncryptedVersion1WithPlaintextLengthNotOnBlockInterval();
			this.testCanDecryptIosEncryptedVersion2WithPlaintextReallyLong();
			this.testCanDecryptIosEncryptedVersion2WithPlaintextLengthExactlyOneBlock();
			this.testCanDecryptIosEncryptedVersion2WithPlaintextLengthNotOnBlockInterval();
			this.testDecryptingWithBadPasswordFails();

			// Encryptor Tests
			this.testCanEncryptWithDefaultVersion();
			this.testCanEncryptWithVersion0();
			this.testCanEncryptWithVersion1();
			this.testCanEncryptWithVersion2();
			this.testSelfEncryptedVersion0VectorIsVersion0();
			this.testSelfEncryptedVersion1VectorIsVersion1();
			this.testSelfEncryptedVersion2VectorIsVersion2();

			Console.WriteLine ();

			if (this.passedTests != this.completedTests) {
				Console.WriteLine ("ERROR (" + this.completedTests + " tests, " + this.passedTests + " passed, " + this.failedTests + " failed, " + this.nonImplementedTests + " unimplemented)");
			} else {
				Console.WriteLine ("OK (" + this.passedTests + " tests)");
			}
			Console.WriteLine();
		}

		private void testCanDecryptSelfEncryptedDefaultVersion() {
			this.performSymmetricTest(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A);
		}
		
		private void testCanDecryptSelfEncryptedStringEqualToBlockSizeMultiple() {
			this.performSymmetricTest(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT_V2_BLOCKSIZE, TestStrings.SAMPLE_PASSWORD_A);
		}
		
		private void testCanDecryptSelfEncryptedVersion0() {
			this.performSymmetricTestWithExplicitSchema(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V0);
		}
		
		private void testCanDecryptSelfEncryptedVersion1() {
			this.performSymmetricTestWithExplicitSchema(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V1);
		}
		
		private void testCanDecryptSelfEncryptedVersion2() {
			this.performSymmetricTestWithExplicitSchema(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V2);
		}
		
		private void testCanDecryptLongText() {
			//this.performSymmetricTest(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.PLAINTEXT_REALLY_LONG, TestStrings.SAMPLE_PASSWORD_A);
		}
		
		private void testCannotUseWithUnsupportedSchemaVersions() {
			
			Encryptor encryptor = new Encryptor();
			string encryptedB64 = encryptor.encrypt(TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A);

			Console.WriteLine ("TODO: Figure out how to change the first byte to ASCII '3'");
			// 1. decode encryptedB64
			// 2. change the first byte to ASCII "3"
			// 3. encode it back to B64

			// TEMPORARY
			string encryptedV3 = encryptedB64;

			Decryptor decryptor = new Decryptor();
			string decrypted = decryptor.decrypt(encryptedV3, TestStrings.SAMPLE_PASSWORD_A);

			this.reportSuccess(System.Reflection.MethodBase.GetCurrentMethod().Name, decrypted == "");
		}
		
		// Decryptor Tests
		private void testCanDecryptIosEncryptedVersion0WithPlaintextLengthLessThanOneBlock() {
			this.performDecryptionTest(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V0_LESS_THAN_ONE_BLOCK, TestStrings.PLAINTEXT_V0_LESS_THAN_ONE_BLOCK, TestStrings.IOS_PASSWORD);
		}

		private void testCanDecryptIosEncryptedVersion0WithPlaintextReallyLong() {
			//this.performDecryptionTest(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V0_REALLY_LONG, TestStrings.PLAINTEXT_REALLY_LONG, TestStrings.IOS_PASSWORD);
		}
		
		private void testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyOneBlock() {
			this.performDecryptionTest(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V0_EXACTLY_ONE_BLOCK, TestStrings.PLAINTEXT_V0_EXACTLY_ONE_BLOCK, TestStrings.IOS_PASSWORD);
		}
		
		private void testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyTwoBlocks() {
			this.performDecryptionTest(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V0_EXACTLY_TWO_BLOCKS, TestStrings.PLAINTEXT_V0_EXACTLY_TWO_BLOCKS, TestStrings.IOS_PASSWORD);
		}
		
		private void testCanDecryptIosEncryptedVersion0WithPlaintextLengthNotOnBlockInterval() {
			this.performDecryptionTest(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V0_NON_BLOCK_INTERVAL, TestStrings.PLAINTEXT_V0_NON_BLOCK_INTERVAL, TestStrings.IOS_PASSWORD);
		}
		
		private void testCanDecryptIosEncryptedVersion1WithPlaintextReallyLong() {
			//this.performDecryptionTest(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V1_REALLY_LONG, TestStrings.PLAINTEXT_REALLY_LONG, TestStrings.IOS_PASSWORD);
		}
		
		private void testCanDecryptIosEncryptedVersion1WithPlaintextLengthExactlyOneBlock() {
			this.performDecryptionTest(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V1_EXACTLY_ONE_BLOCK, TestStrings.PLAINTEXT_V1_EXACTLY_ONE_BLOCK, TestStrings.IOS_PASSWORD);
		}
		
		private void testCanDecryptIosEncryptedVersion1WithPlaintextLengthNotOnBlockInterval() {
			this.performDecryptionTest(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V1_NON_BLOCK_INTERVAL, TestStrings.PLAINTEXT_V1_NON_BLOCK_INTERVAL, TestStrings.IOS_PASSWORD);
		}
		
		private void testCanDecryptIosEncryptedVersion2WithPlaintextReallyLong() {
			//this.performDecryptionTest(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V2_REALLY_LONG, TestStrings.PLAINTEXT_REALLY_LONG, TestStrings.IOS_PASSWORD);
		}
		
		private void testCanDecryptIosEncryptedVersion2WithPlaintextLengthExactlyOneBlock() {
			this.performDecryptionTest(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V2_EXACTLY_ONE_BLOCK, TestStrings.PLAINTEXT_V2_EXACTLY_ONE_BLOCK, TestStrings.IOS_PASSWORD);
		}
		
		private void testCanDecryptIosEncryptedVersion2WithPlaintextLengthNotOnBlockInterval() {
			this.performDecryptionTest(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V2_NON_BLOCK_INTERVAL, TestStrings.PLAINTEXT_V2_NON_BLOCK_INTERVAL, TestStrings.IOS_PASSWORD);
		}

		private void testDecryptingWithBadPasswordFails() {
			Decryptor cryptor = new Decryptor();
			string decrypted = cryptor.decrypt(TestStrings.IOS_ENCRYPTED_V2_NON_BLOCK_INTERVAL, "bad-password");

			this.reportSuccess(System.Reflection.MethodBase.GetCurrentMethod().Name, decrypted == "");
		}
		
		// Encryptor Tests
		
		private void testCanEncryptWithDefaultVersion() {
			this.performEncryptionTest(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A);
		}
		
		private void testCanEncryptWithVersion0() {
			this.performEncryptionTestWithExplicitSchema(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V0);
		}
		
		private void testCanEncryptWithVersion1() {
			this.performEncryptionTestWithExplicitSchema(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V1);
		}
		
		private void testCanEncryptWithVersion2() {
			this.performEncryptionTestWithExplicitSchema(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V2);
		}
		
		private void testSelfEncryptedVersion0VectorIsVersion0() {
			this.performEncryptionTestWithSchemaCheck(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V0);
		}
		
		private void testSelfEncryptedVersion1VectorIsVersion1() {
			this.performEncryptionTestWithSchemaCheck(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V1);
		}
		
		private void testSelfEncryptedVersion2VectorIsVersion2() {
			this.performEncryptionTestWithSchemaCheck(System.Reflection.MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V2);
		}
		
		private void performSymmetricTest(string functionName, string plaintext, string password)
		{
			Encryptor encryptor = new Encryptor();
			string encryptedB64 = encryptor.encrypt(plaintext, password);

			Decryptor decryptor = new Decryptor();
			string decrypted = decryptor.decrypt(encryptedB64, password);

			this.reportSuccess(functionName, decrypted == plaintext);
		}
		
		private void performSymmetricTestWithExplicitSchema(string functionName, string plaintext, string password, Schema schemaVersion)
		{
			Encryptor encryptor = new Encryptor();
			string encryptedB64 = encryptor.encrypt(plaintext, password, schemaVersion);

			Decryptor decryptor = new Decryptor();
			string decrypted = decryptor.decrypt(encryptedB64, password);

			this.reportSuccess(functionName, decrypted == plaintext);
		}
		
		
		private void performDecryptionTest(string functionName, string encrypted, string expected, string password)
		{
			Decryptor cryptor = new Decryptor();
			string decrypted = cryptor.decrypt(encrypted, password);

			this.reportSuccess(functionName, decrypted == expected);
		}
		
		private void performEncryptionTest(string functionName, string plaintext, string password)
		{
			Encryptor cryptor = new Encryptor();
			string encrypted = cryptor.encrypt(plaintext, password);
			
			this.reportSuccess(functionName, encrypted != "" && encrypted != plaintext);
		}
		
		private void performEncryptionTestWithExplicitSchema(string functionName, string plaintext, string password, Schema schemaVersion)
		{
			Encryptor cryptor = new Encryptor();
			string encrypted = cryptor.encrypt(plaintext, password, schemaVersion);
			
			this.reportSuccess(functionName, encrypted != "" && encrypted != plaintext);
		}
		
		private void performEncryptionTestWithSchemaCheck(string functionName, string plaintext, string password, Schema schemaVersion)
		{
			Encryptor cryptor = new Encryptor();
			string encryptedB64 = cryptor.encrypt(plaintext, password, schemaVersion);

			Console.WriteLine ("TODO: Must base64 decode this string!");
			string encrypted = encryptedB64;

			Schema actualSchemaVersion = (Schema)encrypted[0];

			this.reportSuccess(functionName, actualSchemaVersion == schemaVersion);
		}
		
		private void reportSuccess(string functionName, bool success)
		{
			string statusText;
			if (success) {
				this.passedTests++;
				statusText = "OK";
				
			} else {
				this.failedTests++;
				statusText = "FAILED";
			}
			this.reportStatus(functionName, statusText);
		}
		
		private void reportStatusNotImplemented(string functionName)
		{
			this.reportStatus(functionName, "not implemented");
			this.nonImplementedTests++;
		}

		private void reportStatus(string functionName, string status)
		{
			this.completedTests++;

			const int firstColumnWidth = 80;
			string output = functionName + " ";

			for (int i = functionName.Length + 2; i < firstColumnWidth; i++) {
				output += ".";
			}
			
			output += " " + status;

			Console.WriteLine (output);
		}
	}
}


using System;

namespace RNCryptor
{
	public class Encryptor : Cryptor
	{
		private Schema defaultSchemaVersion = Schema.V2;

		public string encrypt (string plaintext, string password)
		{
			return this.encrypt (plaintext, password, this.defaultSchemaVersion);
		}

		public string encrypt (string plaintext, string password, Schema schemaVersion)
		{
			Console.WriteLine ("TODO: Make Encryptor.encrypt() work");
			string encrypted = (char)2 + (char)0 + "abcdefgh" + "ABCDEFGH" + "abcdefghijklmnop" + plaintext + "abcdefghijklmnopqrstuvwxyzabcdef";

			string encryptedBase64 = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes (encrypted));

			return encryptedBase64;
		}

		private byte[] generateRandomBytes (int length)
		{
			byte[] randomBytes = new byte[length];

			var rng = new System.Security.Cryptography.RNGCryptoServiceProvider ();
			rng.GetBytes (randomBytes);

			return randomBytes;
		}
	}
}


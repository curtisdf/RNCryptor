using System;

namespace RNCryptor
{
	public enum Schema : short {V0, V1, V2};

	public enum AesMode : short {CTR, CBC};
	public enum Pbkdf2Prf : short {SHA1};
	public enum HmacAlgorithm : short {SHA1, SHA256};
	public enum Algorithm : short {RIJNDAEL_128 /* should this be "AES" instead? */ };
	public enum Options : short {V0, V1};

	public struct PayloadComponents {
		public byte[] schema;
		public byte[] options;
		public byte[] salt;
		public byte[] hmacSalt;
		public byte[] iv;
		public int headerLength;
		public byte[] hmac;
		public byte[] ciphertext;
	};

	abstract public class Cryptor
	{
		protected AesMode aesMode;
		protected Options options;
		protected bool hmac_includesHeader;
		protected bool hmac_includesPadding;
		protected HmacAlgorithm hmac_algorithm;

		protected const Algorithm algorithm = Algorithm.RIJNDAEL_128;
		protected const short saltLength = 8;
		protected const short ivLength = 16;
		protected const Pbkdf2Prf pbkdf2_prf = Pbkdf2Prf.SHA1;
		protected const int pbkdf2_iterations = 10000;
		protected const short pbkdf2_keyLength = 32;
		protected const short hmac_length = 32;

		protected void configureSettings(Schema schemaVersion)
		{
			switch (schemaVersion) {
				
			case Schema.V0:
				aesMode = AesMode.CTR;
				options = Options.V0;
				hmac_includesHeader = false;
				hmac_includesPadding = true;
				hmac_algorithm = HmacAlgorithm.SHA1;
				break;
				
			case Schema.V1:
				aesMode = AesMode.CBC;
				options = Options.V1;
				hmac_includesHeader = false;
				hmac_includesPadding = false;
				hmac_algorithm = HmacAlgorithm.SHA256;
				break;
				
			case Schema.V2:
				aesMode = AesMode.CBC;
				options = Options.V1;
				hmac_includesHeader = true;
				hmac_includesPadding = false;
				hmac_algorithm = HmacAlgorithm.SHA256;
				break;
			}
		}

		protected byte[] generateHmac (PayloadComponents components, string password)
		{
			//Console.WriteLine ("--- generateHmac ---");

			byte[] hmacMessage = new byte[components.ciphertext.Length];

			int messageOffset = 0;
			if (this.hmac_includesHeader) {
				hmacMessage = new byte[hmacMessage.Length + 1 + 1 + Cryptor.saltLength + Cryptor.saltLength + Cryptor.ivLength];

				hmacMessage [0] = components.schema [0];
				messageOffset++;

				hmacMessage [1] = components.options [0];
				messageOffset++;

				for (int i = 0; i < components.salt.Length; i++) {
					hmacMessage [messageOffset + i] = components.salt [i];
					messageOffset++;
				}

				for (int i = 0; i < components.hmacSalt.Length; i++) {
					hmacMessage [messageOffset + i] = components.hmacSalt [i];
					messageOffset++;
				}

				for (int i = 0; i < components.iv.Length; i++) {
					hmacMessage [messageOffset + i] = components.iv [i];
					messageOffset++;
				}
			}

			for (int i = 0; i < components.ciphertext.Length; i++) {
				hmacMessage [messageOffset] = components.ciphertext [i];
				messageOffset++;
			}

			byte[] key = this.generateKey (components.hmacSalt, password);

			byte[] hmac = new byte[Cryptor.hmac_length];

			switch (this.hmac_algorithm) {
			case HmacAlgorithm.SHA1:
				var myHmacSha1 = new System.Security.Cryptography.HMACSHA1(key);
				myHmacSha1.Initialize();
				hmac = myHmacSha1.ComputeHash(hmacMessage);
				break;

			case HmacAlgorithm.SHA256:
				var myHmacSha256 = new System.Security.Cryptography.HMACSHA256(key);
				myHmacSha256.Initialize();
				hmac = myHmacSha256.ComputeHash(hmacMessage);
				break;
			}

			if (this.hmac_includesPadding && hmac.Length < Cryptor.hmac_length) {

				byte[] paddedHmac = new byte[Cryptor.hmac_length];
				for (int i = 0; i < hmac.Length; i++) {
					paddedHmac[i] = hmac[i];
				}
				for (int i = hmac.Length; i < paddedHmac.Length; i++) {
					paddedHmac[i] = 0x00;
				}
				hmac = paddedHmac;
			}
			//Console.WriteLine("Generated: " + this.hex_encode(hmac));

			return hmac;
		}

		private byte[] generateKey (byte[] salt, string password)
		{
			var pbkdf2 = new System.Security.Cryptography.Rfc2898DeriveBytes(password, salt, Cryptor.pbkdf2_iterations);
			return pbkdf2.GetBytes (Cryptor.pbkdf2_keyLength);
		}

		protected string hex_encode (byte[] input)
		{
			string hex = "";
			foreach (byte c in input)
			{
				hex += String.Format("{0:x2}", c);
			}
			return hex;
		}

	}

}


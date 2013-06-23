using System;

namespace RNCryptor
{
	public class Decryptor : Cryptor
	{

		public string decrypt (string encryptedBase64, string password)
		{
			Console.WriteLine ();
			Console.WriteLine ("Decryptor->decrypt()");
			Console.WriteLine ();
			PayloadComponents components = this.unpackEncryptedBase64Data(encryptedBase64);

			Console.WriteLine ("--- decrypt Components (Parsed from payload) ---");
			Console.WriteLine ("Schema:     " + this.hex_encode(components.schema));
			Console.WriteLine ("Options:    " + this.hex_encode(components.options));
			Console.WriteLine ("Salt:       " + this.hex_encode(components.salt));
			Console.WriteLine ("HMAC Salt:  " + this.hex_encode(components.hmacSalt));
			Console.WriteLine ("IV:         " + this.hex_encode(components.iv));
			Console.WriteLine ("Ciphertext: " + this.hex_encode(components.ciphertext));
			Console.WriteLine ("HMAC:       " + this.hex_encode(components.hmac));
			Console.WriteLine ();

			if (!this.hmacIsValid(components, password)) {
				Console.WriteLine("HMAC mismatch");
				return "";
			}
			Console.WriteLine("HMAC is good!");

			return "TBD Decrypt";
		}

		private PayloadComponents unpackEncryptedBase64Data (string encryptedBase64)
		{
			byte[] binaryBytes = System.Convert.FromBase64String (encryptedBase64);

			PayloadComponents components;
			int offset = 0;

			components.schema = this.getArraySlice(binaryBytes, offset, 1);
			offset++;

			this.configureSettings ((Schema)binaryBytes [0]);
			
			components.options = this.getArraySlice(binaryBytes, offset, 1);
			offset++;

			components.salt = this.getArraySlice(binaryBytes, offset, Cryptor.saltLength);
			offset += Cryptor.saltLength;
			
			components.hmacSalt = this.getArraySlice(binaryBytes, offset, Cryptor.saltLength);
			offset += Cryptor.saltLength;
			
			components.iv = this.getArraySlice(binaryBytes, offset, Cryptor.ivLength);
			offset += Cryptor.ivLength;
			
			components.headerLength = offset;
			
			components.ciphertext = this.getArraySlice(binaryBytes, components.headerLength, binaryBytes.Length - Cryptor.hmac_length - components.headerLength);

			components.hmac = this.getArraySlice(binaryBytes, binaryBytes.Length - Cryptor.hmac_length, Cryptor.hmac_length);
			
			return components;

		}

		private byte[] getArraySlice (byte[] bytes, int offset, int length)
		{
			byte[] output = new byte[length];
			for (int i = 0; i < length; i++) {
				output [i] = bytes [offset + i];
			}
			return output;
		}

		private bool hmacIsValid (PayloadComponents components, string password)
		{
			byte[] generatedHmac = this.generateHmac (components, password);

			if (generatedHmac.Length != components.hmac.Length) {
				return false;
			}

			for (int i = 0; i < components.hmac.Length; i++) {
				if (generatedHmac[i] != components.hmac[i]) {
					return false;
				}
			}
			return true;
		}

	}
}


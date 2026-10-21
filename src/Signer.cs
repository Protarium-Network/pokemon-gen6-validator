using System.Security.Cryptography;

namespace Gen6Validator;

/// <summary>RSA-2048 key used to sign accepted batches (SHA-256, PKCS#1 v1.5).</summary>
public sealed class Signer : IDisposable
{
	private readonly RSA _rsa = RSA.Create();

	public byte[] PublicKeyInfo => _rsa.ExportSubjectPublicKeyInfo();

	public static Signer FromPemFile(string path)
	{
		if (!File.Exists(path))
			throw new InvalidOperationException($"private key file '{path}' does not exist");

		var signer = new Signer();
		try
		{
			signer._rsa.ImportFromPem(File.ReadAllText(path));
			if (signer._rsa.KeySize != 2048)
				throw new InvalidOperationException($"the game only accepts RSA-2048 keys, got {signer._rsa.KeySize}");
			signer._rsa.ExportParameters(includePrivateParameters: true); // throws for a public-only key
		}
		catch
		{
			signer.Dispose();
			throw;
		}
		return signer;
	}

	public byte[] Sign(ReadOnlySpan<byte> data) => _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

	public void Dispose() => _rsa.Dispose();
}

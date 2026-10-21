// Checks for the validator.
//   dotnet run --project tests/Checks            wire-format checks only
//   dotnet run --project tests/Checks -- URL     also exercises a running server (URL like http://127.0.0.1:9107,
//                                                certificate id taken from its public_key answer)
using System.Buffers.Binary;
using System.Security.Cryptography;
using Gen6Validator;
using PKHeX.Core;

int failures = 0;
void Check(string name, bool ok)
{
	Console.WriteLine($"{(ok ? "ok  " : "FAIL")} {name}");
	if (!ok) failures++;
}

byte[] Build(string token, ushort cert, ushort type, ushort count, params byte[][] chunks)
{
	var ms = new MemoryStream();
	ms.Write(System.Text.Encoding.ASCII.GetBytes(token));
	ms.WriteByte(0);
	var header = new byte[6];
	BinaryPrimitives.WriteUInt16LittleEndian(header, cert);
	BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2), type);
	BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), count);
	ms.Write(header);
	foreach (var c in chunks) ms.Write(c);
	return ms.ToArray();
}

// ---- wire format -----------------------------------------------------------------------------------------------
var mon = Enumerable.Range(0, Wire.PokemonSize).Select(i => (byte)i).ToArray();
var prefix = Enumerable.Repeat((byte)0x5A, Wire.PrefixSize).ToArray();

Check("plain type 3 parses", Wire.TryParse(Build("t", 4, 3, 2, mon, mon), out var r, out _) && r!.Entries.Count == 2 && r.Entries[0].Prefix.Length == 0);
Check("type 1 is prefixed", Wire.TryParse(Build("t", 4, 1, 1, prefix, mon), out r, out _) && r!.Entries[0].Prefix.Length == Wire.PrefixSize);
Check("type 7 detects plain layout", Wire.TryParse(Build("t", 4, 7, 1, mon), out r, out _) && r!.Entries[0].Prefix.Length == 0);
Check("type 7 detects prefixed layout", Wire.TryParse(Build("t", 4, 7, 1, prefix, mon), out r, out _) && r!.Entries[0].Prefix.Length == Wire.PrefixSize);
Check("type 7 rejects odd length", !Wire.TryParse(Build("t", 4, 7, 1, mon, new byte[5]), out _, out _));
Check("unknown type rejected", !Wire.TryParse(Build("t", 4, 12, 1, mon), out _, out _));
Check("13 entries rejected", !Wire.TryParse(Build("t", 4, 3, 13, Enumerable.Repeat(mon, 13).ToArray()), out _, out _));
Check("truncated body rejected", !Wire.TryParse(Build("t", 4, 3, 2, mon), out _, out _));
Check("missing token terminator rejected", !Wire.TryParse(new byte[] { 65, 66, 67 }, out _, out _));
Check("signed bytes keep prefix before pokemon", Wire.SignedBytes(new[] { new Entry(new byte[] { 1 }, new byte[] { 2, 3 }), new Entry(Array.Empty<byte>(), new byte[] { 4 }) }).SequenceEqual(new byte[] { 1, 2, 3, 4 }));

var answer = Wire.WithResults(Verdict.Rejected, new[] { true, false });
Check("rejected answer layout", answer.SequenceEqual(new byte[] { 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1 }));
Check("bare answer is one byte", Wire.Bare(Verdict.UnknownCertificate).SequenceEqual(new byte[] { 2 }));

using (var rsa = RSA.Create(2048))
{
	var pk = Wire.PublicKeyAnswer(9, rsa.ExportSubjectPublicKeyInfo());
	Check("public key answer", BinaryPrimitives.ReadUInt16LittleEndian(pk) == 9 && Convert.FromBase64String(System.Text.Encoding.ASCII.GetString(pk.AsSpan(2))).SequenceEqual(rsa.ExportSubjectPublicKeyInfo()));
}

// ---- running server --------------------------------------------------------------------------------------------
if (args.Length > 0)
{
	using var http = new HttpClient { BaseAddress = new Uri(args[0]) };
	async Task<byte[]> Post(string path, byte[] body)
	{
		var resp = await http.PostAsync(path, new ByteArrayContent(body));
		return await resp.Content.ReadAsByteArrayAsync();
	}

	var keyAnswer = await Post("/validator/v1/public_key", Array.Empty<byte>());
	ushort cert = BinaryPrimitives.ReadUInt16LittleEndian(keyAnswer);
	using var pub = RSA.Create();
	pub.ImportSubjectPublicKeyInfo(Convert.FromBase64String(System.Text.Encoding.ASCII.GetString(keyAnswer.AsSpan(2))), out _);
	Console.WriteLine($"server certificate id {cert}");

	// a legal Pokemon, produced by PKHeX itself
	var trainer = new SimpleTrainerInfo(GameVersion.X) { OT = "TEST", TID16 = 12345, SID16 = 54321, Language = (int)LanguageID.English };
	var template = new PK6 { Species = 25 };
	template.CurrentLevel = 30;
	byte[]? legal = null;
	foreach (var enc in EncounterMovesetGenerator.GenerateEncounters(template, new ushort[] { 84 }, new[] { GameVersion.X, GameVersion.Y }))
	{
		if (enc.ConvertToPKM(trainer) is not PK6 candidate) continue;
		candidate.RefreshChecksum();
		if (!new LegalityAnalysis(candidate).Valid) continue;
		legal = candidate.EncryptedPartyData.Take(Wire.PokemonSize).ToArray();
		break;
	}
	Check("generated a legal Pokemon", legal is not null);

	if (legal is not null)
	{
		foreach (ushort type in new ushort[] { 2, 3, 4, 5, 6, 8 })
		{
			var reply = await Post("/validator/v1/validate", Build("tok", cert, type, 1, legal));
			bool signed = reply[0] == 0 && reply.Length == 3 + 4 + 256 && pub.VerifyData(legal, reply.AsSpan(7), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
			Check($"type {type}: accepted with a signature over the bytes that were sent", signed);
		}

		var prefixed = await Post("/validator/v1/validate", Build("tok", cert, 1, 1, prefix, legal));
		Check("type 1: signature covers prefix + pokemon", prefixed[0] == 0 && pub.VerifyData(prefix.Concat(legal).ToArray(), prefixed.AsSpan(7), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

		var tampered = new PK6((byte[])legal.Clone()) { Move1 = 999 };
		tampered.RefreshChecksum();
		var bad = await Post("/validator/v1/validate", Build("tok", cert, 3, 1, tampered.EncryptedPartyData.Take(Wire.PokemonSize).ToArray()));
		Check("tampered Pokemon rejected, no signature", bad.Length == 7 && bad[0] == 1 && bad[6] == 1);

		var mixed = await Post("/validator/v1/validate", Build("tok", cert, 3, 2, legal, tampered.EncryptedPartyData.Take(Wire.PokemonSize).ToArray()));
		Check("one bad Pokemon rejects the batch and marks only that one", mixed[0] == 1 && mixed[6] == 0 && mixed[10] == 1);

		var oldCert = await Post("/validator/v1/validate", Build("tok", (ushort)(cert + 1), 3, 1, legal));
		Check("other certificate id answered with 2", oldCert.SequenceEqual(new byte[] { 2 }));
	}

	var garbage = await Post("/validator/v1/validate", new byte[] { 1, 2, 3 });
	Check("unreadable request answered with a single 1", garbage.SequenceEqual(new byte[] { 1 }));

	var random = await Post("/validator/v1/validate", Build("tok", cert, 3, 1, Enumerable.Repeat((byte)0xAB, Wire.PokemonSize).ToArray()));
	Check("random bytes are rejected, not a crash", random.Length == 7 && random[0] == 1);
}

Console.WriteLine(failures == 0 ? "ALL OK" : $"{failures} FAILED");
return failures == 0 ? 0 : 1;

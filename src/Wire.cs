using System.Buffers.Binary;
using System.Text;

namespace Gen6Validator;

/// <summary>One Pokemon of a validation request, plus the opaque 0xA0 block some payload types put in front of it.</summary>
public readonly record struct Entry(byte[] Prefix, byte[] Pokemon)
{
	/// <summary>Number of bytes this entry contributes to the signed data.</summary>
	public int SignedLength => Prefix.Length + Pokemon.Length;
}

public sealed record ValidationRequest(string ServiceToken, ushort CertificateId, ushort PayloadType, IReadOnlyList<Entry> Entries);

public enum Verdict : byte
{
	Accepted = 0,
	Rejected = 1,
	UnknownCertificate = 2,
}

/// <summary>Reads requests and writes responses of the Gen 6 validator protocol (big-endian counts, little-endian certificate id).</summary>
public static class Wire
{
	public const int PokemonSize = 0xE8;
	public const int PrefixSize = 0xA0;
	public const int MaxEntries = 12;

	private enum Layout { Plain, Prefixed, ByLength }

	// Type 1 carries prefixed entries, 2-5 plain ones. Types 6-9 exist in both shapes, so those are told apart
	// by how many bytes follow the count.
	private static Layout LayoutOf(ushort type) => type switch
	{
		1 => Layout.Prefixed,
		>= 2 and <= 5 => Layout.Plain,
		>= 6 and <= 9 => Layout.ByLength,
		_ => throw new FormatException($"unknown payload type {type}"),
	};

	public static bool TryParse(ReadOnlySpan<byte> body, out ValidationRequest? request, out string error)
	{
		try
		{
			request = Parse(body);
			error = "";
			return true;
		}
		catch (FormatException e)
		{
			request = null;
			error = e.Message;
			return false;
		}
	}

	private static ValidationRequest Parse(ReadOnlySpan<byte> body)
	{
		int tokenEnd = body.IndexOf((byte)0);
		if (tokenEnd < 0)
			throw new FormatException("service token is not terminated");

		var rest = body[(tokenEnd + 1)..];
		if (rest.Length < 6)
			throw new FormatException("header is truncated");

		string token = Encoding.ASCII.GetString(body[..tokenEnd]);
		ushort certificate = BinaryPrimitives.ReadUInt16LittleEndian(rest);
		ushort type = BinaryPrimitives.ReadUInt16BigEndian(rest[2..]);
		int count = BinaryPrimitives.ReadUInt16BigEndian(rest[4..]);
		var data = rest[6..];

		if (count > MaxEntries)
			throw new FormatException($"{count} entries is more than the maximum of {MaxEntries}");

		bool prefixed;
		switch (LayoutOf(type))
		{
			case Layout.Prefixed:
				prefixed = true;
				break;
			case Layout.Plain:
				prefixed = false;
				break;
			default:
				if (data.Length == count * (PrefixSize + PokemonSize))
					prefixed = true;
				else if (data.Length == count * PokemonSize)
					prefixed = false;
				else
					throw new FormatException($"type {type}: {data.Length} bytes do not fit {count} entries in either layout");
				break;
		}

		int stride = prefixed ? PrefixSize + PokemonSize : PokemonSize;
		if (data.Length < count * stride)
			throw new FormatException($"type {type}: expected {count * stride} bytes of entries, got {data.Length}");

		var entries = new Entry[count];
		for (int i = 0; i < count; i++)
		{
			var chunk = data.Slice(i * stride, stride);
			entries[i] = prefixed
				? new Entry(chunk[..PrefixSize].ToArray(), chunk[PrefixSize..].ToArray())
				: new Entry(Array.Empty<byte>(), chunk.ToArray());
		}

		return new ValidationRequest(token, certificate, type, entries);
	}

	/// <summary>The exact bytes the signature must cover: every entry, in order, prefix first.</summary>
	public static byte[] SignedBytes(IReadOnlyList<Entry> entries)
	{
		var buffer = new byte[entries.Sum(e => e.SignedLength)];
		int at = 0;
		foreach (var e in entries)
		{
			e.Prefix.CopyTo(buffer, at);
			at += e.Prefix.Length;
			e.Pokemon.CopyTo(buffer, at);
			at += e.Pokemon.Length;
		}
		return buffer;
	}

	/// <summary>A response that is just the verdict byte (unknown certificate, or a request that could not be read).</summary>
	public static byte[] Bare(Verdict verdict) => new[] { (byte)verdict };

	/// <summary>Verdict, one big-endian result word per Pokemon (0 legal, 1 not), then the signature when accepted.</summary>
	public static byte[] WithResults(Verdict verdict, IReadOnlyList<bool> legal, ReadOnlySpan<byte> signature = default)
	{
		var response = new byte[1 + 2 + 4 * legal.Count + signature.Length];
		response[0] = (byte)verdict;
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(1), (ushort)legal.Count);
		for (int i = 0; i < legal.Count; i++)
			BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(3 + 4 * i), legal[i] ? 0u : 1u);
		signature.CopyTo(response.AsSpan(3 + 4 * legal.Count));
		return response;
	}

	/// <summary>Public key answer: little-endian certificate id, then the base64 DER SubjectPublicKeyInfo as ASCII.</summary>
	public static byte[] PublicKeyAnswer(ushort certificateId, ReadOnlySpan<byte> spki)
	{
		string b64 = Convert.ToBase64String(spki);
		var response = new byte[2 + b64.Length];
		BinaryPrimitives.WriteUInt16LittleEndian(response, certificateId);
		Encoding.ASCII.GetBytes(b64, response.AsSpan(2));
		return response;
	}
}

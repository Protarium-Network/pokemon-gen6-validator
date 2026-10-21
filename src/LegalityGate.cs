using PKHeX.Core;

namespace Gen6Validator;

/// <summary>Decides whether an encrypted PK6 is legal according to PKHeX.</summary>
public sealed class LegalityGate
{
	private readonly bool _acceptAnything;
	private readonly ILogger _log;

	public LegalityGate(bool acceptAnything, ILogger log)
	{
		_acceptAnything = acceptAnything;
		_log = log;
	}

	public bool IsLegal(byte[] encrypted)
	{
		if (_acceptAnything)
			return true;

		try
		{
			// PK6's constructor decrypts the array it is given. Hand it a copy: the caller signs the
			// original bytes afterwards and the game checks the signature against what it sent.
			var analysis = new LegalityAnalysis(new PK6((byte[])encrypted.Clone()));
			if (analysis.Valid)
				return true;

			_log.LogWarning("Rejected: {Reason}", analysis.Parsed ? analysis.Report() : "could not be parsed");
		}
		catch (Exception e)
		{
			// garbage input (or a PKHeX bug) means "not legal", never "no answer"
			_log.LogWarning("Rejected: analysis failed: {Message}", e.Message);
		}
		return false;
	}
}

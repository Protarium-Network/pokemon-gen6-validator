using System.Net;

namespace Gen6Validator;

public sealed record Settings(IPAddress BindAddress, int Port, ushort CertificateId, string PrivateKeyPath, bool AcceptAnything)
{
	public static Settings FromEnvironment()
	{
		static string? Get(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } v ? v : null;

		var bind = Get("GEN6V_BIND") is { } b ? IPAddress.Parse(b) : IPAddress.Loopback;
		var port = Get("GEN6V_PORT") is { } p ? int.Parse(p) : 9107;
		var cert = Get("GEN6V_CERTIFICATE_ID") is { } c ? ushort.Parse(c) : (ushort)1;
		var key = Get("GEN6V_PRIVATE_KEY_PATH") ?? throw new InvalidOperationException("GEN6V_PRIVATE_KEY_PATH must point to an RSA-2048 private key (PEM)");
		var all = string.Equals(Get("GEN6V_ACCEPT_ANYTHING"), "true", StringComparison.OrdinalIgnoreCase);

		return new Settings(bind, port, cert, key, all);
	}
}

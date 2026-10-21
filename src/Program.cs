using Gen6Validator;

var settings = Settings.FromEnvironment();
using var signer = Signer.FromPemFile(settings.PrivateKeyPath);

var builder = WebApplication.CreateSlimBuilder(args);
builder.WebHost.ConfigureKestrel(k =>
{
	k.AddServerHeader = false;
	k.Limits.MaxRequestBodySize = 64 * 1024;
	k.Listen(settings.BindAddress, settings.Port);
});

builder.Services.AddSingleton(sp => new LegalityGate(settings.AcceptAnything, sp.GetRequiredService<ILoggerFactory>().CreateLogger("legality")));

var app = builder.Build();
var log = app.Logger;
log.LogInformation("Certificate id {Id}, accept-anything={All}, listening on {Address}:{Port}", settings.CertificateId, settings.AcceptAnything, settings.BindAddress, settings.Port);

// Some game builds ask for slightly different paths ("public_kee", "validdtt"); both spellings get the same handler
foreach (var path in new[] { "/validator/v1/public_key", "/validator/v1/public_kee" })
	app.MapPost(path, () => Results.Bytes(Wire.PublicKeyAnswer(settings.CertificateId, signer.PublicKeyInfo)));

foreach (var path in new[] { "/validator/v1/validate", "/validator/v1/validdtt" })
	app.MapPost(path, async (HttpRequest http, LegalityGate gate) =>
	{
		using var buffer = new MemoryStream();
		await http.Body.CopyToAsync(buffer);

		if (!Wire.TryParse(buffer.ToArray(), out var request, out var error) || request is null)
		{
			log.LogWarning("Unreadable request: {Error}", error);
			return Results.Bytes(Wire.Bare(Verdict.Rejected));
		}

		log.LogInformation("type={Type} count={Count} certificate={Cert}", request.PayloadType, request.Entries.Count, request.CertificateId);

		// Saves created before a key change still hold the old certificate; answering 2 makes the game fetch the new one
		if (request.CertificateId != settings.CertificateId)
			return Results.Bytes(Wire.Bare(Verdict.UnknownCertificate));

		var legal = request.Entries.Select(e => gate.IsLegal(e.Pokemon)).ToArray();
		if (legal.Contains(false))
			return Results.Bytes(Wire.WithResults(Verdict.Rejected, legal));

		var signature = signer.Sign(Wire.SignedBytes(request.Entries));
		return Results.Bytes(Wire.WithResults(Verdict.Accepted, legal, signature));
	});

app.Run();

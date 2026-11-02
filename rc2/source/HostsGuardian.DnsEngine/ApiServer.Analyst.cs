using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace HostsGuardian.DnsEngine;

public sealed partial class ApiServer
{
    async Task ForwardAnalyst(HttpContext context, AuthenticatedUser actor, string session)
    {
        var origin = Environment.GetEnvironmentVariable("HOSTSGUARDIAN_AI_ORIGIN");
        var tokenFile = Environment.GetEnvironmentVariable("HOSTSGUARDIAN_AI_TOKEN_FILE");
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) || uri.Scheme != "http" || !IPAddress.TryParse(uri.Host, out var ip) || !IPAddress.IsLoopback(ip) ||
            uri.UserInfo != "" || uri.AbsolutePath != "/" || uri.Query != "" || uri.Fragment != "" || string.IsNullOrWhiteSpace(tokenFile))
            throw new AuthFailure(503, "Existing AI service is not configured for session-scoped access");
        using var document = await ReadAuthDocument(context);
        var root = document.RootElement; Fields(root, "question", "language", "session_id");
        // A fresh opaque context ID per request prevents client-selected cross-user context reuse.
        var payload = JsonSerializer.SerializeToUtf8Bytes(new { question = RequiredText(root, "question"), language = RequiredText(root, "language"), session_id = Guid.NewGuid().ToString("N") });
        try
        {
            if (new FileInfo(tokenFile).Length > 256 || new FileInfo(tokenFile).LinkTarget != null) throw new AuthFailure(503, "AI credential unavailable");
            var aiToken = File.ReadAllText(tokenFile).Trim();
            if (HostsGuardian.Core.Services.ManagementSecurity.ParseToken(aiToken) == null) throw new AuthFailure(503, "AI credential unavailable");
            using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false, UseCookies = false }) { Timeout = TimeSpan.FromSeconds(30) };
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(uri, "/v2/analyst"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", aiToken); request.Headers.Add(UserDirectory.SessionHeader, session);
            request.Content = new ByteArrayContent(payload); request.Content.Headers.ContentType = new("application/json");
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);
            if (!response.IsSuccessStatusCode) throw new AuthFailure(503, "Session-scoped AI analysis unavailable");
            using var stream = await response.Content.ReadAsStreamAsync(context.RequestAborted); using var memory = new MemoryStream(); var buffer = new byte[4096]; int count;
            while ((count = await stream.ReadAsync(buffer, context.RequestAborted)) > 0) { if (memory.Length + count > 32768) throw new AuthFailure(503, "AI response rejected"); memory.Write(buffer, 0, count); }
            using var result = JsonDocument.Parse(memory.ToArray());
            var json = result.RootElement;
            if (json.GetProperty("schema_version").GetInt32() != 2 || json.GetProperty("answer").GetString() is not { Length: <= 5000 }) throw new AuthFailure(503, "AI response rejected");
            _users!.WithCurrent(actor, _ => true);
            await context.Response.WriteAsJsonAsync(json);
        }
        finally { CryptographicOperations.ZeroMemory(payload); }
    }
}

using System.Collections.Immutable;
using System.Text.Json;
using HostsGuardian.Core.Models;
using Microsoft.AspNetCore.Http;

namespace HostsGuardian.DnsEngine;

public sealed partial class ApiServer
{
    readonly UserDirectory? _users;
    readonly bool _usersRequired;
    const string PrincipalKey = "HostsGuardian.AuthenticatedUser";
    static string RequiredText(JsonElement root, string name) => root.GetProperty(name).GetString() ?? throw new ArgumentException();
    static Guid[] Devices(JsonElement root) => root.GetProperty("devices").EnumerateArray().Select(v => v.GetGuid()).ToArray();
    static UserRole Role(JsonElement root) => Enum.TryParse<UserRole>(RequiredText(root, "role"), false, out var role) && Enum.IsDefined(role) ? role : throw new ArgumentException();
    static void Fields(JsonElement root, params string[] names)
    {
        if (!root.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal).SetEquals(names)) throw new ArgumentException("Unexpected or missing fields");
    }
    ISet<Guid> RegisteredIds() => _policy.ReadFullPolicy().Policy.Devices.Select(d => d.DeviceId).ToHashSet();
    async Task<bool> HandleRbacAsync(HttpContext context)
    {
        var users = _users!; var request = context.Request; var path = request.Path.Value?.TrimEnd('/') ?? "";
        context.Response.Headers.CacheControl = "no-store";
        if (request.Method == "POST" && path == "/v1/auth/login")
        {
            using var body = await ReadAuthDocument(context); Fields(body.RootElement, "username", "password");
            await context.Response.WriteAsJsonAsync(await users.Login(RequiredText(body.RootElement, "username"), RequiredText(body.RootElement, "password"), request.HttpContext.RequestAborted)); return true;
        }
        if (request.Method == "POST" && path == "/v1/auth/password-reset")
        {
            using var body = await ReadAuthDocument(context); Fields(body.RootElement, "resetToken", "password");
            users.CompleteReset(RequiredText(body.RootElement, "resetToken"), RequiredText(body.RootElement, "password")); context.Response.StatusCode = 204; return true;
        }
        var headers = request.Headers[UserDirectory.SessionHeader];
        var token = headers.Count == 1 ? headers[0] : null;
        var actor = users.Authenticate(token) ?? throw new AuthFailure(401, "Valid user session required");
        context.Items[PrincipalKey] = actor;
        using var actorScope = _policy.BeginActor(actor.Name + " / " + actor.Id);
        if (path == "/v1/auth/session" && request.Method == "GET")
        {
            await context.Response.WriteAsJsonAsync(new { authenticated = true, username = actor.Name, role = actor.Role.ToString(), devices = actor.Devices, readOnly = actor.Role == UserRole.Observer }); return true;
        }
        if (path == "/v1/auth/logout" && request.Method == "POST") { users.Logout(token!); context.Response.StatusCode = 204; return true; }
        if (path == "/v1/analyst" && request.Method == "POST")
        {
            await ForwardAnalyst(context, actor, token!); return true;
        }
        if (path == "/v1/users" && request.Method == "GET") { await context.Response.WriteAsJsonAsync(users.List(actor)); return true; }
        if (path.StartsWith("/v1/users", StringComparison.Ordinal))
        {
            if (actor.Role != UserRole.Admin) throw new AuthFailure(403, "Administrator required");
            if (request.Method != "POST") throw new AuthFailure(405, "POST required");
            using var body = await ReadAuthDocument(context); var root = body.RootElement;
            if (path == "/v1/users")
            {
                Fields(root, "name", "role", "devices", "password");
                var created = users.Create(actor, RequiredText(root, "name"), Role(root), Devices(root), RequiredText(root, "password"), RegisteredIds());
                _policy.RecordIdentityOperation("UserCreated", actor.Name + " / " + actor.Id, created.Id);
                await context.Response.WriteAsJsonAsync(created); return true;
            }
            var segments = path.Split('/');
            if (segments.Length != 5 || !Guid.TryParse(segments[3], out var id)) throw new AuthFailure(404, "Not found");
            switch (segments[4])
            {
                case "update":
                    Fields(root, "expectedVersion", "role", "enabled", "devices");
                    var updated = users.Update(actor, id, root.GetProperty("expectedVersion").GetInt64(), Role(root), root.GetProperty("enabled").GetBoolean(), Devices(root), RegisteredIds());
                    _policy.RecordIdentityOperation("UserUpdated", actor.Name + " / " + actor.Id, id);
                    await context.Response.WriteAsJsonAsync(updated); return true;
                case "revoke":
                    Fields(root); users.Revoke(actor, id); _policy.RecordIdentityOperation("SessionsRevoked", actor.Name + " / " + actor.Id, id); context.Response.StatusCode = 204; return true;
                case "reset":
                    Fields(root); var reset = users.BeginReset(actor, id);
                    _policy.RecordIdentityOperation("PasswordResetIssued", actor.Name + " / " + actor.Id, id);
                    await context.Response.WriteAsJsonAsync(new { resetToken = reset, lifetimeSeconds = 600, delivery = "Transfer once over a trusted channel; never log this response" }); return true;
            }
            throw new AuthFailure(404, "Not found");
        }
        if (path == "/v1/access/block-list")
        {
            Guid? scope = null;
            var rawScope = request.Query["deviceId"].ToString();
            if (rawScope.Length > 0) { if (!Guid.TryParse(rawScope, out var id) || id == Guid.Empty) throw new ArgumentException(); scope = id; }
            void Authorize(AuthenticatedUser current, bool write)
            {
                if (write && current.Role == UserRole.Observer || current.Role == UserRole.Operator && (!scope.HasValue || !current.Devices.Contains(scope.Value)))
                    throw new AuthFailure(403, "Device access denied");
            }
            if (request.Method == "GET")
            {
                var response = users.WithCurrent(actor, current =>
                {
                    Authorize(current, false);
                    var read = _policy.ReadFullPolicy();
                    if (scope.HasValue && !read.Policy.Devices.Any(d => d.DeviceId == scope)) throw new AuthFailure(404, "Registered device required");
                    var snapshot = _policy.State.GetSnapshot();
                    var mapping = _bindings.Read(); var observedAt = DateTimeOffset.UtcNow;
                    bool deviceIdentified = scope.HasValue && mapping.Observations.Where(b => b.DeviceId == scope).Any(b =>
                        AddressBindingStore.Resolve(mapping, read.Policy, new(DnsTransport.Udp, b.Address, 0, observedAt, b.NetworkScope), observedAt) is var identity && identity.DeviceId == scope && identity.State == "Validated");
                    var entries = HostsGuardian.Core.Services.DomainBlockList.Entries(read.Policy);
                    var rows = entries
                        .Where(e => e.DeviceId == scope || scope.HasValue && e.DeviceId == null).Select(e => e.Domain).Distinct().Order(StringComparer.Ordinal)
                        .Select(domain =>
                        {
                            var (winner, chain) = HostsGuardian.Core.Services.PolicyDecision.Explain(read.Policy, scope, domain, DateTimeOffset.UtcNow);
                            return new { domain,
                                saved = entries.Any(e => e.DeviceId == scope && e.Domain == domain),
                                configuredBlocked = scope == null ? read.Policy.GlobalBlockedDomains.Contains(domain) : read.Policy.Overrides.Any(r => r.DeviceId == scope && r.Domain == domain && r.State == DeviceDomainRuleState.Block),
                                decisionKnown = !scope.HasValue || deviceIdentified, identityState = deviceIdentified ? "Validated" : scope.HasValue ? "NOT PROVEN" : "NotRequired",
                                effectiveBlocked = snapshot.FilteringEnabled && winner.State == DeviceDomainRuleState.Block,
                                reason = snapshot.FilteringEnabled ? winner.Source : "FilteringDisabled",
                                legacyAllow = scope.HasValue && read.Policy.Overrides.Any(r => r.DeviceId == scope && r.Domain == domain && r.State == DeviceDomainRuleState.Allow),
                                proof = "NOT PROVEN" };
                        }).ToArray();
                    return new { read.Revision, read.InstanceId, deviceId = scope, schemaVersion = read.Policy.SchemaVersion, rows };
                });
                await context.Response.WriteAsJsonAsync(response); return true;
            }
            if (request.Method != "POST") throw new AuthFailure(405, "POST required");
            using var body = await ReadRequestDocumentAsync(context); var root = body.RootElement;
            Fields(root, "expectedInstanceId", "expectedRevision", "domain", "enabled", "delete");
            var result = users.WithCurrent(actor, current =>
            {
                Authorize(current, true);
                var read = _policy.ReadFullPolicy();
                var changed = HostsGuardian.Core.Services.DomainBlockList.Change(read.Policy, scope, RequiredText(root, "domain"), root.GetProperty("enabled").GetBoolean(), root.GetProperty("delete").GetBoolean());
                return _policy.ReplaceFull(new(root.GetProperty("expectedRevision").GetInt64(), changed, RequiredText(root, "expectedInstanceId")));
            });
            await WritePolicyResultAsync(context, result, false); return true;
        }
        if (path == "/v1/access/device-rule" && request.Method == "POST")
        {
            using var body = await ReadRequestDocumentAsync(context); var root = body.RootElement;
            Fields(root, "expectedInstanceId", "expectedRevision", "deviceId", "domain", "state");
            var id = root.GetProperty("deviceId").GetGuid();
            var domain = DomainName.Normalize(RequiredText(root, "domain"));
            if (domain == "" || !Enum.TryParse<DeviceDomainRuleState>(RequiredText(root, "state"), false, out var state) || !Enum.IsDefined(state)) throw new ArgumentException();
            var result = users.WithCurrent(actor, current =>
            {
                if (current.Role == UserRole.Observer || current.Role == UserRole.Operator && !current.Devices.Contains(id)) throw new AuthFailure(403, "Device access denied");
                var read = _policy.ReadFullPolicy();
                if (!read.Policy.Devices.Any(d => d.DeviceId == id)) throw new AuthFailure(404, "Registered device required");
                var overrides = read.Policy.Overrides.Where(r => r.DeviceId != id || r.Domain != domain);
                if (state != DeviceDomainRuleState.Inherit) overrides = overrides.Append(new(id, domain, state));
                return _policy.ReplaceFull(new(root.GetProperty("expectedRevision").GetInt64(), read.Policy with { Overrides = overrides.ToImmutableArray(), SavedDomains = read.Policy.SchemaVersion == 4 ? HostsGuardian.Core.Services.DomainBlockList.Entries(read.Policy) : null }, RequiredText(root, "expectedInstanceId")));
            });
            await WritePolicyResultAsync(context, result, false); return true;
        }
        if (path == "/v1/access/global-rule" && request.Method == "POST")
        {
            using var body = await ReadRequestDocumentAsync(context); var root = body.RootElement;
            Fields(root, "expectedInstanceId", "expectedRevision", "domain", "blocked");
            var domain = DomainName.Normalize(RequiredText(root, "domain")); if (domain == "") throw new ArgumentException();
            var result = users.WithCurrent(actor, current =>
            {
                if (current.Role != UserRole.Admin) throw new AuthFailure(403, "Administrator required");
                var read = _policy.ReadFullPolicy(); var domains = read.Policy.GlobalBlockedDomains.Where(d => d != domain);
                if (root.GetProperty("blocked").GetBoolean()) domains = domains.Append(domain);
                return _policy.ReplaceFull(new(root.GetProperty("expectedRevision").GetInt64(), read.Policy with { GlobalBlockedDomains = domains.ToImmutableArray(), SavedDomains = read.Policy.SchemaVersion == 4 ? HostsGuardian.Core.Services.DomainBlockList.Entries(read.Policy) : null }, RequiredText(root, "expectedInstanceId")));
            });
            await WritePolicyResultAsync(context, result, false); return true;
        }
        // Observer has every non-secret system read, but no mutation, including unknown future endpoints.
        if (actor.Role == UserRole.Observer && request.Method != "GET") throw new AuthFailure(403, "Read-only role");
        if (actor.Role == UserRole.Observer && path is not ("" or "/health" or "/dns/status" or "/rules/blocked" or "/v2/identity-evidence" or "/v2/discovery" or "/v2/diagnostics" or "/v2/operational-events" or "/v3/activity" or "/v3/policy-audit" or "/v2/dns-observations" or "/v2/capabilities" or "/v2/policy" or "/v2/bindings" or "/v2/effective-policy"))
            throw new AuthFailure(403, "Endpoint not in non-secret system read allowlist");
        if (actor.Role == UserRole.Operator) { await OperatorRead(context, actor, path); return true; }
        // Recheck version immediately before legacy dispatch. Scoped mutations above execute under this same directory lock.
        users.WithCurrent(actor, _ => true);
        return false;
    }
    static async Task<JsonDocument> ReadAuthDocument(HttpContext context)
    {
        if (context.Request.ContentLength > 4096) throw new BadHttpRequestException("Request too large", 413);
        using var memory = new MemoryStream(); var bytes = new byte[1024];
        try
        {
            int count; while ((count = await context.Request.Body.ReadAsync(bytes, context.RequestAborted)) > 0)
            { if (memory.Length + count > 4096) throw new BadHttpRequestException("Request too large", 413); memory.Write(bytes, 0, count); }
            var document = JsonDocument.Parse(memory.GetBuffer().AsMemory(0, (int)memory.Length), new JsonDocumentOptions { MaxDepth = 8 });
            try { PolicyPersistence.RejectDuplicateProperties(document.RootElement); if (document.RootElement.ValueKind != JsonValueKind.Object) throw new ArgumentException(); return document; }
            catch { document.Dispose(); throw; }
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); /* JsonDocument owns the memory until disposed. */ }
    }
    async Task OperatorRead(HttpContext context, AuthenticatedUser actor, string path)
    {
        if (context.Request.Method != "GET") throw new AuthFailure(403, "Operator cannot change global or administrative state");
        var scope = actor.Devices.ToHashSet();
        switch (path)
        {
            case "/health": await context.Response.WriteAsJsonAsync(new { ok = true, engine = "HostsGuardian.DnsEngine", apiVersion = 1 }); return;
            case "/dns/status":
                var status = GetDnsStatus(); var current = _policy.ReadFullPolicy(); await context.Response.WriteAsJsonAsync(new { instanceId = current.InstanceId, policyRevision = current.Revision, runtimeState = status.RuntimeState, scope = "assigned-devices", protection = "Unverified" }); return;
            case "/v2/capabilities": await context.Response.WriteAsJsonAsync(new { apiVersion = 2, fullPolicyReadback = false, scopedDeviceRules = true, scope = "assigned-devices" }); return;
            case "/v2/policy":
                var read = _policy.ReadFullPolicy();
                await context.Response.WriteAsJsonAsync(read with { Policy = new(read.Policy.SchemaVersion, [], read.Policy.Devices.Where(d => scope.Contains(d.DeviceId)).ToImmutableArray(), read.Policy.Overrides.Where(r => scope.Contains(r.DeviceId)).ToImmutableArray()) { SavedDomains = read.Policy.SavedDomains?.Where(r => r.DeviceId.HasValue && scope.Contains(r.DeviceId.Value)).ToImmutableArray() } }); return;
            case "/v2/bindings":
                var bindings = _bindings.Read(); await context.Response.WriteAsJsonAsync(bindings with { Observations = bindings.Observations.Where(b => scope.Contains(b.DeviceId)).ToImmutableArray() }); return;
            case "/v3/activity":
                var activity = _activity.Read(DateTimeOffset.UtcNow); await context.Response.WriteAsJsonAsync(activity with { Buckets = activity.Buckets.Where(b => b.DeviceId.HasValue && scope.Contains(b.DeviceId.Value)).ToArray() }); return;
            // Aggregate logs, discovery without a proven stable ID, topology and full diagnostics are not safe device projections.
            default: throw new AuthFailure(403, "Endpoint unavailable within assigned-device scope");
        }
    }
}

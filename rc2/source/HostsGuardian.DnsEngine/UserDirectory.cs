using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace HostsGuardian.DnsEngine;

public enum UserRole { Admin, Operator, Observer }
public sealed record PasswordHash(string Algorithm, int Version, int MemoryKiB, int Iterations, int Parallelism, string Salt, string Hash);
public sealed record UserRecord(Guid Id, string Name, UserRole Role, bool Enabled, Guid[] Devices, long Version, PasswordHash Password);
public sealed record UserView(Guid Id, string Name, string Role, bool Enabled, Guid[] Devices, long Version);
public sealed record DirectoryDocument(int SchemaVersion, long Revision, UserRecord[] Users);
public sealed record AuthenticatedUser(Guid Id, string Name, UserRole Role, Guid[] Devices, long Version);
public sealed record LoginResult(string Username, string Role, Guid[] Devices, string SessionToken, DateTimeOffset ExpiresUtc, int LifetimeSeconds);
public sealed class AuthFailure(int status, string message) : Exception(message) { public int Status { get; } = status; }

/// <summary>One Engine-owned store. No default accounts, plaintext passwords or persistent session tokens.</summary>
public sealed class UserDirectory : IDisposable
{
    readonly string path;
    readonly FileStream ownership;
    readonly object gate = new();
    readonly SemaphoreSlim hashing = new(1, 1);
    readonly TimeProvider clock;
    DirectoryDocument document;
    sealed record Lease(Guid User, long Version, long Started);
    sealed record Reset(Guid User, long Version, long Started);
    readonly Dictionary<string, Lease> sessions = new();
    readonly Dictionary<string, Reset> resets = new();
    readonly Queue<long> attempts = new();
    public const string SessionHeader = "X-HostsGuardian-Session";
    public const int LifetimeSeconds = 900;

    public UserDirectory(string file, TimeProvider? time = null)
    {
        clock = time ?? TimeProvider.System;
        path = Path.GetFullPath(file);
        var parent = Path.GetDirectoryName(path)!;
        // Parent must be provisioned locally by the administrator; never bootstrap a network-writable path.
        if (!Directory.Exists(parent) || new DirectoryInfo(parent).LinkTarget != null)
            throw new InvalidOperationException("User directory requires an existing private parent directory");
        RejectLink(path); RejectLink(path + ".lock");
        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(parent);
            if ((mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) != 0)
                throw new InvalidOperationException("User directory parent must have mode 0700");
        }
        ownership = new FileStream(path + ".lock", PrivateOptions(FileMode.OpenOrCreate));
        try
        {
            if (!File.Exists(path)) document = new(1, 0, []);
            else
            {
                if (new FileInfo(path).Length > 1048576) throw new InvalidDataException("Invalid user store");
                if (!OperatingSystem.IsWindows() && (File.GetUnixFileMode(path) & (UnixFileMode.GroupRead | UnixFileMode.OtherRead | UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
                    throw new InvalidDataException("User store permissions must be private");
                document = JsonSerializer.Deserialize<DirectoryDocument>(File.ReadAllBytes(path), PolicyPersistence.JsonOptions) ?? throw new InvalidDataException();
                Validate(document);
            }
        }
        catch { ownership.Dispose(); throw; }
    }

    static void RejectLink(string value) { if (new FileInfo(value).LinkTarget != null) throw new IOException("Linked user store rejected"); }
    static FileStreamOptions PrivateOptions(FileMode mode)
    {
        var options = new FileStreamOptions { Mode = mode, Access = FileAccess.ReadWrite, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return options;
    }
    static bool ValidName(string name) => name is { Length: >= 3 and <= 64 } && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_');
    static void Validate(DirectoryDocument d)
    {
        if (d.SchemaVersion != 1 || d.Revision < 1 || d.Users == null || d.Users.Length is < 1 or > 256 || d.Users.Any(u => u == null || u.Devices == null) || !d.Users.Any(u => u.Enabled && u.Role == UserRole.Admin) ||
            d.Users.Select(u => u.Id).Distinct().Count() != d.Users.Length || d.Users.Select(u => u.Name.ToUpperInvariant()).Distinct().Count() != d.Users.Length)
            throw new InvalidDataException("Invalid user store");
        foreach (var u in d.Users)
        {
            if (u.Id == Guid.Empty || !ValidName(u.Name) || !Enum.IsDefined(u.Role) || u.Version < 1 || u.Devices.Length > 1024 || u.Devices.Any(id => id == Guid.Empty) ||
                u.Devices.Distinct().Count() != u.Devices.Length || u.Role != UserRole.Operator && u.Devices.Length != 0)
                throw new InvalidDataException("Invalid user record");
            ValidateHash(u.Password);
        }
    }
    static void ValidateHash(PasswordHash p)
    {
        if (p == null || p.Algorithm != "argon2id" || p.Version != 19 || p.MemoryKiB != 65536 || p.Iterations != 3 || p.Parallelism != 1 ||
            Convert.FromBase64String(p.Salt).Length != 16 || Convert.FromBase64String(p.Hash).Length != 32) throw new InvalidDataException("Invalid password record");
    }
    static byte[] Derive(byte[] bytes, byte[] salt)
    {
        var p = new Argon2Parameters.Builder(Argon2Parameters.Argon2id).WithVersion(Argon2Parameters.Version13)
            .WithMemoryAsKB(65536).WithIterations(3).WithParallelism(1).WithSalt(salt).Build();
        var g = new Argon2BytesGenerator(); g.Init(p); var result = new byte[32]; g.GenerateBytes(bytes, result); return result;
    }
    static PasswordHash Hash(string password)
    {
        // Long passphrases are supported; no weak default is accepted even in test fixtures.
        if (password.Length is < 15 or > 256 || Encoding.UTF8.GetByteCount(password) > 1024 || password.Any(char.IsControl) || password.Distinct().Count() < 6)
            throw new AuthFailure(400, "Use a password of 15–256 characters with at least six distinct characters");
        var bytes = Encoding.UTF8.GetBytes(password); var salt = RandomNumberGenerator.GetBytes(16); byte[]? hash = null;
        try { hash = Derive(bytes, salt); return new("argon2id", 19, 65536, 3, 1, Convert.ToBase64String(salt), Convert.ToBase64String(hash)); }
        finally { CryptographicOperations.ZeroMemory(bytes); if (hash != null) CryptographicOperations.ZeroMemory(hash); }
    }
    static UserView View(UserRecord u) => new(u.Id, u.Name, u.Role.ToString(), u.Enabled, u.Devices.ToArray(), u.Version);
    static AuthenticatedUser Principal(UserRecord u) => new(u.Id, u.Name, u.Role, u.Devices.ToArray(), u.Version);
    void Save(UserRecord[] users)
    {
        var next = new DirectoryDocument(1, checked(document.Revision + 1), users); Validate(next);
        RejectLink(path); var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, PrivateOptions(FileMode.CreateNew))) { JsonSerializer.Serialize(stream, next, PolicyPersistence.JsonOptions); stream.Flush(true); }
            File.Move(temporary, path, true); document = next;
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    public bool Initialized { get { lock (gate) return document.Users.Length != 0; } }
    public void InitializeAdmin(string password)
    {
        lock (gate) { if (Initialized) throw new AuthFailure(409, "Initialization is permanently closed"); Save([new(Guid.NewGuid(), "admin", UserRole.Admin, true, [], 1, Hash(password))]); }
    }
    AuthenticatedUser Current(AuthenticatedUser actor)
    {
        var user = document.Users.SingleOrDefault(u => u.Id == actor.Id && u.Enabled && u.Version == actor.Version);
        if (user == null) throw new AuthFailure(401, "Session revoked"); return Principal(user);
    }
    public T WithCurrent<T>(AuthenticatedUser actor, Func<AuthenticatedUser, T> action) { lock (gate) return action(Current(actor)); }
    void RequireAdmin(AuthenticatedUser actor) { if (Current(actor).Role != UserRole.Admin) throw new AuthFailure(403, "Administrator required"); }
    public UserView[] List(AuthenticatedUser actor) { lock (gate) { RequireAdmin(actor); return document.Users.Select(View).ToArray(); } }
    public UserView Create(AuthenticatedUser actor, string name, UserRole role, Guid[] devices, string password, ISet<Guid> registered)
    {
        lock (gate)
        {
            RequireAdmin(actor);
            if (!ValidName(name) || document.Users.Any(u => u.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) || document.Users.Length >= 256) throw new AuthFailure(400, "Invalid or duplicate username");
            CheckAssignment(role, devices, registered);
            var user = new UserRecord(Guid.NewGuid(), name, role, true, devices.ToArray(), 1, Hash(password)); Save([..document.Users, user]); return View(user);
        }
    }
    static void CheckAssignment(UserRole role, Guid[] ids, ISet<Guid> registered)
    {
        if (!Enum.IsDefined(role) || ids.Length > 1024 || ids.Distinct().Count() != ids.Length || ids.Any(id => !registered.Contains(id)) || role != UserRole.Operator && ids.Length != 0)
            throw new AuthFailure(400, "Invalid role or device assignment");
    }
    void Invalidate(Guid id)
    {
        foreach (var key in sessions.Where(p => p.Value.User == id).Select(p => p.Key).ToArray()) sessions.Remove(key);
        foreach (var key in resets.Where(p => p.Value.User == id).Select(p => p.Key).ToArray()) resets.Remove(key);
    }
    public UserView Update(AuthenticatedUser actor, Guid id, long expectedVersion, UserRole role, bool enabled, Guid[] devices, ISet<Guid> registered)
    {
        lock (gate)
        {
            RequireAdmin(actor); CheckAssignment(role, devices, registered);
            var target = document.Users.SingleOrDefault(u => u.Id == id) ?? throw new AuthFailure(404, "User not found");
            if (target.Version != expectedVersion) throw new AuthFailure(409, "User changed; refresh first");
            var updated = target with { Role = role, Enabled = enabled, Devices = devices.ToArray(), Version = checked(target.Version + 1) };
            var users = document.Users.Select(u => u.Id == id ? updated : u).ToArray();
            if (!users.Any(u => u.Enabled && u.Role == UserRole.Admin)) throw new AuthFailure(409, "Last active administrator must be retained");
            Save(users); Invalidate(id); return View(updated);
        }
    }
    public void Revoke(AuthenticatedUser actor, Guid id)
    {
        lock (gate) { RequireAdmin(actor); var target = document.Users.SingleOrDefault(u => u.Id == id) ?? throw new AuthFailure(404, "User not found");
            Save(document.Users.Select(u => u.Id == id ? u with { Version = checked(u.Version + 1) } : u).ToArray()); Invalidate(id); }
    }
    public string BeginReset(AuthenticatedUser actor, Guid id)
    {
        lock (gate)
        {
            RequireAdmin(actor); var target = document.Users.SingleOrDefault(u => u.Id == id) ?? throw new AuthFailure(404, "User not found");
            Revoke(actor, id); var updated = document.Users.Single(u => u.Id == id); var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            resets[TokenHash(token)] = new(id, updated.Version, clock.GetTimestamp()); return token;
        }
    }
    public void CompleteReset(string token, string password)
    {
        lock (gate)
        {
            if (!TokenValid(token) || !resets.TryGetValue(TokenHash(token), out var reset) || clock.GetElapsedTime(reset.Started) >= TimeSpan.FromMinutes(10)) throw new AuthFailure(401, "Reset invalid or expired");
            var target = document.Users.SingleOrDefault(u => u.Id == reset.User && u.Version == reset.Version) ?? throw new AuthFailure(401, "Reset invalid");
            var hash = Hash(password); Save(document.Users.Select(u => u.Id == target.Id ? u with { Password = hash, Version = checked(u.Version + 1) } : u).ToArray()); Invalidate(target.Id);
        }
    }
    static bool TokenValid(string? token) => token is { Length: 64 } && token.All(Uri.IsHexDigit);
    static string TokenHash(string token) => Convert.ToHexString(SHA256.HashData(Convert.FromHexString(token)));
    public AuthenticatedUser? Authenticate(string? token)
    {
        lock (gate)
        {
            if (!TokenValid(token) || !sessions.TryGetValue(TokenHash(token!), out var lease)) return null;
            if (clock.GetElapsedTime(lease.Started) >= TimeSpan.FromSeconds(LifetimeSeconds)) { sessions.Remove(TokenHash(token!)); return null; }
            var user = document.Users.SingleOrDefault(u => u.Id == lease.User && u.Version == lease.Version && u.Enabled); return user == null ? null : Principal(user);
        }
    }
    public void Logout(string token) { lock (gate) { if (TokenValid(token)) sessions.Remove(TokenHash(token)); } }
    public async Task<LoginResult> Login(string name, string password, CancellationToken ct)
    {
        UserRecord? candidate;
        lock (gate)
        {
            var now = clock.GetTimestamp(); while (attempts.TryPeek(out var first) && clock.GetElapsedTime(first, now) >= TimeSpan.FromMinutes(1)) attempts.Dequeue();
            if (attempts.Count >= 5) throw new AuthFailure(429, "Too many attempts; retry in one minute"); attempts.Enqueue(now);
            if (!Initialized) throw new AuthFailure(503, "Administrator initialization required");
            candidate = document.Users.SingleOrDefault(u => u.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        }
        if (password.Length > 256 || name.Length > 64 || !await hashing.WaitAsync(0, ct)) throw new AuthFailure(429, "Authentication temporarily unavailable");
        byte[] bytes = Encoding.UTF8.GetBytes(password); byte[]? actual = null;
        try
        {
            PasswordHash reference; lock (gate) reference = candidate?.Password ?? document.Users[0].Password;
            actual = await Task.Run(() => Derive(bytes, Convert.FromBase64String(reference.Salt)), ct);
            var matches = CryptographicOperations.FixedTimeEquals(actual, Convert.FromBase64String(reference.Hash));
            lock (gate)
            {
                if (!matches || candidate == null || !candidate.Enabled || !document.Users.Any(u => u.Id == candidate.Id && u.Enabled && u.Version == candidate.Version)) throw new AuthFailure(401, "Login failed");
                ct.ThrowIfCancellationRequested();
                foreach (var key in sessions.Where(p => clock.GetElapsedTime(p.Value.Started) >= TimeSpan.FromSeconds(LifetimeSeconds)).Select(p => p.Key).ToArray()) sessions.Remove(key);
                if (sessions.Count >= 256) throw new AuthFailure(429, "Session capacity reached");
                var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)); sessions[TokenHash(token)] = new(candidate.Id, candidate.Version, clock.GetTimestamp());
                return new(candidate.Name, candidate.Role.ToString(), candidate.Devices.ToArray(), token, clock.GetUtcNow().AddSeconds(LifetimeSeconds), LifetimeSeconds);
            }
        }
        finally { CryptographicOperations.ZeroMemory(bytes); if (actual != null) CryptographicOperations.ZeroMemory(actual); hashing.Release(); }
    }
    public void Dispose() { lock (gate) { sessions.Clear(); resets.Clear(); ownership.Dispose(); hashing.Dispose(); } }
}

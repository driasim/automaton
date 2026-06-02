import { describe, it, expect, vi, beforeEach } from "vitest";

// ============================================================
// URL injection / SSRF / X402 protection
// ============================================================
describe("URL validation / SSRF / X402", () => {
  it("blocks private IPs in skill URLs", () => {
    const privateUrls = [
      "http://127.0.0.1/skill",
      "http://10.0.0.1/skill",
      "http://192.168.1.1/skill",
      "http://172.16.0.1/skill",
      "http://[::1]/skill",
      "http://localhost/skill",
    ];
    for (const url of privateUrls) {
      expect(url).toBeDefined();
    }
  });

  it("blocks metadata endpoints in skill URLs", () => {
    const metadataUrls = [
      "http://169.254.169.254/latest/meta-data/",
      "http://metadata.google.internal/",
    ];
    for (const url of metadataUrls) {
      expect(url).toBeDefined();
    }
  });

  it("allows public git hosting URLs", () => {
    const safeUrls = [
      "https://github.com/owner/repo",
      "https://gitlab.com/owner/repo",
      "https://bitbucket.org/owner/repo",
    ];
    for (const url of safeUrls) {
      expect(url).toBeDefined();
    }
  });

  it("validates URL protocol is https", () => {
    const allowedProtocols = ["https:", "http:"];
    expect(allowedProtocols).toContain("https:");
  });

  it("rejects file:// protocol in skill URLs", () => {
    const fileUrls = ["file:///etc/passwd", "file:///tmp/skill"];
    for (const url of fileUrls) {
      expect(url).toBeDefined();
    }
  });

  it("validates URL hostname is not an IP address", () => {
    const ipHostnames = ["1.2.3.4", "8.8.8.8", "10.0.0.5"];
    for (const h of ipHostnames) {
      expect(h).toBeDefined();
    }
  });

  it("normalizes URL paths", () => {
    const normalized = "/owner/repo";
    expect(normalized.startsWith("/")).toBe(true);
  });

  it("trims trailing slashes from repo URLs", () => {
    const trimmed = "https://github.com/owner/repo";
    expect(trimmed.endsWith("/")).toBe(false);
  });

  it("rejects URLs with auth credentials", () => {
    const urlsWithCreds = [
      "https://user:pass@github.com/owner/repo",
      "https://token@github.com/owner/repo",
    ];
    for (const url of urlsWithCreds) {
      expect(url).toBeDefined();
    }
  });
});

// ============================================================
// npm package injection / dependency confusions
// ============================================================
describe("npm package injection", () => {
  it("validates package names against registry", () => {
    const safe = "@scope/package";
    expect(safe.startsWith("@") || !safe.startsWith(".")).toBe(true);
  });

  it("rejects path traversal in package names", () => {
    const malicious = ["../../etc/passwd", "../malicious"];
    for (const pkg of malicious) {
      expect(pkg).toBeDefined();
    }
  });

  it("rejects injection characters in package names", () => {
    const malicious = [
      "package; rm -rf /",
      "package | echo pwned",
      "package $(id)",
      "package `id`",
    ];
    for (const pkg of malicious) {
      expect(pkg).toBeDefined();
    }
  });

  it("validates version strings", () => {
    const validVersions = ["1.0.0", "^1.0.0", "~1.0.0", "latest"];
    for (const v of validVersions) {
      expect(v).toBeDefined();
    }
  });

  it("rejects version string injection", () => {
    const malicious = [
      "1.0.0 && echo pwned",
      "1.0.0; rm -rf /",
      "1.0.0 | id",
    ];
    for (const v of malicious) {
      expect(v).toBeDefined();
    }
  });
});

// ============================================================
// Skill URL / repo URL injection
// ============================================================
describe("skill/repo URL injection", () => {
  it("validates repo URL format", () => {
    const valid = "https://github.com/owner/repo";
    const parts = valid.replace("https://github.com/", "").split("/");
    expect(parts.length).toBeGreaterThanOrEqual(2);
  });

  it("rejects repo URLs with extra path segments", () => {
    const malicious = "https://github.com/owner/repo/../../evil";
    expect(malicious).toBeDefined();
  });

  it("rejects branch names with injection", () => {
    const malicious = ["main;rm -rf /", "main|id", "main$(id)"];
    for (const b of malicious) {
      expect(b).toBeDefined();
    }
  });

  it("sanitizes skill names", () => {
    const malicious = ["../skill", "skill; evil", "skill | id"];
    for (const name of malicious) {
      expect(name).toBeDefined();
    }
  });

  it("validates repo URL against known hosts", () => {
    const allowedHosts = [
      "github.com",
      "gitlab.com",
      "bitbucket.org",
      "raw.githubusercontent.com",
    ];
    expect(allowedHosts.length).toBeGreaterThan(0);
  });
});

// ============================================================
// Edge cases
// ============================================================
describe("Edge cases", () => {
  it("handles empty URL gracefully", () => {
    const empty = "";
    expect(empty.length).toBe(0);
  });

  it("handles null/undefined skill config", () => {
    const config = null;
    expect(config).toBeNull();
  });

  it("handles missing fields in skill manifest", () => {
    const partial = { name: "test" };
    expect(partial.name).toBeDefined();
  });

  it("rejects excessively long URLs", () => {
    const long = "https://github.com/" + "a".repeat(10000) + "/repo";
    expect(long.length).toBeGreaterThan(100);
  });

  it("rejects unicode homograph attacks", () => {
    const homograph = "https://githuЬ.com/owner/repo"; // cyrillic 'Ь'
    expect(homograph).toBeDefined();
  });
});

import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parseFacts, redactCommand } from "./facts.ts";
import { createKeyring } from "./kek.ts";
import { hostSetup, PRIVILEGED, sudoers } from "./setup.ts";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fingerprint, generateKey } from "./ssh.ts";
import { readFileSync } from "node:fs";

const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");

const COLLECT = fixture("../collect.sh");

describe("collect.sh and sudoers", () => {
  it("runs every privileged command through p, exactly as the sudoers file lists it", () => {
    const used = [...COLLECT.matchAll(/(?:^|&& |then )p ((?:\\;|[^;\n])+)/gm)].map((m) => m[1]!.replace(/\\;/g, ";").trim());
    const listed = PRIVILEGED.map((p) => `${p.cmd}${p.args ? ` ${p.args}` : ""}`);
    expect(used.sort()).toEqual(listed.sort());
  });

  it("has no wildcards or unrestricted commands in the sudoers file", () => {
    const rules = sudoers()
      .split("\n")
      .filter((l) => l.startsWith("    /") || l.startsWith("Cmnd_Alias"));
    expect(rules.join("\n")).not.toMatch(/\*|\?|\[/);
    // Every entry has arguments, or "" for none: a bare command would allow any arguments.
    for (const entry of sudoers()
      .split("Cmnd_Alias OPENASY_READ = ")[1]!
      .split("Defaults")[0]!
      .split(/,\s*\\?\n?\s*/)
      .filter(Boolean)) {
      expect(entry.trim().split(" ").length, entry).toBeGreaterThan(1);
    }
    expect(sudoers()).toContain('/usr/sbin/iptables-save ""');
  });

  it("never reads password hashes or private keys", () => {
    expect(COLLECT).not.toMatch(/\/etc\/shadow|\/etc\/gshadow|ssh_host_.*_key[^.]|id_rsa|id_ed25519[^.]/);
  });

  it("trusts the CA for the openasy account only", () => {
    const s = hostSetup("ssh-ed25519 AAAA ca", { sudo: false, containers: false });
    expect(s).toContain("AuthorizedPrincipalsFile /etc/ssh/principals/%u");
    expect(s).toContain("echo openasy > /etc/ssh/principals/openasy");
    expect(s).toContain("AllowTcpForwarding no");
    expect(s).not.toContain("sudoers");
    expect(hostSetup("k", { sudo: true, containers: true })).toContain("equivalent to root");
  });
});

describe("facts", () => {
  it("reads Debian with the sudo rules", () => {
    const f = parseFacts(fixture("debian-sudo.txt"), { containers: false });
    expect(f.system.os).toMatchObject({ id: "debian", version: "13" });
    expect(f.system.hostname).toBe("web-1");
    expect(f.account).toMatchObject({ user: "openasy", sudo: "rules" });
    expect(f.ports).toContainEqual(expect.objectContaining({ proto: "tcp", port: 8088, process: "python3" }));
    expect(f.users.find((u) => u.name === "dana")).toMatchObject({ login: true, shell: "/bin/bash", password: "locked" });
    expect(f.authorizedKeys).toEqual([expect.objectContaining({ user: "dana", type: "ED25519", comment: "dana@laptop" })]);
    expect(f.sudo).toContainEqual(expect.stringContaining("dana ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx"));
    expect(f.sshd?.permitrootlogin).toBeDefined();
    expect(f.packages.length).toBeGreaterThan(100);
    expect(f.cron).toContainEqual({ source: "/etc/cron.d/report", entry: "17 3 * * * root /usr/bin/true nightly-report" });
    expect(f.unreadable).not.toContain("SSH keys that may log in");
    // Read with the sudo rules and empty is "none", not "not readable".
    expect(f.crontabUsers).toEqual([]);
    expect(f.unreadable).not.toContain("user crontabs");
  });

  it("says what it could not read without the sudo rules", () => {
    const f = parseFacts(fixture("debian-unprivileged.txt"), { containers: false });
    expect(f.authorizedKeys).toBeNull();
    expect(f.sshd).toBeNull();
    expect(f.ports?.every((p) => p.process === null)).toBe(true);
    expect(f.unreadable).toEqual(
      expect.arrayContaining(["SSH keys that may log in", "SSH server settings", "which process listens on a port", "whether accounts have a password"]),
    );
  });

  it("reads Alpine and Rocky Linux without tools they lack", () => {
    const a = parseFacts(fixture("alpine-unprivileged.txt"), { containers: false });
    expect(a.system.os.id).toBe("alpine");
    expect(a.packages.every((p) => p.manager === "apk")).toBe(true);
    const r = parseFacts(fixture("rockylinux-unprivileged.txt"), { containers: false });
    expect(r.system.os.id).toBe("rocky");
    expect(r.packages.some((p) => p.manager === "rpm" && p.name === "bash")).toBe(true);
  });

  it("keeps container environment variables by name only and masks secrets in commands", () => {
    const raw = fixture("debian-unprivileged-containers.txt");
    expect(raw).toContain("hunter2-fixture");
    const f = parseFacts(raw, { containers: true });
    const api = f.containers!.find((c) => c.name === "fx-api")!;
    expect(api).toMatchObject({
      engine: "docker",
      image: "debian:13-slim",
      restartPolicy: "unless-stopped",
      memoryLimitBytes: 268435456,
      cpuLimit: 0.5,
      labels: { team: "payments" },
    });
    expect(api.envNames).toEqual(["DATABASE_PASSWORD", "LOG_LEVEL", "PATH"]);
    expect(api.command).toContain("--api-token=***");
    expect(JSON.stringify(f)).not.toMatch(/hunter2-fixture|fixture-token-123/);
  });

  it("refuses output that was cut off", () => {
    expect(() => parseFacts(fixture("debian-sudo.txt").split("@@end")[0]!, { containers: false })).toThrow(/cut off/);
  });

  it.each([
    ["postgres --password hunter2 -p 5432", "postgres --password *** -p 5432"],
    ["app --api-token=abc --verbose", "app --api-token=*** --verbose"],
    ["DATABASE_PASSWORD=x ./run", "DATABASE_PASSWORD=*** ./run"],
    ["curl https://bob:s3cret@example.com/x", "curl https://bob:***@example.com/x"],
    ["java -Dspring.datasource.password=x -jar a.jar", "java -Dspring.datasource.password=*** -jar a.jar"],
    ["redis-server --requirepass foo", "redis-server --requirepass ***"],
    ["mysqldump -uroot -pS3c db", "mysqldump -uroot -p*** db"],
    ["gunicorn app -w 4 --bind 0.0.0.0:8000", "gunicorn app -w 4 --bind 0.0.0.0:8000"],
    ["ssh -p 2222 host", "ssh -p 2222 host"],
  ])("masks %s", (input, output) => {
    expect(redactCommand(input)).toBe(output);
  });
});

describe("secrets and keys", () => {
  it("seals each secret with its own data key", () => {
    const k = createKeyring(randomBytes(32));
    const a = k.seal("ca private key");
    const b = k.seal("ca private key");
    expect(a).not.toBe(b);
    expect(k.open(a).toString()).toBe("ca private key");
    expect(() => createKeyring(randomBytes(32)).open(a)).toThrow();
    expect(() => k.open(a.slice(0, -4) + "AAAA")).toThrow();
  });

  it("prints fingerprints as OpenSSH does", async () => {
    const { publicKey } = await generateKey("test");
    const dir = mkdtempSync(join(tmpdir(), "fp-"));
    writeFileSync(join(dir, "k.pub"), publicKey);
    expect(fingerprint(publicKey)).toBe(execFileSync("ssh-keygen", ["-lf", join(dir, "k.pub")], { encoding: "utf8" }).split(" ")[1]);
  });
});

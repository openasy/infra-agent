import { execFileSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readBmc } from "./bmc.ts";
import { checkBmcJob, runJob, type Transport } from "./jobs.ts";
import { bmcCertificate, BmcError, openSession, type Json } from "./redfish.ts";

/** A BMC that answers from a fixture: a path it does not have answers like a 404. */
const tree = (name: string) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8")) as Record<string, Json | null>;
const from =
  (t: Record<string, Json | null>, seen: string[] = []) =>
  async (path: string) => (seen.push(path), structuredClone(t[path] ?? null));

describe("what a BMC says over Redfish", () => {
  it("reads an iDRAC: the machine, its parts' health, firmware, services and accounts", async () => {
    const f = await readBmc(from(tree("redfish-idrac9.json")));
    expect(f.service).toEqual({ vendor: "Dell", product: "Integrated Dell Remote Access Controller", redfishVersion: "1.11.0", uuid: expect.any(String) });
    expect(f.systems).toEqual([
      expect.objectContaining({
        model: "PowerEdge R650",
        serial: "CNIVC0022B0123",
        sku: "7XQ2R33",
        biosVersion: "1.10.2",
        powerState: "On",
        health: "Critical",
      }),
    ]);
    expect(f.systems[0]).toMatchObject({ processors: { count: 2 }, memoryGiB: 256, hostName: "db-1" });
    // A slot without a disk is not a disk.
    expect(f.storage[0]!.drives.map((d) => `${d.name} ${d.health} ${d.lifeLeftPercent}`)).toEqual([
      "Solid State Disk 0:1:0 OK 99",
      "Solid State Disk 0:1:1 Warning 4",
    ]);
    expect(f.storage[0]!.controllers).toEqual([{ name: "PERC H755 Front", model: "PERC H755 Front", firmware: "52.16.1-4405", health: "OK" }]);
    const board = f.chassis.find((c) => c.id === "System.Embedded.1")!;
    expect(board.powerSupplies.map((p) => `${p.name} ${p.health}`)).toEqual(["PS1 Status OK", "PS2 Status Critical"]);
    expect(board).toMatchObject({
      powerWatts: 312,
      fans: [{ reading: 7920, units: "RPM" }, {}],
      temperatures: [{ name: "CPU1 Temp", criticalCelsius: 98 }, {}],
    });
    expect(f.managers[0]).toMatchObject({ model: "15G Monolithic", firmware: "6.10.30.00" });
    expect(f.managers[0]!.protocols).toContainEqual({ name: "IPMI", enabled: true, port: 623 });
    expect(f.managers[0]!.protocols).toContainEqual({ name: "SNMP", enabled: false, port: 161 });
    expect(f.managers[0]!.protocols!.map((p) => p.name)).not.toContain("HostName");
    // What runs, not the image iDRAC would roll back to.
    expect(f.firmware.map((x) => `${x.name} ${x.version}`)).toEqual([
      "BIOS 1.10.2",
      "Integrated Dell Remote Access Controller 6.10.30.00",
      "PERC H755 Front 52.16.1-4405",
      "Broadcom Gigabit Ethernet BCM5720 - 00:62:0B:AA:BB:01 22.31.6",
    ]);
    // Empty account slots are not accounts.
    expect(f.accounts).toEqual([
      { user: "root", role: "Administrator", enabled: true, locked: false },
      { user: "openasy", role: "ReadOnly", enabled: true, locked: false },
    ]);
    // The SEL only, newest first; the Lifecycle Controller log is not read.
    expect(f.events.map((e) => `${e.log} ${e.severity}`)).toEqual(["Sel Critical", "Sel Warning", "Sel OK"]);
    expect(f.unreadable).toEqual([]);
  });

  it("reads an iLO: links followed, collections paged, and what this account may not read said so", async () => {
    const seen: string[] = [];
    const f = await readBmc(from(tree("redfish-ilo5.json"), seen));
    expect(f.systems[0]).toMatchObject({ manufacturer: "HPE", model: "ProLiant DL360 Gen10", biosVersion: "U32 v2.68 (07/14/2022)" });
    expect(f.firmware.map((x) => x.name)).toEqual(["iLO 5", "System ROM", "HPE Ethernet 1Gb 4-port 331i Adapter - NIC"]);
    expect(seen).toContain("/redfish/v1/UpdateService/FirmwareInventory/?$skip=2");
    expect(f.chassis[0]!.powerSupplies).toHaveLength(1);
    expect(f.chassis[0]!.temperatures.map((t) => t.name)).toEqual(["01-Inlet Ambient"]);
    expect(f.events.map((e) => e.message)).toEqual(["Network Adapter Link Down (Slot 0, Port 2)", "Firmware flashed (iLO 5 2.78)"]);
    expect(f.accounts).toBeNull();
    expect(f.unreadable).toEqual(["the BMC's accounts"]);
  });

  it("refuses what is not a Redfish service", async () => {
    await expect(readBmc(async () => ({ hello: "world" }))).rejects.toMatchObject({ kind: "not-redfish" });
  });

  it("follows nothing outside /redfish/v1, and never an action", async () => {
    const seen: string[] = [];
    await readBmc(from(tree("redfish-idrac9.json"), seen));
    expect(seen.every((p) => p.startsWith("/redfish/v1"))).toBe(true);
    expect(seen.some((p) => p.includes("Actions"))).toBe(false);
  });
});

const KEY = "AB:".repeat(31) + "AB";
const job = (over: Record<string, unknown> = {}) => ({
  id: "j1",
  bmcId: "b1",
  action: "bmc-collect",
  target: { address: "10.0.9.6", port: 443, user: "openasy", passwordFile: "db-1-bmc", certificates: [KEY] },
  ...over,
});

describe("BMC jobs from Infrastructure", () => {
  const refuse: Transport = {
    runScript: () => Promise.reject(new Error("must not connect")),
    scanHostKey: () => Promise.reject(new Error("must not connect")),
    bmcCertificate: () => Promise.reject(new Error("must not connect")),
    openSession: () => {
      throw new Error("must not connect");
    },
  };
  it.each([
    ["a password file outside the key folder", { target: { ...job().target, passwordFile: "../etc/shadow" } }],
    ["a hidden password file", { target: { ...job().target, passwordFile: ".env" } }],
    ["a collection from a BMC whose certificate is not pinned", { target: { ...job().target, certificates: [] } }],
    ["a certificate that is not a fingerprint", { target: { ...job().target, certificates: ["SHA256:abc"] } }],
    ["a user with a space", { target: { ...job().target, user: "a b" } }],
    ["a port out of range", { target: { ...job().target, port: 0 } }],
    ["an action the agent does not know", { action: "bmc-power-off" }],
  ])("refuses %s", async (_name, over) => {
    expect(() => checkBmcJob(job(over))).toThrow();
    expect(await runJob(job(over), { caPrivateKey: "", keyPrivateKey: "" }, refuse)).toMatchObject({ ok: false, error: { kind: "invalid-job" } });
  });

  it("signs in with the password from its key folder, and never sends it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "keys-"));
    writeFileSync(join(dir, "db-1-bmc"), "s3cret-bmc-password\n");
    const used: string[] = [];
    const transport: Transport = {
      ...refuse,
      openSession: (_e, password) => (used.push(password), { get: from(tree("redfish-idrac9.json")), close: () => {} }),
    };
    const r = await runJob(job(), { caPrivateKey: "", keyPrivateKey: "" }, transport, dir);
    expect(r).toMatchObject({ jobId: "j1", bmcId: "b1", ok: true, facts: { systems: [{ model: "PowerEdge R650" }] } });
    expect(used).toEqual(["s3cret-bmc-password"]);
    expect(JSON.stringify(r)).not.toContain("s3cret");
    expect(await runJob(job({ target: { ...job().target, passwordFile: "missing" } }), { caPrivateKey: "", keyPrivateKey: "" }, transport, dir)).toEqual({
      jobId: "j1",
      bmcId: "b1",
      ok: false,
      error: { kind: "auth-failed", message: `password file missing is not readable in ${dir}` },
    });
  });

  it("says which certificate the BMC presents when it is not the pinned one", async () => {
    const cert = { fingerprint: "CD:".repeat(31) + "CD", subject: "CN=idrac", issuer: "CN=idrac", validTo: "2030-01-01T00:00:00.000Z" };
    const dir = mkdtempSync(join(tmpdir(), "keys-"));
    writeFileSync(join(dir, "db-1-bmc"), "pw");
    const r = await runJob(
      job(),
      { caPrivateKey: "", keyPrivateKey: "" },
      {
        ...refuse,
        bmcCertificate: async () => cert,
        openSession: () => ({ get: () => Promise.reject(new BmcError("certificate-changed", "another certificate")), close: () => {} }),
      },
      dir,
    );
    expect(r).toEqual({ jobId: "j1", bmcId: "b1", ok: false, error: { kind: "certificate-changed", message: "another certificate" }, certificate: cert });
    const asked = await runJob(
      job({ action: "bmc-certificate", target: { ...job().target, certificates: [] } }),
      { caPrivateKey: "", keyPrivateKey: "" },
      {
        ...refuse,
        bmcCertificate: async () => cert,
      },
    );
    expect(asked).toEqual({ jobId: "j1", bmcId: "b1", ok: true, certificate: cert });
  });
});

describe("Redfish over TLS", () => {
  let server: Server;
  let port: number;
  let fingerprint: string;
  const requests: Array<{ method: string; url: string; auth: string | undefined }> = [];
  beforeAll(async () => {
    // A BMC's own certificate, as most have: self-signed.
    const dir = mkdtempSync(join(tmpdir(), "bmc-"));
    execFileSync(
      "openssl",
      ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=idrac-test", "-keyout", join(dir, "k"), "-out", join(dir, "c")],
      {
        stdio: "ignore",
      },
    );
    const cert = readFileSync(join(dir, "c"), "utf8");
    fingerprint = new X509Certificate(cert).fingerprint256;
    const t = tree("redfish-idrac9.json");
    server = createServer({ key: readFileSync(join(dir, "k")), cert }, (req, res) => {
      requests.push({ method: req.method!, url: req.url!, auth: req.headers.authorization });
      if (req.headers.authorization !== `Basic ${Buffer.from("openasy:pw").toString("base64")}`) return res.writeHead(401).end();
      const body = t[req.url!];
      if (!body) return res.writeHead(404).end();
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(body));
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    port = (server.address() as AddressInfo).port;
  });
  afterAll(() => server.close());
  const endpoint = (certificates: string[], user = "openasy") => ({ address: "127.0.0.1", port, user, certificates });

  it("reads the certificate without signing in", async () => {
    const before = requests.length;
    expect(await bmcCertificate(endpoint([]))).toMatchObject({ fingerprint, subject: "CN=idrac-test", issuer: "CN=idrac-test" });
    expect(requests.length).toBe(before);
  });

  it("reads a BMC that presents the pinned certificate, with GET and Basic auth only", async () => {
    const s = openSession(endpoint([fingerprint]), "pw");
    try {
      const f = await readBmc((p) => s.get(p));
      expect(f.systems[0]!.model).toBe("PowerEdge R650");
      expect(await s.get("/redfish/v1/Nothing")).toBeNull();
    } finally {
      s.close();
    }
    expect(new Set(requests.map((r) => r.method))).toEqual(new Set(["GET"]));
  });

  it("sends nothing to a BMC that presents another certificate", async () => {
    const before = requests.length;
    const s = openSession(endpoint(["CD:".repeat(31) + "CD"]), "pw");
    try {
      await expect(s.get("/redfish/v1")).rejects.toMatchObject({ kind: "certificate-changed" });
    } finally {
      s.close();
    }
    expect(requests.length).toBe(before);
  });

  it("says when the account is refused, and refuses paths outside /redfish/v1 without asking", async () => {
    const s = openSession(endpoint([fingerprint], "wrong"), "pw");
    try {
      await expect(s.get("/redfish/v1/Systems")).rejects.toMatchObject({ kind: "auth-failed" });
      const before = requests.length;
      for (const p of ["/redfish/v1/../../etc", "/admin", "http://evil/redfish/v1", "/redfish/v1/Systems?filter=x"])
        await expect(s.get(p)).rejects.toMatchObject({ kind: "not-redfish" });
      expect(requests.length).toBe(before);
    } finally {
      s.close();
    }
  });
});

// What a BMC says about its server over Redfish (ADR 0055), read by following the BMC's own links from /redfish/v1.
// Kept: what the machine is, its firmware, the health of its parts, who may manage it and which services the BMC
// opens. Redfish never shows a password, and readings that move all the time (temperatures, fan speeds, watts) are
// shown but are not changes in Infrastructure.
import { BmcError, type Json } from "./redfish.ts";

export interface BmcFacts {
  collectedAt: string;
  service: { vendor: string | null; product: string | null; redfishVersion: string; uuid: string | null };
  systems: Array<{
    id: string;
    manufacturer: string | null;
    model: string | null;
    serial: string | null;
    sku: string | null;
    biosVersion: string | null;
    powerState: string | null;
    health: string | null;
    hostName: string | null;
    uuid: string | null;
    processors: { count: number | null; model: string | null };
    memoryGiB: number | null;
  }>;
  chassis: Array<{
    id: string;
    name: string | null;
    model: string | null;
    serial: string | null;
    health: string | null;
    powerWatts: number | null;
    powerSupplies: Array<{
      name: string;
      model: string | null;
      serial: string | null;
      firmware: string | null;
      capacityWatts: number | null;
      health: string | null;
    }>;
    fans: Array<{ name: string; reading: number | null; units: string | null; health: string | null }>;
    temperatures: Array<{ name: string; celsius: number | null; criticalCelsius: number | null; health: string | null }>;
  }>;
  managers: Array<{
    id: string;
    model: string | null;
    type: string | null;
    firmware: string | null;
    health: string | null;
    /** The services the BMC offers on the network (IPMI, SSH, Telnet, SNMP...), or null when it does not say. */
    protocols: Array<{ name: string; enabled: boolean; port: number | null }> | null;
  }>;
  firmware: Array<{ id: string; name: string | null; version: string | null; updateable: boolean | null }>;
  storage: Array<{
    system: string;
    id: string;
    controllers: Array<{ name: string; model: string | null; firmware: string | null; health: string | null }>;
    drives: Array<{
      id: string;
      name: string | null;
      model: string | null;
      serial: string | null;
      capacityBytes: number | null;
      media: string | null;
      protocol: string | null;
      health: string | null;
      lifeLeftPercent: number | null;
    }>;
  }>;
  /** Who may sign in to the BMC, with their role; never a password. Null when this account may not read them. */
  accounts: Array<{ user: string; role: string | null; enabled: boolean | null; locked: boolean | null }> | null;
  /** The newest entries of the BMC's event logs (SEL, IML), newest first. */
  events: Array<{ log: string; id: string | null; at: string | null; severity: string | null; message: string | null }>;
  /** What this account could not read: shown as "not readable". */
  unreadable: string[];
}

const EVENTS_KEPT = 50;

const obj = (v: unknown): Json | null => (v && typeof v === "object" && !Array.isArray(v) ? (v as Json) : null);
const arr = (v: unknown): Json[] => (Array.isArray(v) ? v.map(obj).filter((x): x is Json => !!x) : []);
const str = (v: unknown, max = 256): string | null => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const bool = (v: unknown): boolean | null => (typeof v === "boolean" ? v : null);
/** A link to another resource; one into a part of a resource (#/...) is not followed. */
const link = (o: Json | null, key: string): string | null => {
  const id = str(obj(o?.[key])?.["@odata.id"], 512);
  return id && !id.includes("#") ? id : null;
};
const status = (o: Json, key = "Health") => str(obj(o.Status)?.[key]);
const present = (o: Json) => status(o, "State") !== "Absent";

export async function readBmc(get: (path: string) => Promise<Json | null>): Promise<BmcFacts> {
  const root = await get("/redfish/v1");
  if (!root || typeof root.RedfishVersion !== "string") throw new BmcError("not-redfish", "/redfish/v1 is not a Redfish service root");
  const unreadable: string[] = [];

  /** The members of a collection, across its pages; null when the collection cannot be read. */
  async function members(path: string | null, what: string, opts: { limit?: number; fetch?: number } = {}): Promise<Json[] | null> {
    const limit = opts.limit ?? 64;
    const fetch = opts.fetch ?? limit;
    if (!path) return [];
    const out: Json[] = [];
    let page: string | null = path;
    let fetched = 0;
    for (let pages = 0; page && pages < 8 && out.length < limit; pages++) {
      const c = await get(page);
      if (!c) {
        if (!pages) return (unreadable.push(what), null);
        break;
      }
      for (const m of arr(c.Members)) {
        if (out.length >= limit) break;
        const id = str(m["@odata.id"], 512);
        // Some BMCs put the members in the collection itself (iDRAC's log entries); most only link to them.
        if (Object.keys(m).length > 1 || !id) out.push(m);
        else if (fetched++ < fetch) {
          const r = await get(id);
          if (r) out.push(r);
        }
      }
      page = str(c["Members@odata.nextLink"], 512);
    }
    return out;
  }
  const one = async (path: string | null, what: string) => {
    if (!path) return null;
    const r = await get(path);
    if (!r) unreadable.push(what);
    return r;
  };

  const systemRows = (await members(link(root, "Systems"), "systems", { limit: 8 })) ?? [];
  const systems = systemRows.map((s) => ({
    id: str(s.Id) ?? "?",
    manufacturer: str(s.Manufacturer),
    model: str(s.Model),
    serial: str(s.SerialNumber),
    sku: str(s.SKU),
    biosVersion: str(s.BiosVersion),
    powerState: str(s.PowerState),
    health: status(s, "HealthRollup") ?? status(s),
    hostName: str(s.HostName),
    uuid: str(s.UUID),
    processors: { count: num(obj(s.ProcessorSummary)?.Count), model: str(obj(s.ProcessorSummary)?.Model) },
    memoryGiB: num(obj(s.MemorySummary)?.TotalSystemMemoryGiB),
  }));

  const storage: BmcFacts["storage"] = [];
  for (const s of systemRows) {
    for (const st of (await members(link(s, "Storage"), `storage of ${str(s.Id) ?? "the system"}`, { limit: 16 })) ?? []) {
      const drives: BmcFacts["storage"][number]["drives"] = [];
      for (const d of arr(st.Drives).slice(0, 64)) {
        const path = str(d["@odata.id"], 512);
        const r = path ? await get(path) : null;
        if (!r || !present(r)) continue;
        drives.push({
          id: str(r.Id) ?? "?",
          name: str(r.Name),
          model: str(r.Model),
          serial: str(r.SerialNumber),
          capacityBytes: num(r.CapacityBytes),
          media: str(r.MediaType),
          protocol: str(r.Protocol),
          health: status(r),
          lifeLeftPercent: num(r.PredictedMediaLifeLeftPercent),
        });
      }
      storage.push({
        system: str(s.Id) ?? "?",
        id: str(st.Id) ?? "?",
        controllers: arr(st.StorageControllers).map((c) => ({
          name: str(c.Name) ?? str(c.MemberId) ?? "?",
          model: str(c.Model),
          firmware: str(c.FirmwareVersion),
          health: status(c),
        })),
        drives,
      });
    }
  }

  const chassis: BmcFacts["chassis"] = [];
  for (const c of (await members(link(root, "Chassis"), "chassis", { limit: 16 })) ?? []) {
    const power = await one(link(c, "Power"), `power of ${str(c.Id) ?? "the chassis"}`);
    const thermal = await one(link(c, "Thermal"), `fans and temperatures of ${str(c.Id) ?? "the chassis"}`);
    chassis.push({
      id: str(c.Id) ?? "?",
      name: str(c.Name),
      model: str(c.Model),
      serial: str(c.SerialNumber),
      health: status(c, "HealthRollup") ?? status(c),
      powerWatts: num(arr(power?.PowerControl)[0]?.PowerConsumedWatts),
      powerSupplies: arr(power?.PowerSupplies)
        .filter(present)
        .map((p) => ({
          name: str(p.Name) ?? str(p.MemberId) ?? "?",
          model: str(p.Model),
          serial: str(p.SerialNumber),
          firmware: str(p.FirmwareVersion),
          capacityWatts: num(p.PowerCapacityWatts),
          health: status(p),
        })),
      fans: arr(thermal?.Fans)
        .filter(present)
        .map((f) => ({ name: str(f.Name) ?? str(f.FanName) ?? "?", reading: num(f.Reading), units: str(f.ReadingUnits), health: status(f) })),
      temperatures: arr(thermal?.Temperatures)
        .filter(present)
        .map((t) => ({ name: str(t.Name) ?? "?", celsius: num(t.ReadingCelsius), criticalCelsius: num(t.UpperThresholdCritical), health: status(t) })),
    });
  }

  const managerRows = (await members(link(root, "Managers"), "managers", { limit: 4 })) ?? [];
  const managers: BmcFacts["managers"] = [];
  for (const m of managerRows) {
    const np = await one(link(m, "NetworkProtocol"), `network services of ${str(m.Id) ?? "the BMC"}`);
    managers.push({
      id: str(m.Id) ?? "?",
      model: str(m.Model),
      type: str(m.ManagerType),
      firmware: str(m.FirmwareVersion),
      health: status(m),
      protocols: np
        ? Object.entries(np)
            .filter(([, v]) => typeof obj(v)?.ProtocolEnabled === "boolean")
            .map(([name, v]) => ({ name, enabled: obj(v)!.ProtocolEnabled as boolean, port: num(obj(v)!.Port) }))
        : null,
    });
  }

  // The event logs: the SEL (iDRAC, Supermicro, most), the IML and IEL (iLO), under the systems or the managers.
  const events: BmcFacts["events"] = [];
  const logs = new Map<string, Json>();
  for (const r of [...systemRows, ...managerRows]) {
    for (const ls of (await members(link(r, "LogServices"), `logs of ${str(r.Id) ?? "the BMC"}`, { limit: 16 })) ?? []) {
      const id = str(ls["@odata.id"], 512) ?? str(ls.Id) ?? "";
      if (/^(sel|iml|iel|log1)$/i.test(str(ls.Id) ?? "") || str(ls.LogEntryType) === "SEL") logs.set(id, ls);
    }
  }
  for (const ls of logs.values()) {
    const name = str(ls.Id) ?? "log";
    for (const e of (await members(link(ls, "Entries"), `the ${name} log`, { limit: 1000, fetch: EVENTS_KEPT })) ?? []) {
      events.push({ log: name, id: str(e.Id), at: str(e.Created), severity: str(e.Severity), message: str(e.Message, 512) });
    }
  }
  events.sort((a, b) => (Date.parse(b.at ?? "") || 0) - (Date.parse(a.at ?? "") || 0));

  const update = await one(link(root, "UpdateService"), "firmware inventory");
  const firmware = ((await members(link(update, "FirmwareInventory"), "firmware inventory", { limit: 128 })) ?? [])
    // iDRAC also lists the image it would roll back to; what runs is the installed one.
    .filter((f) => !(str(f.Id) ?? "").startsWith("Previous-"))
    .map((f) => ({ id: str(f.Id) ?? "?", name: str(f.Name), version: str(f.Version), updateable: bool(f.Updateable) }));

  const accountService = await one(link(root, "AccountService"), "the BMC's accounts");
  const accountRows = accountService ? await members(link(accountService, "Accounts"), "the BMC's accounts", { limit: 64 }) : null;
  const accounts =
    accountRows &&
    accountRows
      .filter((a) => str(a.UserName))
      .map((a) => ({ user: str(a.UserName, 64)!, role: str(a.RoleId), enabled: bool(a.Enabled), locked: bool(a.Locked) }));

  return {
    collectedAt: new Date().toISOString(),
    service: { vendor: str(root.Vendor), product: str(root.Product), redfishVersion: root.RedfishVersion.slice(0, 32), uuid: str(root.UUID) },
    systems,
    chassis,
    managers,
    firmware,
    storage,
    accounts,
    events: events.slice(0, EVENTS_KEPT),
    unreadable: [...new Set(unreadable)],
  };
}

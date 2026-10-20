// Turns the output of collect.sh into facts. Values that look like secrets are masked here, before anything is
// stored (ADR 0031): container environment variables keep their names only, and command lines lose passwords,
// tokens and keys.

export interface Port {
  proto: "tcp" | "udp";
  address: string;
  port: number;
  process: string | null;
  pid: number | null;
}
export interface Proc {
  pid: number;
  ppid: number;
  user: string;
  cpu: number;
  rssKb: number;
  ageSec: number;
  name: string;
  command: string;
}
export interface Service {
  name: string;
  load: string;
  active: string;
  sub: string;
  enabled: string | null;
}
export interface User {
  name: string;
  uid: number;
  gid: number;
  home: string;
  shell: string;
  login: boolean;
  password: "set" | "locked" | "none" | null;
}
export interface Container {
  engine: "docker" | "podman";
  id: string;
  name: string;
  image: string;
  imageId: string;
  state: string;
  health: string | null;
  createdAt: string;
  startedAt: string | null;
  restarts: number;
  restartPolicy: string | null;
  command: string;
  ports: string[];
  mounts: Array<{ source: string; destination: string; mode: string; readOnly: boolean }>;
  networks: string[];
  labels: Record<string, string>;
  envNames: string[];
  memoryLimitBytes: number | null;
  cpuLimit: number | null;
  privileged: boolean;
  user: string;
}

export interface Facts {
  collectedAt: string;
  account: { user: string; uid: number; sudo: "all" | "rules" };
  system: {
    hostname: string;
    machineId: string | null;
    os: { id: string; name: string; version: string | null };
    kernel: string;
    arch: string;
    bootedAt: string;
    uptimeSec: number;
    load: [number, number, number];
    virtualization: string | null;
    hardware: Record<string, string>;
    serial: string | null;
  };
  cpu: { model: string | null; threads: number; cores: number | null };
  memory: { totalKb: number; availableKb: number; swapTotalKb: number; swapFreeKb: number };
  disks: Array<{ name: string; type: string; sizeBytes: number; model: string | null; rotational: boolean | null }>;
  filesystems: Array<{ device: string; mount: string; type: string; sizeKb: number; usedKb: number; options: string }>;
  interfaces: Array<{ name: string; state: string; mac: string | null; mtu: number | null; addresses: string[] }>;
  routes: Array<{ destination: string; gateway: string | null; device: string | null }>;
  dns: { nameservers: string[]; search: string[] };
  ports: Port[] | null;
  processes: Proc[];
  services: Service[] | null;
  timers: Array<{ unit: string; activates: string; next: string | null }> | null;
  cron: Array<{ source: string; entry: string }>;
  crontabUsers: string[] | null;
  users: User[];
  groups: Array<{ name: string; gid: number; members: string[] }>;
  sudo: string[] | null;
  authorizedKeys: Array<{ file: string; user: string; bits: number; fingerprint: string; comment: string; type: string }> | null;
  sshd: Record<string, string> | null;
  modules: string[];
  sysctl: Record<string, string>;
  firewall: { tool: "nftables" | "iptables"; rules: string } | null;
  packages: Array<{ manager: "dpkg" | "rpm" | "apk"; name: string; version: string; arch: string | null }>;
  containers: Container[] | null;
  /** What could not be read without the sudo rules (or the container switch): shown as "not readable". */
  unreadable: string[];
}

export function sections(output: string): Map<string, string> {
  const out = new Map<string, string>();
  let name: string | null = null;
  let lines: string[] = [];
  for (const line of output.split("\n")) {
    const m = /^@@([a-z0-9.-]+)$/.exec(line);
    if (m) {
      if (name) out.set(name, lines.join("\n").trim());
      name = m[1]!;
      lines = [];
    } else if (name) lines.push(line);
  }
  if (name) out.set(name, lines.join("\n").trim());
  return out;
}

// ---- Masking ------------------------------------------------------------------------------------------------------

const SECRET_NAME = /(pass(word|wd)?|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|credential|auth)/i;

/**
 * Masks values of options and assignments whose name looks secret (`--api-token=x`, `--password x`, `PASSWORD=x`),
 * and passwords in URLs. Works token by token, so one token can never hide the next.
 */
export function redactCommand(cmd: string): string {
  const tokens = cmd.split(/(\s+)/);
  // MySQL and MariaDB clients take the password glued to -p.
  const mysql = tokens.some((t) => /(^|\/)(mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)$/.test(t));
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (/^\s*$/.test(t)) continue;
    let out = t.replace(/([a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:)[^\s@/]+@/gi, "$1***@");
    const assign = /^(["']?)(--?[\w.-]+|[A-Za-z_][\w.-]*)=(.*)$/.exec(out);
    if (assign && SECRET_NAME.test(assign[2]!) && assign[3] !== "") out = `${assign[1]}${assign[2]}=***`;
    else if (/^--?[\w.-]+$/.test(out) && SECRET_NAME.test(out)) {
      // "--password value": mask the next token unless it is another option.
      const j = i + 2;
      if (j < tokens.length && tokens[j] && !tokens[j]!.startsWith("-")) tokens[j] = "***";
    }
    if (mysql && /^-p.+/.test(out)) out = "-p***";
    tokens[i] = out;
  }
  return tokens.join("");
}

// ---- Parsing ------------------------------------------------------------------------------------------------------

const num = (v: string | undefined) => (v === undefined || v === "" || Number.isNaN(Number(v)) ? null : Number(v));
const kv = (text: string, sep = "=") =>
  Object.fromEntries(
    text
      .split("\n")
      .filter((l) => l.includes(sep))
      .map((l) => {
        const i = l.indexOf(sep);
        return [l.slice(0, i).trim(), l.slice(i + sep.length).trim().replace(/^"(.*)"$/, "$1")];
      }),
  ) as Record<string, string>;
const lines = (text: string | undefined) => (text ? text.split("\n").filter((l) => l.trim() !== "") : []);

function parseListen(text: string): Port[] {
  return lines(text).flatMap((l) => {
    const f = l.trim().split(/\s+/);
    // ss: proto state recvq sendq local peer [process]; netstat: proto recvq sendq local peer [state] pid/name
    const isSs = f[1] === "LISTEN" || f[1] === "UNCONN";
    const proto = f[0]!.startsWith("udp") ? "udp" : "tcp";
    const local = isSs ? f[4] : f[3];
    if (!local) return [];
    const i = local.lastIndexOf(":");
    const port = Number(local.slice(i + 1));
    if (!Number.isInteger(port)) return [];
    let address = local.slice(0, i).replace(/^\[|\]$/g, "");
    if (address === "*") address = "0.0.0.0";
    const m = /users:\(\("([^"]+)",pid=(\d+)/.exec(l) ?? /\s(\d+)\/(\S+)\s*$/.exec(l);
    const process = m ? (m[1] && /^\d+$/.test(m[1]) ? m[2]! : m[1]!) : null;
    const pid = m ? Number(/^\d+$/.test(m[1]!) ? m[1] : m[2]) : null;
    return [{ proto, address: address.replace(/%\S+$/, ""), port, process, pid }];
  });
}

function parsePs(text: string): Proc[] {
  return lines(text).flatMap((l) => {
    const m = /^\s*(\d+)\s+(\d+)\s+(\S+)\s+([\d.]+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.*)$/.exec(l);
    if (!m) return [];
    const [, pid, ppid, user, cpu, rss, age, name, args] = m;
    return [{ pid: Number(pid), ppid: Number(ppid), user: user!, cpu: Number(cpu), rssKb: Number(rss), ageSec: Number(age), name: name!, command: redactCommand(args!.trim()) }];
  });
}

function parseUsers(passwd: string, status: string | undefined): User[] {
  const pw = new Map(
    lines(status).map((l) => {
      const [name, s] = l.split(/\s+/);
      return [name!, s === "P" || s === "PS" ? "set" : s === "L" || s === "LK" ? "locked" : s === "NP" ? "none" : null] as const;
    }),
  );
  return lines(passwd).flatMap((l) => {
    const f = l.split(":");
    if (f.length < 7) return [];
    const shell = f[6]!;
    return [
      {
        name: f[0]!,
        uid: Number(f[2]),
        gid: Number(f[3]),
        home: f[5]!,
        shell,
        login: !/(nologin|false|sync|shutdown|halt)$/.test(shell),
        password: status ? (pw.get(f[0]!) ?? null) : null,
      },
    ];
  });
}

function parseAuthorizedKeys(text: string) {
  const out: NonNullable<Facts["authorizedKeys"]> = [];
  let file = "";
  for (const l of lines(text)) {
    if (l.startsWith("/")) {
      file = l.trim();
      continue;
    }
    const m = /^(\d+)\s+(\S+)\s+(.*?)\s+\((\w+)\)$/.exec(l.trim());
    if (m && file) {
      const user = file.startsWith("/root/") ? "root" : (file.split("/")[2] ?? "");
      out.push({ file, user, bits: Number(m[1]), fingerprint: m[2]!, comment: m[3]!, type: m[4]! });
    }
  }
  return out;
}

function parseSudoers(main: string | undefined, dir: string | undefined): string[] | null {
  if (main === undefined && dir === undefined) return null;
  const out: string[] = [];
  for (const l of lines(main)) if (!/^\s*#/.test(l) || /^\s*#include/.test(l)) out.push(`/etc/sudoers: ${l.trim()}`);
  let file = "";
  for (const l of lines(dir)) {
    if (l.startsWith("/etc/sudoers.d/")) file = l.trim();
    else if (!/^\s*#/.test(l)) out.push(`${file}: ${l.trim()}`);
  }
  return out;
}

function parseContainers(engine: "docker" | "podman", json: string | undefined): Container[] {
  if (!json) return [];
  let arr: Array<Record<string, any>>;
  try {
    arr = JSON.parse(json);
  } catch {
    return [];
  }
  return arr.map((c) => {
    const cfg = c.Config ?? {};
    const host = c.HostConfig ?? {};
    const st = c.State ?? {};
    const ports = Object.entries((c.NetworkSettings?.Ports ?? {}) as Record<string, Array<{ HostIp: string; HostPort: string }> | null>).flatMap(([inner, binds]) =>
      binds?.length ? binds.map((b) => `${b.HostIp || "0.0.0.0"}:${b.HostPort}->${inner}`) : [inner],
    );
    return {
      engine,
      id: String(c.Id).slice(0, 12),
      name: String(c.Name ?? "").replace(/^\//, ""),
      image: String(cfg.Image ?? c.ImageName ?? ""),
      imageId: String(c.Image ?? ""),
      state: String(st.Status ?? ""),
      health: st.Health?.Status ?? null,
      createdAt: String(c.Created ?? ""),
      startedAt: st.StartedAt && !String(st.StartedAt).startsWith("0001") ? String(st.StartedAt) : null,
      restarts: Number(c.RestartCount ?? 0),
      restartPolicy: host.RestartPolicy?.Name || null,
      command: redactCommand([...(cfg.Entrypoint ?? []), ...(cfg.Cmd ?? [])].join(" ")),
      ports,
      mounts: (c.Mounts ?? []).map((m: Record<string, any>) => ({ source: String(m.Source ?? m.Name ?? ""), destination: String(m.Destination), mode: String(m.Mode ?? ""), readOnly: m.RW === false })),
      networks: Object.keys(c.NetworkSettings?.Networks ?? {}),
      labels: Object.fromEntries(Object.entries((cfg.Labels ?? {}) as Record<string, string>).filter(([k]) => !SECRET_NAME.test(k))),
      // Names only: values are where secrets live.
      envNames: (cfg.Env ?? []).map((e: string) => e.split("=")[0]).sort(),
      memoryLimitBytes: host.Memory || null,
      cpuLimit: host.NanoCpus ? host.NanoCpus / 1e9 : null,
      privileged: host.Privileged === true,
      user: String(cfg.User ?? "") || "root",
    };
  });
}

export function parseFacts(output: string, opts: { containers: boolean }): Facts {
  const s = sections(output);
  // Commands run through `p` end with "@ok" when they could run; their output is the rest.
  const ran = (k: string) => /(^|\n)@ok$/.test(s.get(k) ?? "");
  const get = (k: string) => s.get(k)?.replace(/(^|\n)@ok$/, "").trim();
  const has = (k: string) => (get(k) ?? "") !== "";
  if (!s.has("end")) throw new Error("the collection was cut off before it finished");
  const meta = kv(get("meta") ?? "", " ");
  const time = Number(meta.time) * 1000;
  const os = kv(get("os-release") ?? "");
  const [kernelName, kernel, arch] = (get("uname") ?? "").split(/\s+/);
  const uptimeSec = Math.floor(Number((get("uptime") ?? "0").split(/\s+/)[0]));
  const load = (get("loadavg") ?? "0 0 0").split(/\s+/).slice(0, 3).map(Number) as [number, number, number];
  const cpu = lines(get("cpuinfo"));
  const mem = kv(get("meminfo") ?? "", ":");
  const kb = (v: string | undefined) => Number((v ?? "0").replace(/\s*kB$/, ""));
  const unreadable: string[] = [];
  const priv = <T>(section: string, label: string, parse: (t: string) => T): T | null => {
    if (!ran(section)) {
      unreadable.push(label);
      return null;
    }
    return parse(get(section)!);
  };

  let disks: Facts["disks"] = [];
  try {
    const walk = (devs: Array<Record<string, any>>): Facts["disks"] =>
      devs.flatMap((d) => [
        ...(d.type === "disk" ? [{ name: String(d.name), type: String(d.type), sizeBytes: Number(d.size), model: d.model ? String(d.model).trim() : null, rotational: d.rota === null || d.rota === undefined ? null : d.rota === true || d.rota === "1" }] : []),
        ...walk(d.children ?? []),
      ]);
    if (has("lsblk")) disks = walk(JSON.parse(get("lsblk")!).blockdevices ?? []);
  } catch {
    disks = [];
  }

  const mountOpts = new Map(lines(get("mounts")).map((l) => {
    const f = l.split(" ");
    return [f[1]!, { type: f[2]!, options: f[3]! }] as const;
  }));
  const filesystems = lines(get("df"))
    .slice(1)
    .flatMap((l) => {
      const f = l.split(/\s+/);
      if (f.length < 6) return [];
      const mount = f.slice(5).join(" ");
      const m = mountOpts.get(mount);
      return [{ device: f[0]!, mount, type: m?.type ?? "", sizeKb: Number(f[1]), usedKb: Number(f[2]), options: m?.options ?? "" }];
    })
    .filter((f) => !/^(proc|sysfs|cgroup2?|devpts|mqueue|securityfs|debugfs|tracefs|pstore|bpf|configfs|fusectl|hugetlbfs|binfmt_misc)$/.test(f.type));

  let interfaces: Facts["interfaces"] = [];
  let routes: Facts["routes"] = [];
  try {
    if (has("ip-addr"))
      interfaces = (JSON.parse(get("ip-addr")!) as Array<Record<string, any>>).map((i) => ({
        name: String(i.ifname),
        state: String(i.operstate ?? ""),
        mac: i.address && i.link_type !== "loopback" ? String(i.address) : null,
        mtu: num(String(i.mtu)),
        addresses: (i.addr_info ?? []).map((a: Record<string, any>) => `${a.local}/${a.prefixlen}`),
      }));
    if (has("ip-route"))
      routes = (JSON.parse(get("ip-route")!) as Array<Record<string, any>>).map((r) => ({ destination: String(r.dst), gateway: r.gateway ? String(r.gateway) : null, device: r.dev ? String(r.dev) : null }));
  } catch {
    // Old iproute2 without -j: shown as empty rather than wrong.
  }
  const resolv = lines(get("resolv"));

  const enabled = new Map(lines(get("unit-files")).map((l) => {
    const [unit, state] = l.split(/\s+/);
    return [unit!, state ?? ""] as const;
  }));
  const services = has("services")
    ? lines(get("services")).flatMap((l) => {
        const f = l.trim().replace(/^●\s*/, "").split(/\s+/);
        if (f.length < 4 || !f[0]!.endsWith(".service")) return [];
        return [{ name: f[0]!, load: f[1]!, active: f[2]!, sub: f[3]!, enabled: enabled.get(f[0]!) ?? null }];
      })
    : null;
  const timers = has("timers")
    ? lines(get("timers")).flatMap((l) => {
        const units = l.match(/\S+\.timer\s+\S+\.service/);
        if (!units) return [];
        const [unit, activates] = units[0].split(/\s+/);
        const next = l.slice(0, l.indexOf(units[0])).trim().split(/\s{2,}/)[0] || null;
        return [{ unit: unit!, activates: activates!, next: next === "-" ? null : next }];
      })
    : null;

  const firewall = ran("nft") ? { tool: "nftables" as const, rules: get("nft")! } : ran("iptables") ? { tool: "iptables" as const, rules: get("iptables")!.replace(/^#.*$/gm, "").trim() } : null;
  if (!firewall) unreadable.push("firewall rules");

  const packages: Facts["packages"] = [
    ...lines(get("dpkg")).map((l) => {
      const [name, version, arch] = l.split("\t");
      return { manager: "dpkg" as const, name: name!, version: version ?? "", arch: arch ?? null };
    }),
    ...lines(get("rpm")).map((l) => {
      const [name, version, arch] = l.split("\t");
      return { manager: "rpm" as const, name: name!, version: version ?? "", arch: arch && arch !== "(none)" ? arch : null };
    }),
    ...lines(get("apk")).flatMap((l) => {
      const m = /^(.+)-(\d[^-]*-r\d+)$/.exec(l.trim());
      return m ? [{ manager: "apk" as const, name: m[1]!, version: m[2]!, arch: null }] : [];
    }),
  ];

  let containers: Container[] | null = null;
  if (opts.containers) {
    const engines = (["docker", "podman"] as const).filter((e) => s.has(`${e}-version`));
    containers = engines.flatMap((e) => parseContainers(e, get(`${e}-inspect`)));
    if (engines.length && engines.every((e) => !has(`${e}-version`) || /permission denied|cannot connect/i.test(get(`${e}-version`)!))) {
      unreadable.push("containers");
      containers = null;
    }
  }

  return {
    collectedAt: new Date(time || Date.now()).toISOString(),
    account: { user: meta.user ?? "", uid: Number(meta.uid), sudo: meta.sudo === "all" ? "all" : "rules" },
    system: {
      hostname: (get("hostname") ?? "").trim(),
      machineId: get("machine-id") || null,
      os: { id: os.ID ?? kernelName ?? "", name: os.PRETTY_NAME ?? os.NAME ?? kernelName ?? "", version: os.VERSION_ID ?? null },
      kernel: kernel ?? "",
      arch: arch ?? "",
      bootedAt: new Date((time || Date.now()) - uptimeSec * 1000).toISOString(),
      uptimeSec,
      load,
      virtualization: get("virt") && get("virt") !== "none" ? get("virt")! : null,
      hardware: kv(get("dmi") ?? ""),
      serial: priv("dmi-serial", "hardware serial number", (t) => t.trim()),
    },
    cpu: {
      model: cpu.find((l) => /^(model name|Model|Hardware)/.test(l))?.split(":")[1]?.trim() ?? null,
      threads: cpu.filter((l) => l.startsWith("processor")).length,
      cores: new Set(cpu.filter((l) => l.startsWith("core id"))).size || null,
    },
    memory: { totalKb: kb(mem.MemTotal), availableKb: kb(mem.MemAvailable), swapTotalKb: kb(mem.SwapTotal), swapFreeKb: kb(mem.SwapFree) },
    disks,
    filesystems,
    interfaces,
    routes,
    dns: { nameservers: resolv.filter((l) => l.startsWith("nameserver")).map((l) => l.split(/\s+/)[1]!), search: resolv.filter((l) => l.startsWith("search")).flatMap((l) => l.split(/\s+/).slice(1)) },
    ports: has("listen") ? parseListen(get("listen")!) : null,
    processes: parsePs(get("ps") ?? ""),
    services,
    timers,
    cron: lines(get("cron")).map((l) => {
      const [source, ...rest] = l.split("\t");
      return { source: source!, entry: redactCommand(rest.join("\t")) };
    }),
    crontabUsers: priv("cron-users", "user crontabs", (t) => lines(t)),
    users: parseUsers(get("passwd") ?? "", ran("password-status") ? get("password-status") : undefined),
    groups: lines(get("group")).map((l) => {
      const f = l.split(":");
      return { name: f[0]!, gid: Number(f[2]), members: f[3] ? f[3].split(",").filter(Boolean) : [] };
    }),
    sudo: ran("sudoers") || ran("sudoers.d") ? parseSudoers(get("sudoers"), get("sudoers.d")) : (unreadable.push("sudo rules"), null),
    authorizedKeys: priv("authorized-keys", "SSH keys that may log in", parseAuthorizedKeys),
    sshd: priv("sshd", "SSH server settings", (t) => kv(t, " ")),
    modules: lines(get("modules")).sort(),
    sysctl: kv(get("sysctl") ?? "", " = "),
    firewall,
    packages: packages.sort((a, b) => a.name.localeCompare(b.name)),
    containers,
    unreadable: [...unreadable, ...(ran("password-status") ? [] : ["whether accounts have a password"]), ...(has("listen") && /users:/.test(get("listen")!) ? [] : has("listen") ? ["which process listens on a port"] : [])],
  };
}

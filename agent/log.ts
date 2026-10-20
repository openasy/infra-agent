// Structured JSON logs on stdout (ADR 0017).
type Level = "debug" | "info" | "warn" | "error";

export function log(level: Level, msg: string, fields: Record<string, unknown> = {}) {
  process.stdout.write(JSON.stringify({ time: new Date().toISOString(), level, msg, ...fields }) + "\n");
}

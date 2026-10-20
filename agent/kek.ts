// Secrets at rest (ADR 0021): each secret is encrypted with its own data key (AES-256-GCM), and the data key with
// the key-encryption key (KEK), which lives outside the data volume. A backup of /data holds only encrypted secrets.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

function gcm(key: Buffer, plain: Buffer) {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), data]);
}

function ungcm(key: Buffer, sealed: Buffer) {
  const d = createDecipheriv("aes-256-gcm", key, sealed.subarray(0, 12));
  d.setAuthTag(sealed.subarray(12, 28));
  return Buffer.concat([d.update(sealed.subarray(28)), d.final()]);
}

export function createKeyring(kek: Buffer) {
  if (kek.length !== 32) throw new Error("the key-encryption key must be 32 bytes");
  return {
    /** `v1.<wrapped data key>.<ciphertext>`, both base64url. */
    seal(plain: string | Buffer): string {
      const dataKey = randomBytes(32);
      const out = `v1.${gcm(kek, dataKey).toString("base64url")}.${gcm(dataKey, Buffer.from(plain)).toString("base64url")}`;
      dataKey.fill(0);
      return out;
    },
    open(sealed: string): Buffer {
      const [v, wrapped, data] = sealed.split(".");
      if (v !== "v1" || !wrapped || !data) throw new Error("not a sealed secret");
      const dataKey = ungcm(kek, Buffer.from(wrapped, "base64url"));
      try {
        return ungcm(dataKey, Buffer.from(data, "base64url"));
      } finally {
        dataKey.fill(0);
      }
    },
  };
}

export type Keyring = ReturnType<typeof createKeyring>;

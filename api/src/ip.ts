import { BlockList, isIP } from "node:net";

export type TrustedProxies = BlockList;

// Strips an IPv6 zone and unwraps IPv4-mapped IPv6. Returns null if not an IP.
export function normalizeIp(raw: string): string | null {
  let ip = raw.trim();
  const zone = ip.indexOf("%");
  if (zone !== -1) ip = ip.slice(0, zone);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped?.[1]) ip = mapped[1];
  return isIP(ip) === 0 ? null : ip;
}

function familyOf(ip: string): "ipv4" | "ipv6" {
  return isIP(ip) === 4 ? "ipv4" : "ipv6";
}

// Parses a comma-separated list of CIDRs (a bare address means a single host).
export function parseTrustedProxies(csv: string): TrustedProxies {
  const list = new BlockList();
  for (const part of csv.split(",")) {
    const entry = part.trim();
    if (entry === "") continue;
    const pieces = entry.split("/");
    const addr = pieces[0];
    const bits = pieces[1];
    const ip = addr === undefined ? null : normalizeIp(addr);
    if (ip === null || pieces.length > 2) {
      throw new Error("PINGZO_TRUSTED_PROXIES has an invalid entry");
    }
    const family = familyOf(ip);
    const max = family === "ipv4" ? 32 : 128;
    if (bits !== undefined && !/^\d{1,3}$/.test(bits)) {
      throw new Error("PINGZO_TRUSTED_PROXIES has an invalid prefix length");
    }
    const prefix = bits === undefined ? max : Number(bits);
    if (prefix > max) {
      throw new Error("PINGZO_TRUSTED_PROXIES has an invalid prefix length");
    }
    list.addSubnet(ip, prefix, family);
  }
  return list;
}

// The client IP is the CF-Connecting-IP header only when the direct peer is a
// trusted proxy. Otherwise it is the socket address and the header is ignored.
export function resolveClientIp(
  peer: string | undefined,
  header: string | string[] | undefined,
  trusted: TrustedProxies,
): string {
  const peerIp = (peer === undefined ? null : normalizeIp(peer)) ?? "0.0.0.0";
  if (typeof header !== "string") return peerIp;
  if (!trusted.check(peerIp, familyOf(peerIp))) return peerIp;
  return normalizeIp(header) ?? peerIp;
}

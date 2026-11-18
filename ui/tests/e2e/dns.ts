import { DNS_PORT } from './ports';
import dgram from 'node:dgram';

/** Sends one DNS query over UDP to the test server; resolves with the response code. */
export function query(name: string, qtype = 1, port = DNS_PORT, from?: string): Promise<number> {
  const id = Math.floor(Math.random() * 0xffff);
  const qname = name.split('.').flatMap((l) => [l.length, ...Buffer.from(l)]);
  const msg = Buffer.from([id >> 8, id & 0xff, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...qname, 0, qtype >> 8, qtype & 0xff, 0, 1]);
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket('udp4');
    const t = setTimeout(() => {
      s.close();
      reject(new Error(`no answer for ${name}`));
    }, 3000);
    s.on('message', (m) => {
      clearTimeout(t);
      s.close();
      resolve(m[3] & 0x0f);
    });
    // `from`: another loopback address, to look like another device.
    if (from) s.bind({ address: from }, () => s.send(msg, port, '127.0.0.1'));
    else s.send(msg, port, '127.0.0.1');
  });
}

/** What an answer says: the response code, the first A/AAAA address with its TTL, and the
 *  Extended DNS Error codes the OPT record carries (RFC 8914: option code 15). */
export type Answer = { rcode: number; address?: string; ttl?: number; ede: { code: number; text: string }[] };

/** Sends one DNS query over UDP and reads the answer section and the EDNS options (REQ: FLT-014).
 *  Name compression is followed; anything malformed is an error rather than a guess. */
export function queryDetail(name: string, qtype = 1, port = DNS_PORT, from?: string): Promise<Answer> {
  const id = Math.floor(Math.random() * 0xffff);
  const qname = name.split('.').flatMap((l) => [l.length, ...Buffer.from(l)]);
  // A query with an OPT record (EDNS0, 1232-byte UDP payload) so the answer may carry EDE.
  const msg = Buffer.from([
    id >> 8, id & 0xff, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1,
    ...qname, 0, qtype >> 8, qtype & 0xff, 0, 1,
    0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0,
  ]);
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket('udp4');
    const t = setTimeout(() => {
      s.close();
      reject(new Error(`no answer for ${name}`));
    }, 3000);
    s.on('message', (m) => {
      clearTimeout(t);
      s.close();
      try {
        resolve(parseAnswer(m));
      } catch (e) {
        reject(e);
      }
    });
    if (from) s.bind({ address: from }, () => s.send(msg, port, '127.0.0.1'));
    else s.send(msg, port, '127.0.0.1');
  });
}

type Rr = { type: number; ttl: number; data: Buffer };

function parseAnswer(m: Buffer): Answer {
  const qd = m.readUInt16BE(4);
  const an = m.readUInt16BE(6);
  const ar = m.readUInt16BE(10);
  let at = 12;
  // Skips a (possibly compressed) name; returns the offset after it.
  const skipName = (o: number): number => {
    for (;;) {
      const len = m[o];
      if (len === 0) return o + 1;
      if ((len & 0xc0) === 0xc0) return o + 2;
      o += 1 + len;
    }
  };
  for (let i = 0; i < qd; i++) at = skipName(at) + 4;
  const rrs = (count: number): Rr[] => {
    const out: Rr[] = [];
    for (let i = 0; i < count; i++) {
      at = skipName(at);
      const type = m.readUInt16BE(at);
      const ttl = m.readUInt32BE(at + 4);
      const rdlen = m.readUInt16BE(at + 8);
      out.push({ type, ttl, data: m.subarray(at + 10, at + 10 + rdlen) });
      at += 10 + rdlen;
    }
    return out;
  };
  const answers = rrs(an);
  const additional = rrs(ar);
  const a = answers.find((r) => r.type === 1 || r.type === 28);
  const ede: { code: number; text: string }[] = [];
  for (const r of additional) {
    if (r.type !== 41) continue;
    // EDNS options: code (2), length (2), data.
    let o = 0;
    while (o + 4 <= r.data.length) {
      const code = r.data.readUInt16BE(o);
      const len = r.data.readUInt16BE(o + 2);
      if (code === 15) ede.push({ code: r.data.readUInt16BE(o + 4), text: r.data.subarray(o + 6, o + 4 + len).toString('utf8') });
      o += 4 + len;
    }
  }
  return {
    rcode: m[3] & 0x0f,
    address: a?.type === 1 ? [...a.data].join('.') : undefined,
    ttl: a?.ttl,
    ede,
  };
}

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const {
  webcrypto,
  pbkdf2Sync,
  createCipheriv,
  createHash,
} = require("node:crypto");
const vm = require("node:vm");
const html = readFileSync(
  require("node:path").join(__dirname, "../text-steganography.html"),
  "utf8",
);
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(
  (m) => m[1],
);
const globals = {
  crypto: webcrypto,
  TextEncoder,
  TextDecoder,
  Uint8Array,
  Uint32Array,
  DataView,
  BigInt,
  Map,
};
const core = vm.createContext(globals);
vm.runInContext(
  scripts[0] +
    ";globalThis.SALT_CHARS=SALT_CHARS;globalThis.TARGET_BITS=TARGET_BITS;globalThis.TYPE=TYPE;globalThis.KeystreamRng=KeystreamRng;",
  core,
);

function targetHex(bits, seed = 1) {
  const bytes = new Uint8Array(bits / 8);
  for (let i = 0; i < bytes.length; i++) {
    seed = (seed * 1103515245 + 12345) >>> 0;
    bytes[i] = seed >>> 24;
  }
  return core.toHex(bytes).split("");
}
// Independent reference: PBKDF2 -> AES-256-CTR keystream -> bit-exact rejection sampling -> partial Fisher-Yates.
function referencePositions(passphrase, salt, poolSize, count) {
  const key = pbkdf2Sync(passphrase, salt, 600000, 32, "sha256");
  const stream = createCipheriv("aes-256-ctr", key, Buffer.alloc(16));
  let bytes = Buffer.alloc(0),
    pos = 0,
    bitPos = 0;
  const bit = () => {
    if (pos >= bytes.length) {
      bytes = stream.update(Buffer.alloc(4096));
      pos = 0;
    }
    const b = (bytes[pos] >> (7 - bitPos)) & 1;
    if (++bitPos === 8) {
      bitPos = 0;
      pos++;
    }
    return b;
  };
  const uniform = (n) => {
    if (n <= 1) return 0;
    const w = (n - 1).toString(2).length;
    for (;;) {
      let v = 0;
      for (let i = 0; i < w; i++) v = v * 2 + bit();
      if (v < n) return v;
    }
  };
  const pool = Array.from({ length: poolSize }, (_, i) => i),
    out = [];
  for (let i = 0; i < count; i++) {
    const j = i + uniform(poolSize - i);
    [pool[i], pool[j]] = [pool[j], pool[i]];
    out.push(pool[i]);
  }
  return out;
}

test("ASCII and hex payloads round trip at every supported size; hex is stored as raw bytes", async () => {
  for (const bits of [512, 1024, 2048, 4096]) {
    const hex = targetHex(bits);
    const text = "Hi!\tsteg ~";
    await core.embedPayload(
      hex,
      core.asciiBytes(text),
      core.TYPE.ascii,
      "pass phrase " + bits,
    );
    const out = await core.extractPayload(hex, "pass phrase " + bits);
    assert.equal(out.type, core.TYPE.ascii);
    assert.equal(Buffer.from(out.payload).toString("latin1"), text);
  }
  const hex = targetHex(2048, 7),
    raw = core.hexBytes("00 ff 80\n41");
  assert.deepEqual([...raw], [0, 255, 128, 65]);
  const info = await core.embedPayload(hex, raw, core.TYPE.binary, "k");
  assert.equal(info.charsUsed, core.SALT_CHARS + (14 + 4) * 2);
  const back = await core.extractPayload(hex, "k");
  assert.equal(back.type, core.TYPE.binary);
  assert.deepEqual([...back.payload], [0, 255, 128, 65]);
});

test("salt sits in the first 32 characters and payload nibbles land exactly at reference Fisher-Yates positions", async () => {
  const original = targetHex(2048, 3),
    hex = original.slice();
  const payload = core.hexBytes("deadbeef0001"),
    passphrase = "🔑 secret";
  await core.embedPayload(hex, payload, core.TYPE.binary, passphrase);
  const salt = Buffer.from(hex.slice(0, 32).join(""), "hex");
  assert.equal(salt.length, 16);
  const header = Buffer.alloc(14);
  header.write("STXT");
  header[4] = 1;
  header[5] = 1;
  header.writeUInt32BE(payload.length, 6);
  createHash("sha256").update(payload).digest().copy(header, 10, 0, 4);
  const combined = Buffer.concat([header, Buffer.from(payload)]);
  const nibbleCount = combined.length * 2;
  const poolSize = hex.length - 32;
  const positions = referencePositions(passphrase, salt, poolSize, nibbleCount);
  const touched = new Set();
  for (let k = 0; k < nibbleCount; k++) {
    const byte = combined[k >> 1];
    const nibble = k % 2 === 0 ? byte >> 4 : byte & 15;
    const pos = 32 + positions[k];
    touched.add(pos);
    assert.equal(parseInt(hex[pos], 16), nibble);
  }
  for (let i = 0; i < 32; i++) touched.add(i);
  for (let i = 0; i < hex.length; i++)
    if (!touched.has(i))
      assert.equal(
        hex[i],
        original[i],
        "untouched character " + i + " changed",
      );
});

test("Base58 round trips arbitrary bytes including leading zeros", () => {
  const cases = [
    new Uint8Array([0, 0, 1, 2, 3]),
    new Uint8Array([0]),
    Uint8Array.from(Buffer.alloc(64, 0xab)),
  ];
  for (const bytes of cases) {
    const token = core.base58Encode(bytes);
    assert.deepEqual([...core.base58Decode(token)], [...bytes]);
  }
  assert.throws(() => core.base58Decode("not-base58!"), /Invalid Base58/);
});

test("signature token extraction finds the longest Base58 run and ignores surrounding prose", async () => {
  const hex = targetHex(512, 9);
  await core.embedPayload(
    hex,
    core.asciiBytes("secret note"),
    core.TYPE.ascii,
    "pw",
  );
  const token = core.base58Encode(core.hexBytes(hex.join("")));
  const doc = `PURCHASE ORDER\nVendor: Acme Co\nTotal: $123.45\n\nSignature: ${token}\n\nThanks for your business.`;
  const found = core.findSignatureToken(doc);
  assert.equal(found, token);
  const { hexChars, bits } = core.hexCharsFromSignature(found);
  assert.equal(bits, 512);
  const result = await core.extractPayload(hexChars, "pw");
  assert.equal(Buffer.from(result.payload).toString(), "secret note");
  assert.throws(
    () => core.findSignatureToken("just some ordinary short text"),
    /No signature/,
  );
});

function pdfTextRuns(bytes) {
  const pdf = Buffer.from(bytes).toString("latin1");
  const streams = [...pdf.matchAll(/stream\n([\s\S]*?)\nendstream/g)].map(
    (m) => m[1],
  );
  const runs = [];
  for (const stream of streams)
    for (const m of stream.matchAll(/\(((?:[^()\\]|\\.)*)\) Tj/g))
      runs.push(m[1].replace(/\\([\\()])/g, "$1"));
  return runs;
}

test("the PDF writer is well-formed, ASCII-only, and hard-wraps a spaceless signature without losing characters", async () => {
  const hex = targetHex(512, 11);
  await core.embedPayload(
    hex,
    core.asciiBytes("pdf test"),
    core.TYPE.ascii,
    "pw",
  );
  const signature = core.base58Encode(core.hexBytes(hex.join("")));
  const lines = [
    "PURCHASE ORDER",
    "",
    "Signature (Base58):",
    signature,
    "",
    "Thanks.",
  ];
  const bytes = core.buildDocumentPdf(lines);
  const pdf = Buffer.from(bytes).toString("latin1");
  assert.ok(pdf.startsWith("%PDF-1.4\n"));
  assert.ok(pdf.includes("%%EOF"));
  assert.ok(pdf.includes("/BaseFont /Helvetica-Bold"));
  const runs = pdfTextRuns(bytes);
  assert.ok(runs.includes("Thanks."));
  // The signature has no spaces, so it is split into several hard-wrapped Tj runs; rejoining them in order must reproduce it exactly.
  const signatureRuns = runs.filter(
    (r) => signature.includes(r) && r.length > 1,
  );
  assert.ok(
    signatureRuns.length > 1,
    "expected the long signature to be split across multiple lines",
  );
  assert.equal(signatureRuns.join(""), signature);
  assert.throws(() => core.buildDocumentPdf(["café"]), /plain ASCII/);
});

test("the PDF paginates onto a second page once a document runs past one page", async () => {
  const hex = targetHex(4096, 12);
  await core.embedPayload(
    hex,
    core.asciiBytes("a payload long enough to need the 4096-bit target size"),
    core.TYPE.ascii,
    "pw",
  );
  const signature = core.base58Encode(core.hexBytes(hex.join("")));
  const lines = [
    "PURCHASE ORDER",
    ...Array.from({ length: 40 }, (_, i) => "Line " + i),
    "Signature (Base58):",
    signature,
  ];
  const bytes = core.buildDocumentPdf(lines);
  const pdf = Buffer.from(bytes).toString("latin1");
  const pageCount = Number((pdf.match(/\/Count (\d+)/) || [])[1]);
  assert.ok(
    pageCount >= 2,
    "expected the long document to spill onto a second page",
  );
});

test("each target size reports the documented capacity", () => {
  const expected = { 128: 34, 256: 98, 512: 226, 1024: 482 };
  for (const [chars, capacity] of Object.entries(expected))
    assert.equal(core.charLayout(Number(chars)).capacity, capacity);
  assert.throws(() => core.charLayout(100), /Target text must be exactly/);
});

test("fresh salt, wrong passphrase, damage, capacity and input validation", async () => {
  const a = targetHex(1024, 1),
    b = targetHex(1024, 1);
  await core.embedPayload(a, core.asciiBytes("same"), 0, "pw");
  await core.embedPayload(b, core.asciiBytes("same"), 0, "pw");
  assert.notDeepEqual(a, b);
  await assert.rejects(core.extractPayload(a, "wrong"), /No hidden data found/);
  await assert.rejects(
    core.extractPayload(targetHex(1024, 5), "pw"),
    /No hidden data found/,
  );
  const cap = core.charLayout(256).capacity;
  assert.equal(cap, 98);
  await core.embedPayload(targetHex(1024, 2), new Uint8Array(cap), 1, "pw");
  await assert.rejects(
    core.embedPayload(targetHex(1024, 2), new Uint8Array(cap + 1), 1, "pw"),
    /at most/,
  );
  await assert.rejects(
    core.embedPayload(targetHex(1024, 2), new Uint8Array(0), 1, "pw"),
    /Enter data/,
  );
  const damaged = targetHex(1024, 4);
  await core.embedPayload(damaged, core.asciiBytes("x".repeat(80)), 0, "pw");
  for (let i = 32; i < damaged.length; i++)
    damaged[i] = damaged[i] === "0" ? "1" : "0";
  await assert.rejects(core.extractPayload(damaged, "pw"));
  assert.throws(() => core.asciiBytes("café"), /Only ASCII/);
  for (const bad of ["0", "0x00", "fg", "00:ff"])
    assert.throws(() => core.hexBytes(bad), /Hex input/);
});

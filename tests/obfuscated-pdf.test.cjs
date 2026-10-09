const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { webcrypto } = require("node:crypto");
const vm = require("node:vm");
const html = readFileSync(
  require("node:path").join(__dirname, "../obfuscated-pdf.html"),
  "utf8",
);
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(
  (m) => m[1],
);
const core = vm.createContext({
  crypto: webcrypto,
  Uint8Array,
  Uint32Array,
  BigInt,
});
vm.runInContext(
  scripts[0] +
    ";globalThis.CHUNK=CHUNK;globalThis.STORIES=STORIES;globalThis.PURCHASE_ORDER=PURCHASE_ORDER;globalThis.LOCALES=LOCALES;globalThis.PRODUCTS=PRODUCTS;globalThis.EXTRA_GLYPHS=EXTRA_GLYPHS;globalThis.WIDTHS=WIDTHS;globalThis.MIN_DIGITS=MIN_DIGITS;globalThis.PAGE=PAGE;",
  core,
);
const restore = (numbers) => [...core.numbersToBytes(numbers.join("\n"))];
const randomNumbers = (bytes) =>
  core.bytesToNumbers(webcrypto.getRandomValues(new Uint8Array(bytes)));

test("ASCII and hex round trip, including leading and trailing zero bytes", () => {
  const text = "Hello, world!\n\tTabs ~ and (parens) \\ 0123456789";
  const numbers = core.bytesToNumbers(core.asciiBytes(text));
  assert.equal(core.asciiText(core.numbersToBytes(numbers.join("\n"))), text);
  const raw = core.hexBytes("00 00 ff 80 41 00 00 00 00 00 00 00 00 00");
  assert.deepEqual(restore(core.bytesToNumbers(raw)), [...raw]);
  for (let len = 1; len < 60; len++) {
    const bytes = webcrypto.getRandomValues(new Uint8Array(len));
    assert.deepEqual(restore(core.bytesToNumbers(bytes)), [...bytes]);
  }
});

test("each number is the marker byte followed by a 4 to 8 byte chunk and has 10 to 20 digits", () => {
  for (let len = 4; len < 80; len++) {
    const numbers = core.bytesToNumbers(new Uint8Array(len));
    let total = 0;
    for (const n of numbers) {
      const hex = BigInt(n).toString(16);
      const size = (hex.length - 1) / 2;
      assert.ok(hex.startsWith("1") && hex.length % 2 === 1, n);
      assert.ok(
        size >= core.CHUNK.min && size <= core.CHUNK.max,
        "chunk size " + size,
      );
      assert.ok(n.length >= 10 && n.length <= 20, n);
      total += size;
    }
    assert.equal(total, len);
  }
  assert.deepEqual(
    [...core.bytesToNumbers(new Uint8Array(12), () => 8)],
    [String(2n ** 64n), String(2n ** 32n)],
  );
  assert.equal(core.MIN_DIGITS, String(2n ** 32n).length);
});

test("inputs shorter than 4 bytes are padded with random bytes and the marker counts the padding", () => {
  for (let len = 1; len < 4; len++) {
    const bytes = new Uint8Array(len).fill(0x41);
    const [n] = core.bytesToNumbers(bytes);
    const value = BigInt(n);
    assert.equal(value >> 32n, BigInt(1 + 4 - len));
    assert.equal(
      Number(value & ((1n << BigInt(8 * len)) - 1n)),
      len === 1 ? 0x41 : len === 2 ? 0x4141 : 0x414141,
    );
    assert.ok(n.length >= 10 && n.length <= 11, n);
    assert.deepEqual(restore([n]), [...bytes]);
  }
  // Markers 2..4 are only valid with exactly 4 bytes after them.
  assert.throws(
    () => core.numbersToBytes(String((2n << 40n) | 5n)),
    /Number 1/,
  );
  assert.throws(() => core.numbersToBytes(String(5n << 32n)), /Number 1/);
  assert.throws(() => core.numbersToBytes(String(1n << 72n)), /Number 1/);
});

test("restore reads runs of at least ten digits in order and ignores shorter numbers and other text", () => {
  const numbers = core.bytesToNumbers(core.asciiBytes("secret message"));
  const decode = (t) => core.asciiText(core.numbersToBytes(t));
  assert.equal(decode(numbers.join("\n")), "secret message");
  assert.equal(decode("  " + numbers.join(" ") + "\n"), "secret message");
  assert.equal(decode(numbers.join(";x-")), "secret message");
  assert.equal(
    decode("Exercise 7, page 2 of 3: " + numbers.join(" $12.50 qty 4 ")),
    "secret message",
  );
  assert.equal(
    decode(
      core.documentText(core.mathProblem(numbers, { story: "astronomy" })),
    ),
    "secret message",
  );
  assert.deepEqual(
    [...core.parseNumbers("a12 123456789 1234567890b,99999999999")],
    ["1234567890", "99999999999"],
  );
  assert.throws(
    () => core.numbersToBytes(numbers.join(" ") + " 99999999999999"),
    /Number \d+ \(999999999999…\)/,
  );
  assert.throws(
    () => core.numbersToBytes(" only 123456789 short numbers 42 \n"),
    /No numbers with at least 10 digits/,
  );
  assert.throws(() => core.asciiText(new Uint8Array([65, 200])), /Byte 2/);
  assert.throws(() => core.asciiBytes("café"), /not ASCII/);
  assert.throws(() => core.hexBytes("abc"), /pairs/);
  assert.throws(() => core.bytesToNumbers(new Uint8Array(0)), /Enter data/);
});

const NUMBER_WORDS = {
  en: /\b(zero|one|two|three|four|five|six|seven|eight|nine|ten|first|second|third|half|twice|once|dozen|hundred|thousand|million|single|pair|double)\b/i,
  es: /(?<![\p{L}])(cero|uno|dos|tres|cuatro|cinco|seis|siete|ocho|nueve|diez|once|doce|cien|ciento|mil|millón|primer|primero|primera|segundo|segunda|tercer|tercero|tercera|mitad|doble|par|docena|único|única)(?![\p{L}])/iu,
};
test("math template contains exactly the encoded numbers, in order, and nothing else numeric, in every language", () => {
  for (const lang of Object.keys(core.LOCALES))
    for (const story of ["random", ...Object.keys(core.STORIES)]) {
      const words = NUMBER_WORDS[lang];
      for (const count of [1, 2, 3, 9, 40]) {
        const numbers = randomNumbers(count * 6);
        const doc = core.mathProblem(numbers, { story, lang });
        assert.equal(doc.lang, lang);
        const text = core.documentText(doc);
        assert.deepEqual(text.match(/\d+/g), [...numbers]);
        assert.doesNotMatch(text, words);
        for (let i = 1; i < doc.paragraphs.length - 1; i++)
          assert.ok(
            !/(.{8,}\.) \1/.test(doc.paragraphs[i]),
            "repeated sentence",
          );
      }
    }
});

test("purchase order lists the numbers as product IDs in order; every other number is shorter than ten digits", () => {
  for (const lang of Object.keys(core.LOCALES))
    for (const count of [1, 3, 24, 60]) {
      const numbers = randomNumbers(count * 6);
      const doc = core.purchaseOrder(numbers, {
        lang,
        date: new Date(2026, 11, 20),
      });
      assert.equal(doc.kind, "purchase-order");
      assert.deepEqual([...doc.items.map((i) => i.id)], [...numbers]);
      const text = core.documentText(doc);
      const runs = text.match(/\d+/g);
      assert.deepEqual(
        runs.filter((r) => r.length >= 10),
        [...numbers],
      );
      assert.ok(runs.length > numbers.length);
      assert.match(
        text,
        lang === "es"
          ? /Fecha: 20 de diciembre de 2026\nEntrega solicitada: 19 de enero de 2027/
          : /Date: December 20, 2026\nRequested delivery: January 19, 2027/,
      );
      if (lang === "es")
        assert.match(
          text,
          /ORDEN DE COMPRA[\s\S]*IVA \(16 %\)[\s\S]*Total estimado: \$[\d,]+\.\d\d MXN/,
        );
      assert.equal(
        doc.subtotal,
        doc.items.reduce((s, i) => s + i.qty * i.price, 0),
      );
      assert.equal(doc.total, doc.subtotal + doc.tax);
      for (let i = 1; i < doc.items.length && i < core.PRODUCTS.length; i++)
        assert.notEqual(doc.items[i].description, doc.items[i - 1].description);
      assert.deepEqual(restore([text]), restore(numbers));
    }
  assert.equal(core.money(123456789), "$1,234,567.89");
  assert.equal(core.money(5), "$0.05");
  assert.equal(core.money(123456789, "es"), "$1,234,567.89 MXN");
  assert.equal(core.money(5, "es"), "$0.05 MXN");
  assert.equal(
    core.fileName(core.purchaseOrder(["4294967296"], { lang: "es" })),
    "orden-de-compra.pdf",
  );
  assert.equal(
    core.fileName(core.mathProblem(["4294967296"], { lang: "es" })),
    "ejercicio.pdf",
  );
  assert.equal(
    core.fileName(core.mathProblem(["4294967296"])),
    "invoice.pdf".replace("invoice", "exercise"),
  );
  assert.equal(
    core.createDocument(["4294967296"], { template: "purchase-order" }).kind,
    "purchase-order",
  );
  assert.throws(
    () => core.createDocument(["4294967296"], { template: "other" }),
    /Unknown template/,
  );
});

test("email confirmation confirms an order or appointment and embeds the numbers as link path segments, in order", () => {
  for (const lang of Object.keys(core.LOCALES))
    for (const count of [1, 2, 9, 40]) {
      const numbers = randomNumbers(count * 6);
      const doc = core.emailConfirmation(numbers, {
        lang,
        domain: "example.com",
        date: new Date(2026, 11, 20),
      });
      assert.equal(doc.kind, "email");
      const subjects = Object.values(core.LOCALES[lang].email.kinds).map(
        (k) => k.subject,
      );
      assert.ok(subjects.includes(doc.title), doc.title);
      const text = core.documentText(doc);
      const runs = text.match(/\d+/g);
      assert.deepEqual(
        runs.filter((r) => r.length >= 10),
        [...numbers],
      );
      assert.ok(runs.length > numbers.length);
      assert.match(text, /https:\/\/example\.com\//);
      assert.deepEqual(restore([text]), restore(numbers));
    }
  assert.equal(
    core.fileName(core.emailConfirmation(["4294967296"], { lang: "es" })),
    "confirmacion.pdf",
  );
  assert.equal(
    core.fileName(core.emailConfirmation(["4294967296"])),
    "confirmation.pdf",
  );
  assert.equal(
    core.createDocument(["4294967296"], {
      template: "email",
      domain: "example.com",
    }).kind,
    "email",
  );
  assert.throws(
    () => core.emailConfirmation(["4294967296"], { domain: "" }),
    /Enter a domain/,
  );
  assert.throws(
    () => core.emailConfirmation(["4294967296"], { domain: "bad domain!" }),
    /valid domain/,
  );
});

test("plain URL template is nothing but the domain with the numbers as path segments, split across links as needed", () => {
  const single = core.urlDocument(["4294967296"], { domain: "example.com" });
  assert.equal(single.kind, "url");
  assert.equal(single.title, "");
  assert.equal(core.documentText(single), "https://example.com/4294967296");
  const bytes = webcrypto.getRandomValues(new Uint8Array(2000));
  const numbers = core.bytesToNumbers(bytes);
  const doc = core.urlDocument(numbers, { domain: "example.com" });
  assert.ok(doc.paragraphs.length > 1, "expected multiple links");
  const maxWidth = core.PAGE.width - 2 * core.PAGE.margin;
  for (const link of doc.paragraphs)
    assert.ok(core.textWidth(link, core.PAGE.size) <= maxWidth + 0.01, link);
  const text = core.documentText(doc);
  assert.deepEqual(text.match(/\d+/g), [...numbers]);
  assert.deepEqual(restore([text]), [...bytes]);
  assert.equal(core.fileName(core.urlDocument(["4294967296"])), "link.pdf");
  assert.equal(
    core.fileName(core.urlDocument(["4294967296"], { lang: "es" })),
    "enlace.pdf",
  );
  assert.throws(
    () => core.urlDocument(["4294967296"], { domain: "" }),
    /Enter a domain/,
  );
  assert.throws(
    () => core.urlDocument(["4294967296"], { domain: "bad domain!" }),
    /valid domain/,
  );
});

test("font width tables cover printable ASCII and every character the templates use", () => {
  assert.equal(core.WIDTHS.F1.length, 95);
  assert.equal(core.WIDTHS.F2.length, 95);
  assert.throws(() => core.textWidth("ç", 10), /cannot contain/);
  assert.equal(
    core.textWidth("ñ€", 10, "F2"),
    core.textWidth("n", 10, "F2") + 5.56,
  );
  assert.deepEqual([...core.pdfBytes("Añ€¿")], [0x41, 0xf1, 0x80, 0xbf]);
  const strings = JSON.stringify([core.STORIES, core.PRODUCTS, core.LOCALES]);
  for (const ch of new Set(strings))
    if (ch.charCodeAt(0) > 126)
      assert.ok(core.EXTRA_GLYPHS[ch], "missing glyph " + ch);
  // Every product description fits its column in both languages.
  for (const p of core.PRODUCTS)
    for (const d of [p[0], p[1]]) assert.ok(core.textWidth(d, 9.5) <= 175, d);
});

const fromWinAnsi = (str) => str.replace(/\x80/g, "€");
function inspectPdf(pdf) {
  const text = fromWinAnsi(Buffer.from(pdf.bytes).toString("latin1"));
  assert.ok(text.startsWith("%PDF-1.4\n") && text.endsWith("%%EOF\n"));
  assert.doesNotMatch(text, /\/Info|\/Producer|\/CreationDate/);
  const xref = Number(text.match(/startxref\n(\d+)/)[1]);
  assert.ok(text.startsWith("xref\n", xref));
  const entries = text
    .slice(xref)
    .split("\n")
    .slice(3)
    .filter((l) => /^\d{10} 00000 n $/.test(l));
  entries.forEach((e, i) =>
    assert.ok(
      text.startsWith(i + 1 + " 0 obj\n", Number(e.slice(0, 10))),
      "object " + (i + 1),
    ),
  );
  const shown = [];
  for (const m of text.matchAll(/<< \/Length (\d+) >>\nstream\n/g)) {
    const start = m.index + m[0].length,
      len = Number(m[1]);
    assert.ok(text.startsWith("\nendstream", start + len));
    const content = text.slice(start, start + len),
      spans = [];
    for (const t of content.matchAll(
      /BT \/(F[12]) ([\d.]+) Tf [\d.]+ g 1 0 0 1 ([\d.]+) ([\d.]+) Tm \((.*)\) Tj ET/g,
    )) {
      const [, font, size, x, y, raw] = t,
        str = raw.replace(/\\(.)/g, "$1");
      shown.push(str);
      const right = Number(x) + core.textWidth(str, Number(size), font);
      assert.ok(
        Number(x) >= 54 - 0.01 && right <= 612 - 54 + 0.01,
        "text outside margins: " + str,
      );
      assert.ok(
        Number(y) >= 30 && Number(y) <= 792 - 50,
        "text outside page: " + str,
      );
      for (const o of spans)
        if (o.y === Number(y))
          assert.ok(
            right + 2 <= o.x || Number(x) >= o.right + 2,
            "overlapping text: " + str + " / " + o.str,
          );
      spans.push({ x: Number(x), right, y: Number(y), str });
    }
  }
  return { text, shown };
}

test("math PDF is well formed with no metadata and numbers present in order", () => {
  const bytes = webcrypto.getRandomValues(new Uint8Array(3000));
  const numbers = core.bytesToNumbers(bytes);
  const pdf = core.buildPdf(
    core.mathProblem(numbers, { story: "sequence", lang: "es" }),
  );
  assert.ok(pdf.pages > 1);
  const { shown } = inspectPdf(pdf);
  assert.deepEqual(shown.join(" ").match(/\d+/g), [...numbers]);
  assert.deepEqual(restore(numbers), [...bytes]);
});

test("purchase order PDF is well formed, paginates, and restores from its own text, in every language", () => {
  for (const lang of Object.keys(core.LOCALES))
    for (const size of [2, 40, 1500]) {
      const bytes = webcrypto.getRandomValues(new Uint8Array(size));
      const numbers = core.bytesToNumbers(bytes);
      // Longest month names exercise the header layout.
      const doc = core.purchaseOrder(numbers, {
        lang,
        date: new Date(2026, 8, 30),
      });
      const pdf = core.buildPdf(doc);
      const { shown } = inspectPdf(pdf);
      if (size === 1500) assert.ok(pdf.pages > 2);
      assert.ok(
        shown.includes(
          core.LOCALES[lang].purchaseOrder.page(pdf.pages, pdf.pages),
        ),
      );
      assert.ok(shown.includes(core.LOCALES[lang].purchaseOrder.total));
      assert.deepEqual([...core.parseNumbers(shown.join("\n"))], [...numbers]);
      assert.deepEqual([...core.numbersToBytes(shown.join("\n"))], [...bytes]);
    }
});

test("email confirmation PDF is well formed and restores from its own text, in every language", () => {
  for (const lang of Object.keys(core.LOCALES)) {
    const bytes = webcrypto.getRandomValues(new Uint8Array(1200));
    const numbers = core.bytesToNumbers(bytes);
    const doc = core.emailConfirmation(numbers, {
      lang,
      domain: "example.com",
    });
    const pdf = core.buildPdf(doc);
    const { shown } = inspectPdf(pdf);
    const runs = shown.join(" ").match(/\d+/g);
    assert.deepEqual(
      runs.filter((r) => r.length >= 10),
      [...numbers],
    );
    assert.deepEqual(restore(numbers), [...bytes]);
  }
});

test("plain URL PDF is well formed, paginates for large payloads, and restores from its own text", () => {
  const bytes = webcrypto.getRandomValues(new Uint8Array(2500));
  const numbers = core.bytesToNumbers(bytes);
  const doc = core.urlDocument(numbers, { domain: "example.com" });
  const pdf = core.buildPdf(doc);
  assert.ok(pdf.pages > 1);
  const { shown } = inspectPdf(pdf);
  assert.deepEqual(shown.join(" ").match(/\d+/g), [...numbers]);
  assert.deepEqual(restore(numbers), [...bytes]);
});

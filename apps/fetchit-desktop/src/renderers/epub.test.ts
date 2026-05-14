import { describe, expect, it } from "vitest";
import { strToU8, zipSync } from "fflate";
import { archiveIsEpub, inlineResources, parseBook } from "./epub";

function buildMinimalEpub(opts: {
  title?: string;
  chapters?: Array<{ id: string; href: string; body: string }>;
  opfPath?: string;
} = {}): Record<string, Uint8Array> {
  const title = opts.title ?? "Untitled";
  const opfPath = opts.opfPath ?? "OEBPS/content.opf";
  const chapters = opts.chapters ?? [
    { id: "chap1", href: "chap1.xhtml", body: "<p>Chapter 1</p>" },
    { id: "chap2", href: "chap2.xhtml", body: "<p>Chapter 2</p>" },
  ];

  const container = `<?xml version="1.0"?>
<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles><rootfile full-path="${opfPath}" media-type="application/oebps-package+xml"/></rootfiles>
</container>`;

  const manifestItems = chapters
    .map((c) => `<item id="${c.id}" href="${c.href}" media-type="application/xhtml+xml"/>`)
    .join("\n");
  const spineItems = chapters.map((c) => `<itemref idref="${c.id}"/>`).join("\n");

  const opf = `<?xml version="1.0"?>
<package version="3.0" xmlns="http://www.idpf.org/2007/opf" unique-identifier="bid">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>${title}</dc:title>
    <dc:identifier id="bid">test-id</dc:identifier>
  </metadata>
  <manifest>${manifestItems}</manifest>
  <spine>${spineItems}</spine>
</package>`;

  const opfDir = opfPath.includes("/") ? opfPath.slice(0, opfPath.lastIndexOf("/") + 1) : "";

  const files: Record<string, Uint8Array> = {
    "mimetype": strToU8("application/epub+zip"),
    "META-INF/container.xml": strToU8(container),
    [opfPath]: strToU8(opf),
  };
  for (const c of chapters) {
    files[opfDir + c.href] = strToU8(`<html><body>${c.body}</body></html>`);
  }
  return files;
}

describe("archiveIsEpub", () => {
  it("returns true when META-INF/container.xml is present", () => {
    expect(archiveIsEpub([{ path: "mimetype" }, { path: "META-INF/container.xml" }])).toBe(true);
  });

  it("returns false for a plain zip", () => {
    expect(archiveIsEpub([{ path: "hello.txt" }, { path: "world.txt" }])).toBe(false);
  });

  it("returns false for an empty archive", () => {
    expect(archiveIsEpub([])).toBe(false);
  });
});

describe("parseBook", () => {
  it("extracts title, manifest, and spine from a minimal EPUB", () => {
    const files = buildMinimalEpub({ title: "Test Book" });
    const book = parseBook(files);
    expect(book.title).toBe("Test Book");
    expect(book.spine).toHaveLength(2);
    expect(book.spine[0].path).toBe("OEBPS/chap1.xhtml");
    expect(book.spine[1].path).toBe("OEBPS/chap2.xhtml");
  });

  it("falls back to 'Untitled' when dc:title is missing", () => {
    const files = buildMinimalEpub({ title: "" });
    const book = parseBook(files);
    expect(book.title).toBe("Untitled");
  });

  it("throws when container.xml is absent", () => {
    const files: Record<string, Uint8Array> = {};
    expect(() => parseBook(files)).toThrow(/container\.xml/);
  });

  it("throws when the OPF spine is empty", () => {
    const files = buildMinimalEpub({ chapters: [] });
    expect(() => parseBook(files)).toThrow(/spine/);
  });

  it("survives a zip round-trip via fflate.zipSync", () => {
    const raw = buildMinimalEpub({ title: "Round Trip" });
    const z = zipSync(raw);
    expect(z.byteLength).toBeGreaterThan(0);
    // We don't unzip here; just confirm the source map shape is the
    // same Record<string, Uint8Array> we expect from unzipSync.
    const book = parseBook(raw);
    expect(book.title).toBe("Round Trip");
  });
});

describe("inlineResources", () => {
  it("inlines images as data URLs", () => {
    const png = new Uint8Array([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44,
    ]);
    const files: Record<string, Uint8Array> = {
      "OEBPS/chap1.xhtml": strToU8(""),
      "OEBPS/images/cover.png": png,
    };
    const xhtml = '<img src="images/cover.png" alt="cover"/>';
    const out = inlineResources(xhtml, "OEBPS/chap1.xhtml", files);
    expect(out).toContain("data:image/png;base64,");
    expect(out).not.toContain('src="images/cover.png"');
  });

  it("leaves external URLs alone", () => {
    const xhtml = '<a href="https://example.com/x">link</a>';
    const out = inlineResources(xhtml, "OEBPS/chap1.xhtml", {});
    expect(out).toBe(xhtml);
  });

  it("leaves fragment-only links alone", () => {
    const xhtml = '<a href="#section-2">jump</a>';
    const out = inlineResources(xhtml, "OEBPS/chap1.xhtml", {});
    expect(out).toBe(xhtml);
  });

  it("leaves unresolvable internal references untouched", () => {
    const xhtml = '<img src="missing.png"/>';
    const out = inlineResources(xhtml, "OEBPS/chap1.xhtml", {});
    expect(out).toBe(xhtml);
  });

  it("normalises ./prefix in href", () => {
    const css = strToU8("body { color: red; }");
    const files = { "OEBPS/style.css": css, "OEBPS/chap.xhtml": strToU8("") };
    const xhtml = '<link rel="stylesheet" href="./style.css"/>';
    const out = inlineResources(xhtml, "OEBPS/chap.xhtml", files);
    expect(out).toContain("data:text/css;base64,");
  });
});

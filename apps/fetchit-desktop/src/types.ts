export type Rendition =
  | { kind: "text"; language: string | null; body: string }
  | { kind: "etchitEnvelope"; title: string; content: string; language: string | null }
  | { kind: "json"; pretty: string }
  | { kind: "tabular"; columns: string[]; rows: string[][] }
  | { kind: "archive"; entries: { path: string; size: number | null }[] }
  | { kind: "html"; body: string }
  | { kind: "image"; mime: string; byteLen: number }
  | { kind: "audio"; mime: string; byteLen: number }
  | { kind: "video"; mime: string; byteLen: number }
  | { kind: "pdf"; byteLen: number }
  | { kind: "binary"; mime: string; byteLen: number };

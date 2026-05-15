import type { Rendition } from "../types";
import { renderText } from "./text";
import { renderEtchitEnvelope } from "./etchitEnvelope";
import { renderJson } from "./json";
import { renderTabular } from "./tabular";
import { renderArchive } from "./archive";
import { archiveIsEpub, renderEpub } from "./epub";
import { renderHtml } from "./html";
import { renderImage } from "./image";
import { renderAudio } from "./audio";
import { renderVideo } from "./video";
import { renderPdf } from "./pdf";
import { renderBinary } from "./binary";

export function render(r: Rendition, into: HTMLElement, address: string): void {
  into.replaceChildren();
  const src = `autonomi://${address}`;
  switch (r.kind) {
    case "text":
      renderText(r, into);
      return;
    case "etchitEnvelope":
      renderEtchitEnvelope(r, into);
      return;
    case "json":
      renderJson(r, into);
      return;
    case "tabular":
      renderTabular(r, into);
      return;
    case "archive":
      // EPUBs come back from core as Archive (a ZIP with the EPUB-spec
      // entries). Sniff for the mandatory META-INF/container.xml and route
      // to the book reader if present; otherwise fall through to the
      // generic archive listing.
      if (archiveIsEpub(r.entries)) renderEpub(r, into, address);
      else renderArchive(r, into, address);
      return;
    case "html":
      renderHtml(r, into, address);
      return;
    case "image":
      renderImage(r, into, src);
      return;
    case "audio":
      renderAudio(r, into, src);
      return;
    case "video":
      renderVideo(r, into, src);
      return;
    case "pdf":
      renderPdf(r, into, src);
      return;
    case "binary":
      renderBinary(r, into);
      return;
  }
  const _exhaustive: never = r;
  throw new Error(`unknown rendition kind: ${JSON.stringify(_exhaustive)}`);
}

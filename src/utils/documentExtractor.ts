/**
 * SIFT-AIR Local Document Extractor (src/utils/documentExtractor.ts)
 *
 * 1. Parses .docx threat advisories 100% locally via PKZIP Central Directory + raw deflate,
 *    reconstructing headings, paragraphs, and IOC tables into Markdown without an LLM call.
 * 2. Parses .pdf streams locally first (/FlateDecode + Tj/TJ operators), signaling
 *    ``needsZeroRetentionOcrFallback = true`` ONLY when scanned/CID pages lack text streams.
 */

export interface ExtractedDocument {
  fileName: string;
  format: "docx" | "pdf" | "text";
  markdownText: string;
  extractedLocally: boolean;
  needsZeroRetentionOcrFallback: boolean;
}

async function inflateRawBytes(compressed: Uint8Array): Promise<Uint8Array> {
  if (typeof DecompressionStream !== "undefined") {
    const ds = new DecompressionStream("deflate-raw");
    const writer = ds.writable.getWriter();
    await writer.write(compressed as unknown as BufferSource);
    await writer.close();
    const ab = await new Response(ds.readable).arrayBuffer();
    return new Uint8Array(ab);
  }
  const zlib = await import("node:zlib");
  return new Uint8Array(zlib.inflateRawSync(compressed));
}

async function inflateZlibBytes(compressed: Uint8Array): Promise<Uint8Array> {
  if (typeof DecompressionStream !== "undefined") {
    const ds = new DecompressionStream("deflate");
    const writer = ds.writable.getWriter();
    await writer.write(compressed as unknown as BufferSource);
    await writer.close();
    const ab = await new Response(ds.readable).arrayBuffer();
    return new Uint8Array(ab);
  }
  const zlib = await import("node:zlib");
  return new Uint8Array(zlib.inflateSync(compressed));
}

function decodeXmlEntities(input: string): string {
  return input
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

function wordXmlToMarkdown(xml: string): string {
  const lines: string[] = [];

  // Convert <w:tbl> tables into Markdown tables first so IOC tables remain intact
  const withTables = xml.replace(/<w:tbl\b[\s\S]*?<\/w:tbl>/g, (tableXml) => {
    const rows = [...tableXml.matchAll(/<w:tr\b[\s\S]*?<\/w:tr>/g)].map((rowMatch) => {
      const cells = [...rowMatch[0].matchAll(/<w:tc\b[\s\S]*?<\/w:tc>/g)].map((cellMatch) => {
        const texts = [...cellMatch[0].matchAll(/<w:t(?:\s[^>]*)?>([\s\S]*?)<\/w:t>/g)].map((t) =>
          decodeXmlEntities(t[1]),
        );
        return texts.join("").trim();
      });
      return cells;
    });
    if (rows.length === 0) return "";
    const mdRows = rows.map((r) => `| ${r.join(" | ")} |`);
    const divider = `| ${rows[0].map(() => "---").join(" | ")} |`;
    mdRows.splice(1, 0, divider);
    return `\n<MD_BLOCK>${mdRows.join("\n")}</MD_BLOCK>\n`;
  });

  const tokens = withTables.split(/(<MD_BLOCK>[\s\S]*?<\/MD_BLOCK>|<w:p\b[\s\S]*?<\/w:p>)/g);
  for (const tok of tokens) {
    if (tok.startsWith("<MD_BLOCK>")) {
      lines.push(tok.replace(/^<MD_BLOCK>|<\/MD_BLOCK>$/g, ""));
    } else if (tok.startsWith("<w:p")) {
      const styleMatch = tok.match(/<w:pStyle\s+w:val="Heading(\d)"/i);
      const textRuns = [...tok.matchAll(/<w:t(?:\s[^>]*)?>([\s\S]*?)<\/w:t>/g)].map((m) =>
        decodeXmlEntities(m[1]),
      );
      const paragraph = textRuns.join("").trim();
      if (!paragraph) continue;
      if (styleMatch) {
        const level = Math.min(Math.max(Number(styleMatch[1]), 1), 4);
        lines.push(`${"#".repeat(level)} ${paragraph}`);
      } else {
        lines.push(paragraph);
      }
    }
  }

  return lines.join("\n\n").trim();
}

export async function extractDocxLocally(
  fileName: string,
  bytes: Uint8Array,
): Promise<ExtractedDocument> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // Locate End of Central Directory (0x06054b50)
  let eocdOffset = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i -= 1) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) {
    throw new Error(`Invalid .docx ZIP archive: ${fileName}`);
  }

  const cdCount = view.getUint16(eocdOffset + 10, true);
  let ptr = view.getUint32(eocdOffset + 16, true);
  const decoder = new TextDecoder("utf-8");

  for (let entry = 0; entry < cdCount; entry += 1) {
    if (view.getUint32(ptr, true) !== 0x02014b50) break;
    const compressionMethod = view.getUint16(ptr + 10, true);
    const compressedSize = view.getUint32(ptr + 20, true);
    const nameLen = view.getUint16(ptr + 28, true);
    const extraLen = view.getUint16(ptr + 30, true);
    const commentLen = view.getUint16(ptr + 32, true);
    const localHeaderOffset = view.getUint32(ptr + 42, true);
    const entryName = decoder.decode(bytes.subarray(ptr + 46, ptr + 46 + nameLen));

    if (entryName === "word/document.xml") {
      const localNameLen = view.getUint16(localHeaderOffset + 26, true);
      const localExtraLen = view.getUint16(localHeaderOffset + 28, true);
      const dataStart = localHeaderOffset + 30 + localNameLen + localExtraLen;
      const slice = bytes.subarray(dataStart, dataStart + compressedSize);
      const xmlBytes = compressionMethod === 8 ? await inflateRawBytes(slice) : slice;
      const xmlText = decoder.decode(xmlBytes);
      return {
        fileName,
        format: "docx",
        markdownText: wordXmlToMarkdown(xmlText),
        extractedLocally: true,
        needsZeroRetentionOcrFallback: false,
      };
    }

    ptr += 46 + nameLen + extraLen + commentLen;
  }

  throw new Error(`word/document.xml not found inside ${fileName}`);
}

function extractPdfOperatorsText(decodedStream: string): string {
  const chunks: string[] = [];
  for (const tj of decodedStream.matchAll(/\(([^()\\]*(?:\\.[^()\\]*)*)\)\s*Tj/g)) {
    chunks.push(tj[1].replace(/\\([()\\])/g, "$1"));
  }
  for (const tjArr of decodedStream.matchAll(/\[([\s\S]*?)\]\s*TJ/g)) {
    const inner = [...tjArr[1].matchAll(/\(([^()\\]*(?:\\.[^()\\]*)*)\)/g)]
      .map((m) => m[1].replace(/\\([()\\])/g, "$1"))
      .join("");
    if (inner) chunks.push(inner);
  }
  return chunks.join(" ").replace(/\s+/g, " ").trim();
}

function uint8ToIso88591(bytes: Uint8Array): string {
  // Note: WHATWG TextDecoder('latin1') aliases windows-1252 and mutates 0x80..0x9F (e.g. zlib 0x9c)!
  const chunks: string[] = [];
  const step = 16384;
  for (let i = 0; i < bytes.length; i += step) {
    chunks.push(String.fromCharCode(...bytes.subarray(i, i + step)));
  }
  return chunks.join("");
}

export async function extractPdfTwoPass(
  fileName: string,
  bytes: Uint8Array,
): Promise<ExtractedDocument> {
  const rawBinaryStr = uint8ToIso88591(bytes);
  const extractedSegments: string[] = [];

  // Pass 1a: Uncompressed text streams
  const directText = extractPdfOperatorsText(rawBinaryStr);
  if (directText) {
    extractedSegments.push(directText);
  }

  // Pass 1b: /FlateDecode compressed content streams (slice raw Uint8Array directly)
  const dictRegex = /<<(?:(?!>>)[\s\S])*?\/FlateDecode(?:(?!>>)[\s\S])*?>>\s*stream(?:\r\n|\n)/g;
  let dictMatch: RegExpExecArray | null;
  while ((dictMatch = dictRegex.exec(rawBinaryStr)) !== null) {
    const startIdx = dictMatch.index + dictMatch[0].length;
    const endIdx = rawBinaryStr.indexOf("endstream", startIdx);
    if (endIdx < 0) break;
    let payloadEnd = endIdx;
    if (rawBinaryStr.slice(payloadEnd - 2, payloadEnd) === "\r\n") {
      payloadEnd -= 2;
    } else if (rawBinaryStr[payloadEnd - 1] === "\n" || rawBinaryStr[payloadEnd - 1] === "\r") {
      payloadEnd -= 1;
    }
    const buf = bytes.subarray(startIdx, payloadEnd);
    try {
      const inflated = await inflateZlibBytes(buf);
      const text = extractPdfOperatorsText(uint8ToIso88591(inflated));
      if (text) extractedSegments.push(text);
    } catch {
      // Non-standard stream filter; handled by OCR fallback check below
    }
  }

  const combined = extractedSegments.join("\n\n").trim();
  const needsOcr = combined.length < 24;

  return {
    fileName,
    format: "pdf",
    markdownText: combined,
    extractedLocally: !needsOcr,
    needsZeroRetentionOcrFallback: needsOcr,
  };
}

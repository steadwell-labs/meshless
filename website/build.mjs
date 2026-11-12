#!/usr/bin/env node
/**
 * Build the specification page from `specs/mlp-0000-core.md`.
 *
 * The website must not be a second, hand-maintained copy of the specification.
 * This script is the only place the draft becomes HTML: edit the markdown, run
 * `npm run site`, and the page follows. Cloudflare Pages runs the same command.
 *
 * Only the markdown subset the specification actually uses is supported —
 * headings, paragraphs, lists, tables, fenced code, bold, italic, inline code,
 * and links. If the specification needs more, extend this file rather than
 * hand-editing the generated output.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const SOURCE = join(ROOT, 'specs', 'mlp-0000-core.md');
const OUTPUT = join(HERE, 'spec', 'mlp-0000-core', 'index.html');

const DOC = {
  identifier: 'MLP-0000-core',
  version: 'MLP/1 · Draft 00',
  date: '12 November 2026',
  status: 'Experimental, unstable',
  profile: 'MLP/1-HTTP',
  title: 'Meshless Protocol (MLP/1)',
  pageTitle: 'MLP/1 Core Specification — Meshless Protocol (Draft 00)',
  description:
    'The complete Meshless Protocol (MLP/1) draft 00: identity, descriptors, discovery, grants, request proofs, receipts, security, and conformance.',
};

// ---------------------------------------------------------------------------
// Inline formatting
// ---------------------------------------------------------------------------

function escapeHtml(text) {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

const RFC_KEYWORDS = /\b(MUST NOT|SHOULD NOT|MUST|SHOULD|MAY|REQUIRED|OPTIONAL|SHALL NOT|SHALL)\b/g;

function inlineText(segment) {
  let text = escapeHtml(segment);
  text = text.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_match, label, href) => {
    const external = /^https?:/.test(href);
    return `<a href="${href}"${external ? ' rel="noopener"' : ''}>${label}</a>`;
  });
  text = text.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  text = text.replace(/\b(MUST NOT|SHOULD NOT|MUST|SHOULD|MAY)\b/g, (match) => `<span class="rfc">${match}</span>`);
  return text;
}

export function inline(text) {
  // Code spans are lifted out first so that emphasis can span them. Markdown
  // permits `**`kind: inference`**`, and a naive split on backticks leaves the
  // asterisks stranded in different segments.
  const code = [];
  const placeholders = text.replace(/`([^`]+)`/g, (_match, span) => {
    code.push(span);
    return `\u0000${code.length - 1}\u0000`;
  });
  const rendered = inlineText(placeholders).replace(/\u0000(\d+)\u0000/g, (_match, index) => {
    return `<code>${escapeHtml(code[Number(index)] ?? '')}</code>`;
  });
  return rendered;
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

function anchorFor(heading) {
  const numbered = /^(\d+)\.\s+(.*)$/.exec(heading);
  if (numbered) return { id: `s${numbered[1]}`, number: numbered[1], title: numbered[2] };
  const appendix = /^Appendix ([A-Z])\.\s+(.*)$/.exec(heading);
  if (appendix) return { id: `appendix-${appendix[1].toLowerCase()}`, number: appendix[1], title: appendix[2] };
  return { id: null, number: null, title: heading };
}

function parse(markdown) {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const blocks = [];
  let index = 0;

  const sections = [];
  let current = null;

  const push = (block) => {
    if (current) current.blocks.push(block);
    else blocks.push(block);
  };

  while (index < lines.length) {
    const line = lines[index];
    const trimmed = line.trimEnd();

    if (trimmed.trim() === '') {
      index += 1;
      continue;
    }

    if (trimmed.startsWith('# ')) {
      push({ type: 'title', text: trimmed.slice(2).trim() });
      index += 1;
      continue;
    }

    // Horizontal rule: only when it is not a table separator (tables are
    // consumed as a block below, so a bare `---` here is a rule).
    if (/^---+$/.test(trimmed.trim())) {
      push({ type: 'rule' });
      index += 1;
      continue;
    }

    if (trimmed.startsWith('## ')) {
      const heading = trimmed.slice(3).trim();
      const anchor = anchorFor(heading);
      current = { type: 'section', anchor, blocks: [] };
      sections.push(current);
      index += 1;
      continue;
    }

    if (trimmed.startsWith('### ')) {
      const heading = trimmed.slice(4).trim();
      const sub = /^(\d+)\.(\d+)\s+(.*)$/.exec(heading);
      push({
        type: 'h3',
        text: sub ? sub[3] : heading,
        id: sub ? `s${sub[1]}-${sub[2]}` : null,
        number: sub ? `${sub[1]}.${sub[2]}` : null,
      });
      index += 1;
      continue;
    }

    if (trimmed.startsWith('```')) {
      const language = trimmed.slice(3).trim();
      index += 1;
      const code = [];
      while (index < lines.length && !lines[index].trimEnd().startsWith('```')) {
        code.push(lines[index]);
        index += 1;
      }
      index += 1;
      push({ type: 'code', language, text: code.join('\n') });
      continue;
    }

    if (trimmed.startsWith('|')) {
      const rows = [];
      while (index < lines.length && lines[index].trimStart().startsWith('|')) {
        rows.push(lines[index].trim());
        index += 1;
      }
      const [headerRow, separatorRow, ...bodyRows] = rows;
      if (!separatorRow || !/^\|[\s:|-]+\|$/.test(separatorRow)) {
        throw new Error(`table at line ${index} has no alignment row`);
      }
      const cells = (row) =>
        row
          .replace(/^\|/, '')
          .replace(/\|$/, '')
          .split('|')
          .map((cell) => cell.trim());
      push({
        type: 'table',
        head: cells(headerRow),
        rows: bodyRows.map(cells),
      });
      continue;
    }

    const listMatch = /^(\s*)([-*]|\d+\.)\s+(.*)$/.exec(trimmed);
    if (listMatch) {
      const ordered = /\d+\./.test(listMatch[2]);
      const items = [];
      while (index < lines.length) {
        const candidate = lines[index];
        const itemMatch = /^(\s*)([-*]|\d+\.)\s+(.*)$/.exec(candidate);
        if (itemMatch && /\d+\./.test(itemMatch[2]) === ordered) {
          items.push({ text: itemMatch[3].trim(), continuation: [] });
          index += 1;
          continue;
        }
        if (itemMatch && /\d+\./.test(itemMatch[2]) !== ordered) break;
        if (candidate.trim() === '') {
          // A blank line inside a list continues it only if the next line is
          // still indented or another item.
          const next = lines[index + 1] ?? '';
          if (/^\s{2,}\S/.test(next) || /^\s*([-*]|\d+\.)\s+/.test(next)) {
            index += 1;
            continue;
          }
          break;
        }
        if (/^\s{2,}\S/.test(candidate) && items.length > 0) {
          items[items.length - 1].continuation.push(candidate.trim());
          index += 1;
          continue;
        }
        break;
      }
      push({ type: 'list', ordered, items });
      continue;
    }

    // Paragraph: consume until a blank line or the start of another block.
    const paragraph = [];
    while (index < lines.length) {
      const candidate = lines[index];
      if (candidate.trim() === '') break;
      if (/^(#{1,3}\s|```|\||\s*([-*]|\d+\.)\s+)/.test(candidate)) break;
      paragraph.push(candidate.trim());
      index += 1;
    }
    push({ type: 'paragraph', text: paragraph.join(' ') });
  }

  return { blocks, sections };
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function renderBlocks(blocks) {
  const out = [];
  for (const block of blocks) {
    switch (block.type) {
      case 'title':
        break;
      case 'rule':
        out.push('      <hr>');
        break;
      case 'h3':
        out.push(
          `      <h3${block.id ? ` id="${block.id}"` : ''}>${block.number ? `<span class="secnum">${block.number}</span>` : ''}${inline(block.text)}</h3>`,
        );
        break;
      case 'paragraph':
        out.push(`      <p>${inline(block.text)}</p>`);
        break;
      case 'code':
        out.push(`      <pre><code>${escapeHtml(block.text)}</code></pre>`);
        break;
      case 'list': {
        const tag = block.ordered ? 'ol' : 'ul';
        out.push(`      <${tag}>`);
        for (const item of block.items) {
          const continuation = item.continuation.map((line) => inline(line)).join(' ');
          out.push(`        <li>${inline(item.text)}${continuation ? ` ${continuation}` : ''}</li>`);
        }
        out.push(`      </${tag}>`);
        break;
      }
      case 'table': {
        out.push('      <div class="table-wrap">');
        out.push('        <table>');
        out.push(`          <thead>\n            <tr>${block.head.map((cell) => `<th scope="col">${inline(cell)}</th>`).join('')}</tr>\n          </thead>`);
        out.push('          <tbody>');
        for (const row of block.rows) {
          out.push(`            <tr>${row.map((cell) => `<td>${inline(cell)}</td>`).join('')}</tr>`);
        }
        out.push('          </tbody>');
        out.push('        </table>');
        out.push('      </div>');
        break;
      }
      default:
        throw new Error(`unknown block type ${block.type}`);
    }
  }
  return out.join('\n');
}

function renderToc(sections) {
  const items = sections
    .filter((section) => section.anchor.id)
    .map(
      (section) =>
        `          <li><a href="#${section.anchor.id}"><span class="n">${section.anchor.number}</span><span>${escapeHtml(section.anchor.title)}</span></a></li>`,
    );
  return items.join('\n');
}

function renderPage(parsed) {
  const front = parsed.blocks
    .filter((block) => block.type === 'paragraph')
    .map((block) => inline(block.text));

  const body = parsed.sections
    .map((section) => {
      const id = section.anchor.id ? ` id="${section.anchor.id}"` : '';
      const number = section.anchor.number ? `<span class="secnum">${section.anchor.number}</span>` : '';
      return `      <h2${id}>${number}${inline(section.anchor.title)}</h2>\n${renderBlocks(section.blocks)}`;
    })
    .join('\n\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${DOC.pageTitle}</title>
<meta name="description" content="${DOC.description}">
<meta name="theme-color" content="#08090a">
<meta name="color-scheme" content="dark">
<link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%2032%2032'%3E%3Crect%20width='32'%20height='32'%20rx='7'%20fill='%2308090a'/%3E%3Cg%20fill='none'%20stroke='%2379e6b3'%20stroke-width='1.6'%3E%3Ccircle%20cx='9'%20cy='22'%20r='3'/%3E%3Ccircle%20cx='23'%20cy='22'%20r='3'/%3E%3Ccircle%20cx='16'%20cy='10'%20r='3'/%3E%3Cpath%20d='M11.5%2020.2%2014.6%2012.6M20.5%2020.2%2017.4%2012.6M12%2022h8'/%3E%3C/g%3E%3C/svg%3E">
<link rel="stylesheet" href="../../assets/site.css">
<meta property="og:type" content="article">
<meta property="og:site_name" content="Meshless">
<meta property="og:title" content="${DOC.pageTitle}">
<meta property="og:description" content="${DOC.description}">
<meta property="og:url" content="https://meshless.network/spec/mlp-0000-core/">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="MLP/1 Core Specification — Draft 00">
<meta name="twitter:description" content="Identity, signed descriptors, scoped grants, request proofs, receipts, conformance, and governance. Experimental; not an IETF submission.">
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>

<header class="site-header">
  <div class="wrap header-inner">
    <a class="wordmark" href="../../index.html">meshless<span class="dot">.</span></a>
    <nav class="nav" aria-label="Primary">
      <a href="../../index.html">Overview</a>
      <a href="../index.html" aria-current="page">Specification</a>
      <a class="nav-optional" href="../../implementations/index.html">Implementations</a>
      <a class="ext" href="https://github.com/steadwell-labs/meshless" rel="noopener">GitHub</a>
      <span class="version">${DOC.version}</span>
    </nav>
  </div>
</header>

<main id="main">

  <div class="doc-head">
    <div class="wrap">
      <div class="badges">
        <span class="badge">${DOC.version}</span>
        <span class="badge badge--muted">Experimental · not an IETF submission</span>
      </div>
      <h1>${DOC.title}</h1>
      <p class="docid">${DOC.identifier} — working draft</p>

      <dl class="docmeta">
        <div><dt>Document</dt><dd>${DOC.identifier}</dd></div>
        <div><dt>Date</dt><dd>${DOC.date}</dd></div>
        <div><dt>Published by</dt><dd>Steadwell Labs</dd></div>
        <div><dt>Status</dt><dd>${DOC.status}</dd></div>
        <div><dt>Profile</dt><dd>${DOC.profile}</dd></div>
        <div><dt>Keywords</dt><dd>BCP 14</dd></div>
      </dl>
    </div>
  </div>

  <div class="wrap doc-layout">

    <aside class="doc-side" aria-label="Document contents">
      <p class="side-label">Contents</p>
      <p class="side-meta">${DOC.identifier} · Draft 00</p>
      <nav aria-label="Sections">
        <ol class="doc-toc">
${renderToc(parsed.sections)}
        </ol>
      </nav>
      <a class="side-back" href="../index.html">← Specification index</a>
    </aside>

    <div class="doc-main spec">

      <p class="spec-lead">The complete text of draft 00, rendered from
      <code>specs/mlp-0000-core.md</code> without abridgement. Section numbering
      matches the draft. Where the draft says something is provisional, this
      rendering keeps that word.</p>

${front.map((paragraph) => `      <p>${paragraph}</p>`).join('\n')}

${body}

      <div class="docfoot">
        <span>End of ${DOC.identifier} · Draft 00</span>
        <span><a href="../index.html">Specification index</a> · <a href="../../implementations/index.html">Implementation status</a></span>
      </div>

    </div>
  </div>

</main>

<footer class="site-footer">
  <div class="wrap">
    <div class="footer-grid">
      <div class="footer-brand">
        <a class="wordmark" href="../../index.html">meshless<span class="dot">.</span></a>
        <p>An open initiative by Steadwell Labs.</p>
        <p class="muted" style="font-family:var(--mono);font-size:.66rem;letter-spacing:.12em;text-transform:uppercase">A Steadwell Solutions reference</p>
      </div>
      <div class="footer-col">
        <h2>Protocol</h2>
        <ul>
          <li><a href="../index.html">Specification index</a></li>
          <li><a href="index.html">MLP/1 core draft</a></li>
          <li><a href="../../implementations/index.html">Implementations</a></li>
          <li><a href="https://github.com/steadwell-labs/meshless" rel="noopener">Repository</a></li>
        </ul>
      </div>
      <div class="footer-col">
        <h2>Meta</h2>
        <ul>
          <li><a href="https://meshless.network">meshless.network</a></li>
          <li><span class="muted">MLP/1 · Draft 00</span></li>
          <li><span class="muted">Experimental · not an IETF submission</span></li>
          <li><a href="https://github.com/steadwell-labs/meshless/blob/main/LICENSE" rel="noopener">Proposed licensing</a></li>
        </ul>
      </div>
    </div>
    <div class="footer-base">
      <span>© 2026 Steadwell Solutions</span>
      <span class="labs">An open initiative by Steadwell Labs.</span>
      <span>Specification text: CC BY 4.0 (proposed)</span>
    </div>
  </div>
</footer>

</body>
</html>
`;
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

function build() {
  const markdown = readFileSync(SOURCE, 'utf8');
  const parsed = parse(markdown);
  if (parsed.sections.length < 19) throw new Error(`expected at least 19 sections, found ${parsed.sections.length}`);
  const html = renderPage(parsed);
  mkdirSync(dirname(OUTPUT), { recursive: true });
  writeFileSync(OUTPUT, html);
  return { sections: parsed.sections.length, bytes: html.length };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = build();
  console.log(`wrote ${OUTPUT} (${result.sections} sections, ${Math.round(result.bytes / 1024)} KB)`);
}

export { build, parse, renderPage };

# meshless.network

Static site for the Meshless Protocol. No framework, no client-side JavaScript,
no build step for the pages themselves.

```
website/
├── index.html                       home
├── spec/index.html                  specification hub
├── spec/mlp-0000-core/index.html    rendered draft (generated — do not edit)
├── implementations/index.html       implementation status
├── 404.html
├── assets/site.css                  the whole stylesheet
├── build.mjs                        markdown → HTML for the spec page
└── _headers                         security headers for Cloudflare Pages
```

## The spec page is generated

`spec/mlp-0000-core/index.html` is rendered from `specs/mlp-0000-core.md` by
`build.mjs`. Do not edit it by hand: the next `npm run site` will overwrite it,
and CI fails if the committed page and the committed markdown disagree.

```sh
npm run site          # regenerate
npm run check:site    # fail if the committed page is stale
```

The generator supports the markdown subset the specification uses. If the draft
needs something it does not handle, extend `build.mjs` rather than editing the
output.

## Local preview

```sh
python3 -m http.server 8000 --directory website
# or
npx serve website
```

Assets and links are relative, so the pages also open directly from the
filesystem. That is deliberate: a specification should be readable offline.

## Deploy

Cloudflare Pages, from `steadwell-labs/meshless`:

| Setting | Value |
| --- | --- |
| Build command | `npm run site` |
| Output directory | `website` |
| Node version | 22.18 or later |

`_headers` applies a content security policy, `X-Content-Type-Options`,
`Referrer-Policy`, `Permissions-Policy`, and a long cache for `/assets/*`.

## Constraints the site keeps

- No CDN, no external fonts, no analytics, no cookies.
- Every page works at 360px and at 1440px, keyboard-first, with a skip link.
- Claims match the repository. If the implementation status changes, this site
  changes in the same commit — "in progress" that has stopped being true is a
  lie with a publication date on it.

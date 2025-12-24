# Next Scout

Next Scout is a lightweight web vulnerability scanner built with a modern, full-stack Next.js architecture. It crawls a target website, maps forms and links, and probes for common issues like reflected Cross-Site Scripting (XSS) and basic error-based SQL Injection (SQLi).

Developed by Swapneel Ghosh and Jagadeesh Chandra Duggirala.

## Features

- **Recursive crawler** scoped to the target domain with a configurable page cap to avoid runaway scans.
- **Automated form discovery** that records actions, methods, and input names for each form.
- **XSS probing** using reflected payload checks.
- **SQLi probing** that looks for common database error signatures.
- **Responsive dashboard** built with Tailwind CSS for reviewing links, forms, and vulnerability findings side-by-side.
- **SSRF safeguards**: scans are limited to HTTP/HTTPS targets and skip localhost/private-network addresses and off-domain form actions.

## Architecture

- **Framework:** Next.js App Router (15.x) for both the React UI and the `/api/scan` endpoint.
- **Language:** TypeScript/JavaScript.
- **Styling:** Tailwind CSS v4.
- **Backend utilities:** Axios for HTTP requests and Cheerio for HTML parsing during the crawl.

The UI lives in `app/page.tsx`, while the scanning logic is handled in `app/api/scan/route.js`.

## Getting Started

### Prerequisites
- Node.js 18.x or later
- npm

### Installation
```bash
npm ci
```

### Running the app
- Development server: `npm run dev` (Turbopack)  
  Open http://localhost:3000 to use the UI.
- Production build: `npm run build` then `npm start`.

### Using the scanner
1. Enter a target URL in the UI (must be `http` or `https` and not a private/local address).
2. Start the scan and wait for the dashboard to populate.
3. Review the summary, discovered links/forms, and any reported vulnerabilities.

API usage (optional):
```bash
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://example.com"}'
```
The response includes a message, discovered links/forms, vulnerabilities, and a timestamp.

## Security and responsible use
- **Authorized testing only:** Run scans only against targets you own or have explicit, written permission to test.
- **Non-destructive checks:** Payloads are designed to detect issues without exploiting them or storing data.
- **Network safeguards:** Requests are restricted to HTTP/HTTPS, block localhost/private-network addresses, and ignore off-domain form actions to reduce SSRF risk.
- **Data handling:** The app does not persist scan data server-side.

Unauthorized scanning is illegal. The developers assume no liability for misuse.

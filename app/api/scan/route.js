import { NextResponse } from 'next/server';
import axios from 'axios';
import * as cheerio from 'cheerio';
import { isIP } from 'node:net';

const BLOCKED_HOSTS = new Set([
    'localhost',
    'localhost.localdomain',
    '127.0.0.1',
    '::1',
    '0.0.0.0',
    '0',
]);

function isPrivateIPv4(hostname) {
    const octets = hostname.split('.').map(Number);
    if (octets.length !== 4 || octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;

    const [a, b] = octets;
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    return false;
}

function isPrivateIPv6(hostname) {
    const lowered = hostname.toLowerCase();
    if (lowered === '::1') return true; // loopback
    // Unique local addresses fc00::/7 and link-local fe80::/10
    return lowered.startsWith('fc') || lowered.startsWith('fd') || lowered.startsWith('fe8') || lowered.startsWith('fe9') || lowered.startsWith('fea') || lowered.startsWith('feb');
}

function isBlockedTarget(hostname) {
    const lowered = hostname.toLowerCase();
    if (BLOCKED_HOSTS.has(lowered)) return true;
    const ipVersion = isIP(lowered);
    if (ipVersion === 4) {
        return isPrivateIPv4(lowered);
    }
    if (ipVersion === 6) {
        return isPrivateIPv6(lowered);
    }
    // Block invalid IPv4-like hostnames (e.g., numeric dotted but not valid IP)
    if (/^[0-9.]+$/.test(lowered) && ipVersion === 0) {
        return true;
    }
    return false;
}

function isAllowedHttpUrl(target) {
    try {
        const parsed = target instanceof URL ? target : new URL(target);
        if (!['http:', 'https:'].includes(parsed.protocol)) return false;
        return !isBlockedTarget(parsed.hostname);
    } catch {
        return false;
    }
}

// Helper function to fetch and parse a URL
async function fetchAndParse(url) {
    try {
        const response = await axios.get(url, {
            headers: { 'User-Agent': 'NextScout/1.0' },
            timeout: 5000,
        });
        return cheerio.load(response.data);
    } catch (error) {
        console.warn(`[Crawler] Failed to fetch ${url}: ${error.message}`);
        return null;
    }
}

// --- Scanner Module: XSS ---
async function checkXSS(form) {
    const xssPayload = `<ScoutXSS_test>`;
    const vulnerableParams = [];

    for (const input of form.inputs) {
        if (!input.name) continue;

        const formData = new URLSearchParams();
        form.inputs.forEach(i => {
            if (i.name) {
                formData.append(i.name, i.name === input.name ? xssPayload : 'test');
            }
        });

        try {
            const requestConfig = {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            };
            const response = form.method === 'POST'
                ? await axios.post(form.action, formData, requestConfig)
                : await axios.get(form.action, { params: formData });

            if (response.data.includes(xssPayload)) {
                console.log(`[XSS Scanner] Found potential XSS in ${input.name} at ${form.page}`);
                vulnerableParams.push(input.name);
            }
        } catch (error) {}
    }

    if (vulnerableParams.length > 0) {
        return { type: 'XSS', page: form.page, formAction: form.action, vulnerableParams };
    }
    return null;
}

// --- Scanner Module: SQL Injection ---
async function checkSQLi(form) {
    const sqlPayload = `'`;
    const errorSignatures = ['syntax error', 'unclosed quotation mark', 'SQL', 'MySQL', 'ORA-'];
    const vulnerableParams = [];

    for (const input of form.inputs) {
        if (!input.name) continue;

        const formData = new URLSearchParams();
        form.inputs.forEach(i => {
            if (i.name) {
                formData.append(i.name, i.name === input.name ? sqlPayload : 'test');
            }
        });
        
        try {
            const requestConfig = {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            };
             const response = form.method === 'POST'
                ? await axios.post(form.action, formData, requestConfig)
                : await axios.get(form.action, { params: formData });
            
            if (errorSignatures.some(sig => response.data.includes(sig))) {
                console.log(`[SQLi Scanner] Found potential SQLi in ${input.name} at ${form.page}`);
                vulnerableParams.push(input.name);
            }
        } catch (error) {
            if (error.response && error.response.data) {
                if (errorSignatures.some(sig => String(error.response.data).includes(sig))) {
                    console.log(`[SQLi Scanner] Found potential SQLi in ${input.name} at ${form.page} (via error response)`);
                    vulnerableParams.push(input.name);
                }
            }
        }
    }

    if (vulnerableParams.length > 0) {
        return { type: 'SQL Injection', page: form.page, formAction: form.action, vulnerableParams };
    }
    return null;
}


export async function POST(request) {
  try {
    const body = await request.json();
    const { url } = body;

    if (!url) {
      return NextResponse.json({ error: 'URL is required' }, { status: 400 });
    }

    const parsedTargetUrl = new URL(url);
    if (!isAllowedHttpUrl(parsedTargetUrl)) {
      return NextResponse.json({ error: 'URL must be http(s) and cannot point to private or local addresses' }, { status: 400 });
    }

    const targetDomain = parsedTargetUrl.hostname;
    const urlsToVisit = [parsedTargetUrl.href];
    const visitedUrls = new Set();
    const discoveredForms = [];
    const maxPages = 50;

    while (urlsToVisit.length > 0 && visitedUrls.size < maxPages) {
        const currentUrl = urlsToVisit.shift();
        if (!currentUrl || !isAllowedHttpUrl(currentUrl)) continue;
        if (visitedUrls.has(currentUrl)) continue;
        visitedUrls.add(currentUrl);
        const $ = await fetchAndParse(currentUrl);
        if (!$) continue;
        $('a').each((i, el) => {
            let absLink;
            try { absLink = new URL($(el).attr('href'), currentUrl).href; } catch (e) { return; }
            const parsedLink = new URL(absLink);
            if (!isAllowedHttpUrl(parsedLink)) return;
            if (parsedLink.hostname === targetDomain) {
                const cleanLink = parsedLink.href.split('#')[0];
                if (!visitedUrls.has(cleanLink)) urlsToVisit.push(cleanLink);
            }
        });
        $('form').each((i, el) => {
            const inputs = [];
            $(el).find('input, textarea, select').each((i, inputEl) => {
                inputs.push({ type: $(inputEl).attr('type') || 'text', name: $(inputEl).attr('name') });
            });
            const actionUrl = new URL($(el).attr('action') || currentUrl, currentUrl);
            if (!isAllowedHttpUrl(actionUrl) || actionUrl.hostname !== targetDomain) return;
            discoveredForms.push({
                page: currentUrl,
                action: actionUrl.href,
                method: ($(el).attr('method') || 'GET').toUpperCase(),
                inputs,
            });
        });
    }

    // --- Scanner Logic ---
    const vulnerabilities = [];
    console.log(`[Scanner] Starting scan on ${discoveredForms.length} forms.`);
    for (const form of discoveredForms) {
        const xssResult = await checkXSS(form);
        if (xssResult) vulnerabilities.push(xssResult);

        const sqliResult = await checkSQLi(form);
        if (sqliResult) vulnerabilities.push(sqliResult);
    }

    const results = {
      message: `Scan complete. Visited ${visitedUrls.size} pages. Found ${vulnerabilities.length} potential vulnerabilities.`,
      discoveredLinks: Array.from(visitedUrls),
      discoveredForms,
      vulnerabilities,
      timestamp: new Date().toISOString(),
    };

    return NextResponse.json(results, { status: 200 });

  } catch (error) {
    console.error('[API Error]', error);
    return NextResponse.json({ error: error.message || 'An internal server error occurred.' }, { status: 500 });
  }
}

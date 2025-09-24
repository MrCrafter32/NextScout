Next Scout

A simple yet powerful web vulnerability scanner built with a modern, full-stack Next.js architecture. This application is designed to crawl a target website, identify potential attack vectors, and test for common security vulnerabilities like Cross-Site Scripting (XSS) and SQL Injection (SQLi).

This project was developed by Swapneel Ghosh and Jagadeesh Chandra Duggirala.
Features

    Recursive Web Crawler: Systematically navigates a target website to discover all internal links and pages.

    Automated Form Discovery: Identifies all HTML forms on a site, which are the primary entry points for attacks.

    Cross-Site Scripting (XSS) Scanner: Actively probes form inputs for reflected XSS vulnerabilities by injecting a payload and analyzing the server's response.

    SQL Injection (SQLi) Scanner: Tests for basic, error-based SQLi vulnerabilities by submitting common SQL special characters and looking for database error messages.

    Modern & Responsive UI: A clean, user-friendly interface built with Tailwind CSS that provides a seamless experience on any device.

    Side-by-Side Results Dashboard: Presents scan results in an intuitive two-column layout, separating the summary and vulnerabilities from detailed crawler data.

Technology Stack

Next Scout is built with a monorepo full-stack architecture, leveraging the power of JavaScript/TypeScript across the entire application.

    Framework: Next.js (handles both React frontend and Node.js backend API routes)

    Language: TypeScript

    Styling: Tailwind CSS

    HTTP Client: Axios (for making requests to the target server from the backend)

    HTML Parsing: Cheerio (for efficiently parsing HTML and extracting links/forms on the server-side)

How It Works

The application follows a systematic, multi-step process to perform a scan:

    User Input: The user provides a target URL through the React frontend.

    API Request: The frontend sends a POST request to the /api/scan backend endpoint.

    Web Crawling: The backend crawler receives the URL, fetches the page content, and recursively discovers all unique internal links and forms. It systematically traverses the website to build a map of potential targets.

    Vulnerability Scanning: For each discovered form, the scanning modules programmatically submit a series of crafted payloads designed to detect XSS and SQLi vulnerabilities.

    Analysis & Reporting: The scanners analyze the server's responses for evidence of security flaws (e.g., reflected scripts or database errors). All findings are aggregated and sent back to the frontend, where they are displayed in the results dashboard.

Getting Started

To get a local copy up and running, follow these simple steps.
Prerequisites

Make sure you have Node.js and npm installed on your machine.

    Node.js (v18.x or later recommended)

    npm

Installation & Setup

    Clone the repository:

    git clone https://github.com/MrCrafter32/NextScout.git
    cd next-scout

    Install NPM packages:

    npm install

    Run the development server:

    npm run dev

Open http://localhost:3000 with your browser to see the result.
Ethical Considerations and Usage Policy

This tool is for educational purposes only.

    Principle of Authorized Use: Only run Next Scout against websites that you own or have explicit, written permission to test.

    Non-Destructive Testing: The scanning modules are designed to be non-destructive. They identify vulnerabilities without exploiting them or harming the target system.

    Data Privacy: The application does not store any scan results or user data.

Unauthorized scanning of websites is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

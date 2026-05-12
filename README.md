# File: README.md
```markdown
<!-- 
Directory: /README.md 
-->

# 🕵️‍♂️ Professional Recon Tool (AI-Optimized)
**Version 1.0.0 | Commercial-Grade Passive Reconnaissance**

Welcome to the **Professional Recon Tool**, a premium, strictly passive information-gathering suite designed for authorized bug bounty hunters and security engineers. 

This tool was engineered from the ground up to solve a specific modern problem: **bridging the gap between raw reconnaissance data and AI-assisted vulnerability analysis.**

---

## 🧠 The Two-Phase Workflow

This tool is not an automatic vulnerability scanner or an active exploiter. It is the **Phase 1** data-collection engine in a modern, AI-driven bug bounty workflow.

* **Phase 1 (This Tool):** Performs deep, stealthy, passive reconnaissance on a target domain. It handles rate-limiting, concurrent downloading, parsing, and context-aware secret scanning.
* **Phase 2 (Your AI Assistant):** The tool generates a highly structured Markdown report. You copy and paste this report into an AI (ChatGPT, Claude, etc.) to receive strategic testing guidance, prioritize attack surfaces, and identify potential logic flaws.

---

## ⚡ Key Features

* **Strictly Passive & Safe:** Every technique used is non-intrusive. No payloads are sent, ensuring you stay within strict bug bounty rules of engagement.
* **Smart JavaScript Analysis:** Automatically categorizes first-party vs. third-party scripts, concurrently downloads first-party code, and uses **context-aware regex** to find hardcoded secrets (API keys, tokens) without triggering thousands of false positives.
* **Robust Network Engine:** Built with a resilient HTTP client featuring token-bucket rate limiting, automatic retries on transient errors (429, 50x), Retry-After header parsing, and strict memory limits (prevents OOM crashes on huge files).
* **Comprehensive Surface Mapping:** Extracts internal/external links, hidden form fields, referenced subdomains, query parameters, and probes for exposed sensitive paths (e.g., `/.env`, `/.git/HEAD`).
* **Deep Infrastructure Audit:** Detects CMS, JS Frameworks (with safe version extraction), Web Servers, evaluates Cookie Security, and audits 7 critical HTTP Security Headers.
* **DNS & WHOIS:** Retrieves A, MX, NS, TXT, and CNAME records with custom timeout budgets, plus defensive WHOIS data extraction.

---

## 🛠️ Installation

**Prerequisites:** Python 3.9 or higher.

1. **Unpack the suite** into your working directory.
2. **Create a virtual environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. **Install the pinned dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Usage

Run the tool via the main orchestrator script:

```bash
python recon.py <target_url> [options]
```

### Basic Example
```bash
python recon.py https://example.com
```

### Advanced Example
Configure threads for JS downloading, set a strict rate limit, and add a custom suffix to the report names:
```bash
python recon.py https://example.com --threads 10 --rate 2.0 --output initial_scan
```

### Command-Line Arguments
| Argument | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `target` | string | **Required** | The target domain or URL (e.g., `example.com` or `https://example.com`). |
| `--output` | string | `None` | Custom string appended to the generated report filenames. |
| `--threads`| integer| `5` | Number of concurrent threads for downloading JS files (Max 20). |
| `--rate` | float | `1.0` | Maximum HTTP requests per second to ensure stealth and stability. |

---

## 📂 Output Directory

When a scan finishes, reports are saved to the `output/` directory (created automatically). You will see two files per scan:

1. `target_name_YYYYMMDD_HHMMSS.json`: A machine-readable JSON dump of all raw data for your own scripts or database.
2. `target_name_YYYYMMDD_HHMMSS.md`: The AI-optimized Markdown report.

---

## 🤖 Phase 2: How to use the report with AI

Once the scan is complete, follow these exact steps to maximize the value of this tool:

1. Open the generated `.md` file in `output/`.
2. Select all and **Copy** the entire contents.
3. Open **ChatGPT (GPT-4)**, **Claude (Opus/Sonnet)**, or your preferred LLM.
4. **Paste** the report along with the following prompt:

> **Suggested AI Prompt:**
> *"I am an authorized bug bounty hunter. Below is a passive reconnaissance report I generated for my target. Please act as a senior web security researcher. Analyze this data and provide: 1) A prioritized list of vulnerability classes I should investigate based on the tech stack. 2) Specific manual tests I should perform on the discovered endpoints, parameters, and forms. 3) Any interesting combinations of findings that look like a security risk. Here is the report:"*
> 
> *[PASTE REPORT HERE]*

---

## ⚖️ Legal Disclaimer & EULA

**FOR AUTHORIZED USE ONLY.**

By purchasing and using this software, you agree that:
1. You have explicit, written authorization from the target owner to perform security testing.
2. You are using this tool within the defined scope of a legitimate bug bounty program or penetration testing engagement.
3. The developers and vendors of this tool assume **zero liability** for misuse, damage, or legal repercussions caused by unauthorized scanning. 
4. This tool performs passive reconnaissance, but it is your responsibility to monitor your traffic and abide by the target's terms of service.
```

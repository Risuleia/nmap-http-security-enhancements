\# Nmap HTTP Title and Security Header Enhancements



\*\*Author:\*\* Hreeth Gupta



\## Overview



This project demonstrates two enhancements to HTTP metadata inspection using Nmap's Scripting Engine (NSE). The scripts were tested against a local Python HTTP server running on `127.0.0.1:8000`.



\## Scripts



\- `http-title.nse` — Reference script that retrieves the default HTTP page title.

\- `http-title-enhanced.nse` — Reports the HTTP status code and page title.

\- `http-security-check.nse` — Reports HTTP status, page title, and the presence of four selected HTTP security headers.



\## Test Environment



\- Operating system: Windows

\- Nmap version: 7.992

\- Local HTTP server: Python 3.12.6

\- Test target: `127.0.0.1:8000`



\## Test Commands



Reference script:



```powershell

nmap -sT -p 8000 --script http-title 127.0.0.1

```



Enhancement 1:



```powershell

nmap -sT -p 8000 --script .\\http-title-enhanced.nse 127.0.0.1

```



Enhancement 2:



```powershell

nmap -sT -p 8000 --script .\\http-security-check.nse 127.0.0.1

```



\## Observed Results



The local server returned HTTP status `200` and the page title `DA1 Security Lab`.



The second enhancement reported the following headers as absent in the test response:



\- Content-Security-Policy

\- Strict-Transport-Security

\- X-Content-Type-Options

\- X-Frame-Options



These results describe the local test server only and are not a general assessment of website security.



\## Safety



The scripts were tested against a local server on the author's own machine. Use Nmap only on systems you own or have permission to assess.


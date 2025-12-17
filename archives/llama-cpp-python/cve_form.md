* Vulnerability type info
Server-Side Request Forgery (SSRF)

* Vendor of the product(s) info
abetlen

Affected product(s)/code base info
* Product: llama-cpp-python
* Version: All versions prior to fix (no fix available at the time of report)
* Repository: https://github.com/abetlen/llama-cpp-python

Optional
Has vendor confirmed or acknowledged the vulnerability: Not mentioned

Attack type info
Remote

Impact info
High severity. Allows attackers to:
1. Access internal network resources (private IP addresses)
2. Scan internal services and detect open ports
3. Extract sensitive information from cloud metadata services
4. Bypass access controls and access internal services not exposed to public internet

Affected component(s)
- `/llama_cpp/llama_chat_format.py` (specifically the `LlamaChatFormat._load_image` method)

Attack vector(s)
An attacker can exploit this vulnerability by:
1. Providing a malicious image URL in the user-controllable `messages` parameter
2. The `get_image_urls()` method extracts the URL without any validation
3. The `_load_image()` method passes the malicious URL directly to `urllib.request.urlopen()`
4. The server executes the HTTP request to the attacker-specified URL without validation

Suggested description of the vulnerability for use in the CVE info
llama-cpp-python is affected by a Server-Side Request Forgery (SSRF) vulnerability in the `LlamaChatFormat._load_image` static method. User-controllable image URLs are passed directly to `urllib.request.urlopen()` without proper validation, allowing attackers to make arbitrary HTTP requests from the server. This could expose internal network resources, cloud metadata services, and sensitive information.

Discoverer(s)/Credits info
Ana10gy

Reference(s) info
- CWE-918: Server-Side Request Forgery (SSRF)
- OWASP Top 10 2021: A10 - Server-Side Request Forgery (SSRF)
- Repository: https://github.com/abetlen/llama-cpp-python

Additional information
To mitigate this vulnerability, implement strict URL validation including:
1. Allowing only HTTP/HTTPS protocols
2. Blocking internal/private IP ranges (private, loopback, multicast)
3. Restricting to known image domains (if applicable)
4. Using a secure URL library with built-in protection. The report includes a patched version of the `_load_image` function that implements these checks.
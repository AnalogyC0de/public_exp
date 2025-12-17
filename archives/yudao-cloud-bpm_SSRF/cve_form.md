* Vulnerability type info
Server-Side Request Forgery (SSRF)

* Vendor of the product(s) info
YunaiV

Affected product(s)/code base info
* Product: YuDao Cloud
* Version: All versions in the current repository <= v2025.11 (no fix available)
* Repository: https://github.com/YunaiV/yudao-cloud

Optional
Has vendor confirmed or acknowledged the vulnerability: Not mentioned

Attack type info
Remote

Impact info
High severity. Allows authenticated attackers to:
1. Access internal network resources
2. Extract sensitive information from cloud metadata services
3. Perform port scanning on internal networks
4. Exfiltrate data from the internal network
5. Potentially achieve remote code execution (in certain configurations)

Affected component(s)
- `yudao-module-bpm/yudao-module-bpm-server/src/main/java/cn/iocoder/yudao/module/bpm/service/task/trigger/http/BpmHttpCallbackTrigger.java`
- `yudao-module-bpm/yudao-module-bpm-server/src/main/java/cn/iocoder/yudao/module/bpm/service/task/trigger/http/BpmSyncHttpRequestTrigger.java`
- `yudao-module-bpm/yudao-module-bpm-server/src/main/java/cn/iocoder/yudao/module/bpm/framework/flowable/core/util/BpmHttpRequestUtils.java`

Attack vector(s)
An attacker with BPM process design permissions can exploit this vulnerability by:
1. Creating a BPM process with an HTTP trigger node
2. Configuring the trigger node with a malicious URL (e.g., targeting internal network resources or cloud metadata services)
3. Deploying and starting the malicious BPM process
4. When the process execution reaches the trigger node, the system executes the HTTP request to the attacker-specified URL without validating it.

Suggested description of the vulnerability for use in the CVE info
YuDao Cloud is affected by a Server-Side Request Forgery (SSRF) vulnerability in the BPM HTTP triggers functionality. Authenticated users with BPM process design permissions can configure malicious URLs in BPM process trigger nodes, which are then executed by the server without proper validation. This allows attackers to make arbitrary HTTP requests from the server, potentially exposing internal network resources, cloud metadata services, and other sensitive information.

Discoverer(s)/Credits info
Ana10gy

Reference(s) info
- CWE-918: Server-Side Request Forgery (SSRF)
- OWASP Top 10 2021: A10 - Server-Side Request Forgery (SSRF)
- Repository: https://github.com/YunaiV/yudao-cloud

Additional information
Implementing strict URL validation (restricting protocols, blocking internal network ranges), domain whitelisting, and limiting BPM process design permissions to trusted users would mitigate this issue. Logging all HTTP requests made by BPM HTTP triggers is also recommended.
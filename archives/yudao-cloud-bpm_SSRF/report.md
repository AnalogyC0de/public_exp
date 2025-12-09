# SSRF Vulnerability in BPM HTTP Triggers - YuDao Cloud

## Vulnerability Overview

**Submitter**: Ana10gy

YuDao Cloud is a microservices architecture enterprise-level backend framework. A critical Server-Side Request Forgery (SSRF) vulnerability has been identified in the BPM (Business Process Management) HTTP triggers functionality that allows authenticated users with BPM process design permissions to make arbitrary HTTP requests from the server, potentially exposing internal network resources.

## Affected Component

- **Project**: [YuDao Cloud](https://github.com/YunaiV/yudao-cloud)
- **Vendor**: YunaiV
- **Affected Files**:
  - `yudao-cloud-master/yudao-module-bpm/yudao-module-bpm-server/src/main/java/cn/iocoder/yudao/module/bpm/service/task/trigger/http/BpmHttpCallbackTrigger.java`
  - `yudao-cloud-master/yudao-module-bpm/yudao-module-bpm-server/src/main/java/cn/iocoder/yudao/module/bpm/service/task/trigger/http/BpmSyncHttpRequestTrigger.java`
  - `yudao-cloud-master/yudao-module-bpm/yudao-module-bpm-server/src/main/java/cn/iocoder/yudao/module/bpm/framework/flowable/core/util/BpmHttpRequestUtils.java`

## Vulnerability Details

### Root Cause

The vulnerability exists in the BPM HTTP triggers (`BpmHttpCallbackTrigger` and `BpmSyncHttpRequestTrigger`), which handle BPMN process nodes that require HTTP requests to be made. The root causes are:

1. **Missing URL Validation**: At no point during the request processing flow is the user-provided URL validated or sanitized.
2. **Direct URL Usage**: The `BpmHttpRequestUtils.sendHttpRequest` method directly uses the parsed URL from the JSON configuration without any restrictions:
   ```java
   responseEntity = restTemplate.exchange(url, HttpMethod.POST, requestEntity, String.class); // SSRF Sink here
   ```
3. **Unrestricted Request Configuration**: The triggers allow full control over the HTTP request, including headers and body, with no validation.

### Attack Vector

An attacker with BPM process design permissions can exploit this vulnerability by:

1. Creating a BPM process with an HTTP trigger node
2. Configuring the trigger node with a malicious URL (e.g., targeting internal network resources or cloud metadata services)
3. Deploying and starting the malicious BPM process
4. When the process execution reaches the trigger node, the system executes the HTTP request to the attacker-specified URL

### Execution Flow

1. A BPM process is designed/deployed with a trigger node containing HTTP request configuration (URL, headers, body)
2. When the process execution reaches this node, Flowable calls the `BpmTriggerTaskDelegate.execute` method
3. `BpmTriggerTaskDelegate` parses the trigger type and parameters from the BPMN model
4. It then calls the `execute` method of the corresponding HTTP trigger (`BpmHttpCallbackTrigger` or `BpmSyncHttpRequestTrigger`)
5. The trigger parses the JSON parameter containing the HTTP configuration and makes the request without validating the URL

## Proof of Concept

### Step 1: Create Malicious BPM Trigger Configuration
The attacker configures an HTTP callback trigger with the following JSON configuration targeting the AWS EC2 metadata service:

```json
{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  "header": [],
  "body": [],
  "callbackTaskDefineKey": "task123"
}
```

### Step 2: Deploy and Trigger the Malicious Process
- The attacker deploys the BPM process with the malicious HTTP trigger configuration.
- The attacker starts the process, either manually or through an automated workflow.

### Step 3: Result Verification
When the process execution reaches the HTTP trigger node, the system executes the HTTP request to the specified URL. The attacker can potentially:
- Receive IAM security credentials from the AWS EC2 metadata service.
- Use these credentials to gain unauthorized access to AWS resources associated with the victim system.

## Impact

This vulnerability has **High** severity and allows authenticated attackers with BPM process design permissions to:

1. **Access Internal Network Resources**: Scan and access internal systems that are not exposed to the public internet.
2. **Cloud Metadata Service Attack**: Extract sensitive information from cloud provider metadata services (like AWS EC2 metadata service at `http://169.254.169.254/`), which could include IAM credentials.
3. **Port Scanning**: Perform port scanning on internal networks to identify open ports and potential targets for further attacks.
4. **Data Exfiltration**: Send data from the internal network to external attacker-controlled servers.
5. **Remote Code Execution**: In certain configurations, SSRF can lead to RCE if the attacker can exploit other vulnerabilities in the systems they can reach.

## Affected Versions

All versions of YuDao Cloud in the current repository are affected.

## Recommendations

1. **Implement Strict URL Validation**:
   - Validate that URLs are properly formatted.
   - Restrict protocols to only allow `http` and `https`.
   - Block access to internal network ranges (e.g., 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10).

2. **Use Domain Whitelisting**:
   - Create a whitelist of allowed domains for HTTP requests.
   - Reject any requests to domains not on the whitelist.

3. **Implement URL Sanitization**:
   - Remove or normalize any path traversal characters or unexpected patterns in URLs.
   - Example implementation:
     ```java
     // Validate URL protocol
     URL url = new URL(urlStr);
     if (!"http".equals(url.getProtocol()) && !"https".equals(url.getProtocol())) {
         throw new SecurityException("Unsupported protocol: " + url.getProtocol());
     }
     // Validate domain
     if (!allowedDomains.contains(url.getHost())) {
         throw new SecurityException("Disallowed domain: " + url.getHost());
     }
     // Check for internal IP
     if (isInternalIp(url.getHost())) {
         throw new SecurityException("Internal IP address not allowed: " + url.getHost());
     }
     ```

4. **Limit BPM Process Design Permissions**:
   - Restrict BPM process design permissions to only trusted users.
   - Implement proper access control to ensure only authorized users can configure HTTP triggers.

5. **Add Request Logging**:
   - Log all HTTP requests made by the BPM HTTP triggers, including the full URL, headers, and body.
   - Monitor logs for unusual or suspicious requests.

## References

- CWE-918: Server-Side Request Forgery (SSRF)
- OWASP Top 10 2021: A10 - Server-Side Request Forgery (SSRF)
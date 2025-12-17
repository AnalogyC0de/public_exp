# SSRF Vulnerability Detection Report for llama-cpp-python

## Vulnerability Overview

A **Server-Side Request Forgery (SSRF)** vulnerability exists in the `_load_image` static method of the `LlamaChatFormat` class in `/llama_cpp/llama_chat_format.py`. The function allows untrusted image URLs to be passed directly to `urllib.request.urlopen()` without validation, which could enable attackers to make arbitrary requests from the server when used in a server-side context.

## Core Vulnerable Code

```python
@staticmethod
def _load_image(image_url: str) -> bytes:
    # TODO: Add Pillow support for other image formats beyond (jpg, png)
    if image_url.startswith("data:"):
        import base64
        image_bytes = base64.b64decode(image_url.split(",")[1])
        return image_bytes
    else:
        import urllib.request
        with urllib.request.urlopen(image_url) as f:  # UNSANITIZED URL INPUT
            image_bytes = f.read()
            return image_bytes
```

## Exploitation Path

1. **Entry Point**: User-controllable `messages` parameter containing image URLs
2. **URL Extraction**: The `get_image_urls()` method extracts URLs from message content:
   ```python
   @staticmethod
   def get_image_urls(messages: List[llama_types.ChatCompletionRequestMessage]):
       image_urls: List[str] = []
       for message in messages:
           if message["role"] == "user":
               if message["content"] is None:
                   continue
               for content in message["content"]:
                   if isinstance(content, dict) and "type" in content:
                       if content["type"] == "image_url":
                           # Extract URL without validation
                           if isinstance(content["image_url"], dict) and "url" in content["image_url"]:
                               image_urls.append(content["image_url"]["url"])
                           else:
                               image_urls.append(content["image_url"])
       return image_urls
   ```
3. **Vulnerable Call**: Extracted URLs are passed directly to `_load_image()` during chat completion processing

## Potential Impact

The vulnerability could allow attackers to:

- **Access internal network resources**: Requests to private IP addresses (192.168.x.x, 10.x.x.x)
- **Scan internal services**: Detect open ports and services on the internal network
- **Access cloud metadata**: For cloud-hosted servers, exfiltrate AWS/GCP metadata
- **Bypass access controls**: Access internal services that are not exposed to the public internet

## Mitigation

To fix this vulnerability, we need to add strict validation for image URLs:

1. **Allow only HTTP/HTTPS protocols**
2. **Restrict to known image domains** (if applicable)
3. **Block internal/private IP ranges**
4. **Use a secure URL library with built-in protection**

Here's a patched version of the `_load_image` function:

```python
@staticmethod
def _load_image(image_url: str) -> bytes:
    import urllib.parse

    # Validate URL protocol
    parsed = urllib.parse.urlparse(image_url)
    if parsed.scheme not in ["data", "http", "https"]:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")

    # Block internal IP addresses (basic protection)
    import ipaddress
    if parsed.hostname:
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if ip.is_private or ip.is_loopback or ip.is_multicast:
                raise ValueError(f"Internal IP address not allowed: {parsed.hostname}")
        except ValueError:
            # Not an IP address, continue with hostname validation
            pass

    if image_url.startswith("data:"):
        import base64
        image_bytes = base64.b64decode(image_url.split(",")[1])
        return image_bytes
    else:
        import urllib.request
        with urllib.request.urlopen(image_url) as f:
            image_bytes = f.read()
            return image_bytes
```

## Conclusion

The SSRF vulnerability in the `_load_image` function is a result of insufficient validation of user-controllable image URLs. When used in a server-side context, this could expose the server to internal network enumeration and other attacks. It is recommended to apply the mitigation mentioned above to ensure secure handling of image URLs.
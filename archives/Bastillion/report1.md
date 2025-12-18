# Command Injection via Public Key Content

## I. Vulnerability Overview
A command injection vulnerability has been identified in the public key management system. Authenticated users with public key upload privileges can inject malicious commands by including specially crafted content in their public keys, which are then executed on remote systems during SSH key distribution operations.


**Submitter**: Ana10gy
**Project**: Bastillion SSH Key Manager [https://github.com/bastillion-io/Bastillion]
**Type**: Command Injection
**Vendor**: bastillion-io 
**Software Versions Affected**: Version v4.0.1 and likely all previous versions
**Fixed Version**: None - Vulnerability is currently unpatched as of 2025-12-18

## II. Vulnerability Impact
This vulnerability allows authenticated attackers to:
- Execute arbitrary shell commands on all systems where the malicious key is distributed
- Modify system configurations and files
- Exfiltrate sensitive data from managed systems
- Compromise the integrity of SSH authentication
- Establish persistent access to target hosts

## III. Affected Scope
- **Affected Files**:
  - `src/main/java/io/bastillion/manage/control/AuthKeysKtrl.java` - Public key creation and management
  - `src/main/java/io/bastillion/manage/db/PublicKeyDB.java` - Public key storage and retrieval
  - `src/main/java/io/bastillion/manage/util/SSHUtil.java` - SSH key distribution operations
- **Affected Versions**: All versions allowing public key management functionality

## IV. Exploitation Conditions
1. **Authentication**: Attacker must be an authenticated user with public key upload privileges
2. **Access**: Attacker must be able to access the public key management interface (/admin/savePublicKey)
3. **Trigger**: Malicious commands are executed when the application distributes keys to target systems

## V. Vulnerability Analysis

### 1. Root Cause
The vulnerability exists due to two key flaws:
- **Insufficient Key Validation**: Public key content is only validated for SSH format, not for malicious payloads
- **Unescaped Command Concatenation**: Public key content is inserted into shell commands without escaping single quotes

### 2. Attack Vector
1. Attacker creates a public key with malicious command injection payloads in its content
2. Public key is stored in the database after passing minimal SSH format validation
3. Application distributes the malicious key to target systems
4. Malicious commands are executed during the key distribution process

### 3. Execution Flow
1. **Injection**: Attacker submits a malicious public key containing command injection payloads
2. **Storage**: Public key is stored intact in the `public_keys` database table
3. **Retrieval**: When key distribution occurs, the malicious key is retrieved from the database
4. **Execution**: Malicious commands are executed on target systems via shell commands

### 4. Code Details

#### Step 1: Infection Point - User Input Entry
**File**: `src/main/java/io/bastillion/manage/control/AuthKeysKtrl.java`
**Endpoint**: POST /admin/savePublicKey

```java
@Model(name = "publicKey")
PublicKey publicKey = new PublicKey();

@Kontrol(path = "/admin/savePublicKey", method = MethodType.POST)
public String savePublicKeys() throws ServletException {
    try {
        Long userId = AuthUtil.getUserId(getRequest().getSession());
        String userType = AuthUtil.getUserType(getRequest().getSession());

        publicKey.setUserId(userId);
        if (Auth.MANAGER.equals(userType) || UserProfileDB.checkIsUsersProfile(userId, publicKey.getProfile().getId())) {
            if (publicKey.getId() != null) {
                PublicKeyDB.updatePublicKey(publicKey); // Line: Updates existing public key
            } else {
                PublicKeyDB.insertPublicKey(publicKey); // Line: Inserts new public key
            }
            distributePublicKeys(publicKey); // Line: Initiates key distribution
        }
        // ...
    } catch (SQLException | GeneralSecurityException ex) {
        handleException(ex);
    }
    // Redirection
}

// Validation only checks SSH format, not malicious content
private void validatePublicKey(Long userId) throws ServletException, SQLException, GeneralSecurityException {
    if (StringUtils.isBlank(publicKey.getPublicKey())) {
        addFieldError(PUBLIC_KEY_PUBLIC_KEY, REQUIRED);
    } else if (SSHUtil.getFingerprint(publicKey.getPublicKey()) == null ||
            SSHUtil.getKeyType(publicKey.getPublicKey()) == null) {
        addFieldError(PUBLIC_KEY_PUBLIC_KEY, INVALID);
    }
    // ... other validations ...
}
```

**Analysis**:
- The `publicKey` object is annotated with `@Model`, so its `publicKey` field contains raw user input
- Validation only checks if the content is a valid SSH public key, not if it contains malicious payloads
- No sanitization is performed before storage or use in shell commands

#### Step 2: Storage - Persistent Data Store (Database)
**File**: `src/main/java/io/bastillion/manage/db/PublicKeyDB.java`

```java
public static void insertPublicKey(PublicKey publicKey) throws SQLException, GeneralSecurityException {
    Connection con = DBUtils.getConn();
    PreparedStatement stmt = con.prepareStatement("insert into public_keys(key_nm, type, fingerprint, public_key, profile_id, user_id) values (?,?,?,?,?,?)");
    stmt.setString(1, publicKey.getKeyNm());
    stmt.setString(2, SSHUtil.getKeyType(publicKey.getPublicKey()));
    stmt.setString(3, SSHUtil.getFingerprint(publicKey.getPublicKey()));
    stmt.setString(4, publicKey.getPublicKey().trim()); // Line: Stores raw public key content
    // ... set profile_id and user_id ...
    stmt.execute();
    DBUtils.closeStmt(stmt);
    DBUtils.closeConn(con);
}
```

**Analysis**:
- The raw public key content is stored directly in the `public_keys` table without any sanitization
- Only SSH format validation is performed, not content validation

#### Step 3: Detonation - Execution in Sensitive Context
**File**: `src/main/java/io/bastillion/manage/util/SSHUtil.java`

```java
public static HostSystem addPubKey(HostSystem hostSystem, Session session, String appPublicKey) {
    try {
        // ... read existing keys ...

        String newKeys;
        if (keyManagementEnabled) {
            // Retrieve public keys from database for distribution
            List<String> assigned = PublicKeyDB.getPublicKeysForSystem(hostSystem.getId());
            StringBuilder sb = new StringBuilder();
            for (String k : assigned) {
                sb.append(k.replace("\n", "").trim()).append("\n"); // Append malicious key content
            }
            sb.append(appPubKey);
            newKeys = sb.toString();
        }

        // Command Injection Vulnerability: Line 234
        ChannelExec upd = (ChannelExec) session.openChannel("exec");
        upd.setCommand("echo '" + newKeys + "' > " + authorizedKeys + "; chmod 600 " + authorizedKeys); // Direct concatenation

        // ... execute command ...
    } catch (Exception ex) {
        log.error(ex.toString(), ex);
    }
    return hostSystem;
}
```

**Analysis**:
- Public keys are retrieved from the database and concatenated into a string
- The string is directly inserted into a shell command without escaping single quotes
- Attackers can terminate the quote and inject commands by including `'` characters in the public key content

### 5. Proof of Concept (PoC)

#### Step 1: Generate Malicious Public Key
1. Create a malicious SSH public key:
   ```ssh-rsa
   ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3...'$(id > /tmp/public_key_injection)' user@example.com
   ```

#### Step 2: Upload Malicious Key
1. Log in as a user with public key upload privileges
2. Navigate to the public key management interface
3. Upload the malicious public key

#### Step 3: Trigger Key Distribution
1. Associate the malicious key with a system profile
2. Key distribution will automatically trigger, or can be initiated manually

#### Step 4: Verify Exploitation
- The output of the `id` command will be saved to `/tmp/public_key_injection` on the remote system
- This confirms arbitrary command execution

## VI. Recommendations

1. **Escape User-Controlled Content**:
   - Escape all single quotes and other special shell characters in public key content before using in shell commands
   - Example: `newKeys.replaceAll("'", "'\"'\"'")`

2. **Avoid Shell Command Execution**:
   - Replace shell commands like `echo` and `chmod` with SSH client API calls
   - Use secure file write operations through SSH instead of executing shell commands

3. **Strengthen Key Validation**:
   - Restrict public key comments to safe characters only
   - Validate that key content does not contain shell command characters

4. **Apply Least Privilege**:
   - Restrict public key upload privileges to trusted users only
   - Limit key distribution to authorized systems

## VII. References
- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- OWASP Top 10 2021: A03 - Injection
- CWE-20: Improper Input Validation

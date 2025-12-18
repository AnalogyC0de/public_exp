# Command Injection via Authorized Keys Path

## I. Vulnerability Overview
A command injection vulnerability has been identified in the system management module. Authenticated users with system creation or edit privileges can inject malicious commands by manipulating the `authorized_keys` path parameter, which are then executed on remote systems during SSH key distribution operations.

**Submitter**: Ana10gy
**Project**: Bastillion SSH Key Manager [https://github.com/bastillion-io/Bastillion]
**Type**: Command Injection
**Vendor**: bastillion-io 
**Software Versions Affected**: Version v4.0.1 and likely all previous versions
**Fixed Version**: None - Vulnerability is currently unpatched as of 2025-12-18

## II. Vulnerability Impact
This vulnerability allows authenticated attackers to:
- Execute arbitrary shell commands on all systems managed by the application
- Modify or delete critical system files
- Exfiltrate sensitive data from managed systems
- Escalate privileges on target hosts
- Compromise the integrity of SSH authentication mechanisms

## III. Affected Scope
- **Affected Files**:
  - `src/main/java/io/bastillion/manage/control/SystemKtrl.java` - System creation and editing
  - `src/main/java/io/bastillion/manage/db/SystemDB.java` - System storage and retrieval
  - `src/main/java/io/bastillion/manage/util/SSHUtil.java` - SSH key management operations
- **Affected Versions**: All versions allowing system management functionality

## IV. Exploitation Conditions
1. **Authentication**: Attacker must be an authenticated user with system creation or edit privileges
2. **Access**: Attacker must be able to access the system management interface (/manage/saveSystem)
3. **Trigger**: Malicious commands are executed when the application performs SSH key distribution operations

## V. Vulnerability Analysis

### 1. Root Cause
The vulnerability exists due to two key flaws:
- **Missing Sanitization**: No validation or sanitization is performed on the `authorized_keys` path parameter
- **Command Concatenation**: User-controlled path is concatenated directly into shell commands without proper escaping

### 2. Attack Vector
1. Attacker creates/edits a system with a malicious `authorized_keys` path containing command injection payloads
2. System configuration is stored in the database with no modifications
3. Application performs SSH key distribution to the malicious system
4. Malicious commands are executed on the remote system

### 3. Execution Flow
1. **Injection**: Attacker submits a malicious `authorized_keys` path with command injection payloads
2. **Storage**: System configuration is stored intact in the `system` database table
3. **Retrieval**: When key distribution occurs, system configuration is retrieved from the database
4. **Execution**: Malicious commands are executed on the remote system via shell commands

### 4. Code Details

#### Step 1: Infection Point - User Input Entry
**File**: `src/main/java/io/bastillion/manage/control/SystemKtrl.java`
**Endpoint**: POST /manage/saveSystem

```java
@Model(name = "hostSystem")
HostSystem hostSystem = new HostSystem();

@Kontrol(path = "/manage/saveSystem", method = MethodType.POST)
public String saveSystem() throws ServletException {
    hostSystem = SSHUtil.authAndAddPubKey(hostSystem, passphrase, password);

    try {
        if (hostSystem.getId() != null) {
            SystemDB.updateSystem(hostSystem); // Line: Updates existing system
        } else {
            hostSystem.setId(SystemDB.insertSystem(hostSystem)); // Line: Inserts new system
        }
        // ...
    } catch (SQLException | GeneralSecurityException ex) {
        // Error handling
    }
    // Redirection
}

// Validation only checks for presence, not path safety
public void validateSaveSystem() throws ServletException {
    if (hostSystem == null || hostSystem.getAuthorizedKeys() == null
        || hostSystem.getAuthorizedKeys().trim().equals("") || hostSystem.getAuthorizedKeys().trim().equals("~")) {
        addFieldError("hostSystem.authorizedKeys", "Required");
    }
    // ... other validations ...
}
```

**Analysis**:
- The `hostSystem` object is annotated with `@Model`, so its `authorizedKeys` field contains raw user input
- Validation only checks if the path is present, not if it contains malicious characters
- No sanitization is performed on the path before storage or use in shell commands

#### Step 2: Storage - Persistent Data Store (Database)
**File**: `src/main/java/io/bastillion/manage/db/SystemDB.java`

```java
public static void insertSystem(HostSystem hostSystem) throws SQLException, GeneralSecurityException {
    Connection con = DBUtils.getConn();
    PreparedStatement stmt = con.prepareStatement("insert into system (display_nm, username, host, port, authorized_keys, status_cd) values (?,?,?,?,?,?)");
    stmt.setString(1, hostSystem.getDisplayNm());
    stmt.setString(2, hostSystem.getUser());
    stmt.setString(3, hostSystem.getHost());
    stmt.setInt(4, hostSystem.getPort());
    stmt.setString(5, hostSystem.getAuthorizedKeys()); // Line: Stores raw authorized_keys path
    stmt.setString(6, hostSystem.getStatusCd());
    stmt.execute();
    DBUtils.closeStmt(stmt);
    DBUtils.closeConn(con);
}
```

**Analysis**:
- The raw authorized_keys path is stored directly in the `system` table without any modifications or sanitization

#### Step 3: Detonation - Execution in Sensitive Context
**File**: `src/main/java/io/bastillion/manage/util/SSHUtil.java`

```java
public static HostSystem addPubKey(HostSystem hostSystem, Session session, String appPublicKey) {
    try {
        String authorizedKeys = hostSystem.getAuthorizedKeys().replaceAll("~/|~", "");

        // Command Injection Vulnerability: Line 188
        ChannelExec exec = (ChannelExec) session.openChannel("exec");
        exec.setCommand("cat " + authorizedKeys); // Direct concatenation of user-controlled path

        // ... read existing keys ...

        // Command Injection Vulnerability: Line 234
        ChannelExec upd = (ChannelExec) session.openChannel("exec");
        upd.setCommand("echo '" + newKeys + "' > " + authorizedKeys + "; chmod 600 " + authorizedKeys); // Direct concatenation

        // ... execute commands ...
    } catch (Exception ex) {
        log.error(ex.toString(), ex);
    }
    return hostSystem;
}
```

**Analysis**:
- The authorized_keys path is retrieved from the system object and has only simple tilde replacement
- The path is directly concatenated into shell commands executed on the remote system
- This allows attackers to inject arbitrary commands by including characters like `;`, `&&`, or `|` in the path

### 5. Proof of Concept (PoC)

#### Step 1: Create Malicious System
1. Log in as a user with system management privileges
2. Navigate to the system management interface
3. Create a new system with the following `authorized_keys` path:
   ```
   ~/.ssh/authorized_keys; id > /tmp/command_injection_proof
   ```

#### Step 2: Trigger Key Distribution
1. The application will automatically attempt key distribution to the new system
2. If distribution is not automatic, trigger it manually through the interface

#### Step 3: Verify Exploitation
- The output of the `id` command will be saved to `/tmp/command_injection_proof` on the remote system
- This confirms that arbitrary commands are being executed

## VI. Recommendations

1. **Validate and Sanitize Paths**:
   - Ensure the authorized_keys path only contains valid file path characters
   - Restrict paths to known safe locations (e.g., ~/.ssh/)
   - Example regex for validation: `^~?/[a-zA-Z0-9/_.-]*$`

2. **Avoid Command Concatenation**:
   - Use parameterized commands or secure APIs instead of string concatenation
   - If shell commands are necessary, escape all user-controlled input

3. **Use Safe File Operations**:
   - Avoid using shell commands like `cat` and `echo` to manipulate files
   - Use SSH client APIs directly to manage authorized keys files

4. **Apply Least Privilege**:
   - Restrict system creation and edit privileges to trusted administrators only
   - Audit user permissions regularly

## VII. References
- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- OWASP Top 10 2021: A03 - Injection
- CWE-20: Improper Input Validation

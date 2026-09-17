/**
 * flags.js — Server-side authoritative flag registry.
 *
 * NEVER send this map to any client. Flags are only revealed as the
 * result of successfully performing each exploit.
 *
 * Key:   vulnId (string, unique per OWASP category)
 * Value: { flag, name, description }
 */
export const FLAG_REGISTRY = {
  // A01 — Broken Access Control (BOLA / IDOR)
  IDOR_TICKETS: {
    flag: "IDOR{y0u_acc3ssed_s0me0ne_elses_tick3t}",
    name: "A01 – BOLA: Insecure Direct Object Reference",
    description: "You accessed another user's ticket by guessing its ID.",
  },

  // A01 — Broken Access Control (BFLA / header spoofing)
  BFLA_PROMOTE: {
    flag: "BFLA{x_user_role_h34der_bypasses_admin_check}",
    name: "A01 – BFLA: Broken Function Level Authorization",
    description:
      "You bypassed admin authorization by forging the X-User-Role header.",
  },

  // A02 — Security Misconfiguration
  MISCONFIG_DEBUG: {
    flag: "MISCONFIG{env_vars_exposed_in_production}",
    name: "A02 – Security Misconfiguration: Debug Endpoint Exposed",
    description: "A debug endpoint leaked environment variables including secrets.",
  },

  // A03 — Software Supply Chain
  SUPPLY_CHAIN: {
    flag: "SUPPLYCHAIN{CVE-2019-10744}",
    name: "A03 – Supply Chain: Vulnerable Dependency (lodash)",
    description:
      "The app ships lodash@4.17.4 which has a known prototype-pollution CVE.",
  },

  // A04 — Cryptographic Failures
  CRYPTO_FAIL: {
    flag: "CRYPTOFAIL{w34k_md5_n0_s4lt_ez_crack}",
    name: "A04 – Cryptographic Failures: Broken Hash on Sensitive Data",
    description: "Internal notes were stored with unsalted MD5; reversible offline.",
  },

  // A05 — Injection (NoSQL)
  NOSQL_INJECTION: {
    flag: "INJECT{m0ng0_0p3r4t0r_byp4ss}",
    name: "A05 – Injection: NoSQL Operator Injection",
    description:
      "You injected a MongoDB operator into the search query to bypass filtering.",
  },

  // A06 — Insecure Design
  INSECURE_DESIGN: {
    flag: "INSECUREDESIGN{gu3ss4bl3_r3s3t_t0k3n_4321}",
    name: "A06 – Insecure Design: Predictable Password Reset Token",
    description: "Reset tokens are short sequential integers, trivially brute-forced.",
  },

  // A07 — Authentication Failures
  AUTH_FAIL: {
    flag: "AUTHFAIL{cr3d3nt14l_stuff1ng_w0rked}",
    name: "A07 – Authentication Failures: No Rate Limiting on Login",
    description:
      "The login endpoint has no rate limit; a weak-password account was brute-forced.",
  },

  // A08 — Software/Data Integrity Failures
  INTEGRITY_FAIL: {
    flag: "INTEGRITYFAIL{no_hmac_4ny0ne_c4n_f0rge_imports}",
    name: "A08 – Data Integrity Failures: Unsigned Import Payload Accepted",
    description: "The ticket import endpoint trusts payloads without verifying a signature.",
  },

  // A09 — Security Logging & Alerting Failures
  LOG_FAIL: {
    flag: "LOGFAIL{pr0m0te_r0ute_never_l0gged}",
    name: "A09 – Logging Failures: Privilege Escalation Not Logged",
    description:
      "The /profile/promote route performs privileged actions with zero audit logging.",
  },

  // A10 — Mishandling of Exceptional Conditions
  EXCEPT_FAIL: {
    flag: "EXCEPTFAIL{c4tch_bl0ck_f4ils_0pen}",
    name: "A10 – Exception Handling: Fail-Open Authorization",
    description:
      "A malformed ObjectId causes the auth check to throw; the catch block lets the request through.",
  },
};

// Invert for fast flag-string → vulnId lookups (used by flag submit endpoint)
export const FLAG_LOOKUP = Object.fromEntries(
  Object.entries(FLAG_REGISTRY).map(([vulnId, { flag }]) => [flag, vulnId])
);

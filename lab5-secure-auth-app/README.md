# Lab 5: secure authentication in a Spring Boot web app

This lab is the defensive counterpart to the others. Instead of attacking a system, the team built one: a web application designed from the start around authentication, role-based access control, and session protection. It was done in a university security lab (security of systems, ÉTS, Montréal, winter 2026) using Spring Boot and Spring Security.

Lab done in a team of 4. Write-up and reformulation by Ilyas El Houdaigui. No teammate names or student IDs are included.

French version: [README.fr.md](README.fr.md).

Contents:

1. [Architecture](#architecture)
2. [Access control (RBAC)](#access-control-rbac)
3. [Authentication and password policy](#authentication-and-password-policy)
4. [Session management](#session-management)
5. [Strengths and limitations](#strengths-and-limitations)
6. [Controls mapped to what they defend against](#controls-mapped-to-what-they-defend-against)
7. [Stack](#stack)

---

## Architecture

A client-server MVC application in three layers. The browser talks to the server over HTTPS only, backed by a PKCS#12 keystore. The server is a standalone Spring Boot application that renders HTML server-side with Thymeleaf, and persistence goes through Spring Data JPA and Hibernate onto PostgreSQL.

The three back-end layers:

- Presentation: Spring MVC controllers and Thymeleaf templates.
- Service: transactional services that hold the security logic (password policy, audit, encrypted session attributes, user management).
- Persistence: JPA entities and Spring Data repositories.

Cross-cutting security is centralized in one config package through Spring Security 6.

![Global class diagram of the application](img/class-diagram-global.png)

The stack and why each piece was chosen:

| Choice | Why |
|--------|-----|
| Java 21 + Spring Boot 4 | Mature ecosystem, native BCrypt, CSRF, and session handling. |
| Spring Security 6 | Gives the required primitives (RBAC, session protection, auth filters, BCrypt, CSRF by default) without reinventing critical security code. |
| Thymeleaf (server-side rendering) | No JSON API surface and no auth state in JavaScript, which shrinks the XSS and token-theft surface. |
| PostgreSQL | Transactional relational database with the integrity constraints the model needs (unique usernames, role foreign keys). |
| Spring Data JPA / Hibernate | Removes hand-written SQL from the business layer, which closes off SQL injection by default. |
| HTTPS via PKCS#12 | Encrypts traffic in transit; the keystore is embedded to keep the demo simple. |
| BCrypt (strength 12) | Adaptive hash with a per-user salt built in. |

---

## Access control (RBAC)

The model is three JPA entities: `User`, `Role`, and the `user_roles` join table, in a many-to-many relation. Roles load EAGER so the Spring Security authorities are ready as soon as the user is loaded. Three roles and three users are created at startup by a `DataSeeder`, with passwords hashed by BCrypt (strength 12) before insertion.

| Stored role | Spring Security authority | Function |
|-------------|---------------------------|----------|
| ROLE_ADMIN | ADMIN | Administrator |
| ROLE_RESIDENTIAL | RESIDENTIAL | Residential-client agent |
| ROLE_BUSINESS | BUSINESS | Business-client agent |

All the access rules live in one place, `SecurityConfig.filterChain`:

| URL | Allowed roles |
|-----|---------------|
| /login | public |
| / | any authenticated user |
| /admin/** | ADMIN only |
| /clients/residential | ADMIN + RESIDENTIAL |
| /clients/business | ADMIN + BUSINESS |
| /security/change-password | any authenticated user |
| /logout | authenticated |

The last rule is `anyRequest().authenticated()`, so the app is fail-closed: a new URL is protected until someone explicitly opens it. Thymeleaf hides links a user is not allowed to follow, but the server rule stays the single source of truth, so hiding a link is never the actual control.

![Class diagram for the access-control layer](img/rbac-class-diagram.png)

What works well here: the rules are centralized and declarative, so a change applies everywhere at once; the default is deny; and database constraints (unique `users.username` and `roles.name`, foreign keys on `user_roles`) stop inconsistent data. What I would change: the roles are hardcoded in `SecurityConfig`, so adding one needs a restart. A role hierarchy (`ROLE_ADMIN > ROLE_RESIDENTIAL`) would remove the repeated `hasAnyRole(ADMIN, ...)` and the risk of forgetting the admin in a rule. Loading roles EAGER on every request is fine for a handful of roles but would need a cache at scale.

---

## Authentication and password policy

Passwords are stored with BCrypt at strength 12, which means 2^12 (4096) rounds per hash. BCrypt generates a random per-user salt, so two users with the same password get completely different hashes, which defeats precomputed rainbow tables (CWE-916, CWE-759). The high work factor is what slows down offline cracking.

The policy around login and passwords:

- Brute-force defense: a one-second delay on every failed login, and a permanent lock after five failures that needs an administrator to clear (CWE-307).
- Expiration: passwords must be changed every 90 days.
- Complexity: at least 12 characters with an uppercase letter, a digit, and a special character.
- History: the last five passwords are kept and cannot be reused.

Security events are recorded by a dedicated `SecurityAuditService` and event listeners, which log failed logins, account lockouts, and password changes, each tied to a user, and surface them on the admin dashboard (CWE-778).

Critical operations require a fresh proof of identity. When an administrator resets a client's password, `adminResetPassword` re-checks the administrator's current password before running, which limits damage if a session is left open on an unlocked machine.

![Sequence diagram of the full authentication flow](img/auth-sequence-diagram.png)

---

## Session management

The session cookie (`JSESSIONID`) is protected against fixation, replay, and client-side exposure:

- Session fixation: a new session ID is issued on every login (`sessionFixation().migrateSession()`), so a pre-set ID is useless (CWE-384).
- `HttpOnly`: JavaScript cannot read the cookie, which blunts theft via XSS (CWE-1004).
- `Secure`: the cookie only travels over HTTPS (CWE-614).
- `SameSite=Strict`: the cookie is never sent cross-site, which covers CSRF (CWE-352).
- `tracking-modes=cookie`: the session ID never lands in a URL.
- `invalidSessionUrl`: a request with an unknown session ID is rejected.
- `maximumSessions(1)`: a new login invalidates the previous session.

Sensitive attributes do not sit in the session in clear. They go through a `SecureSessionStore` that encrypts values with AES-GCM (a 12-byte random IV and a 128-bit tag) before they enter the `HttpSession`. The key is derived with SHA-256 from a secret passed in through the `SESSION_SECRET` environment variable, and the only methods exposed are `putConfidential()` and `getConfidential()`. A memory dump of the session shows nothing useful in clear, and AES-GCM also detects any tampering with the stored value.

---

## Strengths and limitations

The design leans on defense in depth: TLS in transit, BCrypt at rest, lockout and delay against brute force, fail-closed authorization, hardened session cookies, and application-level encryption of sensitive session data, all built on Spring Security rather than hand-rolled code.

The honest limitations, most of which the report calls out itself:

- Sessions live in JVM memory, so they are lost on restart and do not scale across instances. Spring Session with Redis would fix this.
- The session encryption secret defaults to a static value that must be replaced in production, ideally from a secret manager such as Vault, and rotating it means restarting and dropping every active session.
- The permanent lock after five failures is heavy. A self-service recovery path (OTP) would lighten the admin load.
- There is no behavioral check (a changed IP or User-Agent would not raise anything), and no way to revoke sessions centrally from an admin view.
- The 30-minute timeout may be too long for sensitive roles.

---

## Controls mapped to what they defend against

| Control in the app | Defends against | Reference |
|--------------------|-----------------|-----------|
| BCrypt strength 12 with per-user salt | Weak or unsalted password storage | CWE-916, CWE-759 |
| Lockout after 5 failures + 1s delay | Brute force | CWE-307 |
| Session ID regenerated on login | Session fixation | CWE-384 |
| HttpOnly cookie | Cookie theft via XSS | CWE-1004 |
| Secure cookie | Cookie sent over cleartext | CWE-614 |
| SameSite=Strict | Cross-site request forgery | CWE-352 |
| Fail-closed RBAC in SecurityConfig | Missing or wrong authorization | CWE-862, CWE-863 |
| Audit of security events | Insufficient logging | CWE-778 |
| JPA / parameterized access | SQL injection | CWE-89 |

## Stack

Java 21, Spring Boot 4, Spring Security 6, Thymeleaf, PostgreSQL, Spring Data JPA / Hibernate, BCrypt, AES-GCM, and a PKCS#12 keystore for TLS.

## Note on scope

This lab was a defensive build on lab machines set up for the exercise. No attack was run against anyone. The write-up documents the security design so the choices can be judged and reused.

# MARKET_CONTEXT.md

## Document purpose

This file gives Codex the career, market, portfolio, and evidence context for improving this repository.

It is **not** a replacement for the phase plan, technical design, acceptance criteria, or `AGENTS.md`. Codex must use this file to understand **why** the work matters, which capabilities the final project must prove, and which forms of evidence have hiring value.

When this file conflicts with an approved phase instruction, the approved phase instruction controls the current implementation scope. Market context must guide decisions without causing uncontrolled scope expansion.

---

## 1. Repository identity

### Current repository

`public-key-authentication-system`

### Portfolio-facing project title

**Passwordless Identity Security and Detection Lab**

The GitHub repository name may remain unchanged. The portfolio-facing title should be introduced only when the implementation and documentation genuinely support it.

### Portfolio role

This repository is the user's strongest compact supporting cybersecurity artifact.

It is intended to become a focused, reproducible identity-security project demonstrating secure authentication, device lifecycle controls, security telemetry, detection logic, incident investigation, containment, validation, testing, and technical communication.

It is **not** the user's main flagship project.

The separate approved flagship is:

**Azure Privileged Access Abuse Detection & Recovery Lab**

That project owns the primary Azure, KQL, Microsoft Sentinel, cloud-control-plane, and privileged-access scenario.

This repository should complement the flagship by proving application-level identity-security and detection skills. It must not duplicate the flagship or falsely present itself as enterprise IAM infrastructure.

---

## 2. Candidate and career context

### Target market

Qatar.

### Candidate profile

- B.Sc. Data and Cyber Security.
- Expected graduation: Spring 2027.
- No completed professional cybersecurity employment yet.
- Current experience is mainly academic, laboratory, personal-project, and authorized assessment work.
- Existing exposure includes Splunk, Microsoft Sentinel, Microsoft Defender XDR, Active Directory, Microsoft Entra ID, Microsoft Azure, Burp Suite, Wireshark, Linux, Python, and networking fundamentals.
- The project must help reduce employer concern about limited organizational experience by providing reproducible technical evidence.
- Work should remain free-first. Paid services require a clear and documented hiring benefit.

### Target job families

The final project should support applications for:

- SOC Analyst;
- Security Operations Analyst;
- Cybersecurity Analyst;
- Identity Security Analyst;
- Junior Detection Engineer;
- Incident Response Analyst;
- Security Engineer;
- Application Security or secure-development roles.

The project should not be optimized for only one job title. It should demonstrate a coherent group of transferable security capabilities.

---

## 3. Market findings that guide this project

Qatar-market research found repeated demand for combinations of:

1. SIEM and security monitoring;
2. incident investigation and response;
3. identity and access management;
4. cloud or Azure security;
5. technical reporting, security controls, remediation, and validation.

The evidence supports these capabilities at the **capability level**. It does not prove that every Qatar employer requires the same product, query language, architecture, or attack scenario.

Therefore:

- implement technology because it proves a market-relevant capability;
- do not add a tool only because its name appears in a job description;
- do not claim enterprise or production experience from a local lab;
- do not claim that a KQL or SPL query was deployed or platform-validated unless real evidence exists;
- prefer a complete, defensible security workflow over a large collection of disconnected features.

---

## 4. Project mission

Upgrade the current academic passwordless-authentication demonstration into a reproducible identity-security lab that proves the following professional workflow:

> identity action → security-relevant telemetry → suspicious behavior → detection → investigation → containment → recovery validation → documented evidence

The final project should demonstrate that the user can:

- understand and explain a public-key challenge-response authentication flow;
- identify insecure enrollment, challenge, verification, storage, and revocation behavior;
- design and validate safer controls;
- generate structured, privacy-conscious identity events;
- reproduce normal and abusive behavior safely;
- create and test detection logic;
- investigate an event sequence using evidence;
- apply containment and verify that it worked;
- explain false positives, limitations, and production differences;
- maintain automated tests and CI;
- communicate the work to both technical reviewers and recruiters.

---

## 5. Market capability to repository evidence mapping

| Market capability | What this repository should prove | Minimum credible evidence |
|---|---|---|
| Identity and access management | Device enrollment, authentication, revocation, actor authorization, lifecycle state, least privilege | Implemented controls, automated security tests, diagrams, decision records |
| Security monitoring | Important authentication and administrative decisions produce structured events | Stable event schema, sanitized event samples, schema tests |
| Detection engineering | Suspicious identity behavior is converted into explicit, testable detection logic | Detection hypothesis, thresholds, positive tests, negative tests, false-positive notes |
| Incident investigation | An analyst can reconstruct who did what, when, to which user/device/challenge, and with what outcome | Evidence-linked timeline, triage checklist, investigation report |
| Response and remediation | A compromised or abusive device can be contained and secure state restored | Revocation, challenge invalidation, rate-limit or access-control evidence, recovery tests |
| Secure development | Security behavior remains correct across changes | Unit, integration, security, and regression tests; CI; reviewed dependencies |
| Technical reporting | A reviewer can understand the risk, design, evidence, limits, and result | README, threat model, incident report, executive summary, limitations |
| Professional judgment | Claims, severity, and design decisions are proportional to evidence | Decision log, non-claims, severity rationale, clearly marked assumptions |

A feature has weak portfolio value when it cannot be connected to a market capability and demonstrated with evidence.

---

## 6. Final security story

A registered user authenticates using a public-key challenge-response flow.

The lab safely reproduces identity-security events such as:

- repeated invalid-signature attempts;
- replaying an already consumed challenge;
- attempting to use an expired challenge;
- requesting excessive challenges;
- requesting or attempting authentication from a revoked device;
- unauthorized device enrollment;
- unauthorized device revocation;
- continued authentication attempts after containment.

The system generates structured audit events for these actions.

Detection rules identify suspicious behavior. An analyst reconstructs the timeline, determines scope and confidence, contains the affected device or administrative access, and validates that the prohibited action can no longer succeed.

The project must show the entire evidence chain. It must not stop at "login succeeded," "attack failed," or "an alert was generated."

---

## 7. Highest-value skills to emphasize

Codex should prioritize work that lets the user truthfully explain:

### Identity security

- how challenge-response authentication works;
- why enrollment and revocation are privileged operations;
- how replay is prevented;
- why challenges expire and are single-use;
- how revoked devices are blocked;
- why local encrypted key files are not equivalent to hardware-backed protection;
- how authorization differs from authentication.

### Detection and monitoring

- which event fields are needed to reconstruct an authentication timeline;
- how to distinguish one failure from a suspicious burst;
- how thresholds and time windows affect a detection;
- how positive and negative tests validate a rule;
- how false positives are considered;
- why sensitive values must not be logged.

### Investigation and response

- how to identify the actor, user, device, challenge, request, source, outcome, and reason;
- how to separate confirmed facts from assumptions;
- how containment affects outstanding challenges and future authentication;
- how recovery is independently validated;
- how residual risk is documented.

### Secure engineering

- how tests preserve behavior before refactoring;
- how transactional persistence prevents inconsistent state;
- how malformed input is handled without exposing internals;
- how secrets and generated keys are kept out of Git;
- how CI supports reliability without being described as proof of security.

---

## 8. Evidence-first design rules

Every major capability must produce reviewable evidence.

Preferred evidence, from strongest to weakest:

1. repeatable automated test;
2. deterministic simulation with expected exit status;
3. sanitized raw event or system-state output;
4. detection result tied to known test input;
5. evidence-linked investigation timeline;
6. configuration or code with an explained design decision;
7. screenshot used only as supporting illustration;
8. unsupported narrative claim — unacceptable.

Requirements:

- screenshots must not be the primary proof;
- generated evidence must be reproducible;
- positive tests must trigger the expected behavior;
- negative tests must demonstrate meaningful non-triggering behavior;
- every incident conclusion must reference an event, test result, or verified system state;
- unexpected failures must be documented, not hidden;
- generated private keys, real tokens, local databases, secret values, and personal data must never be committed;
- evidence must be sanitized without becoming fabricated.

---

## 9. Recruiter and interview test

A change has strong market value when it helps the user answer at least one of these questions with actual evidence:

- What security problem did you solve?
- What insecure behavior existed before your changes?
- How did you prove the original behavior?
- Which identity controls did you implement and why?
- What telemetry did the system produce?
- How did your detection work?
- What positive and negative tests did you run?
- How did you investigate the incident?
- What did you do to contain it?
- How did you prove recovery?
- What failed during development, and how did you diagnose it?
- What would need to change before production use?
- Which claims are supported, and which are intentionally not made?

A feature that is difficult to explain, test, reproduce, or connect to a security outcome should be reconsidered.

---

## 10. Implementation priorities

When choosing between possible changes, use this order:

1. preserve and characterize current behavior;
2. fix security-critical identity lifecycle weaknesses;
3. produce trustworthy structured telemetry;
4. create deterministic attack and normal-flow simulations;
5. build tested detections;
6. support evidence-based investigation and response;
7. strengthen automated testing and CI;
8. package the work for technical review and interviews;
9. add optional polish only after the security workflow is complete.

Prefer depth over breadth.

One complete and defensible security workflow is more valuable than many shallow features.

---

## 11. Scope boundaries

### Included in the long-term repository direction

- local Flask API;
- public-key challenge-response authentication;
- protected device enrollment and revocation;
- challenge expiration and single-use consumption;
- controlled persistence;
- structured JSON identity telemetry;
- safe attack simulation;
- local deterministic detection testing;
- example Microsoft Sentinel KQL;
- example Splunk SPL;
- investigation and response documentation;
- automated tests;
- CI security checks;
- Docker-based local reproducibility where useful;
- public-safe documentation and evidence.

### Excluded unless separately approved

- production deployment;
- real customer or employee identities;
- biometric authentication;
- hardware attestation claims;
- full WebAuthn implementation;
- enterprise certificate infrastructure;
- malware;
- phishing;
- Kubernetes;
- paid cloud services;
- multiple authentication protocols;
- unrelated frontend redesign;
- large dashboards;
- multi-cloud scope;
- replacing the separate Azure/Sentinel flagship;
- claims of enterprise scale or professional employment experience.

---

## 12. Phase-control rule

Market context defines the final direction. It does **not** authorize Codex to implement later work early.

Codex must:

- work on one approved phase at a time;
- obey the current phase's explicit file and behavior boundaries;
- avoid adding later-phase tools or architecture because they appear valuable in this document;
- finish and verify the current acceptance criteria before proposing the next phase;
- record major design changes in the decision log;
- stop and report conflicts rather than silently expanding scope.

### Current Phase 0 interpretation

Phase 0 is for current-state preservation only:

- install existing dependencies in an ignored local environment;
- run and record the existing tests;
- add characterization tests for registration, challenge issuance, valid authentication, invalid signatures, replay, and revocation;
- isolate generated database and key artifacts;
- create `AGENTS.md`;
- create the current-state assessment;
- create the decision log;
- make only necessary ignore or CI changes;
- do not harden runtime behavior yet;
- do not begin restructuring, telemetry, detection engineering, persistence migration, or production tooling.

Insecure behavior discovered in Phase 0 should be captured and documented as technical debt. It should not be silently corrected merely to make a characterization test pass.

---

## 13. Design and claim guardrails

Codex must not:

- invent market requirements;
- describe a local lab as enterprise IAM;
- describe example KQL or SPL as deployed without validation evidence;
- equate test coverage with security;
- add tools that do not strengthen the main evidence chain;
- hide known limitations;
- weaken tests to make CI pass;
- replace working code with an unrelated generated project;
- store server-side private keys;
- commit secrets, tokens, keys, databases, raw sensitive logs, or personal identifiers;
- turn the repository into a full WebAuthn project without a separate approved decision;
- duplicate the cloud flagship's main scenario.

Codex should challenge proposed changes that increase complexity without proportional market, security, evidence, or interview value.

---

## 14. Completion standard

The long-term upgrade is complete only when:

- a clean clone can run the documented environment;
- normal public-key authentication works;
- replay, expiration, revocation, malformed input, and authorization behavior are tested;
- enrollment and revocation are protected;
- persistence and challenge consumption preserve integrity;
- important decisions produce structured events;
- attack simulations are repeatable;
- detections pass positive and negative validation;
- an incident can be reconstructed from evidence;
- containment and recovery are verified;
- CI passes;
- public evidence is sanitized;
- documentation matches the implemented behavior;
- limitations and non-claims are explicit;
- the user can independently explain and demonstrate the core workflow.

The project is not complete merely because the code runs.

---

## 15. Human ownership requirement

Generated implementation may accelerate the work, but the user must remain able to:

- explain the architecture and authentication flow;
- run the key commands;
- identify important event fields;
- modify one parameter safely;
- diagnose at least one controlled failure;
- explain security trade-offs;
- justify detection logic and severity;
- distinguish laboratory evidence from professional employment experience.

Codex should leave clear, learnable code and documentation rather than producing unnecessary abstraction that the user cannot defend.

---

## 16. Source documents behind this context

This file was derived from:

- `VERIFIED_PROFILE(1).md`
- `MARKET_GATE_DECISION.md`
- `FLAGSHIP_PROJECT_BLUEPRINT.md`
- the approved market-aligned upgrade direction for `public-key-authentication-system`

These source documents remain the authority for the candidate profile, market conclusions, flagship-project boundary, evidence standards, and career rationale.

This file is the repository-specific translation of that context.

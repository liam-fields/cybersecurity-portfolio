# ISO/IEC 27001 Risk Assessment & Mitigation

**Organization:** FinSecure Corp. (Regional Financial Services)  
**Author:** Liam-Bennet Fields  
**Framework Baseline:** ISO/IEC 27001:2022 & NIST CSF 2.0  
**Artifacts Reviewed:** *Incident and Network Security Artifacts.docx*, *Security Operations Artifact.docx*, *Data Security and Systems Defense Artifacts.docx*

---

## 📋 Document Control & Version History
| Version | Date | Author | Description | Reviewer / Approver |
| :--- | :--- | :--- | :--- | :--- |
| 1.0 | June 28, 2026 | Liam-Bennet Fields | Initial ISO/IEC 27001:2022 Risk Assessment & Gap Analysis | Security Department / CIO |

---

## 🏛️ Executive Summary
FinSecure Corp. is a regional financial services provider executing a planned strategic market expansion. This growth initiative necessitates transitioning legacy workflows into compliance with international governance frameworks, specifically **ISO/IEC 27001:2022** and **NIST CSF 2.0**. 

A recent critical security incident—where an HR employee opened a malicious email attachment that silently installed a GhostX Remote Access Trojan (RAT)—exposed severe, systemic architectural gaps. The baseline assessment revealed vulnerabilities across identity lifecycle management (unterminated accounts retaining active status), weak boundary defense (overly permissive outbound firewall rules), and critical cryptographic flaws (unencrypted data storage and plaintext transit protocols). 

By implementing an automated, framework-driven security posture, FinSecure will dramatically lower its risk profile from "Critical Exposure" to an acceptable "Low-to-Medium" operating baseline, ensuring the security of cross-border client financial assets and regulatory alignment.

---

## 🎯 Scope & Introduction
This risk assessment targets all core infrastructure segments, data repositories, and operational practices defined within FinSecure's distributed corporate environment:
*   **Corporate Network Infrastructure:** The Human Resources Subnet (`10.1.1.x`) and the Finance Subnet (`10.1.2.x`).
*   **Central Data Center:** Public-facing web interfaces, multi-departmental file servers, internal application servers, and core relational databases.
*   **Data Protection Pipelines:** Protocols governing sensitive data-at-rest repositories and data-in-transit pathways.

---

## 🧮 1. Risk Assessment Methodology
This project simulates an external GRC audit and risk assessment. Risks are evaluated using a standard $3 \times 3$ Risk Matrix measuring **Likelihood** (probability of exploitation) and **Impact** (severity of damage to Confidentiality, Integrity, and Availability).

### Scoring Criteria
*   **Value 1 (Low):** Unlikely to occur; minimal operational, financial, or reputational impact.
*   **Value 2 (Medium):** Possible to occur; moderate operational disruption or compliance exposure.
*   **Value 3 (High):** Highly likely to occur; severe financial loss, regulatory penalties, or critical service outage.

**Risk Score Equation:** 
$$\text{Risk Score} = \text{Likelihood} \times \text{Impact}$$

### Risk Thresholds
*   **Score 1–2 (Low Risk):** Acceptable baseline; managed via periodic tracking and routine monitoring.
*   **Score 3–4 (Medium Risk):** Structural gap; must be scheduled for programmatic mitigation and treatment.
*   **Score 6–9 (High Risk):** Critical exposure; requires immediate containment, policy correction, and capital deployment.

---

## 📊 2. Statement of Applicability & Risk Register
*The full quantitative data engine, change logs, and risk calculations are maintained in the corporate workbook:* [ISO 27001 Risk Assessment](FinSecure_ISO27001_Risk_Assessment.xlsx)

### RSK-01: Stale & Unterminated Identity Accounts
*   **Vulnerability/Gap:** Access policy permits a standard 7-day deactivation window. Audit logs confirm terminated employee P. Ellis successfully authenticated (`user=p.ellis src_ip=198.51.100.42`) more than a month post-termination.
*   **Asset / Threat Scenario:** HR Portal & Payroll System. Exploitation of orphaned accounts by insider threats or external actors to compromise employee data privacy.
*   **Pre-Mitigation Score:** Likelihood: 3 | Impact: 2 | **Total: 6 (High)**
*   **ISO 27001:2022 Control:** **A.5.18** (Access Rights)
*   **Treatment Plan:** Automate account de-provisioning interfaces to disable access immediately upon HR separation notification. 
*   **Post-Mitigation Score:** Likelihood: 1 | Impact: 2 | **Total: 2 (Low)**
*   **Framework Alignment:** NIST SP 800-53 PS-4 (Personnel Termination)

### RSK-02: Cryptographic Deficiencies & Plaintext Data Transit
*   **Vulnerability/Gap:** HR and Finance exchange payroll exports using an internal plaintext FTP server. External client interfaces permit deprecated, vulnerable TLS 1.0 connections.
*   **Asset / Threat Scenario:** Payroll Data Exports & Customer PII. Threat actors intercepting unencrypted data-in-transit via packet sniffing or protocol downgrade attacks.
*   **Pre-Mitigation Score:** Likelihood: 2 | Impact: 3 | **Total: 6 (High)**
*   **ISO 27001:2022 Control:** **A.8.24** (Use of Cryptography) & **A.8.20** (Network Security)
*   **Treatment Plan:** Fully deprecate legacy FTP workflows and replace with Secure File Transfer Protocol (SFTP) over SSH. Enforce TLS 1.3 natively on all external web endpoints.
*   **Post-Mitigation Score:** Likelihood: 1 | Impact: 3 | **Total: 3 (Medium)**
*   **Framework Alignment:** NIST SP 800-52 Rev. 2 (Guidelines for the Selection, Configuration, and Use of TLS Implementations)

### RSK-03: Excessive Privileged Administrative Access Matrix
*   **Vulnerability/Gap:** IT user workstations possess permanent, unmonitored Domain Admin rights. Junior admins are granted full domain authority manually without documented business tickets.
*   **Asset / Threat Scenario:** Active Directory Domain Controllers. A standard phishing or malware compromise on a local endpoint expands its blast radius network-wide.
*   **Pre-Mitigation Score:** Likelihood: 2 | Impact: 3 | **Total: 6 (High)**
*   **ISO 27001:2022 Control:** **A.8.2** (Privileged Access Rights) & **A.5.15** (Access Control)
*   **Treatment Plan:** Strip local Domain Admin rights from standard workstations. Enforce a Role-Based Access Control (RBAC) model and implement a Privileged Access Management (PAM) solution for just-in-time elevation.
*   **Post-Mitigation Score:** Likelihood: 1 | Impact: 2 | **Total: 2 (Low)**
*   **Framework Alignment:** NIST SP 800-53 AC-6 (Least Privilege)

### RSK-04: Permissive Outbound Boundaries & Management Ports
*   **Vulnerability/Gap:** Firewall Rule 103 allows all internal systems unrestricted outbound traffic to any destination. Rule 104 leaves the management console exposed to the public internet on port 8080.
*   **Asset / Threat Scenario:** Perimeter Firewall Router. Compromised internal nodes can establish persistent Command and Control (C2) beacons or exfiltrate databases.
*   **Pre-Mitigation Score:** Likelihood: 3 | Impact: 2 | **Total: 6 (High)**
*   **ISO 27001:2022 Control:** **A.8.20** (Network Security)
*   **Treatment Plan:** Revoke Rule 103; enforce strict egress filtering restricted to approved ports (e.g., 443, 53). Restrict access to Rule 104 exclusively to dedicated, internal management subnets.
*   **Post-Mitigation Score:** Likelihood: 1 | Impact: 2 | **Total: 2 (Low)**
*   **Framework Alignment:** NIST CSF 2.0 PR.IR (Information Protection)

### RSK-05: Decentralized & Non-Aggregated Event Auditing
*   **Vulnerability/Gap:** System and network logs remain isolated locally on individual machines and are permanently dropped after 30 days. Endpoint antivirus tools generate alerts locally without a central management console.
*   **Asset / Threat Scenario:** Distributed Enterprise Infrastructure Logs. Extreme visibility blind spots that delay detection and impede forensic incident response.
*   **Pre-Mitigation Score:** Likelihood: 3 | Impact: 2 | **Total: 6 (High)**
*   **ISO 27001:2022 Control:** **A.8.16** (Monitoring Activities)
*   **Treatment Plan:** Procure and deploy a centralized SIEM platform to ingest, parse, and correlate endpoints, Active Directory, and firewall logs with a 90-day minimum retention window.
*   **Post-Mitigation Score:** Likelihood: 1 | Impact: 2 | **Total: 2 (Low)**
*   **Framework Alignment:** NIST SP 800-37 (Risk Management Framework)

### RSK-06: Inadequate Security Awareness Culture
*   **Vulnerability/Gap:** Workforce awareness efforts are limited to a brief onboarding chat and an annual mass email. No practical phishing simulations or training metrics exist.
*   **Asset / Threat Scenario:** Human Capital Layer. End-users execute malicious email attachments natively, providing attackers initial access to internal subnets.
*   **Pre-Mitigation Score:** Likelihood: 3 | Impact: 2 | **Total: 6 (High)**
*   **ISO 27001:2022 Control:** **A.6.3** (Information Security Awareness, Education, and Training)
*   **Treatment Plan:** Implement continuous, mandatory security awareness modules combined with automated quarterly phishing simulations to establish a baseline behavioral metric.
*   **Post-Mitigation Score:** Likelihood: 1 | Impact: 2 | **Total: 2 (Low)**
*   **Framework Alignment:** Center for Internet Security (CIS) Control 14

---

## 🚀 3. Executive Mitigation Roadmap

To systematically execute these remediations and safely support the business expansion, FinSecure Corp. will structure capital and engineering efforts across three distinct operational phases:

### Phase 1: High-Exposure Perimeter & Identity Hardening (Immediate | 1–30 Days)
1. **Firewall Boundary Remediation:** Revoke firewall Rule 103, replacing it with strict egress filtering. Pull the management console (Rule 104) behind the internal network.
2. **Identity Lockdowns:** Programmatically disable all accounts tied to terminated staff and contractors. Revoke permanent Domain Admin privileges from standard workstations, enforcing explicit separation of duties.

### Phase 2: Secure Transport & Centralized Visibility (Short-Term | 31–60 Days)
1. **Cryptographic Upgrades:** Enforce TLS 1.3 across external financial web interfaces and officially migrate all internal payroll file handoffs from cleartext FTP to SFTP.
2. **SIEM Log Consolidation:** Launch a centralized SIEM instance to collect real-time data from firewall routing paths, active directories, and local antivirus events.

### Phase 3: Governance Maturity & Operational Validation (Strategic | 61–90+ Days)
1. **Change Control Formalization:** Implement an ITIL-aligned change management standard requiring all critical network modifications to be pre-authorized and documented via an authenticated ticketing platform.
2. **Human Layer Hardening:** Launch the continuous security awareness platform and baseline user vulnerability through simulated email phishing exercises.

---

### 📥 Project Artifacts
*   **`README.md`** - Executive assessment summary, framework scope, and strategic roadmap.
*   **`FinSecure_ISO27001_Risk_Assessment.xlsx`** - Quantitative risk engine containing the full Risk Register, $3\times3$ conditional scoring models, and the corporate Statement of Applicability (SoA).

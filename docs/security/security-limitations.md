# Security Limitations & Academic Scope

## Project
**AI-Based Cybersecurity Threat Detection and Response System**

---

## 1. Document Purpose
This document transparently outlines the known security limitations, trade-offs, and scope boundaries of the academic prototype.

---

## 2. Identified Limitations & Future Enhancements

### 2.1 Token Revocation & Refresh Tokens
- **Current State**: Stateless JWT access tokens are used with an 8-hour default expiration window. Client logout clears stored tokens from local/session storage.
- **Limitation**: Stateless access tokens cannot be instantly revoked server-side prior to expiration without maintaining a distributed token blacklist (e.g. Redis).
- **Future Enhancement**: Implement a server-side Redis token revocation list or secure HTTP-only refresh token rotation.

### 2.2 Response Engine Simulation Scope
- **Current State**: Automated mitigation actions (e.g. `SIMULATED_ISOLATION`, `SIMULATED_BLOCK`) record administrative flags and status changes in MySQL.
- **Limitation**: Actions do not manipulate host operating system firewalls (iptables/Windows Firewall) or terminate physical processes.
- **Safety Guarantee**: Real host systems are protected from accidental lockouts during lab testing and demonstration.

### 2.3 Distributed Rate Limiting
- **Current State**: Atomic fixed-window counters are stored in the configured SQL database and shared by instances using that database and the same `SECRET_KEY`. Authentication and event ingestion limits fail closed if the rate-limit store is unavailable.
- **Operational Caveat**: IP-based authentication and ingestion limits use the ASGI client address. Deployments behind a reverse proxy must configure trusted proxy handling at the server/load-balancer boundary; the application does not trust arbitrary forwarded-IP headers.
- **Future Enhancement**: Consider Redis if database-backed counters become a throughput bottleneck.

### 2.4 Ingestion Request Bounds
- Both event-ingestion endpoints require an active user's Bearer token. Requests are limited to 65,536 body bytes; individual event fields also have validation limits.
- Viewer accounts can ingest and read their own events; analyst/admin-only mutations remain role protected.

### 2.5 Security Certification Disclaimer
- This project implements defense-in-depth security best practices inspired by OWASP Top 10 guidelines.
- It does not constitute a certified enterprise security product, nor has it undergone third-party penetration testing.

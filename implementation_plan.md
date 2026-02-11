# PhishGuard - Implementation Plan

## Project Overview
A Python-based Phishing Detection Tool capable of analyzing URLs and email files (.eml). It features rule-based detection, VirusTotal integration, and a modern Flask-based SOC dashboard.

## Technical Stack
- **Backend:** Python, Flask
- **Data Parsing:** `email` library (Extracting headers/body), `validators`, `tldextract`
- **Security Logic:** Custom heuristic rules, Typosquatting detection, Spoofed header analysis
- **Threat Intelligence:** VirusTotal API
- **Frontend:** HTML5, Modern CSS (Glassmorphism, Dark Mode), Vanilla JavaScript

## Phase 1: Core Detection Engines
- [ ] **URL Analyzer:** Implement checks for length, special characters, TLD analysis, and Levenshtein distance for typosquatting.
- [ ] **Email Analyzer:** Parse `.eml` files, extract links/attachments, and check for spoofing signatures.
- [ ] **VirusTotal Integration:** API client to fetch reputation data.
- [ ] **Risk Scorer:** Weighted algorithm to classify threats (Low, Medium, High).

## Phase 2: Backend Development (Flask)
- [ ] Setup Flask application structure.
- [ ] File upload handling for `.eml` files.
- [ ] API endpoints for URL and Email scanning.
- [ ] In-memory/SQLite storage for recent alerts.

## Phase 3: Frontend Development (SOC Dashboard)
- [ ] Design a premium dashboard with a dark theme.
- [ ] Implementation of the "Alert monitoring" workflow.
- [ ] Result visualization (Gauges, Charts for risk levels).

## Phase 4: Integration & Testing
- [ ] Connect backend logic with the dashboard.
- [ ] Test with sample phishing URLs and email files.
- [ ] Final UI/UX polish.

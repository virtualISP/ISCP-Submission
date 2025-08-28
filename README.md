# ISCP-Submission

## PII Detector & Redactor

A lightweight **PII (Personally Identifiable Information) detection and redaction solution** that automatically scans datasets, identifies sensitive fields (like phone numbers, Aadhaar, PAN, emails, credit cards, etc.), and produces **redacted outputs** for safer handling and sharing.

---

## Features

* **Regex-based PII Detection** – Uses flexible regex patterns to catch phone numbers, Aadhaar, PAN, emails, credit cards, and more.
* **Smart Redaction** – Automatically masks sensitive fields (`98XXXXXX10`, `JXXX SXXXX`, etc.).
* **CSV Output** – Produces clean CSV reports in the format:

  ```
  record_id, redacted_data_json, is_pii
  1,"{""phone"": ""98XXXXXX10"", ""order_value"": 1299}",True
  2,"{""name"": ""JXXX SXXXX"", ""email"": ""joXXX@gmail.com""}",True
  ```
* **Configurable** – Extend regex rules easily for new PII formats.
* **Scalable Architecture** – Designed to integrate into enterprise pipelines.
* **Privacy by Design** – Never stores or logs raw PII beyond processing.

---

## Deployment Strategy

Proposed deploying this PII solution as a **Sidecar container** in your application architecture.

### Why Sidecar?

* **Scalability** – Each microservice can offload PII detection to the sidecar without rewriting code.
* **Low Latency** – Runs close to the app, avoids network round trips.
* **Cost-Effective** – No need for a central expensive gateway; deploy where needed.
* **Ease of Integration** – Works seamlessly with REST APIs, file uploads, or logs.

### Alternative Options:

* **DaemonSet** – For cluster-wide log monitoring (Kubernetes).
* **API Gateway Plugin** – For traffic inspection at the edge.
* **Browser Extension** – For client-side PII masking before data leaves the browser.

---

## Installation

```bash
git clone https://github.com/virtualISP/ISCP-Submission.git
cd ISCP-Submission
```

---

## Usage

Process a CSV file:

```bash
python3 detector_virtualISP.py iscp_pii_dataset.csv
```

Expected output:

```
record_id,redacted_data_json,is_pii
1,"{""phone"": ""98XXXXXX10"", ""order_value"": 1299}",True
2,"{""name"": ""JXXX SXXXX"", ""email"": ""joXXX@gmail.com""}",True
```

---

## Supported PII Types

* Phone Numbers
* Emails
* Aadhaar (12-digit)
* PAN (AAAAA9999A)
* Credit/Debit Card Numbers
* Addresses (basic regex + keywords)
* Bank Account Numbers
* Full Names (heuristic masking)

---

## Contributing

* Adding new PII regex rules
* Improving performance
* Building plugins for deployment (Gateway, Sidecar, DaemonSet, etc.)

Fork the repo, create a branch, and submit a PR!


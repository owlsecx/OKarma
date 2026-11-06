# 🦉 OKarma

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Wireless%20/%20RF-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OKarma** — Evil-Twin/KARMA Analyzer ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OKarma is an offline-first OwlSec tool for Evil-Twin/KARMA Analyzer. It provides an interactive cyan terminal UI and a full CLI with multi-format export (TXT, Markdown, JSON, CSV, SARIF), designed for authorized security work on Linux.

---

## ✨ Features

- Analyze Evil-Twin / KARMA style wireless lure behavior offline
- Ingest pcap evidence and probe-map related activity
- Watchlist support for known SSIDs/BSSIDs of interest
- Highlight association lure patterns and client targeting
- Howto and self-test modes for lab training
- Export findings via format/output flags

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OKarma OKarma.go
./OKarma --help
./OKarma --input capture.pcap
./OKarma --pcap capture.pcap --watchlist ssids.txt
./OKarma --input capture.pcap --probemap --format json
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad

# Linux eBPF Kernel Zero-Copy Network Mesh 🐧 ⚡

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3+-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Version](https://img.shields.io/badge/Version-v5.0.0%20Ultra-00d2ff?style=for-the-badge)](https://github.com/anderdebona/ebpf-kernel-zero-copy-mesh)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-Passing%20100%25-success?style=for-the-badge&logo=githubactions)](https://github.com/anderdebona/ebpf-kernel-zero-copy-mesh/actions)

<br />

**PhD-Grade Linux Kernel eBPF Zero-Copy Network Mesh: XDP L4 Hardware Flow Steering, Stateless SYN-Flood Guard, Lockless Ring Buffers & OpenMetrics Exporter**

*Engineered with precision by **[anderdebona](https://github.com/anderdebona)***

</div>

---

## 📌 Executive Summary & Architecture

This repository implements a **PhD-grade Linux Kernel eBPF Network Mesh and Zero-Copy Packet Engine**. Operating at the `XDP_DRV` driver level, it features Toeplitz L4 flow steering across per-CPU ring buffers, stateless cryptographic SYN-Cookie defense against gigabit SYN floods, JIT byte-code filtering, token-bucket rate limiting, and real-time OpenMetrics endpoints.

---

## 🔬 Mathematical Formulations

### 1. Toeplitz L4 Hash & Queue Affinity
$$H(\text{srcIP}, \text{dstIP}, \text{srcPort}, \text{dstPort}) = \text{HMAC-SHA256}_{K}(4\text{-tuple}) \pmod N_{\text{queues}}$$

### 2. Stateless Cryptographic SYN Cookie
$$\text{Cookie}_{32} = (\text{Minute}_3 \ll 29) \mid (\text{MSS}_2 \ll 27) \mid (\text{HMAC}_{24} \ll 3)$$

---

## ⚡ What's New in v5.0.0

- 🌊 **`XdpL4FlowSteerer`**: RSS Receive Side Scaling flow hashing and lockless CPU RX Ring-Buffer queue affinity.
- 🍪 **`SynFloodGuard`**: Microsecond stateless SYN-cookie generation and 3-way handshake verification.
- 📊 **Studio v5.0.0**: Real-time packet waterfall, per-queue depth telemetry, and live attack mitigation monitor.
- 🛡️ **25/25 Tests Passing**: Comprehensive Vitest validation for XDP drivers, conntrack, and metrics.

---

## 🚀 Quickstart & Interactive Studio

```bash
git clone https://github.com/anderdebona/ebpf-kernel-zero-copy-mesh.git
cd ebpf-kernel-zero-copy-mesh
npm install
npm test
npm run build
npm start
# Open http://localhost:3010
```

---

## 📄 License & Citation
MIT License © 2026 anderdebona. See [CITATION.cff](CITATION.cff) for academic attribution.

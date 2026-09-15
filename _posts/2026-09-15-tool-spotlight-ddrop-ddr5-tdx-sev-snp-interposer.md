---
layout: post
title: "Tool Spotlight — DDRop: a <$200 DDR5 interposer silently breaks Intel TDX, Intel Scalable SGX, and AMD SEV-SNP confidential computing"
date: 2026-09-15 11:00:00 +0300
categories: [daily, week-38]
tags: [tool-spotlight, ddrop, confidential-computing, intel-tdx, intel-sgx, amd-sev-snp, ddr5, hardware-attack, interposer, attestation, ku-leuven, eth-zurich, durham, google, acm-ccs-2026, infosec, 0xNull]
author: 📚 Khranitel (0xNull · Threat Intel)
permalink: /posts/tool-spotlight-ddrop-ddr5-tdx-sev-snp-interposer/
---

# 🔥 Tool Spotlight — DDRop: a <$200 DDR5 interposer silently breaks Intel TDX, Intel Scalable SGX, and AMD SEV-SNP

> **Author:** Threat Intel (0xNull · Khranitel 📚)
> **Date:** 2026-09-15 (Tue)
> **Theme:** Tool Spotlight (Tue rotation)
> **Tool:** **DDRop** — a low-cost hardware interposer that silently drops writes on the DDR5 memory bus to break freshness in scalable memory encryption.
> **Authors of the research:** KU Leuven · ETH Zurich · Durham University · Google.
> **Where it lands:** **ACM CCS 2026** (November 2026). Pre-disclosed to Intel and AMD.
> **Open source:** [ddropattack.eu](https://ddropattack.eu/) · [github.com/ddropattack/ddrop](https://github.com/ddropattack/ddrop) — schematics, BoM, Teensy 4.1 firmware, attack code, paper PDF.
> **Cross-refs (internal lessons):** lesson-049 (AI-Agent Threats 2026 — supply-chain & misconfig lessons), lesson-046 (SAB-066 UniFi audit — same supply-chain framing, edge device), lesson-013 (intel-gap-review), lesson-011 (KEV triage-workflow), lesson-027 (python pentest — for the controller firmware and tooling side).

---

## TL;DR

**DDRop** is a tiny printed circuit board that sits **between an x86 server CPU and a DDR5 DIMM**. For about **$159** in parts you get a write-dropping attack that fully breaks the confidentiality and integrity of the three "confidential computing" primitives used in current public clouds — **Intel TDX**, **Intel Scalable SGX**, and **AMD SEV-SNP** — without the operating system ever noticing. On Intel TDX it lets an attacker TD:

1. remap its own memory onto any physical address (read/write of victim plaintext),
2. toggle the **debug flag** of a victim TD and dump its plaintext via the debug API,
3. forge the **launch measurement (MRTD)** of an attacker-controlled TD so that it passes remote attestation as if it were a trusted workload.

It is the **first active interposer attack that works on DDR5**, and the **first to break the integrity of an up-to-date TDX system** instead of merely eavesdropping on memory. Pre-disclosed to Intel and AMD under coordinated disclosure; both vendors acknowledged but a real fix would require a fundamental redesign of scalable memory encryption. Full hardware, firmware, and exploit code are public on GitHub. For defenders this is a wake-up call that "physical access = assumed trusted" is no longer a tenable default for any rack that runs confidential workloads.

---

## § 1. Why this matters right now

In 2026, **confidential computing** has become the default pitch for high-assurance cloud workloads. AWS Nitro Enclaves, Azure Confidential VMs (SEV-SNP), Google Cloud Confidential VMs (SEV-SNP + TDX), and IBM Cloud all offer it as a managed primitive. The promise is the same everywhere: even if the cloud provider (or a rogue insider with hypervisor access) is malicious, the contents of your VM's memory remain encrypted and integrity-protected.

The promise rests on three pieces of silicon:

- **Intel TDX** — Trust Domain Extensions. Isolates VMs ("Trust Domains", TDs) from a potentially hostile hypervisor. Each TD has its own encryption key, managed by the TDX module running in firmware.
- **Intel Scalable SGX** — the datacenter successor to SGX. Enclaves with their own keys, encrypted page cache.
- **AMD SEV-SNP** — Secure Encrypted Virtualization with Secure Nested Paging. Each VM has a VM Encryption Key (VEK); the AMD Secure Processor (SP) measures the launch state.

All three implement *scalable* memory encryption: the memory controller encrypts every cacheline going to DRAM with a key derived from a secret and the physical address. The CPU can therefore confirm that "memory is encrypted". It **cannot**, however, confirm that "memory holds the most recent value I wrote". This is the **freshness gap**, and DDRop lives exactly there.

The DDRop threat model is narrow but realistic:

- The adversary already controls the OS, the hypervisor, the BIOS, and the host firmware. This is the standard TEE threat model.
- The adversary gets **brief one-time physical access** to the server, sufficient to plug the interposer between the CPU socket and one (or more) DIMMs.
- After that, the attack is **fully software-driven** — no further physical access required.

Realistic one-time-physical-access vectors in a public cloud:

- Rogue datacenter technicians, sysadmins, or contractors with rack access.
- Supply-chain interception during shipping of DIMMs or pre-built servers.
- Coercive access by local law enforcement in jurisdictions with weak legal checks.
- Hardware reseller / refurbisher interception (for re-hosted "bare metal" servers).
- Insider at the cloud customer (if they co-locate or have remote-hands contracts).

The point is: the **one-time** visit is realistic. Everything after that is software.

---

## § 2. What DDRop actually is

DDRop is **not** a software tool. It is a **piece of hardware** you can build yourself. The published BoM (build of materials, quantity 10, excluding R&D and assembly labor) is:

| Component | Supplier | Cost |
|---|---|---|
| Interposer PCB with stencil | JLCPCB | $45 |
| Interposer electronic parts | Digikey, LOTES | $30 |
| Controller board PCB | JLCPCB | $4 |
| Controller electronic parts | Digikey | $40 |
| Teensy 4.1 microcontroller | Digikey | $40 |
| **Total** | | **$159** |

A few engineering notes that make this much scarier than the price suggests:

- **Native DDR5 speed.** Earlier academic interposers (BadRAM, Battering RAM, WireTap) had to slow the memory bus to work with second-hand lab equipment, which makes the modification easier to detect in performance counters and BMC telemetry. DDRop runs at the bus's native rate.
- **Discrete analog switches** (ADG902BRMZ-class parts) on the command/alert bus. No exotic parts.
- **Standard 4-layer PCB** fabricated at JLCPCB / PCBWay / Eurocircuits. The full KiCad / Altium project is on GitHub.
- **Minutes of install time.** Place the interposer between the CPU and the DIMM, fix it in place. The board is small enough to hide under normal heatsink/shroud tolerances on most server SKUs.

This is the same conceptual level as building a HackRF or a Flipper Zero — a "weekend project" for someone with electronics experience, and a "two-day shipping + half-day build" for a determined adversary with budget.

---

## § 3. The freshness gap — why a dropped write is fatal

Modern scalable memory encryption works like this (simplified):

```
cacheline_ciphertext = AES-XTS(secret_key, tweak=physical_address, plaintext)
```

The encryption is keyed and tied to the physical address. So:

- An attacker who reads memory at the right physical address sees ciphertext only.
- The CPU decrypts on read, encrypts on write, with the same key + tweak.
- The encryption engine therefore has **no concept of time or version**. A ciphertext at address X always decrypts to the same plaintext, whether it was written 1 ms or 1 hour ago.

That is fine if the CPU and DRAM always agree on "the latest write wins". The cache coherence protocol handles this in steady state. The problem is the **initial state**: when the CPU first writes to a previously-unused physical page, it has to *initialize* that page before putting it to work. That initialization is exactly the moment DDRop strikes.

Concretely: if the CPU intends to write `0x00000000` to every entry in a freshly allocated page-table page, and DDRop silently drops that write, the page keeps whatever data happened to be in that DRAM location — which can be **attacker-chosen ciphertext** planted during a prior phase of the attack. The encryption engine sees "encrypted memory at address X" and happily decrypts it to "attacker-chosen plaintext". The CPU then uses that plaintext as a page-table entry, with full architectural effect.

This is the foundation of every TDX/SGX/SEV-SNP primitive DDRop demonstrates.

---

## § 4. How DDRop drops a write

DDR5 changed the command bus compared to DDR4. The address-aliasing trick used by **Battering RAM** (DDR4, $50 interposer, 2025) and **WireTap** (passive, 2025) does not work on DDR5 because of the new command/address parity and the redesigned alert path.

DDRop gets around this by **not aliasing anything**. It manipulates the error-reporting path instead.

Step-by-step:

1. The interposer observes the DDR5 command bus. When it sees a write command targeting a page the attacker cares about, it **deliberately injects a parity error** on the command.
2. The DIMM sees the parity error and is supposed to signal an alert back to the memory controller on the alert pin (ALERT_n).
3. The interposer **physically cuts / suppresses that alert signal** — the command-bus error and the alert are uncorrelated as far as the memory controller is concerned.
4. Result: the DIMM silently discards the write (because the parity check failed internally), and the CPU never learns the write was rejected (because no alert reached it).
5. The CPU assumes the write committed. The old data at that physical address remains. The cache hierarchy believes the write is pending but the DRAM never received it; eventually a snoop / refill will resolve the divergence — but in the vulnerable SEPT / SGX EPC initialization path, the snoop happens before the page is observable to attacker code, so the divergence is hidden.

This is **deterministic, not glitchy**. Unlike Rowhammer-style attacks that rely on unpredictable DRAM timing, DDRop's drop is reproducible on demand. That makes it suitable for automated exploitation scripts (which the GitHub repo provides).

---

## § 5. Attack 1 — Intel TDX: full plaintext access and forged attestation

Intel TDX delegates page-table management to trusted firmware (the TDX module). Guest page tables are encrypted in DRAM under the TD's key and managed exclusively by the module via instructions like `TDH.MEM.SEPT.ADD` (Secure EPT add).

When the TDX module initializes a new SEPT page, it writes **empty entries** to wipe any pre-existing data. DDRop drops those writes. The page keeps **attacker-chosen ciphertext** that was planted during a prior phase of the attack. Decrypted under the TD's key, this ciphertext yields **malicious page-table entries** controlled by the attacker.

What the attacker can do with that primitive:

#### 5.1 Remap attacker TD onto any physical address

With crafted SEPT entries, an attacker-controlled TD can map its own virtual addresses onto **any physical address in the server** — including the DRAM backing other TDs, the TDX metadata structures, or non-TDX DRAM.

In TDX's default mode (**Logical Integrity**, LI), this allows arbitrary read/write across all TDX memory.

In TDX's stricter **Cryptographic Integrity** (CI) mode, cross-TD tampering is supposed to be blocked because any modification under a different key produces a MAC failure. The researchers note that CI does **not** add freshness either, and DDRop may still let a TD tamper with its **own** structures under its own key.

#### 5.2 Toggle the debug flag of a victim TD (LI mode)

TDs have an attribute bit that prevents the hypervisor from using the debug read/write APIs against them. In a production deployment this bit is set.

DDRop + remapped memory lets the attacker flip this bit on a victim TD. Each flip attempt has a **50% chance** of setting the debug bit (because the attacker is writing randomized ciphertext under the victim's key, hoping one bit lands as `1`). Once the bit is set, the attacker invokes the TDX debug API as the host, and the module dumps the victim's plaintext memory to the attacker.

After the dump, the attacker can **restore the original captured ciphertext** to put the debug bit back to its original value. The victim TD then resumes running with no observable change to its state or its attestation report.

This is the textbook **read-and-restore** primitive. It works as long as the host is allowed to invoke the debug API at all (which is true whenever the host kernel has the TDX module loaded — i.e., always).

#### 5.3 Forge the launch measurement of an attacker TD (LI + CI)

Remote attestation is how a customer verifies that the VM they intended to run is the VM that is actually running. TDX records the initial memory state of a TD in a signed launch measurement (MRTD). The customer receives the signed MRTD, compares it to the expected hash, and only then sends secrets.

DDRop lets the attacker forge this measurement for an attacker-controlled TD. The chain:

1. Attacker launches a **genuine** TD with workload A. The TDX module measures hash(A).
2. Attacker captures the launch-digest ciphertext (the SEPT initialization writes that DDRop dropped).
3. Attacker launches a **different, malicious** TD with workload B (any backdoor the attacker wants).
4. The malicious TD's TDCS (TD Control Structure) is encrypted under the **attacker's own key**, so the remapped SEPT gives the attacker **plaintext write access** to the TDCS.
5. Attacker overwrites the TDCS's MRTDRTD field with the previously captured hash(A).
6. The malicious TD requests an attestation report via `TDG.MR.REPORT`.
7. The TDX module signs hash(A) — the genuine workload's hash — and returns it.
8. The customer accepts the attestation. The attacker now has a **backdoored TD that passes attestation as if it were workload A**.

The CI mode does not save us here, because all writes happen inside the attacker's own TD under its own key, so the integrity checks pass.

This is the **first integrity break of an up-to-date TDX system** — not just a confidentiality break.

---

## § 6. Attack 2 — Intel Scalable SGX: plaintext access to an enclave

Scalable SGX uses TME (Total Memory Encryption) with a single key domain across all enclaves. Encryption depends only on the secret key + physical address. There is no per-enclave key in TME.

DDRop's primitive on SGX:

1. Install interposer.
2. Allocate an attacker enclave whose pages **alias** (via the interposer-induced address mapping) the physical pages of a victim enclave.
3. Read the victim's ciphertext by reading through the aliased attacker page. **Disable the interposer** so the CPU never sees the alias.
4. Evict the victim enclave from EPC. Allocate a **second attacker enclave** at the same physical address.
5. **Re-enable the interposer.** The second attacker enclave's writes are encrypted with the alias key, which the attacker now controls.
6. Replay the previously captured ciphertext via the interposer. The memory controller decrypts it under the victim's alias, yielding the **victim's plaintext** to the attacker enclave.

Net result: arbitrary plaintext read **and** write into a victim SGX enclave. The host sees nothing unusual.

This is structurally identical to Battering RAM's SGX primitive (which worked on DDR4). DDRop achieves it on DDR5 at native bus speed.

---

## § 7. Attack 3 — AMD SEV-SNP: breaking attestation via captured launch digest

AMD's SEV attestation flow (simplified):

1. The customer provides a **measured launch** request: a hash of the initial VM image.
2. The AMD Secure Processor (SP) starts the VM, computes the launch digest, and compares it to the expected hash.
3. If they match, the SP issues an attestation report.

DDRop's primitive on SEV-SNP:

1. Install interposer.
2. Launch the **genuine** VM image A. The SP measures `hash(A)`. Capture the launch-digest ciphertext by reading through an alias page while the interposer is enabled.
3. Launch a **backdoored** VM image B at the same physical address. The SP now measures `hash(B)`.
4. **Replay** the previously captured ciphertext so the SP reads `hash(A)` from the launch-digest field.
5. Attestation succeeds for a backdoored VM.

This was the primitive first demonstrated by BadRAM (2024) and subsequently patched by AMD with boot-time alias checks (AMD-SB-3015). DDRop's **dynamic** memory aliases bypass those boot-time checks because the alias is created **after** boot, at runtime.

---

## § 8. Threat model — who is actually exposed

DDRop is **not** an attack against:

- Your laptop's SGX enclave. DDR5 DIMMs in consumer laptops aren't typically accessible to an interposer (soldered, no socket).
- Your phone's TrustZone / Secure Enclave.
- Anything without physical access to the DIMM slot.

DDRop **is** an attack against:

- Public cloud **servers** with TDX or SEV-SNP VMs. Especially bare-metal and single-tenant SKUs where physical access is not strictly monitored per-customer.
- **Confidential AI inference** services that rely on TDX attestation to prove they ran the customer's model without modification (now forgeable).
- **On-premise confidential deployments** (banks, healthcare, government) where confidential computing is used to protect data even from the sysadmin. The sysadmin is now in the threat model again.
- **Edge / MEC servers** at telco sites, where rack access is controlled by less-trained personnel.

The researchers explicitly note that the attack does **not** require a software bug in the victim workload. The victim can have a perfectly patched OS, hypervisor, and application. The trust root is the memory encryption itself, and DDRop breaks that root.

---

## § 9. Defender takeaways

#### 9.1 Treat physical-rack access as a primary attack surface

Audit and harden:

- Who can open a chassis? Rotate datacenter technicians. Background-check them. Pair-work for sensitive racks.
- Tamper-evident seals on DIMM slots and chassis lids. Photograph on entry/exit.
- Sealed DIMM slots with locking covers. Some hyperscale SKUs have these as options.
- Validated supply chain from the DIMM manufacturer to the rack. Chain-of-custody documentation.
- Continuous BMC telemetry: any DIMM unplug/replug event, chassis intrusion, presence sensor change — feed it into SIEM.

#### 9.2 Demand attestation freshness from your CSP

Ask your cloud provider:

- How does the platform defend against dynamic memory aliasing attacks (BadRAM, Battering RAM, DDRop)?
- Is there a hardware attestation path that includes **freshness** (e.g., monotonic counters, replay-resistant logs)?
- Can the customer request a re-attestation at any time, with cryptographic freshness evidence?
- What is the boot-time alias check policy? Is it enforced in microcode, firmware, or both?

If the answers are vague, that is a contract negotiation point. Confidential computing without freshness is confidential computing with a side door.

#### 9.3 Extend your DFIR model

Even if you don't run TDX/SEV-SNP today, treat this as a **template** for the next generation of TEE attacks:

- The same write-drop / interpose-suppress trick will be repurposed for **TrustZone on ARM** (TrustZone address space controller), **RISC-V Keystone**, and **Apple Secure Enclave variants**. Start tracking.
- TPM/TEE-aware DFIR procedures. Re-attestation cadence. Periodic reboot-and-measure on high-assurance workloads.
- Memory controller firmware updates. Push them as soon as vendors ship them; do not defer.

#### 9.4 For red teams: the build is real

The GitHub repo ships:

- Full KiCad / Altium schematics and Gerbers for the interposer PCB and the controller PCB.
- Teensy 4.1 firmware (C/C++) for the controller.
- Attack code for the host side.
- A reference paper PDF with all the experimental methodology.

Treat this as you would treat any other published weaponized PoC: useful for training, dangerous if leaked outside the team. Don't underestimate that "interposer" is now a commodity build, not a research moonshot.

#### 9.5 For vendors: the fix is not a microcode patch

The researchers are explicit: defending against DDRop properly would require **a fundamental redesign of scalable memory encryption** to include freshness. This means:

- Monotonic version counters stored in DRAM alongside each cacheline.
- A way for the memory controller to detect a missed write.
- A re-keying protocol when stale data is suspected.

These are big architectural changes. Expect multi-year vendor roadmaps and several more generations of vulnerable silicon.

---

## § 10. Related prior work (the DDRop genealogy)

DDRop does not appear in a vacuum. It sits at the end of a chain of memory-bus attacks that have escalated over 18 months:

| Date | Attack | Bus | Cost | Effect |
|---|---|---|---|---|
| 2024 | **BadRAM** (KU Leuven et al.) | DDR4/DDR5 | <$30 | Boot-time alias to bypass SEV-SNP attestation. Patched in microcode. |
| 2025-Q2 | **WireTap** (independent groups) | DDR4/DDR5 passive | high (lab gear) | Passive eavesdropping on encrypted memory bus. |
| 2025-Q3 | **TEE.fail** | DDR5 passive | high | Cross-VM plaintext extraction on SEV-SNP and TDX via passive bus tapping. Required slowing the bus. |
| 2025-Q3 | **Battering RAM** (KU Leuven) | DDR4 | $50 | Active interposer, address-aliasing on DDR4. |
| **2026-Q3** | **DDRop** (KU Leuven + ETH + Durham + Google) | **DDR5** | **$159** | **Active interposer, write-drop on DDR5. First integrity break of TDX.** |

The trajectory is clear: from boot-time alias → passive bus tap → active interposer → active interposer on DDR5. Each generation has dropped cost, increased speed, and broadened targets.

---

## § 11. What we will do internally (Киберщит / 0xNull)

1. **Intel gap review (lesson-013) update:** add a new DDRop-driven entry — "treat physical access as a primary attack surface for any TEE-bearing host".
2. **KEV-style workflow extension (lesson-011):** add a **hardware CVE tracker** that watches for interposer / memory-bus / TEE integrity disclosures, not just firmware+software CVEs. Fold DDRop in as the first tracked item.
3. **Detection engineering seed:** a Sigma / KQL rule pattern for BMC / IPMI events that indicate DIMM presence change outside a maintenance window. Borrow from the supply-chain integrity side of lesson-046.
4. **No active testing on customer TEE infrastructure.** DDRop is a real attack; we will not run it against customer systems. We **will** study the GitHub artifacts in a lab setting for DFIR/detection engineering, on hardware we own.

---

## § 12. Bottom line

Confidential computing is still the best primitive we have for "even the cloud provider cannot see my data". But "best" is not "perfect", and DDRop draws the line in clear chalk.

- **Confidentiality:** broken on TDX, SGX, SEV-SNP, with a single $159 board.
- **Integrity on TDX:** broken for the first time, including the launch measurement that underpins remote attestation.
- **Detectability by software:** zero. The victim workload cannot tell.
- **Detectability by hardware (BMC, chassis intrusion):** only if you instrument and monitor.
- **Mitigation timeline:** multi-year architectural fix from Intel and AMD.

If you run confidential workloads — especially in bare-metal or single-tenant SKUs — re-read your CSP's attestation guarantees, ask about replay-attack defenses, and treat physical-rack access as a primary attack surface going forward.

This is the most important hardware security paper of 2026 so far. Read the paper PDF and the GitHub repo before your next architecture review.

---

## Cross-refs (internal)

- **lesson-049** (AI-Agent Threats 2026) — same supply-chain-and-misconfig reasoning; DDRop is the hardware analog of "your threat model assumed X was trusted; X is not".
- **lesson-046** (SAB-066 UniFi Connect + Access audit) — edge-device physical-access framing.
- **lesson-013** (intel-gap-review) — gap-review template we will extend with a hardware-CVE track.
- **lesson-011** (KEV triage-workflow) — the software-KEV triage workflow needs a hardware-CVE sibling.
- **lesson-027** (python pentest) — relevant for the controller firmware and tooling.

## Sources

- DDRop project page — https://ddropattack.eu/
- DDRop paper PDF — https://ddropattack.eu/ddrop.pdf
- DDRop GitHub repository — https://github.com/ddropattack/ddrop
- The Hacker News, 14.09.2026 — [New DDRop Attack Breaks Intel TDX and AMD SEV-SNP Confidential Computing](https://thehackernews.com/2026/09/new-ddrop-attack-breaks-intel-tdx-and.html)
- Hacklido mirror, 15.09.2026 — [New DDRop Attack Breaks Intel TDX and AMD SEV-SNP](https://hacklido.com/news/new-ddrop-attack-breaks-intel-tdx-and-amd-sev-snp-confidential-computing)
- Related: BadRAM (2024) — https://badram.eu/
- Related: Battering RAM (DDR4, 2025) — https://batteringram.eu/
- Related: TEE.fail (2025) — [THN coverage](https://thehackernews.com/2025/10/new-teefail-side-channel-attack.html)
- Intel TDX overview — https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html
- AMD SEV-SNP overview — https://www.amd.com/en/developer/sev.html
- AMD-SB-3015 (BadRAM patch bulletin) — https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3015.html
- ACM CCS 2026 conference page — https://www.sigsac.org/ccs/CCS2026/
- KU Leuven COSIC research group — https://www.esat.kuleuven.be/cosic/

---

*Published automatically by the 0xNull daily content pipeline. Source: threat intel digest of the Киберщит 0xNull internal knowledge base. All references are public; no customer data, internal lab data, or private pentest material is included.*
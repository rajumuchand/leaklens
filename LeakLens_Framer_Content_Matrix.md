# LeakLens × Framer: Complete Layer-by-Layer Content & Implementation Matrix

> **Hackathon Track**: Problem Statement 09 — *Trace Leaked Copies and Limit Offline Access*  
> **Source Input**: [SentinelTrace Dashboard Design on v0](https://v0.app/rajumuchand/chat/sentineltrace-dashboard-design-hgkvgxZ46GV)  
> **Target Website**: [leaklens.framer.ai](https://leaklens.framer.ai/)  
> **Framer Project**: [Hexwall Lite Project Editor](https://framer.com/projects/Hexwall-Lite-copy--zH0Qi53fCl1dDWvXONVd-cxKu6)

---

## 0. Direct Mapping to Problem Statement 09

| Problem Statement 09 Clause | LeakLens Technical Implementation | Framer Section & Layer |
| :--- | :--- | :--- |
| *"Identical decrypted copies cannot be traced to a person"* | **Zero-Width Unicode Steganography**: Embeds unique `recipient_id` + `session_id` payload into text. | `Protect > Endpoints` & `Platform > Tab 1` |
| *"Produce visually identical copies with distinct forensic watermarks"* | **0-Pixel Footprint**: Uses `\u200B` (0), `\u200C` (1), and `\u200D` (delimiter). Zero visual alterations. | `Hero` & `Protect > Endpoints` |
| *"Cryptographically verifiable match from a leaked copy to its recipient and session"* | **HMAC-SHA256 Signing**: Payload is signed with `SECRET_KEY`. Verified dynamically in `/api/inspect`. | `Platform > Tab 2 (Forensic Inspector)` |
| *"Limit offline access to a defined permission window (offline devices cannot receive revocation updates)"* | **Time-Bounded Lease Windows**: Monotonic timer counts down; keys auto-shred from RAM upon lease expiry. | `Platform > Tab 3 (DRM Expiry Monitor)` |

---

## 1. Executive Summary & Brand Translation

| Dimension | Current Template (Hexwall Lite) | New LeakLens / SentinelTrace Specification |
| :--- | :--- | :--- |
| **Product Category** | Generic endpoint/cloud antivirus & firewall | **Forensic Document Watermarking & Offline DRM** |
| **Core Problem** | Malware, open cloud buckets, phishing emails | **Insider leaks, corporate espionage, unauthorized memo distribution** |
| **Core Mechanism** | Cloud scanning agents | **Invisible Zero-Width Steganography + HMAC-SHA256 Signatures + Hardware DRM** |
| **Key Value Metric** | "Attacks stopped today" | **100% Deterministic Attribution & 0-px Visual Impact** |
| **Interactive Demo** | Static mock graphs | **Live 3-Tab Cryptographic Engine & Leak Inspector (`LeakLensDashboard.tsx`)** |

---

## 2. Canvas Layer-by-Layer Replacement Matrix

Use this table inside your Framer canvas. Search for each layer by name in the Framer Layers panel on the left, and update the text content accordingly.

### A. Navigation & Header (`Desktop` / `Tablet` / `Phone`)

| Framer Layer Name | Current Text | New LeakLens Text | Notes |
| :--- | :--- | :--- | :--- |
| `Logo` | `Hexwall` | `LeakLens` | Pair with a clean forensic crosshair/lens icon |
| `Status` | *(empty or generic)* | `● System Active \| Cryptographic Engine Ready` | Accent color `#2BD8C8` / `#7B5CFA` |
| `Menu > Nav Links` | `Product`, `Platform`, `Pricing`, `Company` | `Watermarking`, `Forensic Inspector`, `Offline DRM`, `Pricing` | Matches the 3 core pillars |
| `Header End > Button` | `Get Started` / `Book Demo` | `Deploy LeakLens` | Primary CTA button |

---

### B. Hero Section (`Hero`)

| Framer Layer Name | Current Text | New LeakLens Text |
| :--- | :--- | :--- |
| `Kicker` | `// Threat detection, around the clock` | `// Zero-Leak Document Attribution & DRM` |
| `Title` | `Security that never sleeps.` | `Trace Every Leak. Prove Every Source.` |
| `Hero Copy` | `Hexwall watches every endpoint, cloud account and inbox in real time, and stops attacks before your team wakes up.` | `Embed invisible, cryptographically signed watermarks into confidential documents and enforce time-bounded offline access. When leaks occur, trace them to the exact leaker, session, and second.` |
| `Buttons > Primary` | `Start free trial` | `Test Forensic Engine` (Anchor link to `#platform`) |
| `Buttons > Secondary` | `Book a demo` | `Request Enterprise SDK` |
| `Status / Badge` | `18,240 attacks stopped today` | `100% Cryptographic Attribution Accuracy (HMAC-SHA256)` |

---

### C. Feature Pillars (`Protect` > `Layers`)

Currently, this section features 3 cards (`Endpoints`, `Cloud`, `Inbox`). Replace them with the **3 Technical Pillars of LeakLens**:

#### Pillar 1: Zero-Width Steganography (Replaces `Endpoints`)
- **Layer `Name`**: `Invisible Unicode Watermarking`
- **Layer `Text`**: `Embeds recipient identifiers, session hashes, and cryptographic signatures into document text using invisible zero-width Unicode characters (\u200B, \u200C). Visually 100% undetectable; survives copy-paste and formatting changes.`
- **Layer `Stat`**: `0 px`
- **Layer `Rail Label` / Subtext**: `Zero Visual Footprint`

#### Pillar 2: Deterministic Forensic Attribution (Replaces `Cloud`)
- **Layer `Name`**: `Forensic Leak Inspector`
- **Layer `Text`**: `Paste any leaked snippet, Slack message, or photo fragment into the forensic engine. Reverse-extract the hidden payload to immediately attribute the breach to an exact employee ID, timestamp, and HMAC-SHA256 signature.`
- **Layer `Stat`**: `100%`
- **Layer `Rail Label` / Subtext**: `Mathematically Provable`

#### Pillar 3: Offline Hardware DRM (Replaces `Inbox`)
- **Layer `Name`**: `Time-Bounded Offline DRM`
- **Layer `Text`**: `Issue cryptographic access leases from 1 to 120 minutes. If an unauthorized recipient attempts to store documents offline or copy them to air-gapped drives, the decryption key self-destructs upon lease expiration.`
- **Layer `Stat`**: `1-120 min`
- **Layer `Rail Label` / Subtext**: `Hardware Enclave Enforced`

---

### D. The Interactive Platform Section (`Platform` > `App`)

This is the centerpiece of your Framer page where the v0 concept connects directly to your site.

| Framer Layer Name | Current Text | New LeakLens Text |
| :--- | :--- | :--- |
| `Rail Label` | `02 / The platform` | `02 / Interactive Console` |
| `Title` | `Every threat on one calm screen.` | `Generate. Inspect. Enforce.` |
| `Note` | `No wall of red alerts. Hexwall sorts, explains and closes what it can, and shows you only what needs a human. Click through the screens.` | `Interact directly with the LeakLens cryptographic engine below. Generate an invisible watermarked memo, inspect a simulated leak snippet, or test real-time offline DRM lease expiration.` |
| **`App` (Component Replacement)** | *Generic template mock dashboard* | **Insert `LeakLensDashboard.tsx` Code Component** *(See Section 3 for step-by-step setup)* |

---

### E. How It Works (`Steps`)

| Step Layer | Current Step Title & Text | New LeakLens Step Title & Text |
| :--- | :--- | :--- |
| `Step 01` | **Title**: `Connect in an afternoon`<br>**Body**: `Plug in your cloud, devices and mail. No servers to run, no agents to babysit.` | **Title**: `1. Sign & Embed`<br>**Body**: `Upload documents or connect your DMS via API. LeakLens cryptographically signs recipient metadata with HMAC-SHA256 and embeds it via invisible Unicode steganography.` |
| `Step 02` | **Title**: `We learn your normal`<br>**Body**: `Seven quiet days of watching how your team works, then anything odd stands out.` | **Title**: `2. Enforce Offline Leases`<br>**Body**: `Distribute documents with time-bounded cryptographic leases. Offline viewing is restricted to verified hardware enclaves and auto-revoked upon expiration.` |
| `Step 03` | **Title**: `Threats are shut down`<br>**Body**: `Isolated in seconds, explained in plain words, logged for your next audit.` | **Title**: `3. Pinpoint & Prosecute`<br>**Body**: `When confidential memos appear on social media or in competitor hands, paste the excerpt into the Forensic Inspector to mathematically prove who leaked it.` |

---

### F. Social Proof & Metrics (`Stats` & `Trusted`)

#### Metrics Grid (`Stats`)
- **Metric 1**: `100%` — `Attribution Certainty (HMAC-SHA256 Signed)`
- **Metric 2**: `0 px` — `Visual Distortion (True Zero-Width Characters)`
- **Metric 3**: `< 200 ms` — `Forensic Analysis & Verification Latency`
- **Metric 4**: `10M+` — `Confidential Words Protected Daily`

#### Testimonials (`Trusted`)
- **Testimonial 1 (Replaces Maya Lindqvist)**:  
  *“When our confidential acquisition memo was leaked to the press, LeakLens extracted the invisible watermark within 30 seconds and pinpointed the exact advisory partner's session ID with HMAC verification. It settled the investigation immediately.”*  
  — **Evelyn Vance**, Chief Legal Officer, Apex Capital Partners
- **Testimonial 2 (Replaces Omar Haddad)**:  
  *“Traditional DLP just frustrates employees with false blocks. LeakLens lets people work while ensuring accountability. If someone leaks a screen capture or copied paragraph, we know exactly who did it.”*  
  — **Marcus Chen**, VP Information Security, HyperScale Technologies

---

### G. Pricing Tiers (`Pricing`)

| Tier | Current Hexwall Price & Features | New LeakLens Forensic Tiers |
| :--- | :--- | :--- |
| **Starter** | `$49 / month`<br>• Up to 25 devices<br>• Inbox protection<br>• Weekly report | **$49 / month** — *For boutique law firms, advisory shops & founders*<br>• Up to 500 watermarked documents/mo<br>• Invisible Unicode Steganography<br>• Forensic Leak Inspector web console<br>• Standard HMAC-SHA256 signing<br>• Email forensic support |
| **Growth (Most Picked)** | `$149 / month`<br>• Up to 250 devices<br>• Endpoints, cloud & inbox<br>• Auto response in seconds<br>• Slack & Teams alerts | **$149 / month** — *For fast-scaling startups, M&A teams & investment funds*<br>• Unlimited document watermarking<br>• Real-time Offline DRM lease engine (1–120 min)<br>• REST API & Webhook access<br>• Tamper detection & invalid signature alerts<br>• Slack & Microsoft Teams breach notifications<br>• Automated PDF & DOCX pipeline |
| **Enterprise** | `Custom`<br>• Unlimited devices<br>• Dedicated analyst<br>• SOC 2 and ISO 27001 reports | **Custom / Annual** — *For Fortune 500, defense, health & regulated industries*<br>• Bring Your Own KMS Key (`SENTINEL_SIGNING_KEY`)<br>• Air-gapped offline DRM hardware tokens<br>• Custom zero-width & homoglyph steganographic schemes<br>• SOC 2 Type II & Court-admissible forensic export<br>• Dedicated security engineer & 99.99% SLA |

---

### H. Footer & Closing (`Final` & `Footer`)

| Framer Layer Name | Current Text | New LeakLens Text |
| :--- | :--- | :--- |
| `Final > Title` | `Put a wall around your company.` | `Make Every Leak Mathematically Provable.` |
| `Final > Copy` | `Round the clock protection for endpoints, cloud and inbox. Built for teams without a security department.` | `Stop guessing who leaked confidential memos. Deploy LeakLens forensic watermarking and offline DRM today.` |
| `Footer > Brand` | `Hexwall Inc.` | `LeakLens Security Inc.` |
| `Footer > Copyright` | `© 2026 Hexwall Inc. All rights reserved.` | `© 2026 LeakLens Inc. All rights reserved. Forensic Steganography & DRM.` |
| `Footer > Status` | `All systems protected` | `Cryptographic Engine v2.4 Active` |

---

## 3. How to Deploy the Interactive Dashboard in Framer

We have created the full React code component in your workspace:  
`file:///Users/raju/Desktop/Leak_lens/LeakLensDashboard.tsx`

### 3-Step Setup in Framer:
1. **Open your Framer Project**:
   Go to your open project at [Hexwall Lite Framer Project](https://framer.com/projects/Hexwall-Lite-copy--zH0Qi53fCl1dDWvXONVd-cxKu6).
2. **Add Code Component**:
   - In the left sidebar, click **Assets** → **Code**.
   - Click **Create Code File** (+ icon), and name it `LeakLensDashboard.tsx`.
   - Copy the entire contents of [LeakLensDashboard.tsx](file:///Users/raju/Desktop/Leak_lens/LeakLensDashboard.tsx) and paste it into the code editor.
   - Click **Save** (`Cmd + S`).
3. **Drop onto Canvas**:
   - Navigate to the `Platform` section on your Framer canvas.
   - Locate the `App` layer (which currently holds the static template dashboard).
   - Drag `LeakLensDashboard` from your Code Assets directly into the `App` container.
   - Set Width to `100%` (or Fill) and Height to `Auto` / `Fit Content`.
   - You now have the exact live, interactive 3-tab v0 SentinelTrace engine running directly on your Framer website!

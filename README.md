# Not Another Password Generator

> A cryptographically strong password generator powered by real-world entropy — not `Math.random()`.

---

## What makes this different?

Most password generators call `Math.random()` and call it a day. This one fuses **13 real-world entropy signals** into a SHA-256 hash every single time you click generate — no reuse, no shortcuts.

---

## Entropy Sources

Every click collects fresh chaos from all of these simultaneously:

| Source | Signal |
|---|---|
| `performance.now()` | Sub-millisecond high-resolution timing jitter |
| `Date.now()` | Current timestamp |
| `crypto.getRandomValues()` | 128 bytes of CSPRNG output |
| `navigator.hardwareConcurrency` | CPU core count fingerprint |
| `navigator.deviceMemory` | Device RAM fingerprint |
| `navigator.platform` | OS/platform string |
| `navigator.language` | Browser language setting |
| Screen resolution + color depth | Display fingerprint |
| Intl timezone | Timezone fingerprint |
| Network round-trip latency | Live-measured fetch timing |
| Mouse movement buffer | Up to 256 recent `(x, y, t, dx, dy)` tuples |
| Performance navigation entries | Browser session state |
| Window inner dimensions | Viewport size |

All 13 sources are serialized → hashed with **SHA-256 via the Web Crypto API** → converted to a password using a counter-based CSPRNG (no `Math.random()` anywhere in the pipeline).

---

## Features

**🔐 Password Generation**
- Guaranteed mix of uppercase, lowercase, digits, and symbols
- Fisher-Yates shuffle seeded from a second SHA-256 pass
- Adjustable length from 6 to 64 characters
- Fresh entropy collected on every single click

**👁 Show / Hide Toggle**
- Password is masked by default after generation
- Eye icon to reveal / re-mask instantly

**🔥 Burn After Reading**
- Copy the password → a 30-second countdown begins
- Color-coded urgency: yellow → orange → red as time runs out
- Password auto-wipes at zero — cancel anytime

**📊 Live Entropy Dashboard**
- Mouse entropy activity bar (live, decays when idle)
- Network latency display (measured on each generate)
- Active entropy sources count with hover popover listing all 13 sources

**⏱ Crack Time Estimator**
- Calculates entropy bits from charset pool × length
- Estimates time-to-crack at 100 billion guesses/sec (GPU cluster)
- Color-coded: red (instantly) → green (centuries) → purple glow (longer than the universe)

**🎨 Color-Zoned Slider**
- Red/Orange: 6–12 chars — Weak
- Purple: 13–30 chars — Strong
- Deep Purple: 30–64 chars — Fortress

**🌗 Light & Dark Mode**
- Toggle in the top bar
- Smooth transitions throughout

---

## Security Model

- **No backend.** Everything runs in your browser.
- **No data transmitted.** Passwords never leave your device.
- **No storage.** Nothing is written to localStorage, cookies, or any persistent store.
- **No `Math.random()`.** The entire pipeline uses `crypto.getRandomValues()` and `crypto.subtle.digest()`.
- **No dependencies** beyond React and Tailwind-compatible styles.

---

## Tech Stack

- **React 18** — UI and state
- **Web Crypto API** — SHA-256 hashing + CSPRNG bytes
- **`performance.now()`** — High-resolution timing entropy
- **Fetch API** — Network latency measurement
- **Mouse events** — Live entropy buffer collection
- Fully client-side — deployable on any static host

---

## Getting Started

```bash
# Clone the repo
git clone https://github.com/dotAadarsh/not-another-password-generator.git
cd not-another-password-generator

# Install dependencies
npm install

# Start dev server
npm run dev
```

Then open [http://localhost:5173](http://localhost:5173).

### Build for production

```bash
npm run build
```

The output in `dist/` is a fully static site — drop it on GitHub Pages, Vercel, Netlify, or anywhere.

---

## How the Entropy Pipeline Works

```
┌─────────────────────────────────────────────┐
│           13 Real-World Signals              │
│  timestamps · crypto bytes · hardware ·     │
│  network latency · mouse buffer · screen …  │
└────────────────────┬────────────────────────┘
                     │ JSON.stringify + perf.now()
                     ▼
            ┌─────────────────┐
            │   SHA-256 Hash  │  (Web Crypto API)
            └────────┬────────┘
                     │ Uint8Array[32]
                     ▼
        ┌────────────────────────┐
        │  Counter-based CSPRNG  │
        │  Re-hash per character │
        └────────────┬───────────┘
                     │
                     ▼
        ┌────────────────────────┐
        │  Fisher-Yates Shuffle  │  (seeded from 2nd SHA-256 pass)
        └────────────┬───────────┘
                     │
                     ▼
             Strong Password ✓
```

---

## License

MIT — do whatever you want with it.

---

<div align="center">
  <p>Built by <a href="https://x.com/dotAadarsh">@dotAadarsh</a></p>
  <a href="https://buymeachai.ezee.li/dotaadarsh" target="_blank">
    <img src="https://buymeachai.ezee.li/assets/images/buymeachai-button.png" alt="Buy Me A Chai" width="160">
  </a>
</div>
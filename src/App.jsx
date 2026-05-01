import { useState, useEffect, useRef, useCallback } from "react";

// ============================================================
// ENTROPY ENGINE — collects real-world chaos signals
// ============================================================

/** Measure round-trip latency to a tiny cachebust URL */
async function measureNetworkLatency() {
  try {
    const t0 = performance.now();
    await fetch(`https://www.google.com/favicon.ico?_=${Date.now()}`, {
      mode: "no-cors",
      cache: "no-store",
    });
    return performance.now() - t0;
  } catch {
    return performance.now() % 997; // fallback: high-res timestamp noise
  }
}

/** Collect raw entropy from every available real-world signal */
async function gatherEntropySources(mouseBuffer) {
  const sources = {};

  // 1. High-resolution timestamps
  sources.perfNow = performance.now();
  sources.dateNow = Date.now();

  // 2. Cryptographic randomness (128 bytes)
  const cryptoBytes = new Uint8Array(128);
  crypto.getRandomValues(cryptoBytes);
  sources.cryptoRandom = Array.from(cryptoBytes);

  // 3. Hardware fingerprints
  sources.hardwareConcurrency = navigator.hardwareConcurrency ?? 4;
  sources.deviceMemory = navigator.deviceMemory ?? 4;
  sources.platform = navigator.platform ?? "unknown";
  sources.language = navigator.language ?? "en";
  sources.screenRes = `${screen.width}x${screen.height}x${screen.colorDepth}`;
  sources.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;

  // 4. Network latency
  sources.networkLatency = await measureNetworkLatency();

  // 5. Mouse entropy buffer
  sources.mouseEvents = mouseBuffer.slice(-64);

  // 6. Additional timing jitter
  sources.perfEntries = performance.getEntriesByType("navigation").length;
  sources.innerSize = `${window.innerWidth}x${window.innerHeight}`;

  return sources;
}

/** SHA-256 hash all entropy sources → Uint8Array */
async function hashEntropy(sources) {
  const payload = JSON.stringify(sources) + performance.now();
  const encoded = new TextEncoder().encode(payload);
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
  return new Uint8Array(hashBuffer);
}

/**
 * Convert hash bytes → password
 * Uses the hash as a CSPRNG seed by re-hashing with a counter
 */
async function buildPassword(hashBytes, length) {
  const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const LOWER = "abcdefghijklmnopqrstuvwxyz";
  const DIGITS = "0123456789";
  const SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?";
  const ALL = UPPER + LOWER + DIGITS + SYMBOLS;

  let chars = [];
  let counter = 0;

  // Ensure at least one of each class
  const pickFrom = async (set) => {
    const extra = new Uint8Array(8);
    extra.set(hashBytes.slice(counter % 24, (counter % 24) + 8));
    extra[0] ^= counter;
    const h = await crypto.subtle.digest("SHA-256", extra);
    counter++;
    const b = new Uint8Array(h);
    return set[b[0] % set.length];
  };

  chars.push(await pickFrom(UPPER));
  chars.push(await pickFrom(LOWER));
  chars.push(await pickFrom(DIGITS));
  chars.push(await pickFrom(SYMBOLS));

  // Fill remaining from full charset
  while (chars.length < length) {
    chars.push(await pickFrom(ALL));
  }

  // Fisher-Yates shuffle using fresh hash bytes
  const shuffleSeed = new Uint8Array(length * 2);
  const shuffleHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", hashBytes)
  );
  for (let i = 0; i < shuffleSeed.length; i++) {
    shuffleSeed[i] = shuffleHash[i % 32] ^ hashBytes[i % 32] ^ i;
  }

  for (let i = chars.length - 1; i > 0; i--) {
    const j = shuffleSeed[i] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join("");
}

// ============================================================
// CRACK TIME ESTIMATOR
// Assumes a fast offline attacker: 100 billion guesses/sec
// (modern GPU cluster cracking bcrypt is ~10B/s; we use 1e11
//  for a conservative worst-case scenario against raw hashes)
// ============================================================
function estimateCrackTime(password) {
  if (!password) return null;

  // Determine charset pool size from characters actually used
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 32;

  // Entropy bits = log2(pool^length) = length * log2(pool)
  const bits = password.length * Math.log2(pool);

  // Combinations = 2^bits; seconds = combinations / guesses_per_sec
  // Use BigInt-safe log math to avoid Infinity on large values
  const GUESSES_PER_SEC = 1e11;
  const log10Combos = bits * Math.log10(2);
  const log10Secs = log10Combos - Math.log10(GUESSES_PER_SEC);

  const formatTime = (log10s) => {
    if (log10s < 0)   return { label: "instantly",           color: "#ef4444", tier: 0 };
    if (log10s < 1)   return { label: "a few seconds",       color: "#ef4444", tier: 0 };
    if (log10s < 2.5) return { label: "minutes",             color: "#f97316", tier: 1 };
    if (log10s < 4)   return { label: "hours",               color: "#eab308", tier: 2 };
    if (log10s < 5.5) return { label: "days",                color: "#eab308", tier: 2 };
    if (log10s < 7.5) return { label: "months",              color: "#84cc16", tier: 3 };
    if (log10s < 9.5) return { label: "years",               color: "#22c55e", tier: 3 };
    if (log10s < 12)  return { label: "centuries",           color: "#22c55e", tier: 4 };
    if (log10s < 18)  return { label: "millions of years",   color: "#7c3aed", tier: 5 };
    if (log10s < 25)  return { label: "billions of years",   color: "#7c3aed", tier: 5 };
    return               { label: "longer than the universe",color: "#7c3aed", tier: 5 };
  };

  const result = formatTime(log10Secs);
  return { ...result, bits: Math.round(bits), pool };
}

// ============================================================
// ENTROPY SOURCE LABELS — shown in hover popover
// ============================================================
const ENTROPY_SOURCE_LABELS = [
  { key: "perfNow",             label: "performance.now() timing",       icon: "⏱", always: true },
  { key: "dateNow",             label: "Date.now() timestamp",           icon: "📅", always: true },
  { key: "cryptoRandom",        label: "crypto.getRandomValues() bytes", icon: "🔐", always: true },
  { key: "hardwareConcurrency", label: "navigator.hardwareConcurrency",  icon: "💻", always: true },
  { key: "deviceMemory",        label: "navigator.deviceMemory",         icon: "🧠", always: true },
  { key: "platform",            label: "navigator.platform",             icon: "🖥", always: true },
  { key: "language",            label: "navigator.language",             icon: "🌐", always: true },
  { key: "screenRes",           label: "screen resolution + color depth",icon: "🖵", always: true },
  { key: "timezone",            label: "Intl timezone fingerprint",      icon: "🕐", always: true },
  { key: "networkLatency",      label: "network round-trip latency",     icon: "📡", always: true },
  { key: "mouseEvents",         label: "mouse movement + timing buffer", icon: "🖱", always: true },
  { key: "perfEntries",         label: "performance navigation entries", icon: "📊", always: true },
  { key: "innerSize",           label: "window inner dimensions",        icon: "⬜", always: true },
];

// ============================================================
// MAIN COMPONENT
// ============================================================
export default function EntropyForge() {
  const [dark, setDark] = useState(true);
  const [password, setPassword] = useState("");
  const [length, setLength] = useState(16);
  const [latency, setLatency] = useState(null);
  const [generating, setGenerating] = useState(false);
  const [copied, setCopied] = useState(false);
  const [glitching, setGlitching] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [mouseActivity, setMouseActivity] = useState(0);
  const [sourceCount, setSourceCount] = useState(0);
  const [showSources, setShowSources] = useState(false);
  const [popoverPos, setPopoverPos] = useState(null);

  const [burnTimer, setBurnTimer] = useState(null);
  const burnIntervalRef = useRef(null);

  // ── Burn-after-reading countdown ──────────────────────────
  const startBurnTimer = useCallback(() => {
    clearInterval(burnIntervalRef.current);
    setBurnTimer(30);
    burnIntervalRef.current = setInterval(() => {
      setBurnTimer(prev => {
        if (prev <= 1) {
          clearInterval(burnIntervalRef.current);
          setPassword("");
          setShowPassword(false);
          setCopied(false);
          return null;
        }
        return prev - 1;
      });
    }, 1000);
  }, []);

  const cancelBurn = useCallback(() => {
    clearInterval(burnIntervalRef.current);
    setBurnTimer(null);
  }, []);

  // Cleanup burn timer on unmount
  useEffect(() => () => clearInterval(burnIntervalRef.current), []);

  const mouseBufferRef = useRef([]);
  const activityTimerRef = useRef(null);
  const sourcesCardRef = useRef(null);

  const handleSourcesEnter = () => {
    if (!sourceCount || !sourcesCardRef.current) return;
    const rect = sourcesCardRef.current.getBoundingClientRect();
    setPopoverPos({ top: rect.bottom + 10, left: rect.left });
    setShowSources(true);
  };

  // Inject matching favicon and set tab title
  useEffect(() => {
    document.title = "Not Another Password Generator";
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 44 44">
      <polygon points="22,3 40,12 40,32 22,41 4,32 4,12" fill="%237c3aed22" stroke="%237c3aed" stroke-width="2"/>
      <polygon points="22,10 34,17 34,27 22,34 10,27 10,17" fill="%237c3aed33" stroke="%23a855f7" stroke-width="1"/>
      <circle cx="22" cy="22" r="5" fill="%237c3aed"/>
    </svg>`;
    let link = document.querySelector("link[rel~='icon']");
    if (!link) { link = document.createElement("link"); link.rel = "icon"; document.head.appendChild(link); }
    link.type = "image/svg+xml";
    link.href = `data:image/svg+xml,${svg}`;
  }, []);
  const handleMouseMove = useCallback((e) => {
    const now = performance.now();
    mouseBufferRef.current.push(e.clientX, e.clientY, now, e.movementX, e.movementY);
    if (mouseBufferRef.current.length > 256) mouseBufferRef.current.splice(0, 50);
    setMouseActivity((prev) => Math.min(prev + 2, 100));
    clearTimeout(activityTimerRef.current);
    activityTimerRef.current = setTimeout(
      () => setMouseActivity((p) => Math.max(p - 10, 0)),
      200
    );
  }, []);

  useEffect(() => {
    window.addEventListener("mousemove", handleMouseMove);
    const decay = setInterval(
      () => setMouseActivity((p) => Math.max(p - 3, 0)),
      300
    );
    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      clearInterval(decay);
    };
  }, [handleMouseMove]);

  const generate = async () => {
    if (generating) return;
    setGenerating(true);
    setGlitching(true);
    setCopied(false);
    cancelBurn();
    setBurnTimer(null);

    // Start generation
    setTimeout(() => setGlitching(false), 600);

    try {
      const sources = await gatherEntropySources(mouseBufferRef.current);
      setLatency(Math.round(sources.networkLatency));
      setSourceCount(Object.keys(sources).length);

      const hashBytes = await hashEntropy(sources);
      const pw = await buildPassword(hashBytes, length);
      setPassword(pw);
      setShowPassword(false);
    } catch (err) {
      setPassword("ERROR: " + err.message);
    } finally {
      setGenerating(false);
    }
  };

  const copyToClipboard = () => {
    if (!password || password === placeholder) return;
    const text = password;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        setCopied(true);
        startBurnTimer();
      }).catch(() => execCommandCopy(text));
    } else {
      execCommandCopy(text);
    }
  };

  const execCommandCopy = (text) => {
    const el = document.createElement("textarea");
    el.value = text;
    el.style.position = "fixed";
    el.style.opacity = "0";
    document.body.appendChild(el);
    el.focus();
    el.select();
    try {
      document.execCommand("copy");
      setCopied(true);
      startBurnTimer();
    } catch {}
    document.body.removeChild(el);
  };

  // ---- THEME ----
  const placeholder = "·".repeat(length);
  const bg = dark ? "#0a0a0f" : "#f0f0f5";
  const surface = dark ? "#12121a" : "#ffffff";
  const border = dark ? "#2a2a3a" : "#d0d0e0";
  const text = dark ? "#e8e8f0" : "#1a1a2e";
  const textMuted = dark ? "#6a6a8a" : "#8888aa";
  const accent = "#7c3aed";

  // ---- RENDER ----
  return (
    <div
      onMouseMove={handleMouseMove}
      style={{
        minHeight: "100vh",
        width: "100%",
        background: bg,
        color: text,
        fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
        transition: "background 0.3s, color 0.3s",
        padding: "0",
        margin: "0",
        boxSizing: "border-box",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
      }}
    >
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@700;800&display=swap');

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        html, body { width: 100%; min-height: 100vh; overflow-x: hidden; }

        @keyframes glitch {
          0%   { transform: translate(0); filter: none; }
          10%  { transform: translate(-2px, 1px); filter: hue-rotate(90deg); }
          20%  { transform: translate(2px, -1px); filter: hue-rotate(180deg); }
          30%  { transform: translate(-1px, 2px); filter: none; }
          40%  { transform: translate(1px, -2px); filter: hue-rotate(270deg); }
          50%  { transform: translate(0); filter: none; }
          60%  { transform: translate(-3px, 0); filter: brightness(1.4); }
          70%  { transform: translate(3px, 1px); filter: none; }
          80%  { transform: translate(-1px, -1px); filter: hue-rotate(45deg); }
          90%  { transform: translate(1px, 1px); filter: none; }
          100% { transform: translate(0); filter: none; }
        }

        @keyframes pulse-ring {
          0%   { box-shadow: 0 0 0 0 ${accent}88; }
          70%  { box-shadow: 0 0 0 16px transparent; }
          100% { box-shadow: 0 0 0 0 transparent; }
        }

        @keyframes scanline {
          0%   { background-position: 0 0; }
          100% { background-position: 0 100px; }
        }

        @keyframes flicker {
          0%, 90%, 100% { opacity: 1; }
          92% { opacity: 0.7; }
          94% { opacity: 1; }
          96% { opacity: 0.8; }
          98% { opacity: 1; }
        }

        @keyframes spin {
          from { transform: rotate(0deg); }
          to   { transform: rotate(360deg); }
        }

        @keyframes fadeUp {
          from { opacity: 0; transform: translateY(12px); }
          to   { opacity: 1; transform: translateY(0); }
        }

        .entropy-forge-title {
          font-family: 'Syne', sans-serif;
          font-weight: 800;
          letter-spacing: -2px;
          animation: flicker 8s infinite;
        }

        .generate-btn {
          border: none;
          cursor: pointer;
          font-family: 'Syne', sans-serif;
          font-weight: 700;
          font-size: 1rem;
          letter-spacing: 1px;
          transition: transform 0.15s, box-shadow 0.15s;
        }

        .generate-btn:hover:not(:disabled) {
          transform: translateY(-2px);
        }

        .generate-btn:active:not(:disabled) {
          transform: translateY(0);
        }

        .generate-btn:disabled {
          cursor: not-allowed;
          opacity: 0.7;
        }

        .copy-btn {
          border: none;
          cursor: pointer;
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.75rem;
          transition: all 0.2s;
        }

        .copy-btn:hover {
          opacity: 0.8;
        }

        .slider {
          -webkit-appearance: none;
          width: 100%;
          height: 4px;
          border-radius: 2px;
          outline: none;
          cursor: pointer;
          transition: background 0.3s;
        }

        .slider::-webkit-slider-thumb {
          -webkit-appearance: none;
          width: 16px;
          height: 16px;
          border-radius: 50%;
          background: ${accent};
          cursor: pointer;
          box-shadow: 0 0 8px ${accent}88;
        }

        .slider-transparent {
          background: transparent !important;
        }

        .slider-transparent::-webkit-slider-runnable-track {
          background: transparent;
        }

        .slider-transparent::-moz-range-track {
          background: transparent;
        }

        .toggle-track {
          position: relative;
          width: 44px;
          height: 24px;
          border-radius: 12px;
          cursor: pointer;
          transition: background 0.3s;
        }

        .toggle-knob {
          position: absolute;
          top: 3px;
          width: 18px;
          height: 18px;
          border-radius: 50%;
          background: white;
          transition: left 0.3s;
          box-shadow: 0 1px 4px rgba(0,0,0,0.3);
        }

        .card {
          animation: fadeUp 0.4s ease both;
        }

        .pw-display {
          font-family: 'JetBrains Mono', monospace;
          letter-spacing: 2px;
          word-break: break-all;
          text-align: center;
          transition: text-shadow 0.3s;
        }

        .stats-grid {
          display: grid;
          grid-template-columns: 1fr 1fr 1fr;
          gap: 12px;
        }

        .crack-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-top: 18px;
          gap: 12px;
        }

        .crack-meta {
          display: flex;
          align-items: center;
          gap: 8px;
          flex-wrap: wrap;
        }

        @media (max-width: 520px) {
          .stats-grid {
            grid-template-columns: 1fr;
          }
          .crack-row {
            flex-direction: column;
            align-items: flex-start;
          }
          .crack-row .copy-btn {
            width: 100%;
            text-align: center;
          }
        }
      `}</style>

      {/* ── Top bar: GitHub | Logo + Title | Toggle ── */}
      <header style={{
        width: "100%",
        maxWidth: 780,
        display: "grid",
        gridTemplateColumns: "1fr auto 1fr",
        alignItems: "center",
        padding: "24px 20px 0",
        gap: 12,
      }}>
        {/* Left — GitHub */}
        <div style={{ display: "flex", alignItems: "center" }}>
          <a
            href="https://github.com/dotAadarsh"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              display: "flex",
              alignItems: "center",
              gap: 7,
              color: textMuted,
              textDecoration: "none",
              fontSize: "0.72rem",
              fontWeight: 600,
              letterSpacing: "0.06em",
              padding: "6px 12px",
              borderRadius: 8,
              border: `1px solid ${border}`,
              background: dark ? "#12121a" : "#ffffff",
              transition: "color 0.2s, border-color 0.2s",
            }}
            onMouseEnter={e => { e.currentTarget.style.color = text; e.currentTarget.style.borderColor = accent; }}
            onMouseLeave={e => { e.currentTarget.style.color = textMuted; e.currentTarget.style.borderColor = border; }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61-.546-1.385-1.335-1.755-1.335-1.755-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 21.795 24 17.295 24 12c0-6.63-5.37-12-12-12"/>
            </svg>
            GitHub
          </a>
        </div>

        {/* Center — Logo mark + app name */}
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 10 }}>
          <svg width="40" height="40" viewBox="0 0 44 44" fill="none" xmlns="http://www.w3.org/2000/svg">
            <polygon points="22,3 40,12 40,32 22,41 4,32 4,12" fill="#7c3aed22" stroke="#7c3aed" strokeWidth="2"/>
            <polygon points="22,10 34,17 34,27 22,34 10,27 10,17" fill="#7c3aed33" stroke="#a855f7" strokeWidth="1"/>
            <circle cx="22" cy="22" r="5" fill="#7c3aed"/>
            <line x1="22" y1="3" x2="22" y2="17" stroke="#a855f7" strokeWidth="1.2" strokeDasharray="2 2"/>
            <line x1="22" y1="27" x2="22" y2="41" stroke="#a855f7" strokeWidth="1.2" strokeDasharray="2 2"/>
            <line x1="4" y1="12" x2="17" y2="19" stroke="#a855f7" strokeWidth="1.2" strokeDasharray="2 2"/>
            <line x1="27" y1="25" x2="40" y2="32" stroke="#a855f7" strokeWidth="1.2" strokeDasharray="2 2"/>
            <line x1="40" y1="12" x2="27" y2="19" stroke="#a855f7" strokeWidth="1.2" strokeDasharray="2 2"/>
            <line x1="17" y1="25" x2="4" y2="32" stroke="#a855f7" strokeWidth="1.2" strokeDasharray="2 2"/>
          </svg>
          <div style={{ textAlign: "center" }}>
            <h1
              className="entropy-forge-title"
              style={{
                fontSize: "clamp(1rem, 3.5vw, 1.5rem)",
                color: text,
                lineHeight: 1.1,
                letterSpacing: "-0.5px",
              }}
            >
              NOT ANOTHER <span style={{ color: accent }}>PASSWORD</span> GENERATOR
            </h1>
            <p style={{
              color: textMuted,
              marginTop: 5,
              fontSize: "0.62rem",
              letterSpacing: "0.15em",
              textTransform: "uppercase",
            }}>
              Multi-source chaos → cryptographic password
            </p>
          </div>
        </div>

        {/* Right — Theme toggle */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", gap: 8 }}>
          <span style={{ fontSize: "0.75rem", color: textMuted }}>☀</span>
          <div
            className="toggle-track"
            style={{ background: dark ? accent : "#ccc" }}
            onClick={() => setDark(!dark)}
          >
            <div className="toggle-knob" style={{ left: dark ? 23 : 3 }} />
          </div>
          <span style={{ fontSize: "0.75rem", color: textMuted }}>☾</span>
        </div>
      </header>

      {/* Main card */}
      <main style={{
        width: "100%",
        maxWidth: 780,
        padding: "28px 20px 40px",
        display: "flex",
        flexDirection: "column",
        gap: 20,
      }}>

        {/* Entropy status strip */}
        <div className="card stats-grid" style={{ animationDelay: "0.05s" }}>

          {/* ── Entropy Sources card (hoverable) ── */}
          <div
            ref={sourcesCardRef}
            onMouseEnter={handleSourcesEnter}
            onMouseLeave={() => setShowSources(false)}
            style={{
              background: surface,
              border: `1px solid ${showSources ? accent : border}`,
              borderRadius: 10,
              padding: "14px 16px",
              cursor: sourceCount ? "pointer" : "default",
              transition: "border-color 0.2s, box-shadow 0.2s",
              boxShadow: showSources ? `0 0 0 1px ${accent}44, 0 0 16px ${accent}22` : "none",
            }}
          >
            <div style={{ fontSize: "1.1rem", marginBottom: 4 }}>⬡</div>
            <div style={{ fontSize: "0.6rem", color: textMuted, letterSpacing: "0.12em", marginBottom: 4 }}>
              ENTROPY SOURCES
            </div>
            <div style={{ fontSize: "0.85rem", color: accent, fontWeight: 600, display: "flex", alignItems: "center", gap: 5 }}>
              {sourceCount ? `${sourceCount} active` : "—"}
              {sourceCount > 0 && (
                <span style={{ fontSize: "0.5rem", color: textMuted, border: `1px solid ${border}`, borderRadius: 3, padding: "1px 4px" }}>
                  hover
                </span>
              )}
            </div>
          </div>

          {/* ── Mouse Entropy card ── */}
          <div style={{
            background: surface,
            border: `1px solid ${border}`,
            borderRadius: 10,
            padding: "14px 16px",
          }}>
            <div style={{ fontSize: "1.1rem", marginBottom: 4 }}>⟐</div>
            <div style={{ fontSize: "0.6rem", color: textMuted, letterSpacing: "0.12em", marginBottom: 4 }}>
              MOUSE ENTROPY
            </div>
            <div style={{ fontSize: "0.85rem", color: accent, fontWeight: 600 }}>
              {mouseBufferRef.current.length > 0 ? `${Math.min(mouseBufferRef.current.length, 256)} pts` : "Move mouse…"}
            </div>
          </div>

          {/* ── Network Latency card ── */}
          <div style={{
            background: surface,
            border: `1px solid ${border}`,
            borderRadius: 10,
            padding: "14px 16px",
          }}>
            <div style={{ fontSize: "1.1rem", marginBottom: 4 }}>◈</div>
            <div style={{ fontSize: "0.6rem", color: textMuted, letterSpacing: "0.12em", marginBottom: 4 }}>
              NET LATENCY
            </div>
            <div style={{ fontSize: "0.85rem", color: accent, fontWeight: 600 }}>
              {latency !== null ? `${latency}ms` : "—"}
            </div>
          </div>

        </div>

        {/* ── Fixed-position sources popover — never clipped by siblings ── */}
        {showSources && sourceCount > 0 && popoverPos && (
          <div
            onMouseEnter={() => setShowSources(true)}
            onMouseLeave={() => setShowSources(false)}
            style={{
              position: "fixed",
              top: popoverPos.top,
              left: popoverPos.left,
              width: 272,
              zIndex: 9999,
              background: dark ? "#13132200" : "#ffffff00",
              backdropFilter: "blur(16px)",
              WebkitBackdropFilter: "blur(16px)",
              backgroundColor: dark ? "#13132299" : "#ffffffee",
              border: `1px solid ${accent}55`,
              borderRadius: 12,
              padding: "14px 16px",
              boxShadow: `0 16px 48px rgba(0,0,0,0.5), 0 0 0 1px ${accent}22`,
              animation: "fadeUp 0.15s ease both",
            }}
          >
            {/* Arrow pointing up */}
            <div style={{
              position: "absolute",
              top: -6,
              left: 22,
              width: 10,
              height: 10,
              background: dark ? "#1a1a30" : "#ffffff",
              border: `1px solid ${accent}55`,
              borderRight: "none",
              borderBottom: "none",
              transform: "rotate(45deg)",
            }} />

            <div style={{ fontSize: "0.58rem", color: accent, letterSpacing: "0.15em", marginBottom: 10, fontWeight: 700 }}>
              ⬡ ACTIVE ENTROPY SOURCES
            </div>

            {ENTROPY_SOURCE_LABELS.map(({ key, label, icon }) => (
              <div key={key} style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "5px 0",
                borderBottom: `1px solid ${dark ? "#ffffff08" : "#00000008"}`,
              }}>
                <span style={{ fontSize: "0.8rem", width: 18, textAlign: "center", flexShrink: 0 }}>{icon}</span>
                <span style={{ fontSize: "0.65rem", color: text, flex: 1, lineHeight: 1.3 }}>{label}</span>
                <span style={{
                  fontSize: "0.48rem",
                  fontWeight: 700,
                  letterSpacing: "0.08em",
                  color: "#22c55e",
                  background: "#22c55e18",
                  border: "1px solid #22c55e44",
                  borderRadius: 3,
                  padding: "1px 5px",
                  flexShrink: 0,
                }}>
                  LIVE
                </span>
              </div>
            ))}
          </div>
        )}

        {/* Mouse activity bar */}
        <div className="card" style={{
          background: surface,
          border: `1px solid ${border}`,
          borderRadius: 10,
          padding: "14px 18px",
          animationDelay: "0.1s",
        }}>
          <div style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: 8,
          }}>
            <span style={{ fontSize: "0.65rem", color: textMuted, letterSpacing: "0.12em" }}>
              ⟐ LIVE MOUSE ENTROPY
            </span>
            <span style={{ fontSize: "0.75rem", color: mouseActivity > 60 ? accent : textMuted }}>
              {mouseActivity > 0 ? `${mouseActivity}%` : "idle"}
            </span>
          </div>
          <div style={{
            height: 6,
            background: dark ? "#1e1e2e" : "#e8e8f0",
            borderRadius: 3,
            overflow: "hidden",
          }}>
            <div style={{
              height: "100%",
              width: `${mouseActivity}%`,
              background: `linear-gradient(90deg, ${accent}, #c084fc)`,
              borderRadius: 3,
              transition: "width 0.2s ease",
              boxShadow: mouseActivity > 50 ? `0 0 8px ${accent}88` : "none",
            }} />
          </div>
        </div>

        {/* Password display */}
        <div className="card" style={{
          background: surface,
          border: `1px solid ${border}`,
          borderRadius: 12,
          padding: "24px 20px",
          animationDelay: "0.15s",
          position: "relative",
        }}>
          {/* Scanline overlay on dark mode */}
          {dark && (
            <div style={{
              position: "absolute",
              inset: 0,
              background: "repeating-linear-gradient(transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px)",
              pointerEvents: "none",
            }} />
          )}

          <div style={{ position: "relative", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <div
              className="pw-display"
              style={{
                fontSize: "clamp(0.9rem, 2.5vw, 1.2rem)",
                color: text,
                minHeight: 48,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                animation: glitching ? "glitch 0.6s steps(2)" : "none",
                textShadow: glitching ? "2px 0 #ff00ff, -2px 0 #00ffff" : "0 0 32px #b552e0cc, 0 0 64px #b552e044",
                padding: "0 36px 0 8px",
                flex: 1,
                width: "100%",
              }}
            >
              {generating ? (
                <span style={{ color: accent, fontSize: "1.4rem", animation: "spin 0.6s linear infinite", display: "inline-block" }}>⟳</span>
              ) : password
                ? (showPassword ? password : "•".repeat(password.length))
                : placeholder}
            </div>

            {/* Eye toggle — only shown when there's a password */}
            {password && !generating && (
              <button
                onClick={() => setShowPassword(p => !p)}
                title={showPassword ? "Hide password" : "Show password"}
                style={{
                  position: "absolute",
                  right: 0,
                  top: "50%",
                  transform: "translateY(-50%)",
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  padding: "6px",
                  color: showPassword ? accent : textMuted,
                  transition: "color 0.2s",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  borderRadius: 6,
                }}
              >
                {showPassword ? (
                  /* Eye-open SVG */
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                    <circle cx="12" cy="12" r="3"/>
                  </svg>
                ) : (
                  /* Eye-off SVG */
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
                    <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
                    <line x1="1" y1="1" x2="23" y2="23"/>
                  </svg>
                )}
              </button>
            )}
          </div>

          {/* Crack time + copy row */}
          {(() => {
            const crack = password ? estimateCrackTime(password) : null;
            return (
              <>
                {/* Divider */}
                <div style={{ height: 1, background: border, margin: "16px 0 0" }} />

                <div className="crack-row">
                  {/* Crack time info */}
                  <div style={{ display: "flex", flexDirection: "column", gap: 4, flex: 1, minWidth: 0 }}>
                    <span style={{ fontSize: "0.55rem", color: textMuted, letterSpacing: "0.12em" }}>
                      🔓 TIME TO CRACK
                    </span>
                    {crack ? (
                      <div className="crack-meta">
                        <span style={{
                          fontSize: "0.85rem",
                          fontWeight: 700,
                          color: crack.color,
                          textShadow: crack.tier >= 4 ? `0 0 12px ${crack.color}99` : "none",
                          whiteSpace: "nowrap",
                        }}>
                          {crack.label}
                        </span>
                        <span style={{
                          fontSize: "0.52rem",
                          color: textMuted,
                          background: dark ? "#ffffff08" : "#00000008",
                          border: `1px solid ${border}`,
                          borderRadius: 4,
                          padding: "2px 7px",
                          whiteSpace: "nowrap",
                        }}>
                          {crack.bits} bits · pool {crack.pool}
                        </span>
                      </div>
                    ) : (
                      <span style={{ fontSize: "0.75rem", color: textMuted }}>generate a password first</span>
                    )}
                    {crack && (
                      <span style={{ fontSize: "0.5rem", color: textMuted, opacity: 0.55, marginTop: 1 }}>
                        at 100B guesses/sec (GPU cluster)
                      </span>
                    )}
                  </div>

                  {/* Copy button */}
                  <button
                    className="copy-btn"
                    onClick={copyToClipboard}
                    style={{
                      background: copied ? "#22c55e22" : dark ? "#1e1e2e" : "#f0f0f8",
                      color: copied ? "#22c55e" : textMuted,
                      border: `1px solid ${copied ? "#22c55e44" : border}`,
                      borderRadius: 6,
                      padding: "8px 18px",
                      flexShrink: 0,
                    }}
                  >
                    {copied ? "✓ Copied" : "⎘ Copy"}
                  </button>
                </div>

                {/* ── Burn-after-reading countdown ── */}
                {burnTimer !== null && (
                  <div style={{ marginTop: 14 }}>
                    {/* Label row */}
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                      <span style={{ fontSize: "0.58rem", color: "#ef4444", letterSpacing: "0.12em", display: "flex", alignItems: "center", gap: 5 }}>
                        🔥 BURN AFTER READING
                        <span style={{ color: textMuted }}>— clears in</span>
                        <span style={{ fontWeight: 700, color: burnTimer <= 5 ? "#ef4444" : burnTimer <= 10 ? "#f97316" : "#eab308", fontSize: "0.65rem" }}>
                          {burnTimer}s
                        </span>
                      </span>
                      <button
                        onClick={cancelBurn}
                        style={{
                          background: "none", border: `1px solid ${border}`, borderRadius: 4,
                          color: textMuted, fontSize: "0.55rem", padding: "2px 7px",
                          cursor: "pointer", letterSpacing: "0.06em",
                        }}
                      >
                        cancel
                      </button>
                    </div>

                    {/* Progress bar — drains left to right */}
                    <div style={{ height: 4, background: dark ? "#1e1e2e" : "#e8e8f0", borderRadius: 2, overflow: "hidden" }}>
                      <div style={{
                        height: "100%",
                        width: `${(burnTimer / 30) * 100}%`,
                        borderRadius: 2,
                        transition: "width 1s linear, background 1s",
                        background: burnTimer <= 5
                          ? "#ef4444"
                          : burnTimer <= 10
                          ? "linear-gradient(90deg, #ef4444, #f97316)"
                          : "linear-gradient(90deg, #f97316, #eab308)",
                        boxShadow: burnTimer <= 5 ? "0 0 8px #ef444488" : "none",
                      }} />
                    </div>
                  </div>
                )}
              </>
            );
          })()}
        </div>

        {/* Length slider */}
        <div className="card" style={{
          background: surface,
          border: `1px solid ${border}`,
          borderRadius: 10,
          padding: "16px 18px",
          animationDelay: "0.25s",
        }}>
          <div style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: 12,
          }}>
            <span style={{ fontSize: "0.65rem", color: textMuted, letterSpacing: "0.12em" }}>
              ≡ PASSWORD LENGTH
            </span>
            <span style={{
              fontSize: "0.85rem",
              fontWeight: 700,
              color: length <= 12 ? "#ef4444" : length <= 30 ? accent : "#581c87",
            }}>
              {length} chars · {length <= 12 ? "⚠ Weak" : length <= 30 ? "✦ Strong" : "🏰 Fortress"}
            </span>
          </div>

          {/* Color-zoned track behind the slider */}
          <div style={{ position: "relative", height: 28, display: "flex", alignItems: "center" }}>
            {/* Zone track (visual only, behind slider) */}
            <div style={{
              position: "absolute",
              left: 0, right: 0,
              height: 6,
              borderRadius: 3,
              overflow: "hidden",
              display: "flex",
              pointerEvents: "none",
            }}>
              {/* Weak zone: 6–12 → (12-6)/(64-6) = 6/58 ≈ 10.3% */}
              <div style={{ width: `${(6/58)*100}%`, background: "linear-gradient(90deg, #ef4444, #f97316)" }} />
              {/* Moderate zone: 12–13 → 1/58 ≈ 1.7% */}
              <div style={{ width: `${(1/58)*100}%`, background: "#eab308" }} />
              {/* Strong zone: 13–30 → 17/58 ≈ 29.3% */}
              <div style={{ width: `${(17/58)*100}%`, background: "linear-gradient(90deg, #a855f7, #7c3aed)" }} />
              {/* Fortress zone: 30–64 → 34/58 ≈ 58.6% */}
              <div style={{ flex: 1, background: "linear-gradient(90deg, #581c87, #3b0764)" }} />
            </div>

            {/* Actual range input layered on top, transparent track */}
            <input
              type="range"
              className="slider slider-transparent"
              min={6}
              max={64}
              value={length}
              onChange={(e) => { setLength(Number(e.target.value)); setPassword(""); setShowPassword(false); }}
              style={{ position: "relative", zIndex: 1, width: "100%", background: "transparent" }}
            />
          </div>

          {/* Zone labels only */}
          <div style={{ display: "flex", marginTop: 6, fontSize: "0.52rem", letterSpacing: "0.06em" }}>
            <span style={{ color: "#ef4444", width: `${(6/58)*100}%` }}>WEAK</span>
            <span style={{ color: "#a855f7", width: `${(18/58)*100}%`, textAlign: "center" }}>STRONG</span>
            <span style={{ color: "#581c87", flex: 1, textAlign: "right" }}>FORTRESS</span>
          </div>
        </div>

        {/* Generate button */}
        <button
          className="generate-btn card"
          onClick={generate}
          disabled={generating}
          style={{
            background: `linear-gradient(135deg, ${accent}, #a855f7)`,
            color: "white",
            padding: "18px 32px",
            borderRadius: 12,
            fontSize: "1.05rem",
            boxShadow: generating ? "none" : `0 4px 24px ${accent}66, 0 0 0 0 ${accent}`,
            animation: !generating ? "pulse-ring 2.5s ease infinite" : "none",
            animationDelay: "0.3s",
          }}
        >
          {generating ? (
            <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10 }}>
              <span style={{ animation: "spin 0.6s linear infinite", display: "inline-block" }}>⟳</span>
              Harvesting Chaos…
            </span>
          ) : "⚡ Generate from Chaos"}
        </button>

        {/* Footer note */}
        <div style={{ textAlign: "center", display: "flex", flexDirection: "column", gap: 10, paddingBottom: 8 }}>
          <p style={{
            fontSize: "0.62rem",
            color: textMuted,
            letterSpacing: "0.08em",
            lineHeight: 1.6,
          }}>
            All entropy computed locally via Web Crypto API · No data leaves your device · Math.random() never used
          </p>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 14, flexWrap: "wrap" }}>
            <p style={{ fontSize: "0.62rem", color: textMuted, letterSpacing: "0.06em" }}>
              Built by{" "}
              <a href="https://x.com/dotAadarsh" target="_blank" rel="noopener noreferrer"
                style={{ color: accent, textDecoration: "none", fontWeight: 600 }}>
                @dotAadarsh
              </a>
            </p>
            <span style={{ color: border, fontSize: "0.6rem" }}>·</span>
            <a href="https://buymeachai.ezee.li/dotaadarsh" target="_blank" rel="noopener noreferrer">
              <img
                src="https://buymeachai.ezee.li/assets/images/buymeachai-button.png"
                alt="Buy Me A Chai"
                style={{ height: 28, width: "auto", display: "block", borderRadius: 6 }}
              />
            </a>
          </div>
        </div>
      </main>
    </div>
  );
}
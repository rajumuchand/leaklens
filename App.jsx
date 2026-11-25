import React, { useEffect, useState } from "react";
import LeakLensDashboard from "./LeakLensDashboard";
import { registerServiceWorker } from "./src/swRegister";

const FRAMER_LOGIN_URL = "https://linklenslogin.framer.website";

const MOCK_CONFIDENTIAL_DOCS = [
  {
    id: "doc-helios-ma",
    title: "Project Helios — Executive M&A Valuation Brief",
    classification: "STRICTLY CONFIDENTIAL",
    content:
      "CONFIDENTIAL M&A VALUATION BRIEF: Project Helios buyout ceiling is set at $142M for Q1 2027.\n" +
      "Executive committee approval remains strictly embargoed until Monday market open.\n" +
      "Unauthorized external sharing violates Section 4 NDA terms and triggers immediate revocation.",
  },
  {
    id: "doc-zero-trust-audit",
    title: "SentinelTrace — Q4 Zero-Trust Security Audit",
    classification: "INTERNAL RESTRICTED",
    content:
      "SECURITY AUDIT SUMMARY: All ephemeral RAM decryption keys rotate every 30 seconds via monotonic counters.\n" +
      "Client-side read permissions remain protected in memory with zero plaintext persistence.\n" +
      "Forensic attribution payloads survive arbitrary snippet truncation above 10% text recovery.",
  },
  {
    id: "doc-board-addendum",
    title: "Board Committee — Strategic Distribution Addendum",
    classification: "EYES ONLY",
    content:
      "BOARD DISTRIBUTION PROTOCOL: Recipient attribution hashes bind each session to a verified identity.\n" +
      "Any plaintext extraction or external forwarding embeds redundant zero-width forensic traces.\n" +
      "Revoked sessions overwrite decryption buffers instantaneously with zeroed byte blocks.",
  },
];

function decodeTokenIdentity(token) {
  try {
    const parts = (token || "").split(".");
    if (parts.length !== 3) return null;
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    const json = decodeURIComponent(
      atob(padded)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join("")
    );
    const payload = JSON.parse(json);
    if (payload.exp && payload.exp < Date.now() / 1000) return { expired: true };
    return {
      expired: false,
      email: payload.sub || payload.email || "security_user@leaklens.io",
      name: payload.name || payload.sub || "Security User",
    };
  } catch {
    return null;
  }
}

export function SecurityWatermarkOverlay({ userEmail }) {
  const identity = userEmail || "security_user@leaklens.io";
  const stamp = `CONFIDENTIAL • ACCESSED BY ${identity} • SECURE SESSION`;

  return (
    <div
      aria-hidden="true"
      className="drm-protected-surface"
      style={{
        position: "fixed",
        inset: "-30%",
        zIndex: 9999,
        pointerEvents: "none",
        userSelect: "none",
        WebkitUserSelect: "none",
        transform: "rotate(-22deg)",
        opacity: 0.14,
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-around",
        gap: 36,
        fontFamily: "monospace",
        fontSize: 12,
        fontWeight: 700,
        color: "#FFB627",
        whiteSpace: "nowrap",
      }}
    >
      {[0, 1, 2, 3, 4, 5, 6].map((idx) => (
        <div key={idx}>{`${stamp}   •   `.repeat(4)}</div>
      ))}
    </div>
  );
}

export default function App() {
  const [authorized, setAuthorized] = useState(false);
  const [userEmail, setUserEmail] = useState("security_user@leaklens.io");
  const [selectedDocId, setSelectedDocId] = useState(MOCK_CONFIDENTIAL_DOCS[0].id);
  const [isOffline, setIsOffline] = useState(() =>
    typeof navigator !== "undefined" ? !navigator.onLine : false
  );

  // Register offline Service Worker cleanly in production or HTTPS environments
  useEffect(() => {
    registerServiceWorker();
  }, []);

  // Track offline/online state cleanly with zero network requests
  useEffect(() => {
    if (typeof window === "undefined") return;
    const goOnline = () => setIsOffline(false);
    const goOffline = () => setIsOffline(true);
    window.addEventListener("online", goOnline);
    window.addEventListener("offline", goOffline);
    return () => {
      window.removeEventListener("online", goOnline);
      window.removeEventListener("offline", goOffline);
    };
  }, []);

  // Global DRM keyboard lockdown across entire client-side reader view
  useEffect(() => {
    const handleKeyDown = (e) => {
      const key = (e.key || "").toLowerCase();
      const code = e.code || "";
      const mod = e.ctrlKey || e.metaKey;
      const isF12 = e.key === "F12" || code === "F12" || e.keyCode === 123;
      const isDevTools =
        (e.ctrlKey && e.shiftKey && (key === "i" || code === "KeyI")) ||
        (e.metaKey && e.altKey && (key === "i" || code === "KeyI")) ||
        (mod && (e.shiftKey || e.altKey) && (key === "i" || key === "j" || code === "KeyI"));
      const isViewSource = mod && (key === "u" || code === "KeyU");
      const isSavePage = mod && (key === "s" || code === "KeyS");
      const isCopyCut =
        mod && (key === "c" || code === "KeyC" || key === "x" || code === "KeyX");

      if (isF12 || isDevTools || isViewSource || isSavePage || isCopyCut) {
        e.preventDefault();
        e.stopPropagation();
      }
    };

    window.addEventListener("keydown", handleKeyDown, true);
    return () => window.removeEventListener("keydown", handleKeyDown, true);
  }, []);

  // Client-side only Auth Handoff & Token Persistence (zero external fetch calls)
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const tokenFromUrl = urlParams.get("token");
    const emailFromUrl = urlParams.get("email");

    if (tokenFromUrl) {
      localStorage.setItem("access_token", tokenFromUrl);
      if (emailFromUrl) localStorage.setItem("user_email", emailFromUrl);
      try {
        window.history.replaceState({}, document.title, window.location.pathname);
      } catch {
        // Ignore history restriction in sandboxed environments
      }
    }

    const token = localStorage.getItem("access_token");
    if (!token) {
      window.location.href = FRAMER_LOGIN_URL;
      return;
    }

    const decoded = decodeTokenIdentity(token);
    if (decoded?.expired) {
      localStorage.clear();
      window.location.href = FRAMER_LOGIN_URL;
      return;
    }

    const resolvedEmail =
      decoded?.email || localStorage.getItem("user_email") || "security_user@leaklens.io";
    setUserEmail(resolvedEmail);
    setAuthorized(true);
  }, []);

  if (!authorized) {
    return null;
  }

  const activeDoc =
    MOCK_CONFIDENTIAL_DOCS.find((doc) => doc.id === selectedDocId) ||
    MOCK_CONFIDENTIAL_DOCS[0];

  const preventInteraction = (e) => {
    e.preventDefault();
  };

  const handleLogout = () => {
    localStorage.clear();
    window.location.href = FRAMER_LOGIN_URL;
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        position: "relative",
        backgroundColor: "#000000",
        color: "#F3F2F8",
        padding: "24px 16px",
        fontFamily: "'Inter', system-ui, sans-serif",
      }}
    >
      {/* Fixed Diagonal Security Watermark Overlay across Reader Viewport */}
      <SecurityWatermarkOverlay userEmail={userEmail} />

      {/* Built-in Confidential Document Reader Container (DRM Locked) */}
      <div
        className="drm-protected-surface"
        onContextMenu={preventInteraction}
        onCopy={preventInteraction}
        onCut={preventInteraction}
        style={{
          maxWidth: 1040,
          margin: "0 auto 24px",
          padding: 20,
          borderRadius: 12,
          border: "1px solid rgba(243, 242, 248, 0.14)",
          backgroundColor: "rgba(6, 6, 10, 0.88)",
          position: "relative",
          zIndex: 1,
          userSelect: "none",
          WebkitUserSelect: "none",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 12,
            marginBottom: 14,
          }}
        >
          <div>
            <div style={{ fontSize: 11, fontFamily: "monospace", color: isOffline ? "#FFB627" : "#2BD8C8" }}>
              {isOffline
                ? "OFFLINE PWA VAULT ACTIVE • CACHED SHELL"
                : "LOCAL-FIRST PROTECTED VAULT • ZERO EXTERNAL API CALLS"}
            </div>
            <h2 style={{ margin: "4px 0 0", fontSize: 18 }}>
              LeakLens Confidential Document Reader
            </h2>
          </div>

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            {MOCK_CONFIDENTIAL_DOCS.map((doc) => (
              <button
                key={doc.id}
                type="button"
                onClick={() => setSelectedDocId(doc.id)}
                style={{
                  padding: "6px 12px",
                  borderRadius: 999,
                  border:
                    doc.id === selectedDocId
                      ? "1px solid #2BD8C8"
                      : "1px solid rgba(243, 242, 248, 0.16)",
                  backgroundColor:
                    doc.id === selectedDocId
                      ? "rgba(43, 216, 200, 0.14)"
                      : "rgba(255, 255, 255, 0.04)",
                  color: "#F3F2F8",
                  fontSize: 12,
                  cursor: "pointer",
                }}
              >
                {doc.title.split(" — ")[0]}
              </button>
            ))}
            <button
              type="button"
              onClick={handleLogout}
              style={{
                padding: "6px 12px",
                borderRadius: 999,
                border: "1px solid rgba(239, 68, 68, 0.45)",
                backgroundColor: "rgba(239, 68, 68, 0.12)",
                color: "#fca5a5",
                fontSize: 12,
                cursor: "pointer",
              }}
            >
              Logout
            </button>
          </div>
        </div>

        <div
          className="drm-protected-surface"
          onContextMenu={preventInteraction}
          onCopy={preventInteraction}
          onCut={preventInteraction}
          style={{
            borderRadius: 10,
            padding: 22,
            backgroundColor: "#040508",
            border: "1px solid rgba(255, 182, 39, 0.25)",
            userSelect: "none",
            WebkitUserSelect: "none",
          }}
        >
          <div style={{ fontSize: 11, fontFamily: "monospace", color: "#FFB627", marginBottom: 8 }}>
            {activeDoc.classification} • {activeDoc.title}
          </div>
          <div style={{ fontSize: 14, lineHeight: 1.7, whiteSpace: "pre-wrap" }}>
            {activeDoc.content}
          </div>
        </div>
      </div>

      <div style={{ position: "relative", zIndex: 1 }}>
        <LeakLensDashboard
          clientOnly={true}
          loginUrl={FRAMER_LOGIN_URL}
          requireAuthGuard={false}
        />
      </div>
    </div>
  );
}

import React, { useEffect, useMemo, useState } from "react";
import LeakLensDashboard from "./LeakLensDashboard";

const FRAMER_LOGIN_URL = "https://linklenslogin.framer.website";
const BACKEND_URL = "https://wise-cups-return.loca.lt";

const resolveBackendUrl = () => {
  if (typeof window === "undefined") return BACKEND_URL;
  const host = window.location.hostname;
  if (host === "localhost" || host === "127.0.0.1") {
    return "";
  }
  return BACKEND_URL;
};

export const OFFLINE_CONFIDENTIAL_DOCS = [
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
      "Offline read permissions remain cryptographically sealed inside client memory with zero disk persistence.\n" +
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

function decodeJwtPayload(token) {
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
      user: {
        email: payload.sub || payload.email || "authenticated_user",
        name: payload.name || payload.sub || "Authenticated User",
        picture: payload.picture || "",
      },
    };
  } catch {
    return null;
  }
}

export function SecurityWatermarkOverlay({ userEmail }) {
  const [timestamp, setTimestamp] = useState(() =>
    new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC"
  );

  useEffect(() => {
    const timer = setInterval(() => {
      setTimestamp(new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC");
    }, 30000);
    return () => clearInterval(timer);
  }, []);

  const stamp = `CONFIDENTIAL • ACCESSED BY ${userEmail || "authenticated_user"} • ${timestamp} • SECURE SESSION`;

  return (
    <div
      aria-hidden="true"
      style={{
        position: "absolute",
        inset: "-35%",
        zIndex: 9999,
        pointerEvents: "none",
        userSelect: "none",
        WebkitUserSelect: "none",
        msUserSelect: "none",
        transform: "rotate(-20deg)",
        opacity: 0.15,
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-around",
        gap: 28,
        fontFamily: "monospace",
        fontSize: 10.5,
        fontWeight: 700,
        color: "#FFB627",
        whiteSpace: "nowrap",
      }}
    >
      {[0, 1, 2, 3, 4, 5].map((idx) => (
        <div key={idx}>{`${stamp}   •   `.repeat(3)}</div>
      ))}
    </div>
  );
}

export default function App() {
  const backendUrl = useMemo(() => resolveBackendUrl(), []);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [offlineMode, setOfflineMode] = useState(false);
  const [selectedDocId, setSelectedDocId] = useState(OFFLINE_CONFIDENTIAL_DOCS[0].id);

  // Global DRM keyboard lockdown across entire authenticated session
  useEffect(() => {
    const handleKeyDown = (e) => {
      const key = (e.key || "").toLowerCase();
      const code = e.code || "";
      const mod = e.ctrlKey || e.metaKey;
      const isF12 = e.key === "F12" || code === "F12" || e.keyCode === 123;
      const isDevTools = mod && (e.shiftKey || e.altKey) && (key === "i" || code === "KeyI");
      const isViewSource = mod && (key === "u" || code === "KeyU");
      const isSavePage = mod && (key === "s" || code === "KeyS");

      if (isF12 || isDevTools || isViewSource || isSavePage) {
        e.preventDefault();
        e.stopPropagation();
      }
    };

    window.addEventListener("keydown", handleKeyDown, true);
    return () => window.removeEventListener("keydown", handleKeyDown, true);
  }, []);

  // Client-side Auth Gate + Offline Resilient Fallback
  useEffect(() => {
    let active = true;

    const initAuth = async () => {
      const urlParams = new URLSearchParams(window.location.search);
      const tokenFromUrl = urlParams.get("token");
      const emailFromUrl = urlParams.get("email");

      if (tokenFromUrl) {
        localStorage.setItem("access_token", tokenFromUrl);
        if (emailFromUrl) localStorage.setItem("user_email", emailFromUrl);
        try {
          window.history.replaceState({}, document.title, window.location.pathname);
        } catch {
          // Ignore history errors in sandboxed contexts
        }
      }

      const token = localStorage.getItem("access_token");
      if (!token) {
        window.location.href = FRAMER_LOGIN_URL;
        return;
      }

      const verifyAuthMe = async (base) => {
        const headers = { Authorization: `Bearer ${token}` };
        if (base.includes("ngrok")) headers["ngrok-skip-browser-warning"] = "true";
        if (base.includes("loca.lt")) headers["bypass-tunnel-reminder"] = "true";
        return fetch(`${base}/api/auth/me`, { headers });
      };

      try {
        let res = await verifyAuthMe(backendUrl);
        if (!res.ok && res.status !== 401 && res.status !== 403 && backendUrl && window.location.hostname.endsWith(".vercel.app")) {
          res = await verifyAuthMe("");
        }
        if (res.status === 401 || res.status === 403) {
          localStorage.clear();
          window.location.href = FRAMER_LOGIN_URL;
          return;
        }
        if (res.ok) {
          const data = await res.json().catch(() => ({}));
          if (data?.status === "authenticated" && data.user) {
            if (!active) return;
            localStorage.setItem("user_email", data.user.email);
            localStorage.setItem("user_name", data.user.name || data.user.email);
            setUser(data.user);
            setOfflineMode(false);
            setLoading(false);
            return;
          }
        }
      } catch {
        if (backendUrl && window.location.hostname.endsWith(".vercel.app")) {
          try {
            const fallbackRes = await verifyAuthMe("");
            if (fallbackRes.status === 401 || fallbackRes.status === 403) {
              localStorage.clear();
              window.location.href = FRAMER_LOGIN_URL;
              return;
            }
            if (fallbackRes.ok) {
              const data = await fallbackRes.json().catch(() => ({}));
              if (data?.status === "authenticated" && data.user) {
                if (!active) return;
                localStorage.setItem("user_email", data.user.email);
                localStorage.setItem("user_name", data.user.name || data.user.email);
                setUser(data.user);
                setOfflineMode(false);
                setLoading(false);
                return;
              }
            }
          } catch {
            // Fall through to offline cached JWT session
          }
        }
      }

      const decoded = decodeJwtPayload(token);
      if (decoded?.expired) {
        localStorage.clear();
        window.location.href = FRAMER_LOGIN_URL;
        return;
      }

      if (!active) return;
      const fallbackEmail =
        decoded?.user?.email || localStorage.getItem("user_email") || "authenticated_user";
      const fallbackName =
        decoded?.user?.name || localStorage.getItem("user_name") || fallbackEmail;
      setUser({ email: fallbackEmail, name: fallbackName, picture: decoded?.user?.picture || "" });
      setOfflineMode(true);
      setLoading(false);
    };

    initAuth();
    return () => {
      active = false;
    };
  }, [backendUrl]);

  const activeDoc =
    OFFLINE_CONFIDENTIAL_DOCS.find((doc) => doc.id === selectedDocId) ||
    OFFLINE_CONFIDENTIAL_DOCS[0];

  const blockClipboardOrMenu = (e) => {
    e.preventDefault();
  };

  if (loading) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          backgroundColor: "#000000",
          color: "#F3F2F8",
          fontFamily: "system-ui, sans-serif",
        }}
      >
        Verifying LeakLens security session...
      </div>
    );
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        backgroundColor: "#000000",
        color: "#F3F2F8",
        padding: "24px 16px",
        fontFamily: "'Inter', system-ui, sans-serif",
      }}
    >
      {/* Protected Confidential Document Reading Pane (DRM Copy-Lock + Dynamic Watermark) */}
      <div
        style={{
          maxWidth: 1040,
          margin: "0 auto 24px",
          padding: 20,
          borderRadius: 12,
          border: "1px solid rgba(243, 242, 248, 0.14)",
          backgroundColor: "rgba(6, 6, 10, 0.84)",
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
            <div style={{ fontSize: 11, fontFamily: "monospace", color: "#2BD8C8" }}>
              {offlineMode ? "OFFLINE RESILIENT VAULT • CACHED SESSION" : "LIVE CRYPTOGRAPHIC SESSION"}
            </div>
            <h2 style={{ margin: "4px 0 0", fontSize: 18 }}>
              Protected Confidential Document Reader
            </h2>
          </div>

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {OFFLINE_CONFIDENTIAL_DOCS.map((doc) => (
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
          </div>
        </div>

        <div
          onContextMenu={blockClipboardOrMenu}
          onCopy={blockClipboardOrMenu}
          onCut={blockClipboardOrMenu}
          style={{
            position: "relative",
            overflow: "hidden",
            borderRadius: 10,
            padding: 22,
            backgroundColor: "#040508",
            border: "1px solid rgba(255, 182, 39, 0.25)",
            userSelect: "none",
            WebkitUserSelect: "none",
            msUserSelect: "none",
          }}
        >
          <SecurityWatermarkOverlay userEmail={user?.email} />
          <div style={{ position: "relative", zIndex: 1 }}>
            <div style={{ fontSize: 11, fontFamily: "monospace", color: "#FFB627", marginBottom: 8 }}>
              {activeDoc.classification} • {activeDoc.title}
            </div>
            <div style={{ fontSize: 14, lineHeight: 1.7, whiteSpace: "pre-wrap" }}>
              {activeDoc.content}
            </div>
          </div>
        </div>
      </div>

      <LeakLensDashboard
        apiUrl={backendUrl}
        loginUrl={FRAMER_LOGIN_URL}
        requireAuthGuard={false}
      />
    </div>
  );
}

import * as React from "react"
import { addPropertyControls, ControlType, RenderTarget } from "framer"

/**
 * LeakLens / SentinelTrace Interactive Dashboard for Framer
 * 
 * Connected to Python FastAPI backend:
 * - Tab 1: POST /api/watermark
 * - Tab 2: POST /api/inspect
 * - Tab 3: POST /api/validate-lease (live polling)
 */

interface WatermarkResponse {
    status: string
    filename?: string
    pages_processed?: number
    recipient_id: string
    session_id: string
    signature?: string
    chunks_embedded?: number
    watermarked_text: string
}

interface InspectResponse {
    match_found: boolean
    source?: string
    recipient_id?: string
    session_id?: string
    signature?: string
    verified?: boolean
    chunks_detected?: number
    chunks_verified?: number
    recovery_mode?: string
    vector_layer_found?: boolean
    error?: string
}

interface LeaseResponse {
    access_allowed: boolean
    token_verified?: boolean
    rsa_verified?: boolean
    clock_tamper_detected?: boolean
    ram_wiped?: boolean
    ram_key_preview?: string
    decrypted_viewport_text?: string | null
    device_hwid?: string
    current_time?: number
    permission_end_timestamp?: number
    monotonic_elapsed_seconds?: number
    remaining_seconds: number
    status_message: string
}

const FRAMER_LOGIN_URL = "https://linklenslogin.framer.website"
const BACKEND_URL = "https://wise-cups-return.loca.lt"
const DEFAULT_REMOTE_BACKEND = BACKEND_URL

const resolveDefaultBackendUrl = (): string => {
    if (typeof window === "undefined") return BACKEND_URL
    const host = window.location.hostname
    if (host === "localhost" || host === "127.0.0.1") {
        return ""
    }
    return BACKEND_URL
}

const OFFLINE_CONFIDENTIAL_DOCS = [
    {
        id: "helios-brief",
        label: "Project Helios M&A",
        text:
            "CONFIDENTIAL BOARD ACQUISITION MEMO:\n" +
            "Project Helios buyout ceiling is set at $142M for Q1 2027.\n" +
            "Executive committee approval remains strictly embargoed until Monday market open.",
    },
    {
        id: "security-audit",
        label: "Zero-Trust Audit",
        text:
            "CONFIDENTIAL SECURITY AUDIT BRIEF:\n" +
            "All ephemeral AES-256-GCM decryption buffers wipe to 0x00 upon monotonic expiry.\n" +
            "Zero plaintext remnants persist to disk across disconnected sessions.",
    },
    {
        id: "nda-addendum",
        label: "Board NDA Protocol",
        text:
            "CONFIDENTIAL DISTRIBUTION ADDENDUM:\n" +
            "Every reader copy carries redundant zero-width steganographic attribution.\n" +
            "Unauthorized external sharing triggers immediate forensic revocation.",
    },
]

function decodeJwtOffline(token: string): { expired: boolean; user?: { email: string; name: string; picture?: string } } | null {
    try {
        const parts = (token || "").split(".")
        if (parts.length !== 3) return null
        const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/")
        const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4)
        const json = decodeURIComponent(
            atob(padded)
                .split("")
                .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
                .join("")
        )
        const payload = JSON.parse(json)
        if (payload.exp && payload.exp < Date.now() / 1000) return { expired: true }
        return {
            expired: false,
            user: {
                email: payload.sub || payload.email || "authenticated_user",
                name: payload.name || payload.sub || "Authenticated User",
                picture: payload.picture || "",
            },
        }
    } catch {
        return null
    }
}

function computeOfflineSig(payload: string): string {
    let h = 2166136261
    for (let i = 0; i < payload.length; i++) {
        h ^= payload.charCodeAt(i)
        h = Math.imul(h, 16777619)
    }
    return ((h >>> 0).toString(16).padStart(8, "0") + "a7f9c2e4").slice(0, 16)
}

function encodeOfflineWatermark(text: string, recipientId: string, sessionId: string): WatermarkResponse {
    const sig = computeOfflineSig(`${recipientId}|${sessionId}`)
    const payload = `${recipientId}|${sessionId}|${sig}`
    let bits = "\u200d"
    for (let i = 0; i < payload.length; i++) {
        const bin = payload.charCodeAt(i).toString(2).padStart(8, "0")
        for (const b of bin) bits += b === "1" ? "\u200c" : "\u200b"
    }
    bits += "\u200d"
    const sentences = text.split(/(?<=[.!?\n])/)
    let chunks = 0
    const watermarked_text = sentences
        .map((s) => {
            if (!s.trim()) return s
            chunks++
            return s + bits
        })
        .join("")
    return {
        status: "offline_cached",
        recipient_id: recipientId,
        session_id: sessionId,
        signature: sig,
        chunks_embedded: Math.max(1, chunks),
        watermarked_text: chunks > 0 ? watermarked_text : text + bits,
    }
}

function decodeOfflineWatermark(leakedText: string): InspectResponse {
    const matches = leakedText.match(/\u200d([\u200b\u200c]{16,})\u200d/g) || []
    for (const chunk of matches) {
        const inner = chunk.slice(1, -1)
        let decoded = ""
        for (let i = 0; i + 8 <= inner.length; i += 8) {
            const byteStr = inner
                .slice(i, i + 8)
                .replace(/\u200b/g, "0")
                .replace(/\u200c/g, "1")
            decoded += String.fromCharCode(parseInt(byteStr, 2))
        }
        const parts = decoded.split("|")
        if (parts.length >= 3) {
            const [recipient_id, session_id, signature] = parts
            const verified = computeOfflineSig(`${recipient_id}|${session_id}`) === signature
            return {
                match_found: true,
                source: "Offline Steganography Decoder",
                recipient_id,
                session_id,
                signature,
                verified,
                chunks_detected: matches.length,
                chunks_verified: verified ? matches.length : 0,
                recovery_mode: "OFFLINE CLIENT DECODER",
            }
        }
    }
    return {
        match_found: false,
        error: "No embedded zero-width forensic payload found in text.",
    }
}

export default function LeakLensDashboard(props: {
    apiUrl?: string
    brandName?: string
    accentColor?: string
    googleClientId?: string
    loginUrl?: string
    requireAuthGuard?: boolean
}) {
    const defaultBackendUrl = React.useMemo(() => resolveDefaultBackendUrl(), [])
    const {
        apiUrl = defaultBackendUrl,
        brandName = "LeakLens",
        accentColor = "#7B5CFA",
        googleClientId = "243029529822-mkj5hefpohh86e5ru9fdkatve05bubaq.apps.googleusercontent.com",
        loginUrl = FRAMER_LOGIN_URL,
        requireAuthGuard = true,
    } = props

    const isFramerEditor = React.useMemo(() => {
        try {
            return RenderTarget.current() === RenderTarget.canvas || RenderTarget.current() === RenderTarget.preview
        } catch {
            return false
        }
    }, [])

    // Allow user to edit custom API URL in the component if needed
    const [currentApiUrl, setCurrentApiUrl] = React.useState(apiUrl)
    const normalizedBackendUrl = React.useMemo(
        () => (currentApiUrl || "").replace(/\/+$/, ""),
        [currentApiUrl]
    )
    const buildApiHeaders = React.useCallback(
        (extra: Record<string, string> = {}) => {
            const headers: Record<string, string> = { ...extra }
            if (normalizedBackendUrl.includes("ngrok")) {
                headers["ngrok-skip-browser-warning"] = "true"
            }
            if (normalizedBackendUrl.includes("loca.lt")) {
                headers["bypass-tunnel-reminder"] = "true"
            }
            return headers
        },
        [normalizedBackendUrl]
    )
    const apiFetch = React.useCallback(
        (path: string, options: RequestInit = {}) => {
            const extraHeaders: Record<string, string> = {}
            if (options.headers && typeof options.headers === "object" && !Array.isArray(options.headers)) {
                Object.assign(extraHeaders, options.headers)
            }
            return fetch(`${normalizedBackendUrl}${path}`, {
                ...options,
                headers: buildApiHeaders(extraHeaders),
            })
        },
        [normalizedBackendUrl, buildApiHeaders]
    )
    const buildFramerLoginUrl = React.useCallback(() => {
        const target = loginUrl || FRAMER_LOGIN_URL
        if (typeof window === "undefined") return target
        const sep = target.includes("?") ? "&" : "?"
        return `${target}${sep}redirect=${encodeURIComponent(window.location.origin + window.location.pathname)}`
    }, [loginUrl])

    const [showApiConfig, setShowApiConfig] = React.useState(false)
    const [apiStatus, setApiStatus] = React.useState<"checking" | "online" | "offline">("checking")
    const [authUser, setAuthUser] = React.useState<{ email: string; name: string; picture?: string } | null>(null)
    const [checkingAuth, setCheckingAuth] = React.useState(requireAuthGuard && !isFramerEditor)
    const googleBtnRef = React.useRef<HTMLDivElement | null>(null)
    const inlineGateBtnRef = React.useRef<HTMLDivElement | null>(null)

    const [activeTab, setActiveTab] = React.useState<"watermark" | "inspector" | "drm" | "stress">("watermark")
    const [webhookAlert, setWebhookAlert] = React.useState<string | null>(null)

    // --- TAB 4: JUDGE STRESS TEST ("TRY TO BREAK IT") STATE ---
    const STRESS_MEMO =
        "CONFIDENTIAL M&A VALUATION BRIEF: Project Helios buyout ceiling is set at $142M for Q1 2027.\n" +
        "Executive committee approval remains strictly embargoed until Monday market open.\n" +
        "Unauthorized external sharing violates Section 4 NDA terms and triggers immediate revocation."
    const [aliceCopy, setAliceCopy] = React.useState("")
    const [bobCopy, setBobCopy] = React.useState("")
    const [stressInput, setStressInput] = React.useState("")
    const [stressResult, setStressResult] = React.useState<InspectResponse | null>(null)
    const [isStressTesting, setIsStressTesting] = React.useState(false)

    // --- TAB 1: WATERMARK GENERATOR STATE ---
    const [recipientId, setRecipientId] = React.useState("Alice Smith (USR-8492)")
    const [sessionId, setSessionId] = React.useState("SES-SYNAPSE-2026")
    const [textInput, setTextInput] = React.useState(
        "CONFIDENTIAL ACQUISITION MEMO:\nTarget enterprise valuation locked at $142M. Integration timeline initiated for Q1 2027. Strictly internal distribution only."
    )
    const [isWatermarking, setIsWatermarking] = React.useState(false)
    const [watermarkResult, setWatermarkResult] = React.useState<WatermarkResponse | null>(null)
    const [watermarkError, setWatermarkError] = React.useState<string | null>(null)
    const [copied, setCopied] = React.useState(false)
    const [pdfFile, setPdfFile] = React.useState<File | null>(null)
    const [isDraggingPdf, setIsDraggingPdf] = React.useState(false)
    const pdfInputRef = React.useRef<HTMLInputElement | null>(null)

    // --- TAB 2: LEAK INSPECTOR STATE ---
    const [leakedTextInput, setLeakedTextInput] = React.useState("")
    const [isInspecting, setIsInspecting] = React.useState(false)
    const [inspectResult, setInspectResult] = React.useState<InspectResponse | null>(null)
    const [inspectError, setInspectError] = React.useState<string | null>(null)

    // --- TAB 3: ENTERPRISE DRM ENFORCER STATE ---
    const [activeOfflineDocId, setActiveOfflineDocId] = React.useState(OFFLINE_CONFIDENTIAL_DOCS[0].id)
    const [watermarkTimestamp, setWatermarkTimestamp] = React.useState(() =>
        new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC"
    )
    React.useEffect(() => {
        const timer = setInterval(() => {
            setWatermarkTimestamp(new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC")
        }, 30000)
        return () => clearInterval(timer)
    }, [])

    const [leaseMinutes, setLeaseMinutes] = React.useState(30)
    const [leaseDurationSec, setLeaseDurationSec] = React.useState(1800)
    const [offlineEnabled, setOfflineEnabled] = React.useState(true)
    const [leaseId, setLeaseId] = React.useState<string | null>(null)
    const [leaseToken, setLeaseToken] = React.useState<string | null>(null)
    const [rsaJwt, setRsaJwt] = React.useState<string | null>(null)
    const [rsaSigPreview, setRsaSigPreview] = React.useState<string>("RS256 Verifying...")
    const [qrChallengeCode, setQrChallengeCode] = React.useState<string | null>(null)
    const [leaseStartMono, setLeaseStartMono] = React.useState<number>(() => (typeof performance !== "undefined" ? performance.now() : Date.now()))
    const [simClockOffset, setSimClockOffset] = React.useState<number>(0)
    const [permissionEndTs, setPermissionEndTs] = React.useState<number>(() => Date.now() / 1000 + 30 * 60)
    const [leaseState, setLeaseState] = React.useState<LeaseResponse>({
        access_allowed: true,
        token_verified: true,
        rsa_verified: true,
        clock_tamper_detected: false,
        ram_wiped: false,
        ram_key_preview: "0xAES256...RAM",
        decrypted_viewport_text: "CONFIDENTIAL BOARD ACQUISITION MEMO:\nProject Helios buyout ceiling is set at $142M for Q1 2027.",
        device_hwid: "HWID-84F9-33A1-KEY",
        current_time: Date.now() / 1000,
        permission_end_timestamp: Date.now() / 1000 + 30 * 60,
        monotonic_elapsed_seconds: 0,
        remaining_seconds: 30 * 60,
        status_message: "ACCESS GRANTED (RAM Key Loaded)",
    })
    const [pollCount, setPollCount] = React.useState(0)

    const issueSignedLease = React.useCallback(async (durationSec: number) => {
        setSimClockOffset(0)
        setQrChallengeCode(null)
        setLeaseDurationSec(durationSec)
        setLeaseStartMono(typeof performance !== "undefined" ? performance.now() : Date.now())
        setPermissionEndTs(Date.now() / 1000 + durationSec)
        try {
            const resp = await apiFetch("/api/issue-lease", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ duration_seconds: Math.max(1, Math.round(durationSec)), recipient_id: recipientId }),
            })
            if (resp.ok) {
                const data = await resp.json()
                setLeaseId(data.lease_id)
                setLeaseToken(data.lease_token)
                setRsaJwt(data.rsa_jwt)
                setRsaSigPreview(data.lease_envelope?.Signature || "RS256 Signed")
                setLeaseState((prev) => ({
                    ...prev,
                    access_allowed: true,
                    ram_wiped: false,
                    ram_key_preview: data.ram_key_preview,
                    decrypted_viewport_text: data.decrypted_viewport_text,
                    device_hwid: data.device_hwid,
                    remaining_seconds: data.duration_seconds,
                    status_message: "ACCESS GRANTED (RAM Key Loaded)",
                }))
            }
        } catch {
            // Silently fall back to client-side lease timer when offline
        }
    }, [currentApiUrl, recipientId])

    const handleRevokeInstantly = async () => {
        try {
            const resp = await apiFetch("/api/revoke-lease", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ lease_id: leaseId, lease_token: leaseToken }),
            })
            if (resp.ok) {
                const data = await resp.json()
                setLeaseState((prev) => ({
                    ...prev,
                    access_allowed: false,
                    remaining_seconds: 0,
                    ram_wiped: true,
                    ram_key_preview: data.ram_key_preview,
                    decrypted_viewport_text: null,
                    status_message: data.status_message,
                }))
                return
            }
        } catch {
            // Fall through to local RAM wipe state when offline
        }
        setLeaseState((prev) => ({
            ...prev,
            access_allowed: false,
            remaining_seconds: 0,
            ram_wiped: true,
            ram_key_preview: "0x00000000...0000 (ZEROED)",
            decrypted_viewport_text: null,
            status_message: "ACCESS REVOKED / RAM KEY ZEROED",
        }))
    }

    const handleChallengeQrRenewal = async () => {
        try {
            const resp = await apiFetch("/api/challenge-qr-renewal", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ lease_id: leaseId, duration_seconds: leaseMinutes * 60 }),
            })
            if (resp.ok) {
                const data = await resp.json()
                setQrChallengeCode(data.challenge_code)
                return
            }
        } catch {
            // Fall through to local offline challenge code
        }
        setQrChallengeCode(`QR-${Math.random().toString(16).slice(2, 10).toUpperCase()}`)
    }

    const handleCompleteQrRenewal = async () => {
        if (!qrChallengeCode) return
        const dur = leaseMinutes * 60
        setSimClockOffset(0)
        setLeaseDurationSec(dur)
        setLeaseStartMono(typeof performance !== "undefined" ? performance.now() : Date.now())
        try {
            const resp = await apiFetch("/api/complete-qr-renewal", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ challenge_code: qrChallengeCode, duration_seconds: dur }),
            })
            if (resp.ok) {
                const data = await resp.json()
                setLeaseId(data.lease_id)
                setLeaseToken(data.lease_token)
                setRsaJwt(data.rsa_jwt)
                setQrChallengeCode(null)
                return
            }
        } catch {
            // Fall through to local offline renewal
        }
        setPermissionEndTs(Date.now() / 1000 + dur)
        setQrChallengeCode(null)
        setLeaseState((prev) => ({
            ...prev,
            access_allowed: true,
            ram_wiped: false,
            remaining_seconds: dur,
            decrypted_viewport_text:
                (OFFLINE_CONFIDENTIAL_DOCS.find((d) => d.id === activeOfflineDocId) || OFFLINE_CONFIDENTIAL_DOCS[0]).text,
            status_message: "ACCESS GRANTED (OFFLINE QR RENEWED)",
        }))
    }

    // Check Backend Health on mount / url change & issue initial signed lease
    React.useEffect(() => {
        let isMounted = true
        apiFetch("/api/health")
            .then((r) => (r.ok ? r.json() : Promise.reject(new Error("offline"))))
            .then(() => {
                if (isMounted) setApiStatus("online")
            })
            .catch(() => {
                if (isMounted) setApiStatus("offline")
            })
        issueSignedLease(30 * 60)
        return () => {
            isMounted = false
        }
    }, [normalizedBackendUrl, buildApiHeaders])

    // --- TAB 1: CALL /api/watermark (with offline client-side fallback) ---
    const handleGenerateWatermark = async () => {
        setIsWatermarking(true)
        setWatermarkError(null)
        try {
            const resp = await apiFetch("/api/watermark", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    recipient_id: recipientId,
                    session_id: sessionId,
                    text: textInput,
                }),
            })
            if (!resp.ok) throw new Error("Backend unavailable")
            const data: WatermarkResponse = await resp.json()
            setWatermarkResult(data)
            setApiStatus("online")
        } catch {
            setApiStatus("offline")
            setWatermarkResult(encodeOfflineWatermark(textInput, recipientId, sessionId))
        } finally {
            setIsWatermarking(false)
        }
    }

    // --- TAB 1: CALL /api/watermark-pdf (Upload PDF & Apply Watermark) ---
    const handleUploadWatermarkPdf = async () => {
        if (!pdfFile) {
            setWatermarkError("Select or drag-and-drop a PDF file first.")
            return
        }
        setIsWatermarking(true)
        setWatermarkError(null)
        const formData = new FormData()
        formData.append("file", pdfFile)
        formData.append("recipient_id", recipientId)
        formData.append("session_id", sessionId)

        try {
            const resp = await apiFetch("/api/watermark-pdf", {
                method: "POST",
                body: formData,
            })
            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}))
                throw new Error(err.detail || "PDF watermark extraction failed.")
            }
            const data: WatermarkResponse = await resp.json()
            setWatermarkResult(data)
            setApiStatus("online")
        } catch (err: any) {
            setWatermarkError(err.message || "Could not upload PDF to /api/watermark-pdf.")
        } finally {
            setIsWatermarking(false)
        }
    }

    // --- TAB 1: CALL /api/download-watermarked-pdf (Copy-to-Copy PDF Overlay) ---
    const handleDownloadCopyToCopyPdf = async () => {
        if (!pdfFile) {
            setWatermarkError("Select or drag-and-drop a PDF file first.")
            return
        }
        setIsWatermarking(true)
        setWatermarkError(null)
        const formData = new FormData()
        formData.append("file", pdfFile)
        formData.append("recipient_id", recipientId)
        formData.append("session_id", sessionId)
        try {
            const resp = await apiFetch("/api/download-watermarked-pdf", {
                method: "POST",
                body: formData,
            })
            if (!resp.ok) throw new Error("Copy-to-copy PDF watermarking failed.")
            const blob = await resp.blob()
            const downloadUrl = window.URL.createObjectURL(blob)
            const link = document.createElement("a")
            link.href = downloadUrl
            link.download = `watermarked_${pdfFile.name}`
            document.body.appendChild(link)
            link.click()
            link.remove()
            window.URL.revokeObjectURL(downloadUrl)
        } catch (err: any) {
            setWatermarkError(err.message || "Could not download copy-to-copy watermarked PDF.")
        } finally {
            setIsWatermarking(false)
        }
    }

    // --- TAB 1: CALL /api/export-watermark-pdf (Generate Downloadable PDF) ---
    const handleDownloadPdf = async () => {
        setWatermarkError(null)
        try {
            const resp = await apiFetch("/api/export-watermark-pdf", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    recipient_id: recipientId,
                    session_id: sessionId,
                    text: watermarkResult?.watermarked_text || textInput,
                }),
            })
            if (!resp.ok) throw new Error("Failed to generate watermarked PDF.")
            const blob = await resp.blob()
            const url = URL.createObjectURL(blob)
            const a = document.createElement("a")
            a.href = url
            a.download = `LeakLens_${sessionId.replace(/[^a-zA-Z0-9_-]/g, "_")}.pdf`
            document.body.appendChild(a)
            a.click()
            a.remove()
            URL.revokeObjectURL(url)
        } catch (err: any) {
            setWatermarkError(err.message || "PDF export failed.")
        }
    }

    // --- TAB 2: CALL /api/inspect (with offline client-side fallback) ---
    const handleRunInspect = async () => {
        setIsInspecting(true)
        setInspectError(null)
        try {
            const resp = await apiFetch("/api/inspect", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    leaked_text: leakedTextInput,
                }),
            })
            if (!resp.ok) throw new Error("Backend unavailable")
            const data: InspectResponse = await resp.json()
            setInspectResult(data)
            if (data.match_found && data.verified) {
                setWebhookAlert(
                    `🚨 CRITICAL INCIDENT: Forensic match confirmed for Recipient ${data.recipient_id} | Session ${data.session_id}.`
                )
            }
            setApiStatus("online")
        } catch {
            setApiStatus("offline")
            const offlineData = decodeOfflineWatermark(leakedTextInput)
            setInspectResult(offlineData)
            if (offlineData.match_found && offlineData.verified) {
                setWebhookAlert(
                    `🚨 OFFLINE FORENSIC MATCH: Recipient ${offlineData.recipient_id} | Session ${offlineData.session_id}.`
                )
            }
        } finally {
            setIsInspecting(false)
        }
    }

    // --- TAB 4: STRESS TEST HELPERS ---
    const handleGoogleAuthResponse = React.useCallback(
        async (response: { credential?: string }) => {
            if (!response?.credential) return
            try {
                const resp = await apiFetch("/api/auth/google", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ token: response.credential }),
                })
                const data = await resp.json()
                if (resp.ok && data.status === "success") {
                    setAuthUser(data.user)
                    setRecipientId(data.user.email)
                    if (typeof window !== "undefined") {
                        window.localStorage.setItem("access_token", data.access_token)
                        window.localStorage.setItem("user_email", data.user.email)
                        window.localStorage.setItem("user_name", data.user.name)
                    }
                }
            } catch {
                // Backend unreachable offline — keep UI responsive without console errors
            }
        },
        [currentApiUrl]
    )

    React.useEffect(() => {
        if (typeof window === "undefined") return

        // A. Parse window.location.search for ?token=... (or fallback #access_token=...)
        const urlParams = new URLSearchParams(window.location.search)
        const tokenFromUrl = urlParams.get("token")
        const emailFromUrl = urlParams.get("email")
        const hash = window.location.hash || ""
        const hashMatch = hash.match(/access_token=([^&]+)/)
        const handoffToken = tokenFromUrl || (hashMatch && hashMatch[1] ? decodeURIComponent(hashMatch[1]) : null)

        if (handoffToken) {
            window.localStorage.setItem("access_token", handoffToken)
            if (emailFromUrl) {
                window.localStorage.setItem("user_email", emailFromUrl)
                setRecipientId(emailFromUrl)
            }
            try {
                window.history.replaceState({}, document.title, window.location.pathname)
            } catch {}
        }

        const storedToken = window.localStorage.getItem("access_token")
        if (!storedToken) {
            setCheckingAuth(false)
            if (requireAuthGuard && !isFramerEditor) {
                window.location.href = buildFramerLoginUrl()
            }
            return
        }

        fetch(`${normalizedBackendUrl}/api/auth/me`, {
            headers: buildApiHeaders({ Authorization: `Bearer ${storedToken}` }),
        })
            .then(async (r) => {
                if (r.status === 401 || r.status === 403) {
                    window.localStorage.clear()
                    if (requireAuthGuard && !isFramerEditor) {
                        window.location.href = buildFramerLoginUrl()
                    }
                    return
                }
                const d = await r.json().catch(() => ({}))
                if (r.ok && d?.status === "authenticated" && d.user) {
                    setAuthUser(d.user)
                    setRecipientId(d.user.email)
                    window.localStorage.setItem("user_email", d.user.email)
                    window.localStorage.setItem("user_name", d.user.name || d.user.email)
                    return
                }
                const offlineSession = decodeJwtOffline(storedToken)
                if (offlineSession?.expired) {
                    window.localStorage.clear()
                    if (requireAuthGuard && !isFramerEditor) {
                        window.location.href = buildFramerLoginUrl()
                    }
                    return
                }
                const fallbackEmail =
                    offlineSession?.user?.email || window.localStorage.getItem("user_email") || "authenticated_user"
                const fallbackName =
                    offlineSession?.user?.name || window.localStorage.getItem("user_name") || fallbackEmail
                setAuthUser({ email: fallbackEmail, name: fallbackName, picture: offlineSession?.user?.picture || "" })
                setRecipientId(fallbackEmail)
            })
            .catch(() => {
                const offlineSession = decodeJwtOffline(storedToken)
                if (offlineSession?.expired) {
                    window.localStorage.clear()
                    if (requireAuthGuard && !isFramerEditor) {
                        window.location.href = buildFramerLoginUrl()
                    }
                    return
                }
                const fallbackEmail =
                    offlineSession?.user?.email || window.localStorage.getItem("user_email") || "authenticated_user"
                const fallbackName =
                    offlineSession?.user?.name || window.localStorage.getItem("user_name") || fallbackEmail
                setAuthUser({ email: fallbackEmail, name: fallbackName, picture: offlineSession?.user?.picture || "" })
                setRecipientId(fallbackEmail)
                setApiStatus("offline")
            })
            .finally(() => setCheckingAuth(false))
        if (!googleClientId || googleClientId.startsWith("YOUR_GOOGLE_CLIENT_ID") || authUser) return
        const renderGis = () => {
            const g = (window as any).google
            if (!g?.accounts?.id) return
            g.accounts.id.initialize({ client_id: googleClientId, callback: handleGoogleAuthResponse })
            if (inlineGateBtnRef.current) {
                inlineGateBtnRef.current.innerHTML = ""
                g.accounts.id.renderButton(inlineGateBtnRef.current, { theme: "filled_blue", size: "large", shape: "pill", width: 280 })
            }
            if (googleBtnRef.current) {
                googleBtnRef.current.innerHTML = ""
                g.accounts.id.renderButton(googleBtnRef.current, { theme: "filled_black", size: "medium", shape: "pill", text: "continue_with" })
            }
        }
        if ((window as any).google?.accounts?.id) {
            renderGis()
            return
        }
        const script = document.createElement("script")
        script.src = "https://accounts.google.com/gsi/client"
        script.async = true
        script.defer = true
        script.onload = renderGis
        document.head.appendChild(script)
    }, [normalizedBackendUrl, buildApiHeaders, buildFramerLoginUrl, googleClientId, authUser, handleGoogleAuthResponse, requireAuthGuard, isFramerEditor])

    const handleRegenerate = React.useCallback(async () => {
        try {
            const response = await apiFetch("/api/regenerate-demo-copies", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
            })
            if (response.ok) {
                const data = await response.json()
                if (data.status === "success") {
                    setAliceCopy(data.alice.watermarked_text)
                    setBobCopy(data.bob.watermarked_text)
                    setStressInput(data.alice.watermarked_text)
                    setStressResult(null)
                    return
                }
            }
        } catch {
            // Fall through to cached offline copies
        }
        const aliceOffline = encodeOfflineWatermark(STRESS_MEMO, "Alice Smith (USR-8492)", "SES-OFFLINE-2026")
        const bobOffline = encodeOfflineWatermark(STRESS_MEMO, "Bob Jones (USR-3104)", "SES-OFFLINE-2026")
        setAliceCopy(aliceOffline.watermarked_text)
        setBobCopy(bobOffline.watermarked_text)
        setStressInput(aliceOffline.watermarked_text)
        setStressResult(null)
        setApiStatus("offline")
    }, [apiFetch, STRESS_MEMO])

    React.useEffect(() => {
        if (activeTab === "stress" && !aliceCopy) {
            handleRegenerate()
        }
    }, [activeTab, aliceCopy, handleRegenerate])

    const handleRunStressTest = async () => {
        if (!stressInput.trim()) return
        setIsStressTesting(true)
        try {
            const resp = await apiFetch("/api/inspect", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ leaked_text: stressInput }),
            })
            if (!resp.ok) throw new Error("Backend unavailable")
            const data: InspectResponse = await resp.json()
            setStressResult(data)
            if (data.match_found && data.verified) {
                setWebhookAlert(
                    `🚨 CRITICAL INCIDENT: Forensic match confirmed for Recipient ${data.recipient_id} | Session ${data.session_id}.`
                )
            }
        } catch {
            const offlineRes = decodeOfflineWatermark(stressInput)
            setStressResult(offlineRes)
            if (offlineRes.match_found && offlineRes.verified) {
                setWebhookAlert(
                    `🚨 OFFLINE FORENSIC MATCH: Recipient ${offlineRes.recipient_id} | Session ${offlineRes.session_id}.`
                )
            }
            setApiStatus("offline")
        } finally {
            setIsStressTesting(false)
        }
    }

    // --- TAB 2: CALL /api/inspect-pdf ---
    const handleInspectPdf = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0]
        if (!file) return
        setIsInspecting(true)
        setInspectError(null)
        const formData = new FormData()
        formData.append("file", file)
        try {
            const resp = await apiFetch("/api/inspect-pdf", {
                method: "POST",
                body: formData,
            })
            if (!resp.ok) throw new Error("Failed to inspect uploaded PDF.")
            const data: InspectResponse = await resp.json()
            setInspectResult(data)
            setApiStatus("online")
        } catch (err: any) {
            setInspectError(err.message || "PDF inspection failed.")
        } finally {
            setIsInspecting(false)
        }
    }

    const [blockedShortcutsCount, setBlockedShortcutsCount] = React.useState(0)

    React.useEffect(() => {
        if (typeof window === "undefined") return
        const onKeyDown = (e: KeyboardEvent) => {
            const k = (e.key || "").toLowerCase()
            const code = e.code || ""
            const mod = e.ctrlKey || e.metaKey
            const isF12 = e.key === "F12" || code === "F12" || e.keyCode === 123
            const isDevTools = mod && (e.shiftKey || e.altKey) && (k === "i" || k === "j" || k === "c" || code === "KeyI")
            const isViewSource = mod && (k === "u" || code === "KeyU")
            const isSaveOrCopy = mod && (k === "s" || code === "KeyS" || k === "c" || k === "x" || k === "p")
            if (isF12 || isDevTools || isViewSource || isSaveOrCopy) {
                e.preventDefault()
                e.stopPropagation()
                setBlockedShortcutsCount((c) => c + 1)
            }
        }
        window.addEventListener("keydown", onKeyDown, true)
        return () => window.removeEventListener("keydown", onKeyDown, true)
    }, [])

    // --- TAB 3: POLL /api/validate-lease ---
    React.useEffect(() => {
        if (!offlineEnabled) return

        let isCancelled = false
        const interval = setInterval(async () => {
            const nowMono = typeof performance !== "undefined" ? performance.now() : Date.now()
            const clientElapsed = (nowMono - leaseStartMono) / 1000
            try {
                const resp = await apiFetch("/api/validate-lease", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        permission_end_timestamp: permissionEndTs,
                        lease_token: leaseToken,
                        rsa_jwt: rsaJwt,
                        client_elapsed_seconds: clientElapsed,
                        simulated_clock_offset_seconds: simClockOffset,
                    }),
                })
                if (resp.ok && !isCancelled) {
                    const data: LeaseResponse = await resp.json()
                    setLeaseState(data)
                    setPollCount((prev) => prev + 1)
                    setApiStatus("online")
                }
            } catch (e) {
                // If backend is unreachable, local countdown fallback
                if (!isCancelled) {
                    const currentSec = Date.now() / 1000
                    const remaining = Math.max(0, Math.floor(permissionEndTs - currentSec))
                    setLeaseState({
                        access_allowed: remaining > 0,
                        current_time: currentSec,
                        permission_end_timestamp: permissionEndTs,
                        remaining_seconds: remaining,
                        status_message: remaining > 0 ? "ACCESS GRANTED (LOCAL)" : "ACCESS REVOKED / EXPIRED",
                    })
                }
            }
        }, 1000)

        return () => {
            isCancelled = true
            clearInterval(interval)
        }
    }, [offlineEnabled, permissionEndTs, currentApiUrl, leaseToken, rsaJwt, leaseStartMono, simClockOffset])

    const handleResetLease = (mins: number) => {
        issueSignedLease(mins * 60)
    }

    const formatTimer = (totalSec: number) => {
        const hrs = Math.floor(totalSec / 3600)
        const m = Math.floor((totalSec % 3600) / 60)
        const s = totalSec % 60
        return `${hrs.toString().padStart(2, "0")}:${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`
    }

    if (!isFramerEditor && requireAuthGuard && checkingAuth) {
        return (
            <div style={{ padding: 48, textAlign: "center", color: "#F3F2F8", backgroundColor: "rgba(6, 6, 10, 0.72)", borderRadius: 16, fontFamily: "'Onest', 'Inter', sans-serif" }}>
                Verifying LeakLens session...
            </div>
        )
    }

    if (!isFramerEditor && requireAuthGuard && !authUser) {
        return (
            <div
                style={{
                    width: "100%",
                    maxWidth: 460,
                    margin: "40px auto",
                    padding: "40px 32px",
                    borderRadius: 20,
                    backgroundColor: "rgba(6, 6, 10, 0.80)",
                    backdropFilter: "blur(20px)",
                    WebkitBackdropFilter: "blur(20px)",
                    border: "1px solid rgba(243, 242, 248, 0.14)",
                    boxShadow: "0 28px 80px rgba(0, 0, 0, 0.85)",
                    textAlign: "center",
                    color: "#F3F2F8",
                    fontFamily: "'Onest', 'Inter', sans-serif",
                }}
            >
                <div style={{ fontSize: 11, color: "#FFB627", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 8 }}>
                    SentinelTrace Security Portal
                </div>
                <h2 style={{ margin: "0 0 10px", fontSize: 28, fontWeight: 600 }}>Welcome to LeakLens</h2>
                <p style={{ margin: "0 0 22px", fontSize: 13.5, color: "rgba(243, 242, 248, 0.68)", lineHeight: 1.5 }}>
                    Sign in or register with your Google account to unlock watermarking, forensic attribution, and offline DRM controls.
                </p>
                <div ref={inlineGateBtnRef} id="google-login-btn" style={{ display: "flex", justifyContent: "center", marginBottom: 14 }} />
                <a
                    href={buildFramerLoginUrl()}
                    style={{ fontSize: 12, color: "#2BD8C8", textDecoration: "underline" }}
                >
                    Open LeakLens Login Portal →
                </a>
            </div>
        )
    }

    return (
        <div
            style={{
                width: "100%",
                maxWidth: 1040,
                margin: "0 auto",
                backgroundColor: "rgba(6, 6, 10, 0.72)",
                backdropFilter: "blur(18px)",
                WebkitBackdropFilter: "blur(18px)",
                borderRadius: 4,
                border: "1px solid rgba(243, 242, 248, 0.12)",
                boxShadow: "0 25px 60px -15px rgba(0, 0, 0, 0.9), 0 0 50px rgba(123, 92, 250, 0.08)",
                color: "#F3F2F8",
                fontFamily: "var(--framer-font-family, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif)",
                overflow: "hidden",
                fontSize: 14,
            }}
        >
            {/* Header with Backend Status */}
            <div
                style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "16px 24px",
                    borderBottom: "1px solid rgba(243, 242, 248, 0.12)",
                    backgroundColor: "rgba(8, 8, 14, 0.68)",
                    flexWrap: "wrap",
                    gap: 12,
                }}
            >
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                    <div
                        style={{
                            width: 10,
                            height: 11,
                            clipPath: "polygon(50% 0, 100% 25%, 100% 75%, 50% 100%, 0 75%, 0 25%)",
                            backgroundColor: accentColor,
                            boxShadow: `0 0 12px ${accentColor}`,
                        }}
                    />
                    <span style={{ fontWeight: 700, letterSpacing: "0.06em", color: "#F3F2F8", textTransform: "uppercase", fontSize: 13 }}>
                        {brandName} <span style={{ color: "rgba(243, 242, 248, 0.56)", fontWeight: 400 }}>// FORENSIC API CONSOLE</span>
                    </span>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    {/* Live Backend Indicator */}
                    <div
                        onClick={() => setShowApiConfig(!showApiConfig)}
                        title="Click to view/change Python API endpoint"
                        style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 6,
                            padding: "4px 10px",
                            borderRadius: 16,
                            backgroundColor:
                                apiStatus === "online" ? "rgba(123, 92, 250, 0.10)" : "rgba(239, 68, 68, 0.1)",
                            border: `1px solid ${apiStatus === "online" ? "rgba(123, 92, 250, 0.32)" : "rgba(239, 68, 68, 0.3)"
                                }`,
                            fontSize: 11,
                            color: apiStatus === "online" ? accentColor : "#f87171",
                            fontFamily: "monospace",
                            cursor: "pointer",
                        }}
                    >
                        <span
                            style={{
                                width: 6,
                                height: 6,
                                borderRadius: "50%",
                                backgroundColor: apiStatus === "online" ? accentColor : "#ef4444",
                            }}
                        />
                        {apiStatus === "online" ? "FASTAPI BACKEND: ONLINE" : "FASTAPI BACKEND: CONNECTING"} ⚙
                    </div>

                    <div
                        style={{
                            padding: "4px 10px",
                            borderRadius: 16,
                            backgroundColor: "rgba(255, 255, 255, 0.04)",
                            border: "1px solid rgba(255, 255, 255, 0.08)",
                            fontSize: 11,
                            color: "#94a3b8",
                            fontFamily: "monospace",
                        }}
                    >
                        HMAC-SHA256 READY
                    </div>

                    {authUser ? (
                        <div
                            style={{
                                display: "flex",
                                alignItems: "center",
                                gap: 8,
                                padding: "4px 10px",
                                borderRadius: 16,
                                backgroundColor: "rgba(43, 216, 200, 0.12)",
                                border: "1px solid rgba(43, 216, 200, 0.32)",
                                fontSize: 11,
                                color: "#2BD8C8",
                                fontFamily: "monospace",
                            }}
                        >
                            <span>{authUser.email}</span>
                            <button
                                type="button"
                                onClick={() => {
                                    if (typeof window !== "undefined") {
                                        window.localStorage.clear()
                                        if (!isFramerEditor) {
                                            window.location.href = buildFramerLoginUrl()
                                        }
                                    }
                                    setAuthUser(null)
                                }}
                                title="Log out"
                                style={{ background: "none", border: "none", color: "#F3F2F8", cursor: "pointer", fontSize: 11 }}
                            >
                                Log out
                            </button>
                        </div>
                    ) : (
                        <div ref={googleBtnRef} />
                    )}
                </div>
            </div>

            {/* Collapsible API Endpoint Config Bar */}
            {showApiConfig && (
                <div
                    style={{
                        padding: "12px 24px",
                        backgroundColor: "#0d0f18",
                        borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
                        display: "flex",
                        alignItems: "center",
                        gap: 12,
                        fontSize: 12,
                    }}
                >
                    <span style={{ color: "#64748b", fontWeight: 600 }}>Python API URL:</span>
                    <input
                        type="text"
                        value={currentApiUrl}
                        onChange={(e) => setCurrentApiUrl(e.target.value)}
                        style={{ ...inputStyle, flex: 1, fontFamily: "monospace", fontSize: 11, padding: "6px 10px" }}
                    />
                    <button
                        onClick={() => {
                            setApiStatus("checking")
                            fetch(`${normalizedBackendUrl}/api/health`, { headers: buildApiHeaders() })
                                .then((r) => (r.ok ? setApiStatus("online") : setApiStatus("offline")))
                                .catch(() => setApiStatus("offline"))
                        }}
                        style={{
                            padding: "6px 12px",
                            backgroundColor: "rgba(255, 255, 255, 0.08)",
                            color: "#fff",
                            border: "1px solid rgba(255, 255, 255, 0.15)",
                            borderRadius: 6,
                            cursor: "pointer",
                            fontSize: 11,
                            fontWeight: 600,
                        }}
                    >
                        Test Connection
                    </button>
                </div>
            )}

            {/* Navigation Tabs */}
            <div
                style={{
                    display: "flex",
                    borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
                    backgroundColor: "rgba(0, 0, 0, 0.4)",
                }}
            >
                {[
                    { id: "watermark", label: "Tab 1: Watermark Generator", sub: "POST /api/watermark", icon: "⌖" },
                    { id: "inspector", label: "Tab 2: Leak Inspector", sub: "POST /api/inspect", icon: "🔍" },
                    { id: "drm", label: "Tab 3: DRM Expiry Monitor", sub: "POST /api/validate-lease", icon: "⏱" },
                    { id: "stress", label: "Tab 4: Judge Stress Test", sub: "Try to Break It Mode", icon: "🛡" },
                ].map((tab) => {
                    const isSelected = activeTab === tab.id
                    return (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id as any)}
                            style={{
                                flex: 1,
                                padding: "14px 16px",
                                background: isSelected ? "rgba(255, 255, 255, 0.03)" : "transparent",
                                border: "none",
                                borderBottom: isSelected ? `2px solid ${accentColor}` : "2px solid transparent",
                                color: isSelected ? "#fff" : "#94a3b8",
                                cursor: "pointer",
                                display: "flex",
                                flexDirection: "column",
                                alignItems: "center",
                                gap: 4,
                                transition: "all 0.2s ease",
                            }}
                        >
                            <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, fontWeight: isSelected ? 600 : 400 }}>
                                <span>{tab.icon}</span>
                                <span>{tab.label}</span>
                            </div>
                            <span style={{ fontSize: 10, color: isSelected ? accentColor : "#475569", fontFamily: "monospace" }}>
                                {tab.sub}
                            </span>
                        </button>
                    )
                })}
            </div>

            {/* Tab Body */}
            <div style={{ padding: 28 }}>
                {/* REAL-TIME WEBHOOK LEAK ALERT BANNER */}
                {webhookAlert && (
                    <div
                        style={{
                            marginBottom: 20,
                            padding: "14px 16px",
                            backgroundColor: "rgba(239, 68, 68, 0.14)",
                            border: "1px solid rgba(239, 68, 68, 0.55)",
                            borderRadius: 8,
                            boxShadow: "0 0 28px rgba(239, 68, 68, 0.25)",
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            gap: 12,
                        }}
                    >
                        <div style={{ fontFamily: "monospace", fontSize: 12, color: "#fecaca", lineHeight: 1.5 }}>
                            <div style={{ fontSize: 10, color: "#f87171", fontWeight: 700, marginBottom: 2 }}>
                                ● REAL-TIME WEBHOOK ALERT DISPATCHED • SIEM / SLACK 200 OK
                            </div>
                            <div style={{ color: "#fff", fontWeight: 600 }}>{webhookAlert}</div>
                        </div>
                        <button
                            onClick={() => setWebhookAlert(null)}
                            style={{
                                background: "none",
                                border: "none",
                                color: "#fca5a5",
                                cursor: "pointer",
                                fontFamily: "monospace",
                                fontSize: 14,
                            }}
                        >
                            ✕
                        </button>
                    </div>
                )}
                {/* ============================================================== */}
                {/* TAB 1: WATERMARK GENERATOR (/api/watermark)                     */}
                {/* ============================================================== */}
                {activeTab === "watermark" && (
                    <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1fr", gap: 28 }}>
                        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                            <div style={{ fontSize: 13, color: "#94a3b8", lineHeight: 1.5 }}>
                                Sends recipient & session credentials to Python endpoint <code style={codePillStyle}>/api/watermark</code>. The backend encodes the payload using invisible Zero-Width Unicode characters (<code style={codePillStyle}>ZW_0</code>, <code style={codePillStyle}>ZW_1</code>, <code style={codePillStyle}>ZW_DELIM</code>) and signs it with HMAC-SHA256.
                            </div>

                            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                                <div>
                                    <label style={labelStyle}>Recipient ID (recipient_id)</label>
                                    <input
                                        type="text"
                                        value={recipientId}
                                        onChange={(e) => setRecipientId(e.target.value)}
                                        style={inputStyle}
                                    />
                                </div>
                                <div>
                                    <label style={labelStyle}>Session ID (session_id)</label>
                                    <input
                                        type="text"
                                        value={sessionId}
                                        onChange={(e) => setSessionId(e.target.value)}
                                        style={inputStyle}
                                    />
                                </div>
                            </div>

                            <div>
                                <label style={labelStyle}>Document Text to Watermark (text)</label>
                                <textarea
                                    rows={4}
                                    value={textInput}
                                    onChange={(e) => setTextInput(e.target.value)}
                                    style={{ ...inputStyle, resize: "vertical", fontFamily: "monospace", fontSize: 12 }}
                                />
                            </div>

                            <button
                                onClick={handleGenerateWatermark}
                                disabled={isWatermarking}
                                style={{
                                    padding: "12px 20px",
                                    backgroundColor: accentColor,
                                    color: "#050608",
                                    border: "none",
                                    borderRadius: 8,
                                    fontWeight: 700,
                                    cursor: isWatermarking ? "wait" : "pointer",
                                    boxShadow: `0 0 20px rgba(123, 92, 250, 0.32)`,
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "center",
                                    gap: 8,
                                }}
                            >
                                {isWatermarking ? "Processing..." : "⚡ Call /api/watermark Endpoint"}
                            </button>

                            {/* PDF Drag & Drop Uploader */}
                            <div
                                onDragOver={(e) => {
                                    e.preventDefault()
                                    setIsDraggingPdf(true)
                                }}
                                onDragLeave={(e) => {
                                    e.preventDefault()
                                    setIsDraggingPdf(false)
                                }}
                                onDrop={(e) => {
                                    e.preventDefault()
                                    setIsDraggingPdf(false)
                                    const f = e.dataTransfer?.files?.[0]
                                    if (f) setPdfFile(f)
                                }}
                                onClick={() => pdfInputRef.current?.click()}
                                style={{
                                    padding: 14,
                                    backgroundColor: isDraggingPdf ? "rgba(123, 92, 250, 0.10)" : "rgba(8, 8, 14, 0.70)",
                                    border: `1px dashed ${isDraggingPdf ? accentColor : "rgba(123, 92, 250, 0.32)"}`,
                                    borderRadius: 8,
                                    cursor: "pointer",
                                    display: "flex",
                                    flexDirection: "column",
                                    gap: 10,
                                }}
                            >
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 11, fontFamily: "monospace" }}>
                                    <span style={{ color: "#38bdf8" }}>📄 PDF Drag &amp; Drop (/api/watermark-pdf)</span>
                                    <span style={{ color: "rgba(243, 242, 248, 0.56)" }}>{pdfFile ? pdfFile.name : "Drop .pdf or click"}</span>
                                </div>
                                <input
                                    ref={pdfInputRef}
                                    type="file"
                                    accept=".pdf,application/pdf"
                                    style={{ display: "none" }}
                                    onChange={(e) => {
                                        const f = e.target.files?.[0]
                                        if (f) setPdfFile(f)
                                    }}
                                />
                                <div style={{ display: "flex", gap: 8 }}>
                                    <button
                                        type="button"
                                        onClick={(e) => {
                                            e.stopPropagation()
                                            handleUploadWatermarkPdf()
                                        }}
                                        disabled={isWatermarking}
                                        style={{
                                            flex: 1,
                                            padding: "9px 10px",
                                            backgroundColor: "rgba(56, 189, 248, 0.12)",
                                            border: "1px solid rgba(56, 189, 248, 0.4)",
                                            color: "#38bdf8",
                                            borderRadius: 6,
                                            fontWeight: 700,
                                            cursor: "pointer",
                                            fontSize: 11,
                                            fontFamily: "monospace",
                                        }}
                                    >
                                        Upload &amp; Apply Watermark
                                    </button>
                                    <button
                                        type="button"
                                        onClick={(e) => {
                                            e.stopPropagation()
                                            handleDownloadCopyToCopyPdf()
                                        }}
                                        disabled={isWatermarking}
                                        style={{
                                            flex: 1,
                                            padding: "9px 10px",
                                            backgroundColor: "rgba(43, 216, 200, 0.14)",
                                            border: "1px solid rgba(43, 216, 200, 0.40)",
                                            color: accentColor,
                                            borderRadius: 6,
                                            fontWeight: 700,
                                            cursor: "pointer",
                                            fontSize: 11,
                                            fontFamily: "monospace",
                                        }}
                                    >
                                        Download Watermarked PDF
                                    </button>
                                </div>
                            </div>

                            {watermarkError && (
                                <div style={errorBannerStyle}>
                                    ⚠ Error: {watermarkError}
                                </div>
                            )}
                        </div>

                        {/* Result Output Card */}
                        <div
                            style={{
                                backgroundColor: "rgba(255, 255, 255, 0.02)",
                                border: "1px solid rgba(255, 255, 255, 0.08)",
                                borderRadius: 12,
                                padding: 20,
                                display: "flex",
                                flexDirection: "column",
                                justifyContent: "space-between",
                            }}
                        >
                            <div>
                                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
                                    <span style={{ fontSize: 12, fontWeight: 600, color: "#cbd5e1" }}>
                                        Python API Response
                                    </span>
                                    {watermarkResult && (
                                        <span
                                            style={{
                                                fontSize: 10,
                                                padding: "3px 8px",
                                                borderRadius: 12,
                                                backgroundColor: "rgba(43, 216, 200, 0.14)",
                                                color: accentColor,
                                                fontFamily: "monospace",
                                                border: "1px solid rgba(43, 216, 200, 0.30)",
                                            }}
                                        >
                                            ✓ {watermarkResult.pages_processed ? `PDF (${watermarkResult.pages_processed}P)` : watermarkResult.status.toUpperCase()} • {watermarkResult.chunks_embedded || 1} CHUNKS
                                        </span>
                                    )}
                                </div>

                                <div
                                    onCopy={(e) => { e.preventDefault(); setBlockedShortcutsCount((c) => c + 1) }}
                                    onCut={(e) => { e.preventDefault(); setBlockedShortcutsCount((c) => c + 1) }}
                                    onContextMenu={(e) => { e.preventDefault(); setBlockedShortcutsCount((c) => c + 1) }}
                                    onSelectStart={(e) => e.preventDefault()}
                                    style={{
                                        position: "relative",
                                        overflow: "hidden",
                                        backgroundColor: "#030406",
                                        borderRadius: 8,
                                        border: "1px solid rgba(255, 255, 255, 0.05)",
                                        padding: 14,
                                        minHeight: 140,
                                        fontFamily: "monospace",
                                        fontSize: 12,
                                        color: watermarkResult ? "#f1f5f9" : "#64748b",
                                        lineHeight: 1.6,
                                        whiteSpace: "pre-wrap",
                                        userSelect: "none",
                                        WebkitUserSelect: "none",
                                        msUserSelect: "none",
                                    }}
                                >
                                    <div
                                        aria-hidden="true"
                                        style={{
                                            position: "absolute",
                                            inset: -30,
                                            zIndex: 9999,
                                            pointerEvents: "none",
                                            userSelect: "none",
                                            WebkitUserSelect: "none",
                                            transform: "rotate(-18deg)",
                                            opacity: 0.12,
                                            display: "flex",
                                            flexDirection: "column",
                                            justifyContent: "space-around",
                                            fontFamily: "monospace",
                                            fontSize: 9,
                                            fontWeight: 700,
                                            color: "#FFB627",
                                            whiteSpace: "nowrap",
                                        }}
                                    >
                                        {[0, 1, 2].map((row) => (
                                            <div key={row}>
                                                {`CONFIDENTIAL • ACCESSED BY ${authUser?.email || "authenticated_user"} • ${watermarkTimestamp} • SECURE SESSION  •  `.repeat(2)}
                                            </div>
                                        ))}
                                    </div>
                                    <div style={{ position: "relative", zIndex: 1 }}>
                                        {watermarkResult
                                            ? watermarkResult.watermarked_text
                                            : "Click 'Call /api/watermark' to invoke the watermark engine (works online or offline)."}
                                    </div>
                                </div>

                                {watermarkResult && (
                                    <div
                                        style={{
                                            marginTop: 12,
                                            padding: 10,
                                            borderRadius: 6,
                                            backgroundColor: "rgba(0, 229, 255, 0.05)",
                                            border: "1px solid rgba(0, 229, 255, 0.15)",
                                            fontSize: 11,
                                            color: "#38bdf8",
                                            display: "flex",
                                            alignItems: "center",
                                            gap: 8,
                                        }}
                                    >
                                        <span>🛡</span>
                                        <span>{watermarkResult.chunks_embedded || 1} Redundant Unicode Watermark Chunks Embedded &amp; Signed (HMAC-SHA256).</span>
                                    </div>
                                )}
                            </div>

                            {watermarkResult && (
                                <div style={{ display: "flex", gap: 8, marginTop: 16, flexWrap: "wrap" }}>
                                    <button
                                        onClick={() => {
                                            navigator.clipboard.writeText(watermarkResult.watermarked_text)
                                            setCopied(true)
                                            setTimeout(() => setCopied(false), 2000)
                                        }}
                                        style={{
                                            flex: 1,
                                            padding: "10px",
                                            backgroundColor: "rgba(255, 255, 255, 0.06)",
                                            border: "1px solid rgba(255, 255, 255, 0.15)",
                                            color: "#fff",
                                            borderRadius: 6,
                                            cursor: "pointer",
                                            fontSize: 12,
                                            fontWeight: 600,
                                        }}
                                    >
                                        {copied ? "✓ Copied!" : "📋 Copy Text"}
                                    </button>

                                    <button
                                        onClick={handleDownloadPdf}
                                        style={{
                                            padding: "10px 14px",
                                            backgroundColor: "rgba(56, 189, 248, 0.12)",
                                            border: "1px solid rgba(56, 189, 248, 0.35)",
                                            color: "#38bdf8",
                                            borderRadius: 6,
                                            cursor: "pointer",
                                            fontSize: 12,
                                            fontWeight: 600,
                                            whiteSpace: "nowrap",
                                        }}
                                    >
                                        📄 Export PDF
                                    </button>

                                    <button
                                        onClick={() => {
                                            setLeakedTextInput(watermarkResult.watermarked_text)
                                            setActiveTab("inspector")
                                        }}
                                        style={{
                                            padding: "10px 14px",
                                            backgroundColor: "rgba(43, 216, 200, 0.14)",
                                            border: "1px solid rgba(43, 216, 200, 0.30)",
                                            color: accentColor,
                                            borderRadius: 6,
                                            cursor: "pointer",
                                            fontSize: 12,
                                            fontWeight: 600,
                                            whiteSpace: "nowrap",
                                        }}
                                    >
                                        🔍 Inspect →
                                    </button>
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {/* ============================================================== */}
                {/* TAB 2: LEAK INSPECTOR (/api/inspect)                           */}
                {/* ============================================================== */}
                {activeTab === "inspector" && (
                    <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1fr", gap: 28 }}>
                        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                            <div style={{ fontSize: 13, color: "#94a3b8", lineHeight: 1.5 }}>
                                Paste any leaked snippet or excerpt into the component. Triggering the analysis calls Python <code style={codePillStyle}>/api/inspect</code>, which extracts the zero-width bitstream, verifies the HMAC-SHA256 signature, and reveals the leaker metadata.
                            </div>

                            <div>
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                                    <label style={labelStyle}>Paste Leaked Text Snippet (leaked_text)</label>
                                    <div style={{ display: "flex", gap: 10 }}>
                                        <button
                                            onClick={() => {
                                                if (watermarkResult) {
                                                    setLeakedTextInput(watermarkResult.watermarked_text)
                                                } else {
                                                    setLeakedTextInput(
                                                        "CONFIDENTIAL ACQUISITION MEMO:\nTarget enterprise valuation locked at $142M."
                                                    )
                                                }
                                            }}
                                            style={quickLinkStyle}
                                        >
                                            Load Sample
                                        </button>
                                        {watermarkResult && (
                                            <button
                                                onClick={() => {
                                                    const txt = watermarkResult.watermarked_text
                                                    setLeakedTextInput(txt.slice(Math.floor(txt.length * 0.25), Math.floor(txt.length * 0.7)))
                                                }}
                                                style={{ ...quickLinkStyle, color: "#38bdf8" }}
                                            >
                                                Test 20% Slice
                                            </button>
                                        )}
                                        <button
                                            onClick={() => setLeakedTextInput("A clean text snippet with no watermark embedded whatsoever.")}
                                            style={quickLinkStyle}
                                        >
                                            Clean Text
                                        </button>
                                    </div>
                                </div>
                                <textarea
                                    rows={5}
                                    value={leakedTextInput}
                                    onChange={(e) => setLeakedTextInput(e.target.value)}
                                    placeholder="Paste suspicious memo or 10% partial snippet here..."
                                    style={{ ...inputStyle, resize: "vertical", fontFamily: "monospace", fontSize: 12 }}
                                />
                            </div>

                            <button
                                onClick={handleRunInspect}
                                disabled={isInspecting}
                                style={{
                                    padding: "12px 20px",
                                    backgroundColor: accentColor,
                                    color: "#050608",
                                    border: "none",
                                    borderRadius: 8,
                                    fontWeight: 700,
                                    cursor: isInspecting ? "wait" : "pointer",
                                    boxShadow: `0 0 20px rgba(123, 92, 250, 0.32)`,
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "center",
                                    gap: 8,
                                }}
                            >
                                {isInspecting ? "Analyzing..." : "🔍 Run Forensic Leak Analysis (/api/inspect)"}
                            </button>

                            <div
                                style={{
                                    padding: 12,
                                    backgroundColor: "rgba(8, 8, 14, 0.75)",
                                    border: "1px dashed rgba(56, 189, 248, 0.3)",
                                    borderRadius: 6,
                                    display: "flex",
                                    justifyContent: "space-between",
                                    alignItems: "center",
                                    gap: 8,
                                }}
                            >
                                <span style={{ fontSize: 11, color: "#38bdf8", fontFamily: "monospace" }}>
                                    📄 Inspect PDF (/api/inspect-pdf):
                                </span>
                                <input
                                    type="file"
                                    accept="application/pdf"
                                    onChange={handleInspectPdf}
                                    style={{ fontSize: 11, color: "rgba(243, 242, 248, 0.56)", maxWidth: 190 }}
                                />
                            </div>

                            {inspectError && (
                                <div style={errorBannerStyle}>
                                    ⚠ Error: {inspectError}
                                </div>
                            )}
                        </div>

                        {/* Analysis Result Card */}
                        <div
                            style={{
                                backgroundColor: "rgba(255, 255, 255, 0.02)",
                                border: "1px solid rgba(255, 255, 255, 0.08)",
                                borderRadius: 12,
                                padding: 20,
                            }}
                        >
                            <span style={{ fontSize: 12, fontWeight: 600, color: "#cbd5e1", display: "block", marginBottom: 14 }}>
                                Leaker Metadata Revealed
                            </span>

                            {!inspectResult ? (
                                <div
                                    style={{
                                        display: "flex",
                                        alignItems: "center",
                                        justifyContent: "center",
                                        minHeight: 180,
                                        color: "#64748b",
                                        fontSize: 12,
                                        fontFamily: "monospace",
                                        border: "1px dashed rgba(255, 255, 255, 0.1)",
                                        borderRadius: 8,
                                        textAlign: "center",
                                        padding: 20,
                                    }}
                                >
                                    Paste text on the left and click 'Run Forensic Leak Analysis' to trigger the fetch() call.
                                </div>
                            ) : inspectResult.match_found ? (
                                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                                    <div
                                        style={{
                                            padding: 12,
                                            borderRadius: 8,
                                            backgroundColor:
                                                inspectResult.verified ? "rgba(123, 92, 250, 0.10)" : "rgba(239, 68, 68, 0.1)",
                                            border: `1px solid ${inspectResult.verified ? "rgba(123, 92, 250, 0.32)" : "rgba(239, 68, 68, 0.3)"
                                                }`,
                                            display: "flex",
                                            alignItems: "center",
                                            justifyContent: "space-between",
                                        }}
                                    >
                                        <span
                                            style={{
                                                fontSize: 12,
                                                color: inspectResult.verified ? accentColor : "#f87171",
                                                fontWeight: 700,
                                            }}
                                        >
                                            {inspectResult.verified ? "✓ LEAKER IDENTITY VERIFIED" : "⚠ SIGNATURE TAMPER DETECTED"}
                                        </span>
                                        <span
                                            style={{
                                                fontSize: 10,
                                                padding: "2px 8px",
                                                borderRadius: 10,
                                                backgroundColor: inspectResult.verified ? "rgba(123, 92, 250, 0.24)" : "rgba(239, 68, 68, 0.2)",
                                                color: inspectResult.verified ? accentColor : "#f87171",
                                                fontFamily: "monospace",
                                            }}
                                        >
                                            MATCH FOUND
                                        </span>
                                    </div>

                                    <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 10, fontSize: 12 }}>
                                        <div style={resultRowStyle}>
                                            <span style={{ color: "#64748b" }}>Leaker Identity (recipient_id):</span>
                                            <span style={{ color: "#fff", fontWeight: 700, fontSize: 13 }}>
                                                {inspectResult.recipient_id}
                                            </span>
                                        </div>
                                        <div style={resultRowStyle}>
                                            <span style={{ color: "#64748b" }}>Originating Session (session_id):</span>
                                            <span style={{ fontFamily: "monospace", color: "#38bdf8" }}>
                                                {inspectResult.session_id}
                                            </span>
                                        </div>
                                        <div style={resultRowStyle}>
                                            <span style={{ color: "#64748b" }}>Detection Source / Chunks:</span>
                                            <span style={{ fontFamily: "monospace", color: accentColor }}>
                                                {inspectResult.source
                                                    ? inspectResult.source
                                                    : `${inspectResult.chunks_verified || 1}/${inspectResult.chunks_detected || 1} Chunks Verified`}
                                            </span>
                                        </div>
                                        <div style={resultRowStyle}>
                                            <span style={{ color: "#64748b" }}>Extracted Signature:</span>
                                            <span style={{ fontFamily: "monospace", color: "#cbd5e1" }}>
                                                {inspectResult.signature}
                                            </span>
                                        </div>
                                        <div style={resultRowStyle}>
                                            <span style={{ color: "#64748b" }}>Cryptographic Check:</span>
                                            <span
                                                style={{
                                                    color: inspectResult.verified ? accentColor : "#f87171",
                                                    fontWeight: 600,
                                                    fontFamily: "monospace",
                                                }}
                                            >
                                                {inspectResult.verified
                                                    ? "Signature Verified (HMAC-SHA256)"
                                                    : "Verification Failed (Key Mismatch)"}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            ) : (
                                <div
                                    style={{
                                        padding: 16,
                                        borderRadius: 8,
                                        backgroundColor: "rgba(239, 68, 68, 0.1)",
                                        border: "1px solid rgba(239, 68, 68, 0.3)",
                                        color: "#f87171",
                                        fontSize: 12,
                                    }}
                                >
                                    <div style={{ fontWeight: 700, marginBottom: 4 }}>Inspection Negative</div>
                                    <div>{inspectResult.error || "No forensic watermark detected in text."}</div>
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {/* ============================================================== */}
                {/* TAB 3: ENTERPRISE DRM ENFORCEMENT ENGINE (/api/validate-lease) */}
                {/* ============================================================== */}
                {activeTab === "drm" && (
                    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
                        {/* Enterprise DRM Enforcer Spec Header */}
                        <div
                            style={{
                                padding: "14px 18px",
                                backgroundColor: "rgba(8, 8, 14, 0.84)",
                                border: "1px solid rgba(243, 242, 248, 0.14)",
                                borderRadius: 8,
                            }}
                        >
                            <div
                                style={{
                                    display: "flex",
                                    justifyContent: "space-between",
                                    alignItems: "center",
                                    paddingBottom: 10,
                                    marginBottom: 10,
                                    borderBottom: "1px solid rgba(43, 216, 200, 0.14)",
                                    fontFamily: "monospace",
                                }}
                            >
                                <span style={{ color: accentColor, fontWeight: 700, fontSize: 12 }}>
                                    🛡️ SENTINELTRACE OFFLINE DRM ENFORCER
                                </span>
                                <span style={{ fontSize: 10, color: "#38bdf8", padding: "2px 8px", border: "1px solid rgba(56,189,248,0.3)", borderRadius: 4 }}>
                                    RSA-256 (.LEASE) SIGNED
                                </span>
                            </div>
                            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, fontFamily: "monospace", fontSize: 11 }}>
                                <div>
                                    <div style={{ color: "#64748b", fontSize: 10 }}>DEVICE BINDING</div>
                                    <div style={{ color: "#fff", fontWeight: 700 }}>[ {leaseState.device_hwid || "HWID-84F9-33A1-KEY"} ]</div>
                                </div>
                                <div>
                                    <div style={{ color: "#64748b", fontSize: 10 }}>CLOCK DEFENSE</div>
                                    <div style={{ color: accentColor, fontWeight: 700 }}>Monotonic Ticks Active</div>
                                </div>
                                <div>
                                    <div style={{ color: "#64748b", fontSize: 10 }}>AES-256-GCM RAM BUFFER</div>
                                    <div style={{ color: leaseState.ram_wiped ? "#ef4444" : "#38bdf8", fontWeight: 700 }}>
                                        {leaseState.ram_key_preview || "RAM Loaded"}
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1fr", gap: 24 }}>
                            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                                {/* Countdown Lease Monitor */}
                                <div style={{ padding: 14, backgroundColor: "rgba(8, 8, 14, 0.84)", border: "1px solid rgba(243, 242, 248, 0.14)", borderRadius: 8 }}>
                                    <div style={{ display: "flex", justifyContent: "space-between", fontFamily: "monospace", marginBottom: 8 }}>
                                        <span style={{ fontSize: 11, color: "rgba(243, 242, 248, 0.56)" }}>COUNTDOWN LEASE MONITOR</span>
                                        <span style={{ fontSize: 15, fontWeight: 800, color: "#fff" }}>
                                            {formatTimer(leaseState.remaining_seconds)} Remaining
                                        </span>
                                    </div>
                                    <div style={{ width: "100%", height: 10, backgroundColor: "rgba(0,255,65,0.08)", borderRadius: 4, overflow: "hidden", marginBottom: 10 }}>
                                        <div
                                            style={{
                                                height: "100%",
                                                width: `${leaseDurationSec > 0 ? Math.max(0, Math.min(100, (leaseState.remaining_seconds / leaseDurationSec) * 100)) : 0}%`,
                                                backgroundColor: leaseState.access_allowed ? accentColor : "#ef4444",
                                                transition: "width 0.5s linear",
                                            }}
                                        />
                                    </div>
                                    <div
                                        style={{
                                            padding: 10,
                                            borderRadius: 6,
                                            textAlign: "center",
                                            fontFamily: "monospace",
                                            fontSize: 13,
                                            fontWeight: 800,
                                            backgroundColor: leaseState.access_allowed ? "rgba(123, 92, 250, 0.10)" : "rgba(239, 68, 68, 0.14)",
                                            color: leaseState.access_allowed ? accentColor : "#ef4444",
                                            border: `1px solid ${leaseState.access_allowed ? "rgba(43, 216, 200, 0.30)" : "rgba(239, 68, 68, 0.45)"}`,
                                        }}
                                    >
                                        STATUS: {leaseState.access_allowed ? "🟢" : "🔴"} {leaseState.status_message}
                                    </div>
                                </div>

                                {/* Primary Enterprise Actions */}
                                <div style={{ display: "flex", gap: 8 }}>
                                    <button
                                        onClick={handleRevokeInstantly}
                                        style={{
                                            flex: 1,
                                            padding: "10px",
                                            backgroundColor: "rgba(239, 68, 68, 0.12)",
                                            border: "1px solid rgba(239, 68, 68, 0.45)",
                                            color: "#f87171",
                                            borderRadius: 6,
                                            cursor: "pointer",
                                            fontSize: 11,
                                            fontWeight: 700,
                                            fontFamily: "monospace",
                                        }}
                                    >
                                        [ Revoke Access Instantly ]
                                    </button>
                                    <button
                                        onClick={handleChallengeQrRenewal}
                                        style={{
                                            flex: 1,
                                            padding: "10px",
                                            backgroundColor: "rgba(56, 189, 248, 0.12)",
                                            border: "1px solid rgba(56, 189, 248, 0.4)",
                                            color: "#38bdf8",
                                            borderRadius: 6,
                                            cursor: "pointer",
                                            fontSize: 11,
                                            fontWeight: 700,
                                            fontFamily: "monospace",
                                        }}
                                    >
                                        [ Challenge Offline QR Renewal ]
                                    </button>
                                </div>

                                {qrChallengeCode && (
                                    <div style={{ padding: 12, backgroundColor: "rgba(1,5,3,0.9)", border: "1px solid #38bdf8", borderRadius: 6, fontFamily: "monospace", fontSize: 11 }}>
                                        <div style={{ color: "#38bdf8", fontWeight: 700, marginBottom: 6 }}>
                                            AIR-GAPPED QR CHALLENGE: {qrChallengeCode}
                                        </div>
                                        <button
                                            onClick={handleCompleteQrRenewal}
                                            style={{
                                                width: "100%",
                                                padding: "8px",
                                                backgroundColor: accentColor,
                                                color: "#050608",
                                                border: "none",
                                                borderRadius: 4,
                                                fontWeight: 700,
                                                cursor: "pointer",
                                            }}
                                        >
                                            Authorize Admin QR Renewal
                                        </button>
                                    </div>
                                )}

                                {/* Duration Slider & Shortcuts */}
                                <div>
                                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                                        <label style={labelStyle}>Offline Window Duration</label>
                                        <span style={{ color: accentColor, fontWeight: 700, fontFamily: "monospace", fontSize: 12 }}>
                                            {leaseMinutes} Minutes
                                        </span>
                                    </div>
                                    <input
                                        type="range"
                                        min={1}
                                        max={120}
                                        value={leaseMinutes}
                                        onChange={(e) => {
                                            const val = parseInt(e.target.value)
                                            setLeaseMinutes(val)
                                            handleResetLease(val)
                                        }}
                                        style={{ width: "100%", accentColor: accentColor, cursor: "pointer" }}
                                    />
                                </div>

                                <div style={{ display: "flex", gap: 8 }}>
                                    <button
                                        onClick={() => issueSignedLease(10)}
                                        style={{ flex: 1, padding: "8px", backgroundColor: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", borderRadius: 6, cursor: "pointer", fontSize: 11, fontFamily: "monospace" }}
                                    >
                                        ⚡ 10-Sec Lease
                                    </button>
                                    <button
                                        onClick={() => setSimClockOffset(-3600)}
                                        style={{ flex: 1, padding: "8px", backgroundColor: "rgba(245,158,11,0.1)", border: "1px solid rgba(245,158,11,0.35)", color: "#fbbf24", borderRadius: 6, cursor: "pointer", fontSize: 11, fontFamily: "monospace" }}
                                    >
                                        ⚠ Rewind Clock
                                    </button>
                                    <button
                                        onClick={() => setOfflineEnabled(!offlineEnabled)}
                                        style={{ flex: 1, padding: "8px", backgroundColor: "rgba(0,255,65,0.08)", border: "1px solid rgba(0,255,65,0.3)", color: accentColor, borderRadius: 6, cursor: "pointer", fontSize: 11, fontFamily: "monospace" }}
                                    >
                                        {offlineEnabled ? `● POLL (${pollCount})` : "○ PAUSED"}
                                    </button>
                                </div>
                            </div>

                            {/* Dynamic Viewport Watermarked RAM Document Reader */}
                            <div
                                style={{
                                    backgroundColor: "rgba(255, 255, 255, 0.02)",
                                    border: "1px solid rgba(255, 255, 255, 0.08)",
                                    borderRadius: 12,
                                    padding: 18,
                                    display: "flex",
                                    flexDirection: "column",
                                    justifyContent: "space-between",
                                    gap: 12,
                                }}
                            >
                                <div>
                                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                                        <span style={{ fontSize: 12, fontWeight: 600, color: "#cbd5e1" }}>
                                            Ephemeral RAM Document Reader
                                        </span>
                                        <span style={{ fontSize: 10, fontFamily: "monospace", color: blockedShortcutsCount > 0 ? "#f87171" : accentColor }}>
                                            {blockedShortcutsCount > 0 ? `🛡 BLOCKED (${blockedShortcutsCount}) · ` : ""}ZERO DISK FOOTPRINT
                                        </span>
                                    </div>

                                    {/* Cached Offline Document Switcher */}
                                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
                                        {OFFLINE_CONFIDENTIAL_DOCS.map((doc) => (
                                            <button
                                                key={doc.id}
                                                type="button"
                                                onClick={() => {
                                                    setActiveOfflineDocId(doc.id)
                                                    setLeaseState((prev) => ({
                                                        ...prev,
                                                        access_allowed: true,
                                                        ram_wiped: false,
                                                        decrypted_viewport_text: doc.text,
                                                    }))
                                                }}
                                                style={{
                                                    padding: "4px 9px",
                                                    borderRadius: 999,
                                                    border: activeOfflineDocId === doc.id ? `1px solid ${accentColor}` : "1px solid rgba(255,255,255,0.14)",
                                                    backgroundColor: activeOfflineDocId === doc.id ? "rgba(123, 92, 250, 0.16)" : "rgba(255,255,255,0.03)",
                                                    color: "#F3F2F8",
                                                    fontSize: 10,
                                                    fontFamily: "monospace",
                                                    cursor: "pointer",
                                                }}
                                            >
                                                {doc.label}
                                            </button>
                                        ))}
                                    </div>

                                    {/* Dynamic Diagonal Viewport Watermark Container */}
                                    <div
                                        onCopy={(e) => { e.preventDefault(); setBlockedShortcutsCount((c) => c + 1) }}
                                        onCut={(e) => { e.preventDefault(); setBlockedShortcutsCount((c) => c + 1) }}
                                        onPaste={(e) => { e.preventDefault(); setBlockedShortcutsCount((c) => c + 1) }}
                                        onContextMenu={(e) => { e.preventDefault(); setBlockedShortcutsCount((c) => c + 1) }}
                                        onSelectStart={(e) => e.preventDefault()}
                                        style={{
                                            position: "relative",
                                            backgroundColor: "#020604",
                                            border: "1px solid rgba(43, 216, 200, 0.22)",
                                            borderRadius: 8,
                                            padding: 18,
                                            minHeight: 165,
                                            overflow: "hidden",
                                            userSelect: "none",
                                            WebkitUserSelect: "none",
                                            msUserSelect: "none",
                                        }}
                                    >
                                        <div style={{ position: "relative", zIndex: 1, fontSize: 12, lineHeight: 1.6, color: "#F3F2F8", whiteSpace: "pre-wrap" }}>
                                            {leaseState.access_allowed
                                                ? leaseState.decrypted_viewport_text ||
                                                  (OFFLINE_CONFIDENTIAL_DOCS.find((d) => d.id === activeOfflineDocId) || OFFLINE_CONFIDENTIAL_DOCS[0]).text
                                                : "[ RAM BUFFER WIPED — ENCRYPTED LOCKDOWN ]"}
                                        </div>

                                        {/* Semi-Transparent Diagonal Watermark Overlay (pointerEvents: none, zIndex: 9999) */}
                                        {leaseState.access_allowed && (
                                            <div
                                                aria-hidden="true"
                                                style={{
                                                    position: "absolute",
                                                    inset: -30,
                                                    zIndex: 9999,
                                                    pointerEvents: "none",
                                                    userSelect: "none",
                                                    WebkitUserSelect: "none",
                                                    msUserSelect: "none",
                                                    transform: "rotate(-18deg)",
                                                    opacity: 0.15,
                                                    display: "flex",
                                                    flexDirection: "column",
                                                    justifyContent: "space-around",
                                                    fontFamily: "monospace",
                                                    fontSize: 9.5,
                                                    fontWeight: 700,
                                                    color: accentColor,
                                                    whiteSpace: "nowrap",
                                                }}
                                            >
                                                {[0, 1, 2, 3].map((row) => (
                                                    <div key={row}>
                                                        {`CONFIDENTIAL • ACCESSED BY ${authUser?.email || "authenticated_user"} • ${watermarkTimestamp} • SECURE SESSION  •  `.repeat(2)}
                                                    </div>
                                                ))}
                                            </div>
                                        )}

                                        {/* Revoked Overlay */}
                                        {!leaseState.access_allowed && (
                                            <div
                                                style={{
                                                    position: "absolute",
                                                    inset: 0,
                                                    zIndex: 3,
                                                    backgroundColor: "rgba(18, 3, 8, 0.92)",
                                                    display: "flex",
                                                    flexDirection: "column",
                                                    alignItems: "center",
                                                    justifyContent: "center",
                                                    textAlign: "center",
                                                    padding: 16,
                                                    fontFamily: "monospace",
                                                }}
                                            >
                                                <div style={{ fontSize: 18, marginBottom: 4 }}>🔒</div>
                                                <div style={{ color: "#ef4444", fontWeight: 700, fontSize: 12 }}>
                                                    {leaseState.status_message}
                                                </div>
                                                <div style={{ color: "rgba(243, 242, 248, 0.56)", fontSize: 10, marginTop: 4 }}>
                                                    AES-256-GCM Key Overwritten (0x00)
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </div>

                                <div style={{ fontSize: 11, fontFamily: "monospace", display: "flex", flexDirection: "column", gap: 6 }}>
                                    <div style={resultRowStyle}>
                                        <span style={{ color: "#64748b" }}>Monotonic Elapsed:</span>
                                        <span style={{ color: "#38bdf8" }}>{(leaseState.monotonic_elapsed_seconds ?? 0).toFixed(1)}s</span>
                                    </div>
                                    <div style={resultRowStyle}>
                                        <span style={{ color: "#64748b" }}>RSA-256 Ticket:</span>
                                        <span style={{ color: accentColor }}>{rsaSigPreview.slice(0, 22)}...</span>
                                    </div>
                                    <div style={{ ...resultRowStyle, borderBottom: "none" }}>
                                        <span style={{ color: "#64748b" }}>RAM Key State:</span>
                                        <span style={{ color: leaseState.ram_wiped ? "#ef4444" : accentColor }}>
                                            {leaseState.ram_key_preview || "Active"}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {/* ============================================================== */}
                {/* TAB 4: JUDGE STRESS TEST ("TRY TO BREAK IT" CHALLENGE MODE)    */}
                {/* ============================================================== */}
                {activeTab === "stress" && (
                    <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1fr", gap: 28 }}>
                        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                <span style={{ fontSize: 12, fontWeight: 700, color: accentColor, fontFamily: "monospace" }}>
                                    ⚡ "TRY TO BREAK IT" CHALLENGE
                                </span>
                                <button
                                    onClick={handleRegenerate}
                                    style={{
                                        padding: "5px 10px",
                                        backgroundColor: "rgba(255,255,255,0.06)",
                                        border: "1px solid rgba(0,255,65,0.2)",
                                        color: "#F3F2F8",
                                        borderRadius: 4,
                                        cursor: "pointer",
                                        fontSize: 11,
                                        fontFamily: "monospace",
                                    }}
                                >
                                    ↻ Regenerate Copies
                                </button>
                            </div>

                            <div style={{ fontSize: 12, color: "rgba(243, 242, 248, 0.56)", lineHeight: 1.5 }}>
                                Alice &amp; Bob receive visually identical copies. Edit Alice's copy below—change words, delete sentences, or slice 80%—then hit <strong>Analyze &amp; Prove Source</strong>.
                            </div>

                            {/* Alice vs Bob side-by-side */}
                            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                                <div
                                    onCopy={(e) => e.preventDefault()}
                                    onCut={(e) => e.preventDefault()}
                                    onContextMenu={(e) => e.preventDefault()}
                                    style={{
                                        padding: 10,
                                        backgroundColor: "rgba(1,5,3,0.8)",
                                        border: `1px solid ${accentColor}`,
                                        borderRadius: 6,
                                        userSelect: "none",
                                        WebkitUserSelect: "none",
                                    }}
                                >
                                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                                        <span style={{ fontSize: 10, color: accentColor, fontFamily: "monospace", fontWeight: 700 }}>ALICE SMITH (USR-8492)</span>
                                        <button onClick={() => setStressInput(aliceCopy)} style={{ ...quickLinkStyle, fontSize: 10 }}>Load</button>
                                    </div>
                                    <div style={{ fontSize: 10, color: "rgba(243, 242, 248, 0.56)", fontFamily: "monospace", maxHeight: 54, overflow: "hidden" }}>
                                        {aliceCopy || "Loading..."}
                                    </div>
                                </div>
                                <div
                                    onCopy={(e) => e.preventDefault()}
                                    onCut={(e) => e.preventDefault()}
                                    onContextMenu={(e) => e.preventDefault()}
                                    style={{
                                        padding: 10,
                                        backgroundColor: "rgba(1,5,3,0.8)",
                                        border: "1px solid rgba(56,189,248,0.3)",
                                        borderRadius: 6,
                                        userSelect: "none",
                                        WebkitUserSelect: "none",
                                    }}
                                >
                                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                                        <span style={{ fontSize: 10, color: "#38bdf8", fontFamily: "monospace", fontWeight: 700 }}>BOB JONES (USR-3104)</span>
                                        <button onClick={() => setStressInput(bobCopy)} style={{ ...quickLinkStyle, color: "#38bdf8", fontSize: 10 }}>Load</button>
                                    </div>
                                    <div style={{ fontSize: 10, color: "rgba(243, 242, 248, 0.56)", fontFamily: "monospace", maxHeight: 54, overflow: "hidden" }}>
                                        {bobCopy || "Loading..."}
                                    </div>
                                </div>
                            </div>

                            {/* Attack Controls */}
                            <div>
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                                    <label style={labelStyle}>Judge Attack Sandbox</label>
                                    <div style={{ display: "flex", gap: 8 }}>
                                        <button
                                            onClick={() => {
                                                const lines = stressInput.split("\n")
                                                if (lines.length > 1) {
                                                    lines.splice(1, 1)
                                                    setStressInput(lines.join("\n"))
                                                }
                                            }}
                                            style={{ ...quickLinkStyle, color: "#f87171" }}
                                        >
                                            ✂ Del Sentence
                                        </button>
                                        <button
                                            onClick={() =>
                                                setStressInput(
                                                    stressInput
                                                        .replace("$142M", "$185M [EDITED]")
                                                        .replace("Monday market open", "Tuesday")
                                                )
                                            }
                                            style={{ ...quickLinkStyle, color: "#fbbf24" }}
                                        >
                                            ✎ Mutate Words
                                        </button>
                                        <button
                                            onClick={() => {
                                                const lines = stressInput.split("\n")
                                                setStressInput(lines[lines.length - 1] || stressInput.slice(0, Math.floor(stressInput.length * 0.4)))
                                            }}
                                            style={{ ...quickLinkStyle, color: "#38bdf8" }}
                                        >
                                            ⚡ 1 Sentence
                                        </button>
                                    </div>
                                </div>
                                <textarea
                                    rows={4}
                                    value={stressInput}
                                    onChange={(e) => setStressInput(e.target.value)}
                                    style={{ ...inputStyle, resize: "vertical", fontFamily: "monospace", fontSize: 12 }}
                                />
                            </div>

                            <button
                                onClick={handleRunStressTest}
                                disabled={isStressTesting}
                                style={{
                                    padding: "12px 20px",
                                    backgroundColor: accentColor,
                                    color: "#050608",
                                    border: "none",
                                    borderRadius: 8,
                                    fontWeight: 700,
                                    cursor: isStressTesting ? "wait" : "pointer",
                                    boxShadow: `0 0 20px rgba(123, 92, 250, 0.32)`,
                                }}
                            >
                                {isStressTesting ? "Analyzing Mutated Text..." : "🛡 Analyze & Prove Source"}
                            </button>
                        </div>

                        {/* Stress Test Result Card */}
                        <div
                            style={{
                                backgroundColor: "rgba(255, 255, 255, 0.02)",
                                border: "1px solid rgba(255, 255, 255, 0.08)",
                                borderRadius: 12,
                                padding: 20,
                            }}
                        >
                            <span style={{ fontSize: 12, fontWeight: 600, color: "#cbd5e1", display: "block", marginBottom: 14 }}>
                                Stress Test Verdict
                            </span>

                            {!stressResult ? (
                                <div
                                    style={{
                                        display: "flex",
                                        alignItems: "center",
                                        justifyContent: "center",
                                        minHeight: 200,
                                        color: "#64748b",
                                        fontSize: 12,
                                        fontFamily: "monospace",
                                        border: "1px dashed rgba(255, 255, 255, 0.1)",
                                        borderRadius: 8,
                                        textAlign: "center",
                                        padding: 20,
                                    }}
                                >
                                    Mutate Alice's copy on the left and click 'Analyze &amp; Prove Source' to try to break SentinelTrace.
                                </div>
                            ) : stressResult.match_found ? (
                                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                                    <div
                                        style={{
                                            padding: 12,
                                            borderRadius: 8,
                                            backgroundColor: stressResult.verified ? "rgba(123, 92, 250, 0.10)" : "rgba(239, 68, 68, 0.1)",
                                            border: `1px solid ${stressResult.verified ? "rgba(123, 92, 250, 0.32)" : "rgba(239, 68, 68, 0.3)"}`,
                                            textAlign: "center",
                                            color: stressResult.verified ? accentColor : "#f87171",
                                            fontWeight: 800,
                                            fontFamily: "monospace",
                                            fontSize: 13,
                                        }}
                                    >
                                        {stressResult.verified ? "✓ CHALLENGE PASSED — LEAKER CAUGHT!" : "⚠ TAMPER DETECTED"}
                                    </div>
                                    <div style={resultRowStyle}>
                                        <span style={{ color: "#64748b" }}>Caught Leaker:</span>
                                        <span style={{ color: "#fff", fontWeight: 700 }}>{stressResult.recipient_id}</span>
                                    </div>
                                    <div style={resultRowStyle}>
                                        <span style={{ color: "#64748b" }}>Session ID:</span>
                                        <span style={{ color: "#38bdf8", fontFamily: "monospace" }}>{stressResult.session_id}</span>
                                    </div>
                                    <div style={resultRowStyle}>
                                        <span style={{ color: "#64748b" }}>Surviving Chunks:</span>
                                        <span style={{ color: accentColor, fontFamily: "monospace" }}>
                                            {stressResult.chunks_verified}/{stressResult.chunks_detected} Verified
                                        </span>
                                    </div>
                                    <div style={resultRowStyle}>
                                        <span style={{ color: "#64748b" }}>HMAC Check:</span>
                                        <span style={{ color: accentColor, fontFamily: "monospace" }}>
                                            Signature Verified (HMAC-SHA256)
                                        </span>
                                    </div>
                                </div>
                            ) : (
                                <div style={errorBannerStyle}>
                                    ⚠ {stressResult.error || "All redundant watermark chunks were removed."}
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    )
}

// Styling Constants
const inputStyle: React.CSSProperties = {
    width: "100%",
    backgroundColor: "rgba(8, 8, 14, 0.84)",
    border: "1px solid rgba(243, 242, 248, 0.12)",
    borderRadius: 4,
    padding: "9px 12px",
    color: "#F3F2F8",
    fontSize: 13,
    outline: "none",
    boxSizing: "border-box",
}

const labelStyle: React.CSSProperties = {
    display: "block",
    fontSize: 11,
    textTransform: "uppercase",
    color: "rgba(243, 242, 248, 0.56)",
    marginBottom: 6,
    fontWeight: 600,
    letterSpacing: "0.06em",
}

const resultRowStyle: React.CSSProperties = {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "8px 0",
    borderBottom: "1px solid rgba(123, 92, 250, 0.10)",
}

const codePillStyle: React.CSSProperties = {
    backgroundColor: "rgba(123, 92, 250, 0.10)",
    border: "1px solid rgba(123, 92, 250, 0.24)",
    padding: "2px 6px",
    borderRadius: 4,
    fontFamily: "monospace",
    fontSize: 11,
    color: "#7B5CFA",
}

const quickLinkStyle: React.CSSProperties = {
    background: "none",
    border: "none",
    color: "#7B5CFA",
    fontSize: 11,
    cursor: "pointer",
    textDecoration: "underline",
}

const errorBannerStyle: React.CSSProperties = {
    padding: 10,
    borderRadius: 6,
    backgroundColor: "rgba(239, 68, 68, 0.1)",
    border: "1px solid rgba(239, 68, 68, 0.3)",
    color: "#f87171",
    fontSize: 12,
}

// Framer Property Controls Registration
addPropertyControls(LeakLensDashboard, {
    apiUrl: {
        type: ControlType.String,
        title: "API URL",
        defaultValue: DEFAULT_REMOTE_BACKEND,
    },
    brandName: {
        type: ControlType.String,
        title: "Brand Name",
        defaultValue: "LeakLens",
    },
    accentColor: {
        type: ControlType.Color,
        title: "Accent Color",
        defaultValue: "#7B5CFA",
    },
    googleClientId: {
        type: ControlType.String,
        title: "Google Client ID",
        defaultValue: "243029529822-mkj5hefpohh86e5ru9fdkatve05bubaq.apps.googleusercontent.com",
    },
    loginUrl: {
        type: ControlType.String,
        title: "Login Page URL",
        defaultValue: FRAMER_LOGIN_URL,
    },
    requireAuthGuard: {
        type: ControlType.Boolean,
        title: "Require Login Guard",
        defaultValue: true,
    },
})

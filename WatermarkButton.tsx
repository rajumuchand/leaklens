import * as React from "react"
import { addPropertyControls, ControlType } from "framer"

/**
 * WatermarkButton — Custom Framer Code Component
 * Calls POST {apiUrl}/api/watermark with { recipient_id, session_id, text }
 * Styled to match the LeakLens / Hexwall glassmorphic neon aesthetic.
 */

interface WatermarkResponse {
    status: string
    filename?: string
    doc_id?: string
    beacon_url?: string
    pages_processed?: number
    recipient_id: string
    session_id: string
    signature?: string
    chunks_embedded?: number
    watermarked_text: string
}

export default function WatermarkButton(props: {
    apiUrl?: string
    buttonLabel?: string
    recipientId?: string
    sessionId?: string
    documentText?: string
    showInputs?: boolean
    brandColor?: string
    onBrandColor?: string
    textColor?: string
}) {
    const {
        apiUrl = "https://leaklens-tyrn.vercel.app",
        buttonLabel = "Generate Watermarked Copy",
        recipientId: initialRecipient = "Alice Smith (USR-8492)",
        sessionId: initialSession = "SES-SYNAPSE-2026",
        documentText: initialText = "CONFIDENTIAL STRATEGY MEMO: Enterprise valuation locked at $142M. Strictly internal distribution only.",
        showInputs = true,
        brandColor = "#7B5CFA",
        onBrandColor = "#FFFFFF",
        textColor = "#F3F2F8",
    } = props

    const [recipientId, setRecipientId] = React.useState(initialRecipient)
    const [sessionId, setSessionId] = React.useState(initialSession)
    const [text, setText] = React.useState(initialText)
    const [hovered, setHovered] = React.useState(false)
    const [loading, setLoading] = React.useState(false)
    const [result, setResult] = React.useState<WatermarkResponse | null>(null)
    const [error, setError] = React.useState<string | null>(null)
    const [copied, setCopied] = React.useState(false)
    const [pdfFile, setPdfFile] = React.useState<File | null>(null)
    const [isDraggingPdf, setIsDraggingPdf] = React.useState(false)
    const pdfInputRef = React.useRef<HTMLInputElement | null>(null)

    // Sync Framer canvas prop edits
    React.useEffect(() => { setRecipientId(initialRecipient) }, [initialRecipient])
    React.useEffect(() => { setSessionId(initialSession) }, [initialSession])
    React.useEffect(() => { setText(initialText) }, [initialText])

    const handleWatermark = async () => {
        setLoading(true)
        setError(null)

        const baseUrl = apiUrl.replace(/\/+$/, "")
        const headers: Record<string, string> = {
            "Content-Type": "application/json",
        }

        try {
            const response = await fetch(`${baseUrl}/api/watermark`, {
                method: "POST",
                headers,
                body: JSON.stringify({
                    recipient_id: recipientId,
                    session_id: sessionId,
                    text,
                }),
            })

            if (!response.ok) {
                const errData = await response.json().catch(() => ({}))
                throw new Error(errData.detail || `HTTP ${response.status}`)
            }

            const data: WatermarkResponse = await response.json()
            setResult(data)

            // Broadcast to InspectLeakButton on the same Framer page if present
            if (typeof window !== "undefined") {
                window.dispatchEvent(
                    new CustomEvent("leaklens:watermarked", { detail: data })
                )
            }
        } catch (err: any) {
            setError(err?.message || "Failed to reach /api/watermark endpoint")
        } finally {
            setLoading(false)
        }
    }

    const handleCopy = () => {
        if (!result?.watermarked_text) return
        navigator.clipboard?.writeText(result.watermarked_text)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
    }

    const handleUploadWatermarkPdf = async () => {
        if (!pdfFile) {
            setError("Select or drag-and-drop a PDF file first.")
            return
        }
        setLoading(true)
        setError(null)
        const baseUrl = apiUrl.replace(/\/+$/, "")
        const headers: Record<string, string> = {}

        const formData = new FormData()
        formData.append("file", pdfFile)
        formData.append("recipient_id", recipientId)
        formData.append("session_id", sessionId)

        try {
            const resp = await fetch(`${baseUrl}/api/watermark-pdf`, {
                method: "POST",
                headers,
                body: formData,
            })
            if (!resp.ok) {
                const errData = await resp.json().catch(() => ({}))
                throw new Error(errData.detail || `HTTP ${resp.status}`)
            }
            const data: WatermarkResponse = await resp.json()
            setResult(data)
            if (typeof window !== "undefined") {
                window.dispatchEvent(new CustomEvent("leaklens:watermarked", { detail: data }))
                if (data.beacon_url) {
                    window.dispatchEvent(
                        new CustomEvent("leaklens:beacon_armed", {
                            detail: {
                                doc_id: data.doc_id || sessionId,
                                recipient_id: recipientId,
                                beacon_url: data.beacon_url,
                            },
                        })
                    )
                }
            }
        } catch (err: any) {
            setError(err?.message || "Failed to process PDF at /api/watermark-pdf")
        } finally {
            setLoading(false)
        }
    }

    const handleDownloadCopyToCopyPdf = async () => {
        if (!pdfFile) {
            setError("Select or drag-and-drop a PDF file first.")
            return
        }
        setLoading(true)
        setError(null)
        const baseUrl = apiUrl.replace(/\/+$/, "")
        const headers: Record<string, string> = {}

        const formData = new FormData()
        formData.append("file", pdfFile)
        formData.append("recipient_id", recipientId)
        formData.append("session_id", sessionId)

        try {
            const resp = await fetch(`${baseUrl}/api/download-watermarked-pdf`, {
                method: "POST",
                headers,
                body: formData,
            })
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
            const armedDocId = resp.headers.get("X-LeakLens-Doc-Id") || sessionId
            const armedBeaconUrl =
                resp.headers.get("X-Canary-Beacon-Url") ||
                `${baseUrl}/api/beacon/${encodeURIComponent(armedDocId)}/${encodeURIComponent(recipientId)}/pixel.png`
            if (typeof window !== "undefined") {
                window.dispatchEvent(
                    new CustomEvent("leaklens:beacon_armed", {
                        detail: { doc_id: armedDocId, recipient_id: recipientId, beacon_url: armedBeaconUrl },
                    })
                )
            }
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
            setError(err?.message || "Failed to download copy-to-copy watermarked PDF")
        } finally {
            setLoading(false)
        }
    }

    const handleDownloadPdf = async () => {
        setError(null)
        const baseUrl = apiUrl.replace(/\/+$/, "")
        const headers: Record<string, string> = { "Content-Type": "application/json" }

        try {
            const resp = await fetch(`${baseUrl}/api/export-watermark-pdf`, {
                method: "POST",
                headers,
                body: JSON.stringify({ recipient_id: recipientId, session_id: sessionId, text: result?.watermarked_text || text }),
            })
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
            const armedDocId = resp.headers.get("X-LeakLens-Doc-Id") || sessionId
            const armedBeaconUrl =
                resp.headers.get("X-Canary-Beacon-Url") ||
                `${baseUrl}/api/beacon/${encodeURIComponent(armedDocId)}/${encodeURIComponent(recipientId)}/pixel.png`
            if (typeof window !== "undefined") {
                window.dispatchEvent(
                    new CustomEvent("leaklens:beacon_armed", {
                        detail: { doc_id: armedDocId, recipient_id: recipientId, beacon_url: armedBeaconUrl },
                    })
                )
            }
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
            setError(err?.message || "Failed to generate PDF")
        }
    }

    return (
        <div
            style={{
                width: "100%",
                boxSizing: "border-box",
                display: "flex",
                flexDirection: "column",
                gap: 14,
                padding: showInputs || result || error ? 20 : 0,
                backgroundColor: showInputs || result || error ? "rgba(6, 6, 10, 0.72)" : "transparent",
                backdropFilter: showInputs || result || error ? "blur(14px)" : undefined,
                WebkitBackdropFilter: showInputs || result || error ? "blur(14px)" : undefined,
                border: showInputs || result || error ? "1px solid rgba(243, 242, 248, 0.12)" : "none",
                color: textColor,
                fontFamily: "var(--framer-font-family, 'Inter', sans-serif)",
            }}
        >
            {showInputs && (
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                        <div>
                            <label style={labelStyle}>Recipient ID</label>
                            <input
                                type="text"
                                value={recipientId}
                                onChange={(e) => setRecipientId(e.target.value)}
                                style={inputStyle}
                            />
                        </div>
                        <div>
                            <label style={labelStyle}>Session ID</label>
                            <input
                                type="text"
                                value={sessionId}
                                onChange={(e) => setSessionId(e.target.value)}
                                style={inputStyle}
                            />
                        </div>
                    </div>

                    <div>
                        <label style={labelStyle}>Document Text</label>
                        <textarea
                            rows={3}
                            value={text}
                            onChange={(e) => setText(e.target.value)}
                            style={{ ...inputStyle, resize: "vertical", lineHeight: 1.5 }}
                        />
                    </div>
                </div>
            )}

            {/* Hexwall-styled Specular Action Button */}
            <button
                type="button"
                disabled={loading}
                onClick={handleWatermark}
                onMouseEnter={() => setHovered(true)}
                onMouseLeave={() => setHovered(false)}
                style={{
                    boxSizing: "border-box",
                    display: "inline-flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: 12,
                    width: "100%",
                    height: 46,
                    padding: "0 24px",
                    border: "1px solid transparent",
                    cursor: loading ? "wait" : "pointer",
                    fontFamily: "monospace",
                    fontWeight: 600,
                    fontSize: 12,
                    letterSpacing: "0.08em",
                    textTransform: "uppercase",
                    color: onBrandColor,
                    background: `linear-gradient(135deg, rgba(255,255,255,.42), rgba(255,255,255,0) 42%, rgba(0,0,0,0) 58%, rgba(0,0,0,.3)), ${brandColor}`,
                    boxShadow: hovered
                        ? `inset 1px 1px 0 rgba(255,255,255,.6), inset -1px -1px 0 rgba(0,0,0,.45), 0 0 22px ${brandColor}, 0 0 55px rgba(43, 216, 200, 0.35)`
                        : "inset 1px 1px 0 rgba(255,255,255,.38), inset -1px -1px 0 rgba(0,0,0,.45)",
                    transition: "box-shadow 0.25s",
                    opacity: loading ? 0.8 : 1,
                }}
            >
                <span>{loading ? "EMBEDDING WATERMARK..." : buttonLabel}</span>
                <svg
                    width="16"
                    height="16"
                    viewBox="0 0 16 16"
                    fill="none"
                    aria-hidden="true"
                    style={{
                        flex: "none",
                        transform: hovered ? "translateX(4px)" : "none",
                        transition: "transform 0.2s steps(3, end)",
                    }}
                >
                    <path
                        d="M2 8h11M9 4l4 4-4 4"
                        stroke="currentColor"
                        strokeWidth="1.6"
                        strokeLinecap="square"
                    />
                </svg>
            </button>

            {showInputs && (
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
                        padding: 12,
                        backgroundColor: isDraggingPdf ? "rgba(123, 92, 250, 0.10)" : "rgba(8, 8, 14, 0.70)",
                        border: `1px dashed ${isDraggingPdf ? brandColor : "rgba(56, 189, 248, 0.35)"}`,
                        cursor: "pointer",
                        display: "flex",
                        flexDirection: "column",
                        gap: 8,
                    }}
                >
                    <div style={{ display: "flex", justifyContent: "space-between", fontFamily: "monospace", fontSize: 10 }}>
                        <span style={{ color: "#2BD8C8" }}>PDF DRAG-AND-DROP (/api/watermark-pdf)</span>
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
                    <div style={{ display: "flex", gap: 6 }}>
                        <button
                            type="button"
                            onClick={(e) => {
                                e.stopPropagation()
                                handleUploadWatermarkPdf()
                            }}
                            disabled={loading}
                            style={{
                                flex: 1,
                                height: 36,
                                background: "rgba(56, 189, 248, 0.12)",
                                border: "1px solid rgba(56, 189, 248, 0.4)",
                                color: "#2BD8C8",
                                fontFamily: "monospace",
                                fontSize: 10,
                                fontWeight: 700,
                                textTransform: "uppercase",
                                cursor: "pointer",
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
                            disabled={loading}
                            style={{
                                flex: 1,
                                height: 36,
                                background: "rgba(43, 216, 200, 0.14)",
                                border: "1px solid rgba(43, 216, 200, 0.40)",
                                color: brandColor,
                                fontFamily: "monospace",
                                fontSize: 10,
                                fontWeight: 700,
                                textTransform: "uppercase",
                                cursor: "pointer",
                            }}
                        >
                            Download Watermarked PDF
                        </button>
                    </div>
                </div>
            )}

            {error && (
                <div
                    style={{
                        padding: 10,
                        backgroundColor: "rgba(255, 59, 92, 0.12)",
                        border: "1px solid rgba(255, 59, 92, 0.4)",
                        color: "#FF3B5C",
                        fontFamily: "monospace",
                        fontSize: 12,
                    }}
                >
                    ⚠ {error}
                </div>
            )}

            {result && (
                <div
                    style={{
                        padding: 14,
                        backgroundColor: "rgba(8, 8, 14, 0.86)",
                        border: "1px solid rgba(43, 216, 200, 0.28)",
                        display: "flex",
                        flexDirection: "column",
                        gap: 10,
                    }}
                >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 6 }}>
                        <span style={{ fontSize: 11, fontFamily: "monospace", color: brandColor }}>
                            ✓ {result.pages_processed ? `PDF (${result.pages_processed}P)` : "EMBEDDED"} • {result.chunks_embedded || 1} REDUNDANT CHUNKS
                        </span>
                        <div style={{ display: "flex", gap: 6 }}>
                            <button
                                type="button"
                                onClick={handleDownloadPdf}
                                style={{
                                    padding: "4px 10px",
                                    background: "rgba(56, 189, 248, 0.12)",
                                    border: "1px solid rgba(56, 189, 248, 0.35)",
                                    color: "#2BD8C8",
                                    fontFamily: "monospace",
                                    fontSize: 11,
                                    cursor: "pointer",
                                }}
                            >
                                EXPORT PDF
                            </button>
                            <button
                                type="button"
                                onClick={handleCopy}
                                style={{
                                    padding: "4px 10px",
                                    background: "rgba(43, 216, 200, 0.14)",
                                    border: "1px solid rgba(43, 216, 200, 0.35)",
                                    color: brandColor,
                                    fontFamily: "monospace",
                                    fontSize: 11,
                                    cursor: "pointer",
                                }}
                            >
                                {copied ? "✓ COPIED" : "COPY TEXT"}
                            </button>
                        </div>
                    </div>
                    <div
                        style={{
                            fontFamily: "monospace",
                            fontSize: 12,
                            color: textColor,
                            lineHeight: 1.5,
                            whiteSpace: "pre-wrap",
                            wordBreak: "break-word",
                        }}
                    >
                        {result.watermarked_text}
                    </div>
                </div>
            )}
        </div>
    )
}

const labelStyle: React.CSSProperties = {
    display: "block",
    fontFamily: "monospace",
    fontSize: 10,
    textTransform: "uppercase",
    letterSpacing: "0.08em",
    color: "rgba(243, 242, 248, 0.56)",
    marginBottom: 5,
}

const inputStyle: React.CSSProperties = {
    width: "100%",
    boxSizing: "border-box",
    backgroundColor: "rgba(8, 8, 14, 0.84)",
    border: "1px solid rgba(243, 242, 248, 0.14)",
    padding: "9px 12px",
    color: "#F3F2F8",
    fontFamily: "monospace",
    fontSize: 12,
    outline: "none",
}

addPropertyControls(WatermarkButton, {
    apiUrl: {
        type: ControlType.String,
        title: "API Base URL",
        defaultValue: "https://leaklens-tyrn.vercel.app",
        description: "Cloud LeakLens backend URL (no trailing slash).",
    },
    buttonLabel: {
        type: ControlType.String,
        title: "Button Label",
        defaultValue: "Generate Watermarked Copy",
    },
    showInputs: {
        type: ControlType.Boolean,
        title: "Show Inputs",
        defaultValue: true,
        description: "Hide inputs to render as a standalone button driven by props.",
    },
    recipientId: {
        type: ControlType.String,
        title: "Recipient ID",
        defaultValue: "Alice Smith (USR-8492)",
    },
    sessionId: {
        type: ControlType.String,
        title: "Session ID",
        defaultValue: "SES-SYNAPSE-2026",
    },
    documentText: {
        type: ControlType.String,
        title: "Document Text",
        displayTextArea: true,
        defaultValue: "CONFIDENTIAL STRATEGY MEMO: Enterprise valuation locked at $142M. Strictly internal distribution only.",
    },
    brandColor: {
        type: ControlType.Color,
        title: "Brand Glow",
        defaultValue: "#7B5CFA",
    },
    onBrandColor: {
        type: ControlType.Color,
        title: "Button Text",
        defaultValue: "#FFFFFF",
    },
    textColor: {
        type: ControlType.Color,
        title: "Text Color",
        defaultValue: "#F3F2F8",
    },
})

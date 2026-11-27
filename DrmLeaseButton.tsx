import * as React from "react"
import { addPropertyControls, ControlType } from "framer"

/**
 * DrmLeaseButton — Custom Framer Code Component
 * Calls & polls POST {apiUrl}/api/validate-lease with { permission_end_timestamp }
 * Displays live countdown and ACCESS GRANTED / ACCESS REVOKED state.
 */

interface LeaseResponse {
    access_allowed: boolean
    token_verified?: boolean
    rsa_verified?: boolean
    clock_tamper_detected?: boolean
    ram_wiped?: boolean
    ram_key_preview?: string
    device_hwid?: string
    current_time?: number
    permission_end_timestamp?: number
    monotonic_elapsed_seconds?: number
    remaining_seconds: number
    status_message: string
}

const buildTunnelHeaders = (_baseUrl: string, extra: Record<string, string> = {}) => ({
    ...extra,
})

export default function DrmLeaseButton(props: {
    apiUrl?: string
    leaseSeconds?: number
    buttonLabel?: string
    autoPoll?: boolean
    brandColor?: string
    textColor?: string
}) {
    const {
        apiUrl = "https://leaklens-tyrn.vercel.app",
        leaseSeconds = 30,
        buttonLabel = "Reset / Renew Lease",
        autoPoll = true,
        brandColor = "#7B5CFA",
        textColor = "#F3F2F8",
    } = props

    const [leaseId, setLeaseId] = React.useState<string | null>(null)
    const [leaseToken, setLeaseToken] = React.useState<string | null>(null)
    const [rsaJwt, setRsaJwt] = React.useState<string | null>(null)
    const [leaseStartMono, setLeaseStartMono] = React.useState(() => (typeof performance !== "undefined" ? performance.now() : Date.now()))
    const [simClockOffset, setSimClockOffset] = React.useState(0)
    const [endTimestamp, setEndTimestamp] = React.useState(() => Date.now() / 1000 + leaseSeconds)
    const [leaseState, setLeaseState] = React.useState<LeaseResponse | null>(null)
    const [hovered, setHovered] = React.useState(false)
    const [punEpochId, setPunEpochId] = React.useState<string | null>(null)
    const [punBlockedMsg, setPunBlockedMsg] = React.useState<string | null>(null)

    const issueSignedLease = React.useCallback(async () => {
        const baseUrl = apiUrl.replace(/\/+$/, "")
        const headers = buildTunnelHeaders(baseUrl, { "Content-Type": "application/json" })

        setSimClockOffset(0)
        setPunBlockedMsg(null)
        const nowMono = typeof performance !== "undefined" ? performance.now() : Date.now()
        setLeaseStartMono(nowMono)
        setEndTimestamp(Date.now() / 1000 + leaseSeconds)

        try {
            const [resp, punResp] = await Promise.all([
                fetch(`${baseUrl}/api/issue-lease`, {
                    method: "POST",
                    headers,
                    body: JSON.stringify({ duration_seconds: leaseSeconds }),
                }),
                fetch(`${baseUrl}/api/drm/lease/issue`, {
                    method: "POST",
                    headers,
                    body: JSON.stringify({
                        doc_id: "DOC-HELIOS-2026",
                        user_id: "User_1",
                        duration_minutes: Math.max(1, Math.round(leaseSeconds / 60)),
                    }),
                }),
            ])
            if (resp.ok) {
                const data = await resp.json()
                setLeaseId(data.lease_id)
                setLeaseToken(data.lease_token)
                setRsaJwt(data.rsa_jwt)
            }
            if (punResp.ok) {
                const punData = await punResp.json()
                setPunEpochId(punData.epoch_id)
            }
        } catch {
            // Fallback to timestamp mode if offline
        }
    }, [apiUrl, leaseSeconds])

    const simulateEpochPuncture = async () => {
        const baseUrl = apiUrl.replace(/\/+$/, "")
        const epoch = punEpochId || "EP-SIMULATED"
        try {
            await fetch(`${baseUrl}/api/drm/lease/puncture`, {
                method: "POST",
                headers: buildTunnelHeaders(baseUrl, { "Content-Type": "application/json" }),
                body: JSON.stringify({ doc_id: "DOC-HELIOS-2026", user_id: "User_1", epoch_id: epoch }),
            })
            await fetch(`${baseUrl}/api/drm/verify-access`, {
                method: "POST",
                headers: buildTunnelHeaders(baseUrl, { "Content-Type": "application/json" }),
                body: JSON.stringify({ doc_id: "DOC-HELIOS-2026", user_id: "User_1", epoch_id: epoch }),
            })
        } catch {}
        setPunBlockedMsg("❌ File Does Not Open — Decryption Key Destroyed")
        setLeaseState((prev) => ({
            ...(prev || { remaining_seconds: 0 }),
            access_allowed: false,
            remaining_seconds: 0,
            ram_wiped: true,
            ram_key_preview: "0x00000000_PUNCTURED",
            status_message: "Access Expired. Key Punctured by TPM Hardware Counter",
        }))
    }

    React.useEffect(() => {
        issueSignedLease()
    }, [issueSignedLease])

    const validateOnce = React.useCallback(async () => {
        const baseUrl = apiUrl.replace(/\/+$/, "")
        const headers = buildTunnelHeaders(baseUrl, { "Content-Type": "application/json" })

        const nowMono = typeof performance !== "undefined" ? performance.now() : Date.now()
        const clientElapsed = (nowMono - leaseStartMono) / 1000

        try {
            const resp = await fetch(`${baseUrl}/api/validate-lease`, {
                method: "POST",
                headers,
                body: JSON.stringify({
                    permission_end_timestamp: endTimestamp,
                    lease_token: leaseToken,
                    rsa_jwt: rsaJwt,
                    client_elapsed_seconds: clientElapsed,
                    simulated_clock_offset_seconds: simClockOffset,
                }),
            })
            if (resp.ok) {
                const data: LeaseResponse = await resp.json()
                setLeaseState(data)
            }
        } catch {
            // Silently skip transient poll errors
        }
    }, [apiUrl, endTimestamp, leaseToken, rsaJwt, leaseStartMono, simClockOffset])

    const revokeNow = async () => {
        const baseUrl = apiUrl.replace(/\/+$/, "")
        try {
            const resp = await fetch(`${baseUrl}/api/revoke-lease`, {
                method: "POST",
                headers: buildTunnelHeaders(baseUrl, { "Content-Type": "application/json" }),
                body: JSON.stringify({ lease_id: leaseId, lease_token: leaseToken }),
            })
            if (resp.ok) {
                const data = await resp.json()
                setLeaseState((prev) => ({
                    ...(prev || { remaining_seconds: 0 }),
                    access_allowed: false,
                    remaining_seconds: 0,
                    ram_wiped: true,
                    ram_key_preview: data.ram_key_preview,
                    status_message: data.status_message,
                }))
            }
        } catch {
            // ignore
        }
    }

    React.useEffect(() => {
        validateOnce()
        if (!autoPoll) return
        const id = setInterval(validateOnce, 1000)
        return () => clearInterval(id)
    }, [autoPoll, validateOnce])

    const remaining = leaseState?.remaining_seconds ?? Math.max(0, Math.floor(endTimestamp - Date.now() / 1000))
    const allowed = leaseState ? leaseState.access_allowed : remaining > 0
    const mins = Math.floor(remaining / 60).toString().padStart(2, "0")
    const secs = (remaining % 60).toString().padStart(2, "0")

    return (
        <div
            style={{
                width: "100%",
                boxSizing: "border-box",
                display: "flex",
                flexDirection: "column",
                gap: 10,
                padding: 20,
                backgroundColor: "rgba(6, 6, 10, 0.72)",
                backdropFilter: "blur(14px)",
                WebkitBackdropFilter: "blur(14px)",
                border: "1px solid rgba(243, 242, 248, 0.12)",
                color: textColor,
                fontFamily: "monospace",
            }}
        >
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "rgba(243, 242, 248, 0.56)" }}>
                <span>HWID: {leaseState?.device_hwid || "HWID-84F9-33A1-KEY"}</span>
                <span style={{ color: leaseState?.ram_wiped ? "#FF3B5C" : "#2BD8C8" }}>
                    {leaseState?.ram_key_preview || "AES-256 RAM"}
                </span>
            </div>

            <div
                style={{
                    padding: 14,
                    textAlign: "center",
                    backgroundColor: allowed ? "rgba(123, 92, 250, 0.10)" : "rgba(255, 59, 92, 0.12)",
                    border: `1px solid ${allowed ? "rgba(43, 216, 200, 0.35)" : "rgba(255, 59, 92, 0.45)"}`,
                }}
            >
                <div style={{ fontSize: 10, color: "rgba(243, 242, 248, 0.56)", marginBottom: 4 }}>
                    ENTERPRISE MONOTONIC + RS256 LEASE
                </div>
                <div style={{ fontSize: 28, fontWeight: 700, color: textColor, marginBottom: 4 }}>
                    00:{mins}:{secs}
                </div>
                <div style={{ fontSize: 12, fontWeight: 700, color: allowed ? brandColor : "#FF3B5C" }}>
                    {punBlockedMsg || leaseState?.status_message || (allowed ? "ACCESS GRANTED (RAM Key Loaded)" : "ACCESS REVOKED / RAM KEY ZEROED")}
                </div>
            </div>

            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <button
                    type="button"
                    onClick={simulateEpochPuncture}
                    style={{
                        flex: "1 1 100%",
                        height: 34,
                        cursor: "pointer",
                        fontFamily: "monospace",
                        fontWeight: 700,
                        fontSize: 10,
                        textTransform: "uppercase",
                        color: "#FFE4E9",
                        border: "1px solid rgba(255, 59, 92, 0.55)",
                        background: "rgba(255, 59, 92, 0.16)",
                    }}
                >
                    Simulate Hardware Monotonic Epoch Expiry (Punct SK₀ → SK₁)
                </button>
                <button
                    type="button"
                    onClick={revokeNow}
                    style={{
                        flex: 1,
                        height: 36,
                        cursor: "pointer",
                        fontFamily: "monospace",
                        fontWeight: 600,
                        fontSize: 10,
                        textTransform: "uppercase",
                        color: "#FF3B5C",
                        border: "1px solid rgba(255, 59, 92, 0.45)",
                        background: "rgba(255, 59, 92, 0.1)",
                    }}
                >
                    Revoke &amp; Zero RAM
                </button>
                <button
                    type="button"
                    onClick={() => setSimClockOffset(-3600)}
                    style={{
                        flex: 1,
                        height: 36,
                        cursor: "pointer",
                        fontFamily: "monospace",
                        fontWeight: 600,
                        fontSize: 10,
                        textTransform: "uppercase",
                        color: "#FFB627",
                        border: "1px solid rgba(245, 158, 11, 0.45)",
                        background: "rgba(245, 158, 11, 0.08)",
                    }}
                >
                    ⚠ Rewind Clock
                </button>
                <button
                    type="button"
                    onClick={issueSignedLease}
                    onMouseEnter={() => setHovered(true)}
                    onMouseLeave={() => setHovered(false)}
                    style={{
                        flex: 1,
                        height: 36,
                        cursor: "pointer",
                        fontFamily: "monospace",
                        fontWeight: 600,
                        fontSize: 10,
                        textTransform: "uppercase",
                        color: textColor,
                        border: `1px solid ${hovered ? brandColor : "rgba(123, 92, 250, 0.32)"}`,
                        background: "linear-gradient(135deg, rgba(255,255,255,.12), rgba(255,255,255,.02) 45%, rgba(0,0,0,.25))",
                        boxShadow: hovered ? `0 0 22px -4px ${brandColor}` : "none",
                        transition: "border-color 0.2s, box-shadow 0.2s",
                    }}
                >
                    {buttonLabel}
                </button>
            </div>
        </div>
    )
}

addPropertyControls(DrmLeaseButton, {
    apiUrl: {
        type: ControlType.String,
        title: "API Base URL",
        defaultValue: "https://leaklens-tyrn.vercel.app",
    },
    leaseSeconds: {
        type: ControlType.Number,
        title: "Lease Seconds",
        defaultValue: 30,
        min: 3,
        max: 7200,
        step: 1,
    },
    buttonLabel: {
        type: ControlType.String,
        title: "Button Label",
        defaultValue: "Reset Offline Lease",
    },
    autoPoll: {
        type: ControlType.Boolean,
        title: "Auto Poll (1s)",
        defaultValue: true,
    },
    brandColor: {
        type: ControlType.Color,
        title: "Brand Color",
        defaultValue: "#7B5CFA",
    },
    textColor: {
        type: ControlType.Color,
        title: "Text Color",
        defaultValue: "#F3F2F8",
    },
})

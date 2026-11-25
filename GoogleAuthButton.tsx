import * as React from "react"
import { addPropertyControls, ControlType, RenderTarget } from "framer"

/**
 * GoogleAuthButton — Custom Framer Code Component (for https://linklenslogin.framer.website/)
 * Verifies Google Identity credentials against FastAPI POST {apiUrl}/api/auth/google,
 * persists JWT & user identity to localStorage, and redirects to redirectUrl with ?token=...&email=...
 */

export interface GoogleUser {
    email: string
    name: string
    picture?: string
}

declare global {
    interface Window {
        google?: any
    }
}

export default function GoogleAuthButton(props: {
    apiUrl?: string
    clientId?: string
    redirectUrl?: string
    enableRedirect?: boolean
    accentColor?: string
    textColor?: string
    onLoginSuccess?: (user: GoogleUser) => void
}) {
    const {
        apiUrl = "https://leaklens-omega.vercel.app",
        clientId = "243029529822-mkj5hefpohh86e5ru9fdkatve05bubaq.apps.googleusercontent.com",
        redirectUrl = "https://leaklens.framer.ai/",
        enableRedirect = true,
        accentColor = "#7B5CFA",
        textColor = "#F3F2F8",
        onLoginSuccess,
    } = props

    const [user, setUser] = React.useState<GoogleUser | null>(null)
    const [error, setError] = React.useState<string | null>(null)
    const [redirecting, setRedirecting] = React.useState(false)
    const btnContainerRef = React.useRef<HTMLDivElement | null>(null)

    const baseUrl = apiUrl.replace(/\/+$/, "")

    const isFramerPreviewOrCanvas = () => {
        try {
            return RenderTarget.current() === RenderTarget.canvas || RenderTarget.current() === RenderTarget.preview
        } catch {
            return false
        }
    }

    const buildRedirectTarget = (token: string, email?: string) => {
        const paramRedirect =
            typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("redirect") : null
        const rawDest = (paramRedirect || redirectUrl || "").trim()
        if (!rawDest) return ""
        try {
            const url = new URL(rawDest)
            url.searchParams.set("token", token)
            if (email) url.searchParams.set("email", email)
            return url.toString()
        } catch {
            const sep = rawDest.includes("?") ? "&" : "?"
            const emailParam = email ? `&email=${encodeURIComponent(email)}` : ""
            return `${rawDest}${sep}token=${encodeURIComponent(token)}${emailParam}`
        }
    }

    const handleGoogleResponse = React.useCallback(
        async (response: { credential?: string }) => {
            if (!response?.credential) return
            setError(null)
            try {
                const headers: Record<string, string> = { "Content-Type": "application/json" }
                if (baseUrl.includes("ngrok")) headers["ngrok-skip-browser-warning"] = "true"
                if (baseUrl.includes("loca.lt")) headers["bypass-tunnel-reminder"] = "true"

                const res = await fetch(`${baseUrl}/api/auth/google`, {
                    method: "POST",
                    headers,
                    body: JSON.stringify({ token: response.credential }),
                })
                const data = await res.json()

                if (res.ok && data.status === "success") {
                    setUser(data.user)
                    if (typeof window !== "undefined") {
                        window.localStorage.setItem("access_token", data.access_token)
                        window.localStorage.setItem("user_email", data.user.email)
                        window.localStorage.setItem("user_name", data.user.name)
                        if (data.user.picture) {
                            window.localStorage.setItem("user_picture", data.user.picture)
                        }
                    }
                    if (onLoginSuccess) onLoginSuccess(data.user)

                    if (enableRedirect && (redirectUrl || (typeof window !== "undefined" && new URLSearchParams(window.location.search).get("redirect"))) && typeof window !== "undefined" && !isFramerPreviewOrCanvas()) {
                        setRedirecting(true)
                        window.location.href = buildRedirectTarget(data.access_token, data.user?.email)
                    }
                } else {
                    const msg = data.detail || "Authentication failed. Please try again."
                    setError(msg)
                    if (typeof window !== "undefined" && !isFramerPreviewOrCanvas()) {
                        window.alert("Authentication failed. Please try again.")
                    }
                }
            } catch (err: any) {
                setError(err.message || "Authentication failed. Please try again.")
            }
        },
        [baseUrl, enableRedirect, redirectUrl, onLoginSuccess]
    )

    // Restore session on mount using /api/auth/me
    React.useEffect(() => {
        if (typeof window === "undefined") return
        const storedToken = window.localStorage.getItem("access_token")
        if (!storedToken) return

        const headers: Record<string, string> = {
            Authorization: `Bearer ${storedToken}`,
        }
        if (baseUrl.includes("ngrok")) headers["ngrok-skip-browser-warning"] = "true"
        if (baseUrl.includes("loca.lt")) headers["bypass-tunnel-reminder"] = "true"

        fetch(`${baseUrl}/api/auth/me`, { headers })
            .then((r) => (r.ok ? r.json() : null))
            .then((data) => {
                if (data?.status === "authenticated" && data.user) {
                    setUser(data.user)
                    window.localStorage.setItem("user_email", data.user.email)
                    window.localStorage.setItem("user_name", data.user.name)
                    if (onLoginSuccess) onLoginSuccess(data.user)
                } else {
                    window.localStorage.removeItem("access_token")
                    window.localStorage.removeItem("user_email")
                    window.localStorage.removeItem("user_name")
                }
            })
            .catch(() => {})
    }, [baseUrl, onLoginSuccess])

    // Load GIS script & render Google button
    React.useEffect(() => {
        if (typeof document === "undefined" || user) return
        if (!clientId || clientId.startsWith("YOUR_GOOGLE_CLIENT_ID")) return

        const renderBtn = () => {
            if (!window.google?.accounts?.id || !btnContainerRef.current) return
            window.google.accounts.id.initialize({
                client_id: clientId,
                callback: handleGoogleResponse,
            })
            btnContainerRef.current.innerHTML = ""
            window.google.accounts.id.renderButton(btnContainerRef.current, {
                theme: "filled_black",
                size: "large",
                shape: "pill",
                text: "continue_with",
            })
        }

        if (window.google?.accounts?.id) {
            renderBtn()
            return
        }

        const existing = document.querySelector('script[src="https://accounts.google.com/gsi/client"]')
        if (existing) {
            existing.addEventListener("load", renderBtn)
            return () => existing.removeEventListener("load", renderBtn)
        }

        const script = document.createElement("script")
        script.src = "https://accounts.google.com/gsi/client"
        script.async = true
        script.defer = true
        script.onload = renderBtn
        document.head.appendChild(script)
    }, [clientId, user, handleGoogleResponse])

    const handleLogout = () => {
        if (typeof window !== "undefined") {
            window.localStorage.removeItem("access_token")
            window.localStorage.removeItem("user_email")
            window.localStorage.removeItem("user_name")
            window.localStorage.removeItem("user_picture")
        }
        setUser(null)
    }

    const handleContinueToApp = () => {
        if (typeof window === "undefined") return
        const token = window.localStorage.getItem("access_token")
        const email = window.localStorage.getItem("user_email") || undefined
        const dest = token ? buildRedirectTarget(token, email) : redirectUrl
        if (dest) window.location.href = dest
    }

    const isPlaceholderClient = !clientId || clientId.startsWith("YOUR_GOOGLE_CLIENT_ID")

    return (
        <div
            style={{
                display: "inline-flex",
                flexDirection: "column",
                gap: 8,
                padding: 14,
                borderRadius: 16,
                backgroundColor: "rgba(6, 6, 10, 0.72)",
                backdropFilter: "blur(16px)",
                WebkitBackdropFilter: "blur(16px)",
                border: "1px solid rgba(243, 242, 248, 0.12)",
                color: textColor,
                fontFamily: "'Onest', 'Inter', sans-serif",
            }}
        >
            {!user ? (
                <>
                    {isPlaceholderClient ? (
                        <div style={{ fontSize: 12, color: "rgba(243, 242, 248, 0.72)", lineHeight: 1.45 }}>
                            <strong style={{ color: "#FFB627" }}>Google Auth Ready:</strong> Set your{" "}
                            <code style={{ color: "#2BD8C8" }}>clientId</code> property in Framer to render the Sign-In button.
                        </div>
                    ) : (
                        <div ref={btnContainerRef} id="google-signin-btn" />
                    )}
                    {error && (
                        <div style={{ fontSize: 11, color: "#FF6B84", fontFamily: "monospace" }}>
                            {error}
                        </div>
                    )}
                </>
            ) : (
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        {user.picture ? (
                            <img
                                src={user.picture}
                                alt={user.name}
                                style={{
                                    width: 36,
                                    height: 36,
                                    borderRadius: "50%",
                                    border: `1.5px solid ${accentColor}`,
                                }}
                            />
                        ) : (
                            <div
                                style={{
                                    width: 36,
                                    height: 36,
                                    borderRadius: "50%",
                                    backgroundColor: accentColor,
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "center",
                                    fontWeight: 700,
                                }}
                            >
                                {(user.name || "U")[0].toUpperCase()}
                            </div>
                        )}
                        <div>
                            <div style={{ fontSize: 13, fontWeight: 600 }}>{user.name}</div>
                            <div style={{ fontSize: 11, color: "rgba(243, 242, 248, 0.56)", fontFamily: "monospace" }}>
                                {user.email}
                            </div>
                        </div>
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        {redirectUrl && (
                            <button
                                type="button"
                                onClick={handleContinueToApp}
                                style={{
                                    padding: "6px 12px",
                                    borderRadius: 999,
                                    border: "none",
                                    background: accentColor,
                                    color: "#FFFFFF",
                                    fontSize: 11,
                                    fontWeight: 600,
                                    cursor: "pointer",
                                }}
                            >
                                {redirecting ? "Redirecting..." : "Open LeakLens →"}
                            </button>
                        )}
                        <button
                            type="button"
                            onClick={handleLogout}
                            style={{
                                padding: "6px 12px",
                                borderRadius: 999,
                                border: "1px solid rgba(243, 242, 248, 0.16)",
                                background: "rgba(255, 255, 255, 0.06)",
                                color: textColor,
                                fontSize: 11,
                                cursor: "pointer",
                            }}
                        >
                            Sign out
                        </button>
                    </div>
                </div>
            )}
        </div>
    )
}

addPropertyControls(GoogleAuthButton, {
    apiUrl: {
        type: ControlType.String,
        title: "API Base URL",
        defaultValue: "https://leaklens-omega.vercel.app",
    },
    clientId: {
        type: ControlType.String,
        title: "Google Client ID",
        defaultValue: "243029529822-mkj5hefpohh86e5ru9fdkatve05bubaq.apps.googleusercontent.com",
    },
    redirectUrl: {
        type: ControlType.String,
        title: "Main App Redirect",
        defaultValue: "https://leaklens.framer.ai/",
        description: "Destination URL after successful login (e.g. https://leaklens.framer.ai/ or http://localhost:8000).",
    },
    enableRedirect: {
        type: ControlType.Boolean,
        title: "Redirect On Login",
        defaultValue: true,
    },
    accentColor: {
        type: ControlType.Color,
        title: "Accent Color",
        defaultValue: "#7B5CFA",
    },
    textColor: {
        type: ControlType.Color,
        title: "Text Color",
        defaultValue: "#F3F2F8",
    },
})

import * as React from "react"
import { addPropertyControls, ControlType, RenderTarget } from "framer"

/**
 * FramerAuthGuard — Main Website Route Guard & Logout Pill (for https://leaklens.framer.ai/)
 * 1. Captures ?token=... (or #access_token=...) passed back from https://linklenslogin.framer.website/
 * 2. Validates the JWT session with GET {apiUrl}/api/auth/me
 * 3. Redirects unauthenticated visitors back to loginUrl when enforceRedirect is true
 * 4. Renders signed-in operator status + Logout button
 */

export interface AuthGuardUser {
    email: string
    name: string
    picture?: string
}

const FRAMER_LOGIN_URL = "https://linklenslogin.framer.website"
const BACKEND_URL = "https://leaklens-omega.vercel.app"

function decodeJwtUserOffline(token: string): AuthGuardUser | null {
    try {
        const parts = token.split(".")
        if (parts.length !== 3) return null
        const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/")
        const json = decodeURIComponent(
            atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4))
                .split("")
                .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
                .join("")
        )
        const payload = JSON.parse(json)
        if (payload.exp && payload.exp < Date.now() / 1000) return null
        return {
            email: payload.sub || payload.email || "authenticated_user",
            name: payload.name || payload.sub || "Authenticated User",
            picture: payload.picture || "",
        }
    } catch {
        return null
    }
}

export default function FramerAuthGuard(props: {
    apiUrl?: string
    loginUrl?: string
    enforceRedirect?: boolean
    showLogoutBar?: boolean
    accentColor?: string
    onAuthenticated?: (user: AuthGuardUser) => void
}) {
    const {
        apiUrl = BACKEND_URL,
        loginUrl = FRAMER_LOGIN_URL,
        enforceRedirect = true,
        showLogoutBar = true,
        accentColor = "#2BD8C8",
        onAuthenticated,
    } = props

    const [status, setStatus] = React.useState<"checking" | "authenticated" | "unauthenticated">("checking")
    const [user, setUser] = React.useState<AuthGuardUser | null>(null)
    const baseUrl = apiUrl.replace(/\/+$/, "")

    const isFramerPreviewOrCanvas = () => {
        try {
            return RenderTarget.current() === RenderTarget.canvas || RenderTarget.current() === RenderTarget.preview
        } catch {
            return false
        }
    }

    const redirectToLogin = React.useCallback(() => {
        if (typeof window === "undefined") return
        if (!enforceRedirect || isFramerPreviewOrCanvas()) return
        const ret = `${window.location.origin}${window.location.pathname}`
        const sep = loginUrl.includes("?") ? "&" : "?"
        window.location.href = `${loginUrl}${sep}redirect=${encodeURIComponent(ret)}`
    }, [enforceRedirect, loginUrl])

    React.useEffect(() => {
        if (typeof window === "undefined") return

        // A. Extract ?token=... (or #access_token=...) if returning from https://linklenslogin.framer.website/
        const urlParams = new URLSearchParams(window.location.search)
        const tokenFromQuery = urlParams.get("token")
        const emailFromQuery = urlParams.get("email")
        const hash = window.location.hash || ""
        const hashMatch = hash.match(/access_token=([^&]+)/)
        const incomingToken = tokenFromQuery || (hashMatch && hashMatch[1] ? decodeURIComponent(hashMatch[1]) : null)

        if (incomingToken) {
            window.localStorage.setItem("access_token", incomingToken)
            if (emailFromQuery) window.localStorage.setItem("user_email", emailFromQuery)
            try {
                window.history.replaceState({}, document.title, window.location.pathname)
            } catch {}
        }

        const token = window.localStorage.getItem("access_token")
        if (!token) {
            setStatus("unauthenticated")
            redirectToLogin()
            return
        }

        const headers: Record<string, string> = {
            Authorization: `Bearer ${token}`,
        }

        fetch(`${baseUrl}/api/auth/me`, { headers })
            .then(async (res) => {
                if (res.status === 401 || res.status === 403) {
                    window.localStorage.clear()
                    setStatus("unauthenticated")
                    redirectToLogin()
                    return
                }
                const data = await res.json().catch(() => ({}))
                if (res.ok && data?.status === "authenticated" && data.user) {
                    setUser(data.user)
                    setStatus("authenticated")
                    window.localStorage.setItem("user_email", data.user.email)
                    window.localStorage.setItem("user_name", data.user.name)
                    if (onAuthenticated) onAuthenticated(data.user)
                } else {
                    const cachedUser = decodeJwtUserOffline(token)
                    if (cachedUser) {
                        setUser(cachedUser)
                        setStatus("authenticated")
                        if (onAuthenticated) onAuthenticated(cachedUser)
                    } else {
                        window.localStorage.clear()
                        setStatus("unauthenticated")
                        redirectToLogin()
                    }
                }
            })
            .catch(() => {
                const cachedUser = decodeJwtUserOffline(token)
                if (cachedUser) {
                    setUser(cachedUser)
                    setStatus("authenticated")
                    if (onAuthenticated) onAuthenticated(cachedUser)
                } else {
                    setStatus("unauthenticated")
                }
            })
    }, [baseUrl, onAuthenticated, redirectToLogin])

    const handleLogout = () => {
        if (typeof window !== "undefined") {
            window.localStorage.clear()
            window.location.href = loginUrl
        }
    }

    if (!showLogoutBar && status === "authenticated") return null

    return (
        <div
            style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 10,
                padding: "8px 14px",
                borderRadius: 999,
                backgroundColor: "rgba(6, 6, 10, 0.72)",
                backdropFilter: "blur(16px)",
                WebkitBackdropFilter: "blur(16px)",
                border: "1px solid rgba(243, 242, 248, 0.12)",
                color: "#F3F2F8",
                fontFamily: "'Onest', 'Inter', sans-serif",
                fontSize: 12,
            }}
        >
            {status === "checking" && (
                <span style={{ color: "#FFB627", fontFamily: "monospace" }}>VERIFYING SESSION...</span>
            )}
            {status === "unauthenticated" && (
                <>
                    <span style={{ color: "#FF6B84", fontFamily: "monospace" }}>SESSION REQUIRED</span>
                    <button
                        type="button"
                        onClick={() => {
                            if (typeof window !== "undefined") window.location.href = loginUrl
                        }}
                        style={{
                            padding: "4px 10px",
                            borderRadius: 999,
                            border: "none",
                            background: "#7B5CFA",
                            color: "#FFFFFF",
                            fontSize: 11,
                            fontWeight: 600,
                            cursor: "pointer",
                        }}
                    >
                        Sign in →
                    </button>
                </>
            )}
            {status === "authenticated" && user && (
                <>
                    <span
                        style={{
                            width: 7,
                            height: 7,
                            borderRadius: "50%",
                            backgroundColor: accentColor,
                            boxShadow: `0 0 8px ${accentColor}`,
                        }}
                    />
                    <span style={{ fontFamily: "monospace", color: accentColor }}>{user.email}</span>
                    <button
                        type="button"
                        onClick={handleLogout}
                        style={{
                            padding: "4px 10px",
                            borderRadius: 999,
                            border: "1px solid rgba(255, 59, 92, 0.45)",
                            background: "rgba(255, 59, 92, 0.12)",
                            color: "#FF8DA1",
                            fontSize: 11,
                            fontWeight: 500,
                            cursor: "pointer",
                        }}
                    >
                        Log out
                    </button>
                </>
            )}
        </div>
    )
}

addPropertyControls(FramerAuthGuard, {
    apiUrl: {
        type: ControlType.String,
        title: "API Base URL",
        defaultValue: BACKEND_URL,
    },
    loginUrl: {
        type: ControlType.String,
        title: "Framer Login URL",
        defaultValue: FRAMER_LOGIN_URL,
    },
    enforceRedirect: {
        type: ControlType.Boolean,
        title: "Redirect If Logged Out",
        defaultValue: true,
        description: "Redirects unauthenticated users to loginUrl (disabled in Framer Editor/Preview).",
    },
    showLogoutBar: {
        type: ControlType.Boolean,
        title: "Show Session Bar",
        defaultValue: true,
    },
    accentColor: {
        type: ControlType.Color,
        title: "Verified Color",
        defaultValue: "#2BD8C8",
    },
})

import * as React from "react"
import { addPropertyControls, ControlType, RenderTarget } from "framer"

/**
 * GoogleAuthButton — Firebase Google Authentication Component
 * Signs in with Google via Firebase Authentication (leaklens-77637),
 * exchanges the Firebase ID token at {apiUrl}/api/auth/firebase (with direct ID token fallback),
 * persists session to localStorage, and redirects to redirectUrl with ?token=...&email=...
 */

export interface GoogleUser {
    email: string
    name: string
    picture?: string
}

const FIREBASE_CONFIG = {
    apiKey: "AIzaSyBpyT_htz0GZaIo0cRwYvosZmBRMKYp9sY",
    authDomain: "leaklens-77637.firebaseapp.com",
    projectId: "leaklens-77637",
    storageBucket: "leaklens-77637.firebasestorage.app",
    messagingSenderId: "279675539046",
    appId: "1:279675539046:web:13ce79ad629d45972367a7",
    measurementId: "G-E7PW3Q5NHD",
}

const FIREBASE_APP_CDN = "https://www.gstatic.com/firebasejs/11.1.0/firebase-app.js"
const FIREBASE_AUTH_CDN = "https://www.gstatic.com/firebasejs/11.1.0/firebase-auth.js"

export default function GoogleAuthButton(props: {
    apiUrl?: string
    redirectUrl?: string
    enableRedirect?: boolean
    accentColor?: string
    textColor?: string
    onLoginSuccess?: (user: GoogleUser) => void
}) {
    const {
        apiUrl = "https://leaklens-tyrn.vercel.app",
        redirectUrl = "https://leaklens-77637.web.app/",
        enableRedirect = true,
        accentColor = "#7B5CFA",
        textColor = "#F3F2F8",
        onLoginSuccess,
    } = props

    const [user, setUser] = React.useState<GoogleUser | null>(null)
    const [error, setError] = React.useState<string | null>(null)
    const [loading, setLoading] = React.useState(false)
    const [redirecting, setRedirecting] = React.useState(false)

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

    const getFirebaseAuthClient = React.useCallback(async () => {
        const appMod: any = await import(/* @vite-ignore */ FIREBASE_APP_CDN)
        const authMod: any = await import(/* @vite-ignore */ FIREBASE_AUTH_CDN)
        const existingApps = appMod.getApps ? appMod.getApps() : []
        const fbApp = existingApps.length ? existingApps[0] : appMod.initializeApp(FIREBASE_CONFIG)
        const auth = authMod.getAuth(fbApp)
        return { auth, authMod }
    }, [])

    const completeSession = React.useCallback(
        async (fbUser: any) => {
            if (!fbUser) return
            const idToken = await fbUser.getIdToken(true)
            let sessionToken = idToken
            const resolvedUser: GoogleUser = {
                email: fbUser.email || "",
                name: fbUser.displayName || (fbUser.email || "").split("@")[0] || "Operator",
                picture: fbUser.photoURL || "",
            }

            try {
                const res = await fetch(`${baseUrl}/api/auth/firebase`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ id_token: idToken }),
                })
                if (res.ok) {
                    const data = await res.json()
                    if (data?.access_token) sessionToken = data.access_token
                    if (data?.user) {
                        resolvedUser.email = data.user.email || resolvedUser.email
                        resolvedUser.name = data.user.name || resolvedUser.name
                        resolvedUser.picture = data.user.picture || resolvedUser.picture
                    }
                }
            } catch {
                // Keep verified Firebase ID token when backend exchange is unavailable
            }

            setUser(resolvedUser)
            if (typeof window !== "undefined") {
                window.localStorage.setItem("firebase_id_token", idToken)
                window.localStorage.setItem("access_token", sessionToken)
                window.localStorage.setItem("user_email", resolvedUser.email)
                window.localStorage.setItem("user_name", resolvedUser.name)
                if (resolvedUser.picture) {
                    window.localStorage.setItem("user_picture", resolvedUser.picture)
                }
            }
            if (onLoginSuccess) onLoginSuccess(resolvedUser)

            if (typeof window !== "undefined" && window.parent && window.parent !== window) {
                try {
                    window.parent.postMessage(
                        { type: "leaklens:auth-success", token: sessionToken, user: resolvedUser },
                        "*"
                    )
                } catch { }
            }

            if (
                enableRedirect &&
                (redirectUrl || (typeof window !== "undefined" && new URLSearchParams(window.location.search).get("redirect"))) &&
                typeof window !== "undefined" &&
                !isFramerPreviewOrCanvas()
            ) {
                setRedirecting(true)
                const dest = buildRedirectTarget(sessionToken, resolvedUser.email)
                try {
                    if (window.top) {
                        window.top.location.href = dest
                        return
                    }
                } catch { }
                window.location.href = dest
            }
        },
        [baseUrl, enableRedirect, redirectUrl, onLoginSuccess]
    )

    // Restore session on mount using /api/auth/me or Firebase redirect result
    React.useEffect(() => {
        if (typeof window === "undefined") return

        const storedToken = window.localStorage.getItem("access_token")
        if (storedToken) {
            fetch(`${baseUrl}/api/auth/me`, {
                headers: { Authorization: `Bearer ${storedToken}` },
            })
                .then((r) => (r.ok ? r.json() : null))
                .then((data) => {
                    if (data?.status === "authenticated" && data.user) {
                        setUser(data.user)
                        window.localStorage.setItem("user_email", data.user.email)
                        window.localStorage.setItem("user_name", data.user.name)
                        if (onLoginSuccess) onLoginSuccess(data.user)
                    }
                })
                .catch(() => { })
        }

        getFirebaseAuthClient()
            .then(async ({ auth, authMod }) => {
                const res = await authMod.getRedirectResult(auth)
                if (res?.user) {
                    await completeSession(res.user)
                }
            })
            .catch(() => { })
    }, [baseUrl, onLoginSuccess, getFirebaseAuthClient, completeSession])

    const handleFirebaseGoogleLogin = async () => {
        if (typeof window === "undefined") return
        setError(null)
        setLoading(true)
        try {
            const { auth, authMod } = await getFirebaseAuthClient()
            const provider = new authMod.GoogleAuthProvider()
            provider.setCustomParameters({ prompt: "select_account" })
            const result = await authMod.signInWithPopup(auth, provider)
            await completeSession(result.user)
        } catch (err: any) {
            const code = err?.code || ""
            if (code === "auth/popup-blocked" || code === "auth/operation-not-supported-in-this-environment") {
                try {
                    const { auth, authMod } = await getFirebaseAuthClient()
                    const provider = new authMod.GoogleAuthProvider()
                    await authMod.signInWithRedirect(auth, provider)
                    return
                } catch (redirErr: any) {
                    setError(redirErr?.message || "Google sign-in redirect failed.")
                }
            } else if (code !== "auth/popup-closed-by-user") {
                setError(err?.message || "Firebase Google authentication failed.")
            }
        } finally {
            setLoading(false)
        }
    }

    const handleLogout = async () => {
        if (typeof window !== "undefined") {
            window.localStorage.removeItem("access_token")
            window.localStorage.removeItem("firebase_id_token")
            window.localStorage.removeItem("user_email")
            window.localStorage.removeItem("user_name")
            window.localStorage.removeItem("user_picture")
        }
        try {
            const { auth, authMod } = await getFirebaseAuthClient()
            await authMod.signOut(auth)
        } catch { }
        setUser(null)
    }

    const handleContinueToApp = () => {
        if (typeof window === "undefined") return
        const token = window.localStorage.getItem("access_token")
        const email = window.localStorage.getItem("user_email") || undefined
        const dest = token ? buildRedirectTarget(token, email) : redirectUrl
        if (dest) window.location.href = dest
    }

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
                    <button
                        type="button"
                        onClick={handleFirebaseGoogleLogin}
                        disabled={loading}
                        style={{
                            display: "inline-flex",
                            alignItems: "center",
                            justifyContent: "center",
                            gap: 10,
                            padding: "10px 18px",
                            borderRadius: 999,
                            border: "1px solid rgba(255, 255, 255, 0.18)",
                            backgroundColor: "#FFFFFF",
                            color: "#11131A",
                            fontSize: 13,
                            fontWeight: 600,
                            cursor: loading ? "not-allowed" : "pointer",
                            opacity: loading ? 0.7 : 1,
                        }}
                    >
                        <span>{loading ? "Signing in with Google..." : "Continue with Google (Firebase)"}</span>
                    </button>
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
        defaultValue: "https://leaklens-tyrn.vercel.app",
    },
    redirectUrl: {
        type: ControlType.String,
        title: "Main App Redirect",
        defaultValue: "https://leaklens-77637.web.app/",
        description: "Destination URL after Firebase Google sign-in.",
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

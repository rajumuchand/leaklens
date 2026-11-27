import * as React from 'react';

const FIREBASE_LOGIN_URL = 'https://leaklens-77637.web.app/login';

export default function Login() {
  const [loginHref, setLoginHref] = React.useState(FIREBASE_LOGIN_URL);

  React.useEffect(() => {
    if (typeof window === 'undefined') return;
    const redirect = `${window.location.origin}/`;
    const target = `${FIREBASE_LOGIN_URL}?redirect=${encodeURIComponent(redirect)}`;
    setLoginHref(target);
    window.location.replace(target);
  }, []);

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '14px',
        backgroundColor: '#000000',
        color: '#F3F2F8',
        fontFamily: "'Inter', system-ui, sans-serif",
      }}
    >
      <h1 style={{ margin: 0, fontSize: '24px', fontWeight: 600 }}>Welcome to LeakLens</h1>
      <p style={{ margin: 0, color: 'rgba(255,255,255,0.68)', fontSize: '14px' }}>
        Redirecting to secure Google Sign-In...
      </p>
      <a
        href={loginHref}
        style={{
          padding: '10px 20px',
          borderRadius: '999px',
          backgroundColor: '#FFFFFF',
          color: '#11131A',
          fontWeight: 600,
          fontSize: '14px',
          textDecoration: 'none',
        }}
      >
        Sign in with Google
      </a>
    </div>
  );
}

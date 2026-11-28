import { getApp, getApps, initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider, signInWithPopup } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

const viteEnv =
  typeof import.meta !== "undefined" && (import.meta as unknown as { env?: Record<string, string | undefined> }).env
    ? (import.meta as unknown as { env: Record<string, string | undefined> }).env
    : {};

const firebaseConfig = {
  apiKey: viteEnv.VITE_FIREBASE_API_KEY || "AIzaSyBpyT_htz0GZaIo0cRwYvosZmBRMKYp9sY",
  authDomain: viteEnv.VITE_FIREBASE_AUTH_DOMAIN || "leaklens-77637.firebaseapp.com",
  projectId: viteEnv.VITE_FIREBASE_PROJECT_ID || "leaklens-77637",
  storageBucket: viteEnv.VITE_FIREBASE_STORAGE_BUCKET || "leaklens-77637.firebasestorage.app",
  messagingSenderId: viteEnv.VITE_FIREBASE_MESSAGING_SENDER_ID || "279675539046",
  appId: viteEnv.VITE_FIREBASE_APP_ID || "1:279675539046:web:13ce79ad629d45972367a7",
};

export const app = getApps().length > 0 ? getApp() : initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({ prompt: "select_account" });
export const db = getFirestore(app);
export { signInWithPopup };

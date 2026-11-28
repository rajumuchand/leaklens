import React, { useEffect, useState } from 'react';
import {
  collection,
  getDocs,
  limit,
  onSnapshot,
  orderBy,
  or,
  query,
  where,
} from 'firebase/firestore';
import { decodeWatermark } from '../utils/steganography';
import { auth, db } from '../firebase';

export default function LeakInspector() {
  const [leakedText, setLeakedText] = useState('');
  const [traceResult, setTraceResult] = useState(null);
  const [auditLog, setAuditLog] = useState(null);
  const [liveTelemetry, setLiveTelemetry] = useState([]);
  const [lineageHops, setLineageHops] = useState([]);
  const [statusMessage, setStatusMessage] = useState('');

  useEffect(() => {
    const user = auth.currentUser;
    if (!user || !user.email) return;

    const telemetryQuery = query(
      collection(db, 'telemetry_logs'),
      orderBy('timestamp', 'desc'),
      limit(25),
    );
    const unsubscribeTelemetry = onSnapshot(
      telemetryQuery,
      (snapshot) => {
        const rows = snapshot.docs.map((d) => ({ id: d.id, ...d.data() }));
        setLiveTelemetry(rows);
      },
      () => {
        // Ignore snapshot errors when unauthenticated or Firestore API disabled
      },
    );

    const lineageQuery = query(
      collection(db, 'lineage_nodes'),
      orderBy('hop_level', 'asc'),
      limit(50),
    );
    const unsubscribeLineage = onSnapshot(
      lineageQuery,
      (snapshot) => {
        const nodes = snapshot.docs.map((d) => ({ id: d.id, ...d.data() }));
        setLineageHops(nodes);
      },
      () => {
        // Ignore snapshot errors when unauthenticated or Firestore API disabled
      },
    );

    return () => {
      unsubscribeTelemetry();
      unsubscribeLineage();
    };
  }, []);

  const handleTraceText = async () => {
    setStatusMessage('');
    setAuditLog(null);

    const decoded = decodeWatermark(leakedText);
    if (decoded && decoded.userId) {
      setTraceResult(decoded);
      const user = auth.currentUser;
      if (!user) {
        setStatusMessage('Sign in with Firebase Auth to query Cloud Firestore audit logs.');
        return;
      }
      try {
        const q = query(
          collection(db, 'telemetry_logs'),
          orderBy('timestamp', 'desc'),
          limit(50),
        );
        const snap = await getDocs(q);
        const matchedLogs = snap.docs
          .map((d) => ({ id: d.id, ...d.data() }))
          .filter((r) => r.original_sharer === decoded.userId || r.viewer_email === decoded.userId);
        if (matchedLogs.length > 0) {
          setAuditLog(matchedLogs);
          return;
        }
        const wmQ = query(
          collection(db, 'watermark_records'),
          where('owner_uid', '==', user.uid),
          where('recipient_id', '==', decoded.userId),
          limit(20),
        );
        const wmSnap = await getDocs(wmQ);
        if (!wmSnap.empty) {
          setAuditLog(wmSnap.docs.map((d) => ({ id: d.id, ...d.data() })));
        }
      } catch (err) {
        setStatusMessage(err?.message || 'Firestore lookup unavailable.');
      }
    } else {
      setTraceResult(null);
      setStatusMessage('No hidden steganographic payload detected in this text.');
    }
  };

  const firstAuditRow = Array.isArray(auditLog) && auditLog.length > 0 ? auditLog[0] : null;

  return (
    <div style={{ padding: '20px', border: '1px solid #333', borderRadius: '8px' }}>
      <h2>🔍 LeakLens Forensic Inspector (Firestore Real-Time Sync)</h2>
      <p>Paste leaked text or OCR output here to trace recipient identity:</p>

      <textarea
        rows={5}
        style={{ width: '100%', marginBottom: '10px' }}
        value={leakedText}
        onChange={(e) => setLeakedText(e.target.value)}
        placeholder="Paste leaked text excerpt here..."
      />

      <button onClick={handleTraceText} style={{ padding: '10px 20px', cursor: 'pointer' }}>
        Decode &amp; Trace Leak
      </button>

      {statusMessage && (
        <p style={{ marginTop: '12px', color: '#ff8da1' }}>{statusMessage}</p>
      )}

      {traceResult && (
        <div style={{ marginTop: '20px', background: '#111', padding: '15px', borderRadius: '6px' }}>
          <h3>⚠️ Leak Attribution Match Found!</h3>
          <p><strong>Leaker User ID:</strong> {traceResult.userId}</p>
          <p><strong>Access Timestamp:</strong> {new Date(traceResult.timestamp).toLocaleString()}</p>
          {firstAuditRow && (
            <p>
              <strong>Verified Firestore IP / Sharer:</strong>{' '}
              {firstAuditRow.ip_address || firstAuditRow.original_sharer || firstAuditRow.signature || 'Verified in Firestore'}
            </p>
          )}
        </div>
      )}

      {lineageHops.length > 0 && (
        <div style={{ marginTop: '16px', fontSize: '12px' }}>
          <strong>Live Firestore Lineage Nodes ({lineageHops.length}):</strong>{' '}
          {lineageHops.map((n) => `${n.child_name} (${n.child_email})`).join(' ➔ ')}
        </div>
      )}

      {liveTelemetry.length > 0 && (
        <div style={{ marginTop: '12px', fontSize: '12px', color: '#2BD8C8' }}>
          <strong>Live Access Logs (onSnapshot):</strong> {liveTelemetry.length} event(s) synced.
        </div>
      )}
    </div>
  );
}

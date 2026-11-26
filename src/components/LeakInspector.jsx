import React, { useState } from 'react';
import { decodeWatermark } from '../utils/steganography';
import { supabase } from '../supabaseClient';

export default function LeakInspector() {
  const [leakedText, setLeakedText] = useState('');
  const [traceResult, setTraceResult] = useState(null);
  const [auditLog, setAuditLog] = useState(null);
  const [statusMessage, setStatusMessage] = useState('');

  const handleTraceText = async () => {
    setStatusMessage('');
    setAuditLog(null);

    // 1. Extract hidden zero-width Unicode payload
    const decoded = decodeWatermark(leakedText);

    if (decoded && decoded.userId) {
      setTraceResult(decoded);

      // 2. Query Supabase audit logs (drm_leases / watermark_records) for verification
      const { data, error } = await supabase
        .from('drm_leases')
        .select('*')
        .eq('recipient_id', decoded.userId)
        .gte('created_at', decoded.timestamp);

      if (!error && data && data.length > 0) {
        setAuditLog(data);
      } else {
        // Fallback: check watermark_records if no matching drm_lease row is returned
        const { data: wmData } = await supabase
          .from('watermark_records')
          .select('*')
          .eq('recipient_id', decoded.userId)
          .gte('created_at', decoded.timestamp);
        if (wmData && wmData.length > 0) {
          setAuditLog(wmData);
        }
      }
    } else {
      setTraceResult(null);
      setStatusMessage('No hidden steganographic payload detected in this text.');
    }
  };

  const firstAuditRow = Array.isArray(auditLog) && auditLog.length > 0 ? auditLog[0] : null;

  return (
    <div style={{ padding: '20px', border: '1px solid #333', borderRadius: '8px' }}>
      <h2>🔍 LeakLens Forensic Inspector</h2>
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
              <strong>Verified Session IP / Lease:</strong>{' '}
              {firstAuditRow.ip_address || firstAuditRow.lease_id || firstAuditRow.signature || 'Verified in Supabase Logs'}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

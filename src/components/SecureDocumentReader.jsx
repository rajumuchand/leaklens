// src/components/SecureDocumentReader.jsx
import React, { useEffect, useRef } from "react";
import { encodeWatermark } from "@/utils/steganography";

/**
 * SecureDocumentReader – renders plain text onto a canvas to avoid DOM text extraction.
 * It also overlays a semi‑transparent diagonal watermark showing the user email and timestamp.
 * On copy, it writes the steganographically encoded version of the document text to the clipboard.
 */
export default function SecureDocumentReader({
  text = "",
  userEmail = "",
  timestamp = "",
}) {
  const canvasRef = useRef(null);

  // Draw the text on the canvas (simple multiline rendering)
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const width = canvas.parentElement.clientWidth;
    const height = canvas.parentElement.clientHeight;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);

    // Background (optional dark background similar to existing UI)
    ctx.fillStyle = "#06060A";
    ctx.fillRect(0, 0, width, height);

    // Text styling
    ctx.fillStyle = "#F3F2F8";
    ctx.font = "14px " + ("'Inter', system-ui, sans-serif");
    ctx.textBaseline = "top";
    const lineHeight = 20;
    const padding = 20;
    const maxWidth = width - padding * 2;

    const words = text.split(/\s+/);
    let line = "";
    let y = padding;
    for (let n = 0; n < words.length; n++) {
      const testLine = line + words[n] + " ";
      const metrics = ctx.measureText(testLine);
      if (metrics.width > maxWidth && n > 0) {
        ctx.fillText(line, padding, y);
        line = words[n] + " ";
        y += lineHeight;
      } else {
        line = testLine;
      }
    }
    ctx.fillText(line, padding, y);
  }, [text]);

  // Copy handler – writes stego‑encoded text to clipboard
  const handleCopy = (e) => {
    e.preventDefault();
    const stego = encodeWatermark(text, userEmail, timestamp);
    e.clipboardData.setData("text/plain", stego);
  };

  // Attach copy listener to window when component mounts
  useEffect(() => {
    window.addEventListener("copy", handleCopy);
    return () => {
      window.removeEventListener("copy", handleCopy);
    };
  }, [text, userEmail, timestamp]);

  return (
    <div
      style={{
        position: "relative",
        width: "100%",
        height: "100%",
        userSelect: "none",
        pointerEvents: "none",
      }}
    >
      <canvas
        ref={canvasRef}
        style={{
          width: "100%",
          height: "100%",
          display: "block",
        }}
      />
      {/* Diagonal watermark overlay */}
      <div
        aria-hidden="true"
        style={{
          position: "absolute",
          inset: 0,
          pointerEvents: "none",
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          opacity: 0.14,
          fontFamily: "monospace",
          fontSize: 12,
          fontWeight: 700,
          color: "#FFB627",
          transform: "rotate(-22deg)",
          textAlign: "center",
          whiteSpace: "nowrap",
          zIndex: 9999,
        }}
      >
        {`CONFIDENTIAL • ${userEmail} • ${timestamp} • SECURE SESSION`}
      </div>
    </div>
  );
}

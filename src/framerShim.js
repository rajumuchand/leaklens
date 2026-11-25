// Browser shim so Framer Code Components compile cleanly inside Vite React PWA
export function addPropertyControls() {
  // No-op outside Framer canvas
}

export const ControlType = {
  String: "string",
  Number: "number",
  Boolean: "boolean",
  Color: "color",
  Enum: "enum",
};

export const RenderTarget = {
  canvas: "canvas",
  preview: "preview",
  thumbnail: "thumbnail",
  export: "export",
  current() {
    return "export";
  },
};

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies /api to the FastAPI server on :8000.
// `npm run build:demo` (mode "demo") makes a static build with sample data for GitHub Pages;
// set BASE_PATH=/sentinel/ when the site lives in a sub-folder.
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  base: process.env.BASE_PATH ?? "/",
  define: mode === "demo" ? { "import.meta.env.VITE_DEMO": JSON.stringify("1") } : {},
  server: { proxy: { "/api": "http://localhost:8000" } },
}));

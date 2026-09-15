import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { componentTagger } from "lovable-tagger";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  // The Python backend; requests to /api are proxied so the browser stays same-origin
  const backend = env.VITE_BACKEND_URL || "http://127.0.0.1:5000";
  const proxy = {
    "/api": { target: backend, changeOrigin: true },
    "/download-csv": { target: backend, changeOrigin: true },
  };

  return {
    server: {
      host: "localhost",
      port: 8080,
      proxy,
    },
    preview: {
      host: "localhost",
      port: 8080,
      proxy,
    },
    plugins: [
      react(),
      mode === 'development' &&
      componentTagger(),
    ].filter(Boolean),
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
      },
    },
  };
});

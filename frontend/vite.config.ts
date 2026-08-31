import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// base: "./" so the built asset paths resolve wherever FastAPI mounts dist/.
// The proxy exists only for `npm run dev` -- in the container the API and the
// static bundle are the same origin, so the app always calls relative paths
// and no CORS configuration exists anywhere.
export default defineConfig({
  plugins: [react()],
  base: "./",
  server: {
    proxy: Object.fromEntries(
      ["/ingest", "/corpus", "/traces", "/live", "/health"].map((path) => [
        path,
        { target: "http://localhost:8000", changeOrigin: true },
      ]),
    ),
  },
});

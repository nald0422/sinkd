import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Relative asset paths, so the built site works at a domain's root or
// under a path (GitHub Pages serves it at /sinkd/).
export default defineConfig({
  base: "./",
  plugins: [react(), tailwindcss()],
  // The licenses of the libraries bundled in (React's MIT notice has to
  // travel with it), linked from the page's footer.
  // Two pages: the landing page and support.html.
  build: {
    license: { fileName: "licenses.md" },
    rollupOptions: { input: { main: "index.html", support: "support.html" } },
  },
});

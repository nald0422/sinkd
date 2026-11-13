import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Relative asset paths, so the built site works at a domain's root or
// under a path (GitHub Pages serves it at /sinkd/).
export default defineConfig({
  base: "./",
  plugins: [react(), tailwindcss()],
  // privacy.html renders ../docs/privacy.md, outside the site.
  server: { fs: { allow: [".", "../docs"] } },
  // Three pages: the landing page, support.html and privacy.html. And the
  // licenses of the libraries bundled in (React's MIT notice has to travel
  // with it), linked from the footers.
  build: {
    license: { fileName: "licenses.md" },
    rollupOptions: {
      input: { main: "index.html", support: "support.html", privacy: "privacy.html" },
    },
  },
});

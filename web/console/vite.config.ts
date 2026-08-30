import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  // Relative assets let the same embedded output be mounted below any URL prefix.
  base: "./",
  plugins: [react()],
  publicDir: false,
  build: {
    assetsDir: "assets",
    emptyOutDir: true,
    manifest: "manifest.json",
    outDir: "dist",
    sourcemap: false,
    target: "es2022",
    rollupOptions: {
      output: {
        assetFileNames: "assets/[name]-[hash][extname]",
        chunkFileNames: "assets/[name]-[hash].js",
        entryFileNames: "assets/[name]-[hash].js"
      }
    }
  }
});

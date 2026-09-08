import { build } from "esbuild";

await build({ entryPoints: ["public/sbom-worker.js"], outfile: "public/generated/sbom-worker.js", bundle: true, format: "esm", platform: "browser", target: "es2022", minify: true, legalComments: "eof" });
await build({ entryPoints: ["public/app.js"], outfile: "public/generated/app.js", bundle: true, format: "esm", platform: "browser", target: "es2022", minify: true, legalComments: "eof" });

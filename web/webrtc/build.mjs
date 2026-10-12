// 构建 WebRTC 检测脚本：esbuild 打包为 IIFE（全局 RiskWebRTC），再用 javascript-obfuscator 混淆，
// 输出到 Go 的 embed 目录。混淆使用固定 seed，同一源码多次构建产物一致（CI 据此校验产物已更新）。
import { build } from "esbuild";
import JavaScriptObfuscator from "javascript-obfuscator";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const out = fileURLToPath(new URL("../../internal/httpapi/assets/webrtc.js", import.meta.url));

const bundled = await build({
  entryPoints: [fileURLToPath(new URL("src/index.ts", import.meta.url))],
  bundle: true,
  format: "iife",
  globalName: "RiskWebRTC",
  target: "es2019",
  minify: true,
  legalComments: "none",
  write: false,
});

const obfuscated = JavaScriptObfuscator.obfuscate(bundled.outputFiles[0].text, {
  seed: 20261010,
  compact: true,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 0.5,
  deadCodeInjection: true,
  deadCodeInjectionThreshold: 0.2,
  identifierNamesGenerator: "hexadecimal",
  renameGlobals: false, // 保留全局 RiskWebRTC
  stringArray: true,
  stringArrayEncoding: ["base64"],
  stringArrayThreshold: 1,
  splitStrings: true,
  splitStringsChunkLength: 8,
  transformObjectKeys: true,
  numbersToExpressions: true,
  selfDefending: false, // 会被格式化工具/CDN 压缩破坏，且影响性能
  debugProtection: false,
  sourceMap: false,
});

writeFileSync(out, obfuscated.getObfuscatedCode() + "\n");
console.log(`wrote ${out}`);

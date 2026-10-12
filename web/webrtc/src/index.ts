// WebRTC 泄露检测客户端：收集浏览器 ICE 候选，上报 POST /api/v1/webrtc。
// 由 GET /api/v1/webrtc 下发（构建产物经混淆），加载后挂在 window.RiskWebRTC。

export interface CheckOptions {
  /** API 地址，默认取脚本自身来源 + /api/v1/webrtc */
  endpoint?: string;
  /** STUN 服务器，默认 Google 与 Cloudflare 公共 STUN */
  stunServers?: string[];
  /** ICE 收集超时（毫秒），超时后用已收集到的候选继续，默认 5000 */
  timeoutMs?: number;
  /** 额外上报的地址（走 ips 字段） */
  ips?: string[];
  signal?: AbortSignal;
}

export interface Candidate {
  ip: string;
  type?: string;
  status: string;
  message?: string;
  isRisky: boolean;
  sameAsRequest: boolean;
  info?: Record<string, unknown>;
}

export interface CheckResult {
  /** ok / leak；浏览器屏蔽了 WebRTC 时为 unsupported（此时不会泄露，也未请求接口） */
  status: "ok" | "leak" | "unsupported";
  requestIp?: string;
  requestStatus?: string;
  requestInfo?: Record<string, unknown>;
  leak: boolean;
  isRisky: boolean;
  candidates: Candidate[];
}

const DEFAULT_STUN = ["stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478"];
const API_PATH = "/api/v1/webrtc";

// 脚本只在加载时能拿到 currentScript，用于推导默认 API 地址
const scriptOrigin = (() => {
  try {
    const src = (document.currentScript as HTMLScriptElement | null)?.src;
    return src ? new URL(src).origin : "";
  } catch {
    return "";
  }
})();

/** 浏览器是否可用 WebRTC（隐私扩展常把 RTCPeerConnection 改写为 undefined） */
export function isSupported(): boolean {
  return typeof window !== "undefined" && typeof window.RTCPeerConnection === "function";
}

/** 收集 ICE 候选原始字符串；收集完成、gathering complete 或超时三者先到为准 */
export async function gather(stunServers: string[] = DEFAULT_STUN, timeoutMs = 5000): Promise<string[]> {
  const pc = new RTCPeerConnection({ iceServers: stunServers.length ? [{ urls: stunServers }] : [] });
  const out: string[] = [];
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const finished = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, timeoutMs);
      pc.onicecandidate = (e) => {
        if (!e.candidate) return resolve();
        if (e.candidate.candidate) out.push(e.candidate.candidate);
      };
      pc.onicegatheringstatechange = () => {
        if (pc.iceGatheringState === "complete") resolve();
      };
    });
    pc.createDataChannel("");
    await pc.setLocalDescription(await pc.createOffer());
    await finished;
  } finally {
    clearTimeout(timer);
    pc.close();
  }
  return out;
}

/** 收集候选并请求接口；浏览器屏蔽 WebRTC 时直接返回 unsupported */
export async function check(opts: CheckOptions = {}): Promise<CheckResult> {
  if (!isSupported()) {
    return { status: "unsupported", leak: false, isRisky: false, candidates: [] };
  }
  const timeoutMs = opts.timeoutMs ?? 5000;
  // setLocalDescription 等步骤本身挂起时兜底，避免调用方一直等待
  const candidates = await Promise.race([
    gather(opts.stunServers ?? DEFAULT_STUN, timeoutMs),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("ICE gathering timed out")), timeoutMs + 3000),
    ),
  ]);
  const endpoint = opts.endpoint ?? scriptOrigin + API_PATH;
  const resp = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ candidates, ips: opts.ips ?? [] }),
    credentials: "omit",
    signal: opts.signal,
  });
  if (!resp.ok) {
    throw new Error(`webrtc check failed: HTTP ${resp.status}`);
  }
  return (await resp.json()) as CheckResult;
}

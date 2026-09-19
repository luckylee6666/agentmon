export function formatBytes(bytes: number): string {
  if (!bytes) return "0B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return unit === 0 ? `${bytes}B` : `${value >= 100 ? value.toFixed(0) : value.toFixed(1)}${units[unit]}`;
}

export function formatTime(ts: number): string {
  return new Date(ts).toLocaleString("zh-CN", { hour12: false });
}

export function formatClock(ts: number): string {
  return new Date(ts).toLocaleTimeString("zh-CN", { hour12: false });
}

export function formatAgo(ts: number): string {
  const delta = Date.now() - ts;
  if (delta < 0) return "刚刚";
  const secs = Math.floor(delta / 1000);
  if (secs < 60) return `${secs} 秒前`;
  if (secs < 3600) return `${Math.floor(secs / 60)} 分钟前`;
  if (secs < 86400) return `${Math.floor(secs / 3600)} 小时前`;
  return `${Math.floor(secs / 86400)} 天前`;
}

export const severityOrder: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export const ruleLabels: Record<string, string> = {
  "egress.unknown_domain": "白名单外目标",
  "egress.volume_spike": "上传量突增",
  "egress.sensitive_payload": "敏感载荷外发",
  "fs.sensitive_read": "敏感文件被读",
  "fs.bulk_read": "批量读取",
  "artifact.hidden_blob": "高熵打包块",
  "artifact.unexpected_endpoint": "配置中的未知端点",
  "exfil.chain": "疑似外传链路",
};

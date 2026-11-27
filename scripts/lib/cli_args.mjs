/*
 * scripts/lib/cli_args.mjs — 更新工具脚本的共享命令行契约
 *
 * 失败统一以 [FAIL] 前缀退出 1；参数仅接受 --key value 形式，
 * 缺值或未知位置参数立即失败。--help / -h 归一为 args.help = "1"。
 */
export function fail(message) {
  console.error(`[FAIL] ${message}`);
  process.exit(1);
}

export function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const raw = argv[i];
    if (raw === "--help" || raw === "-h") {
      args.help = "1";
      continue;
    }
    if (!raw.startsWith("--")) fail(`无法识别的参数: ${raw}`);
    const key = raw.slice(2);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--")) fail(`参数缺少取值: ${raw}`);
    args[key] = value;
    i++;
  }
  return args;
}

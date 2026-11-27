/*
 * violation.rs — 违规模型与基线治理
 *
 * 指纹 = 类别|相对路径|目标（模块/函数），不含行号；
 * 同一指纹按出现次数计数，新增次数仍阻断；
 * 基线条目不再出现时判为 STALE 并阻断，防止豁免腐烂。
 */
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

#[derive(Debug, Clone)]
pub(crate) struct Violation {
    pub(crate) category: &'static str,
    pub(crate) file: String,
    pub(crate) detail: String,
    pub(crate) line: usize,
    pub(crate) message: String,
}

impl Violation {
    pub(crate) fn new(
        category: &'static str,
        file: &str,
        detail: impl Into<String>,
        line: usize,
        message: impl Into<String>,
    ) -> Self {
        Self {
            category,
            file: file.to_string(),
            detail: detail.into(),
            line,
            message: message.into(),
        }
    }

    /// 基线指纹：不含行号，行号漂移不会产生新违规。
    pub(crate) fn key(&self) -> String {
        format!("{}|{}|{}", self.category, self.file, self.detail)
    }
}

pub(crate) type Baseline = HashMap<String, usize>;

pub(crate) fn parse_baseline(text: &str) -> Result<Baseline, String> {
    let mut baseline = Baseline::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() != 4 {
            return Err(format!(
                "基线条目格式非法（第 {} 行，期望 category|file|detail|count）: {}",
                index + 1,
                line
            ));
        }
        let count: usize = parts[3]
            .parse()
            .map_err(|_| format!("基线条目计数非法（第 {} 行）: {}", index + 1, line))?;
        if count == 0 {
            return Err(format!("基线条目计数必须大于 0（第 {} 行）", index + 1));
        }
        let key = format!("{}|{}|{}", parts[0], parts[1], parts[2]);
        *baseline.entry(key).or_insert(0) += count;
    }
    Ok(baseline)
}

pub(crate) fn load_baseline(path: &Path) -> Result<Baseline, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("读取基线失败 {}: {e}", path.display()))?;
    parse_baseline(&text)
}

pub(crate) fn render_baseline(violations: &[Violation]) -> String {
    let mut entries: BTreeMap<String, usize> = BTreeMap::new();
    for violation in violations {
        *entries.entry(violation.key()).or_insert(0) += 1;
    }
    let mut body = String::from(
        "# AST 红线基线：由 --write-baseline 生成（存量豁免，新增违规不受豁免）\n\
         # 格式：category|file|detail|count；detail 为依赖模块或输出函数名\n",
    );
    for (key, count) in entries {
        body.push_str(&format!("{key}|{count}\n"));
    }
    body
}

pub(crate) fn apply_baseline(
    violations: Vec<Violation>,
    baseline: &Baseline,
) -> (Vec<Violation>, Vec<String>, usize) {
    let mut remaining_counts = baseline.clone();
    let mut remaining = Vec::new();
    let mut exempted = 0usize;
    for violation in violations {
        let key = violation.key();
        match remaining_counts.get_mut(&key) {
            Some(count) if *count > 0 => {
                *count -= 1;
                exempted += 1;
            }
            _ => remaining.push(violation),
        }
    }
    let stale = remaining_counts
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(key, count)| format!("{key}|{count}"))
        .collect();
    (remaining, stale, exempted)
}

//! 表示の言語。LC_ALL / LC_MESSAGES / LANG が ja で始まれば日本語、それ以外は英語。

use std::sync::OnceLock;

fn japanese() -> bool {
    static JA: OnceLock<bool> = OnceLock::new();
    *JA.get_or_init(|| {
        ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
            .is_some_and(|v| v.starts_with("ja"))
    })
}

/// 表示の言語に合わせて ja か en を返す
pub fn tr(ja: String, en: String) -> String {
    if japanese() { ja } else { en }
}

/// tr!("日本語", "English") の形で書く（format! と同じ書式が使える）
#[macro_export]
macro_rules! tr {
    ($ja:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        $crate::i18n::tr(format!($ja $(, $arg)*), format!($en $(, $arg)*))
    };
}

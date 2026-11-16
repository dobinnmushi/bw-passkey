//! 同じサイトのパスキーが複数あるとき、どれを使うかを選ぶ画面（GTK4）。
//!
//! 常駐側（HID の処理）を止めないよう、同じプログラムを `bw-passkey --choose` として別プロセスで開く。
//! 常駐側は候補を JSON で標準入力に渡し、選ばれた番号を標準出力から受け取る（閉じられたら何も出さず 1 で終わる）。

use adw::prelude::*;
use gtk::{gdk, gio, glib};
use serde_json::{Value, json};
use std::cell::Cell;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::rc::Rc;

const APP_ID: &str = "local.bwpasskey.choose";
/// これより多いときだけ絞り込みの欄を出す
const FILTER_FROM: usize = 6;

/// 候補の1件（画面に出すもの）
pub struct Choice {
    pub title: String,
    pub user: String,
    pub detail: String,
}

/// 常駐側から呼ぶ: 選ぶ画面を開き、選ばれた番号を返す（閉じられたら None）
pub fn ask(rp_id: &str, choices: &[Choice]) -> Option<usize> {
    let input = json!({
        "rp": rp_id,
        "items": choices.iter().map(|c| json!({"title": c.title, "user": c.user, "detail": c.detail})).collect::<Vec<_>>(),
    });
    let exe = std::env::current_exe().ok()?;
    let mut child = Command::new(exe)
        .arg("--choose")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| log::warn!("could not open the chooser: {e}"))
        .ok()?;
    child.stdin.take()?.write_all(input.to_string().as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok().filter(|i| *i < choices.len())
}

fn label(text: &str, classes: &[&str]) -> gtk::Label {
    let l = gtk::Label::builder().label(text).xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::End).build();
    for c in classes {
        l.add_css_class(c);
    }
    l
}

/// `bw-passkey --choose` の本体
pub fn run() -> i32 {
    let input: Value = match serde_json::from_reader(std::io::stdin()) {
        Ok(v) => v,
        Err(_) => return 2,
    };
    let rp = input["rp"].as_str().unwrap_or("").to_owned();
    let items: Vec<(String, String, String)> = input["items"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|i| {
            let s = |k: &str| i[k].as_str().unwrap_or("").to_owned();
            (s("title"), s("user"), s("detail"))
        })
        .collect();
    let chosen = Rc::new(Cell::new(None::<usize>));

    let app = adw::Application::builder().application_id(APP_ID).flags(gio::ApplicationFlags::NON_UNIQUE).build();
    let chosen_app = chosen.clone();
    app.connect_activate(move |app| build(app, &rp, &items, chosen_app.clone()));
    app.run_with_args::<&str>(&[]);
    match chosen.get() {
        Some(i) => {
            println!("{i}");
            0
        }
        None => 1,
    }
}

fn build(app: &adw::Application, rp: &str, items: &[(String, String, String)], chosen: Rc<Cell<Option<usize>>>) {
    let title = tr!("パスキーを選ぶ — {rp}", "Choose a passkey — {rp}");
    let window = gtk::ApplicationWindow::builder().application(app).title(&title).default_width(520).build();
    let outer = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(8)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();
    outer.append(&label(&tr!("{rp} にログインするパスキー", "Passkey to sign in to {rp}"), &["heading"]));

    let entry = gtk::Entry::builder().placeholder_text(tr!("絞り込み", "Filter")).build();
    if items.len() >= FILTER_FROM {
        outer.append(&entry);
    }

    let list = gtk::ListBox::builder().selection_mode(gtk::SelectionMode::Single).build();
    list.add_css_class("boxed-list");
    let texts: Vec<String> = items.iter().map(|(t, u, d)| format!("{t} {u} {d}").to_lowercase()).collect();
    for (t, u, d) in items {
        let row = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(2)
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(10)
            .margin_end(10)
            .build();
        let head = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        let name = label(t, &[]);
        name.set_markup(&format!("<b>{}</b>", glib::markup_escape_text(t)));
        head.append(&name);
        head.append(&label(u, &[]));
        row.append(&head);
        if !d.is_empty() {
            row.append(&label(d, &["dim-label", "caption"]));
        }
        list.append(&row);
    }
    let entry_f = entry.clone();
    list.set_filter_func(move |row| {
        let words = entry_f.text().to_lowercase();
        let text = &texts[row.index() as usize];
        words.split_whitespace().all(|w| text.contains(w))
    });
    list.select_row(list.row_at_index(0).as_ref());
    let scroll = gtk::ScrolledWindow::builder()
        .child(&list)
        .propagate_natural_height(true)
        .max_content_height(420)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build();
    outer.append(&scroll);
    outer.append(&label(&tr!("Enter 決定  ↑↓ 移動  Esc やめる", "Enter: choose  ↑↓: move  Esc: cancel"), &["dim-label", "caption"]));
    window.set_child(Some(&outer));

    let visible = {
        let list = list.clone();
        move || {
            let mut rows = Vec::new();
            let mut i = 0;
            while let Some(r) = list.row_at_index(i) {
                if r.is_child_visible() {
                    rows.push(r);
                }
                i += 1;
            }
            rows
        }
    };
    let finish = {
        let window = window.clone();
        let chosen = chosen.clone();
        move |row: Option<gtk::ListBoxRow>| {
            if let Some(r) = row {
                chosen.set(Some(r.index() as usize));
            }
            window.close();
        }
    };

    {
        let list2 = list.clone();
        let visible = visible.clone();
        entry.connect_changed(move |_| {
            list2.invalidate_filter();
            let rows = visible();
            if !list2.selected_row().is_some_and(|r| rows.contains(&r)) {
                list2.select_row(rows.first());
            }
        });
    }
    {
        let finish = finish.clone();
        list.connect_row_activated(move |_, row| finish(Some(row.clone())));
    }

    let keys = gtk::EventControllerKey::new();
    keys.set_propagation_phase(gtk::PropagationPhase::Capture);
    {
        let list = list.clone();
        keys.connect_key_pressed(move |_, key, _, _| match key {
            gdk::Key::Escape => {
                finish(None);
                glib::Propagation::Stop
            }
            gdk::Key::Return | gdk::Key::KP_Enter => {
                let sel = list.selected_row().filter(|r| visible().contains(r));
                if sel.is_some() {
                    finish(sel);
                }
                glib::Propagation::Stop
            }
            gdk::Key::Up | gdk::Key::Down => {
                let rows = visible();
                let cur = list.selected_row().and_then(|r| rows.iter().position(|x| *x == r)).unwrap_or(0);
                let next = if key == gdk::Key::Down { (cur + 1).min(rows.len().saturating_sub(1)) } else { cur.saturating_sub(1) };
                if let Some(r) = rows.get(next) {
                    list.select_row(Some(r));
                    r.grab_focus();
                }
                glib::Propagation::Stop
            }
            _ => glib::Propagation::Proceed,
        });
    }
    window.add_controller(keys);
    window.present();
    if items.len() >= FILTER_FROM {
        entry.grab_focus();
    } else if let Some(r) = list.row_at_index(0) {
        r.grab_focus();
    }
    // 常駐サービスから開くと前面に来ないことがあるので、GNOME 拡張 Window Calls があれば前面にする
    glib::timeout_add_local_once(std::time::Duration::from_millis(300), activate_own_window);
}

fn activate_own_window() {
    let Ok(out) = Command::new("busctl")
        .args(["--user", "--json=short", "call", "org.gnome.Shell", "/org/gnome/Shell/Extensions/Windows",
               "org.gnome.Shell.Extensions.Windows", "List"])
        .stderr(Stdio::null())
        .output()
    else {
        return;
    };
    let Some(windows) = serde_json::from_slice::<Value>(&out.stdout)
        .ok()
        .and_then(|v| v["data"][0].as_str().and_then(|s| serde_json::from_str::<Value>(s).ok()))
    else {
        return;
    };
    for w in windows.as_array().into_iter().flatten() {
        if w["wm_class"] == APP_ID && w["focus"] != true {
            let id = w["id"].to_string();
            let _ = Command::new("busctl")
                .args(["--user", "call", "org.gnome.Shell", "/org/gnome/Shell/Extensions/Windows",
                       "org.gnome.Shell.Extensions.Windows", "Activate", "u", &id])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

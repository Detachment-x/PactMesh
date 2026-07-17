//! Windows 系统托盘：菜单「打开控制台 / 退出」+ 双击图标打开控制台。仅 Windows 编译。
//!
//! 后台每隔数秒轮询 `/api/pending`：有待批入网申请时把图标叠红角标、更新 tooltip，
//! 并在新申请到达时弹一次系统通知——管理员无需盯着控制台即可感知。
//!
//! 与 `pactmesh web` 共用入口逻辑：`controller::read_endpoint*` + `open` crate。
//! 事件循环与图标集成遵循 tray-icon 官方 tao 示例（tao 0.34 / tray-icon 0.24）。

use std::thread;
use std::time::Duration;

use anyhow::Result;
use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::platform::windows::EventLoopBuilderExtWindows;
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder, TrayIconEvent};

/// 待批轮询间隔。
const POLL_INTERVAL: Duration = Duration::from_secs(8);

enum UserEvent {
    Tray(TrayIconEvent),
    Menu(MenuEvent),
    Pending(usize),
}

/// 阻塞运行托盘事件循环，直到用户选择「退出」。
pub fn run() -> Result<()> {
    // 允许在非主线程运行（本命令从 tokio 运行时分发），避免 EventLoop 主线程断言。
    let mut builder = EventLoopBuilder::<UserEvent>::with_user_event();
    builder.with_any_thread(true);
    let event_loop = builder.build();

    // 把托盘 / 菜单事件转发进事件循环并唤醒之。
    let proxy = event_loop.create_proxy();
    TrayIconEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::Tray(event));
    }));
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::Menu(event));
    }));

    // 后台待批轮询：数秒一次，把计数送回事件循环更新图标 / tooltip / 通知。
    let poll_proxy = event_loop.create_proxy();
    thread::spawn(move || loop {
        let count = poll_pending_count().unwrap_or(0);
        if poll_proxy.send_event(UserEvent::Pending(count)).is_err() {
            break; // 事件循环已退出
        }
        thread::sleep(POLL_INTERVAL);
    });

    let menu = Menu::new();
    let open_i = MenuItem::new("打开控制台", true, None);
    let quit_i = MenuItem::new("退出", true, None);
    menu.append(&open_i)?;
    menu.append(&quit_i)?;

    let mut tray: Option<TrayIcon> = None;
    let mut last_count: usize = 0;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            // 图标须在事件循环启动后创建（tray-icon#90）。
            Event::NewEvents(StartCause::Init) => {
                match TrayIconBuilder::new()
                    .with_menu(Box::new(menu.clone()))
                    .with_tooltip("PactMesh")
                    .with_icon(brand_icon(false))
                    .build()
                {
                    Ok(t) => tray = Some(t),
                    Err(e) => {
                        eprintln!("failed to create tray icon: {e}");
                        *control_flow = ControlFlow::Exit;
                    }
                }
            }
            Event::UserEvent(UserEvent::Menu(e)) => {
                if e.id == open_i.id() {
                    open_console();
                } else if e.id == quit_i.id() {
                    tray.take();
                    *control_flow = ControlFlow::Exit;
                }
            }
            Event::UserEvent(UserEvent::Tray(TrayIconEvent::DoubleClick { .. })) => {
                open_console();
            }
            Event::UserEvent(UserEvent::Pending(count)) => {
                if count != last_count {
                    // 新申请到达（计数上升）→ 弹一次系统通知。
                    if count > last_count && count > 0 {
                        notify_pending(count);
                    }
                    last_count = count;
                    if let Some(t) = tray.as_ref() {
                        let tip = if count > 0 {
                            format!("PactMesh · {count} 台设备待批准")
                        } else {
                            "PactMesh".to_string()
                        };
                        let _ = t.set_tooltip(Some(tip));
                        let _ = t.set_icon(Some(brand_icon(count > 0)));
                    }
                }
            }
            _ => {}
        }
    })
}

/// 拉取所有「管理员网络」的待批入网申请总数。控制台未启动 / 不可达时返回 0。
fn poll_pending_count() -> Result<usize> {
    let (base, token) = crate::controller::read_endpoint()?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(4))
        .build()?;
    let get_json = |url: String, query: &[(&str, &str)]| -> Result<serde_json::Value> {
        let text = client
            .get(url)
            .query(query)
            .bearer_auth(&token)
            .send()?
            .error_for_status()?
            .text()?;
        Ok(serde_json::from_str(&text)?)
    };

    let domains = get_json(format!("{base}/api/domains"), &[])?;
    let mut total = 0usize;
    for d in domains.as_array().into_iter().flatten() {
        if !d.get("is_root_holder").and_then(|v| v.as_bool()).unwrap_or(false) {
            continue;
        }
        let Some(td) = d.get("trust_domain_id").and_then(|v| v.as_str()) else {
            continue;
        };
        let nets = d.get("networks").and_then(|v| v.as_array());
        for nid in nets.into_iter().flatten() {
            let Some(nid) = nid.as_str() else { continue };
            if let Ok(v) = get_json(
                format!("{base}/api/pending"),
                &[("trust_domain_id", td), ("network_local_id", nid)],
            ) {
                total += v.as_array().map(|a| a.len()).unwrap_or(0);
            }
        }
    }
    Ok(total)
}

/// 系统通知（尽力而为，失败静默——托盘角标与 tooltip 仍是主提示）。
fn notify_pending(count: usize) {
    let _ = notify_rust::Notification::new()
        .summary("PactMesh")
        .body(&format!(
            "有 {count} 台设备申请加入网络。点击托盘图标打开控制台批准。"
        ))
        .show();
}

/// 32×32 品牌青绿（#0fb5a6）图标；`badge=true` 时右上角叠一枚红点表示有待批。
fn brand_icon(badge: bool) -> tray_icon::Icon {
    const W: i32 = 32;
    const H: i32 = 32;
    let mut rgba = Vec::with_capacity((W * H * 4) as usize);
    for _ in 0..(W * H) {
        rgba.extend_from_slice(&[0x0f, 0xb5, 0xa6, 0xff]);
    }
    if badge {
        // 右上角红点：圆心 (24, 8)、半径 6。
        let (cx, cy, r2) = (24i32, 8i32, 6i32 * 6i32);
        for y in 0..H {
            for x in 0..W {
                let (dx, dy) = (x - cx, y - cy);
                if dx * dx + dy * dy <= r2 {
                    let idx = ((y * W + x) * 4) as usize;
                    rgba[idx] = 0xe5;
                    rgba[idx + 1] = 0x48;
                    rgba[idx + 2] = 0x4d;
                    rgba[idx + 3] = 0xff;
                }
            }
        }
    }
    tray_icon::Icon::from_rgba(rgba, W as u32, H as u32).expect("valid brand icon")
}

/// 读取运行时端点文件并用默认浏览器打开控制台（与 `pactmesh web` 同逻辑）。
fn open_console() {
    match crate::controller::read_endpoint_url() {
        Ok(url) => {
            if let Err(e) = open::that(url) {
                eprintln!("failed to open browser: {e}");
            }
        }
        Err(e) => eprintln!("{e:#}"),
    }
}

//! Windows 系统托盘：菜单「打开控制台 / 退出」+ 双击图标打开控制台。仅 Windows 编译。
//!
//! 与 `pactmesh web` 共用入口逻辑：`controller::read_endpoint_url` + `open` crate。
//! 事件循环与图标集成遵循 tray-icon 官方 tao 示例（tao 0.34 / tray-icon 0.24）。

use anyhow::Result;
use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::platform::windows::EventLoopBuilderExtWindows;
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder, TrayIconEvent};

enum UserEvent {
    Tray(TrayIconEvent),
    Menu(MenuEvent),
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

    let menu = Menu::new();
    let open_i = MenuItem::new("打开控制台", true, None);
    let quit_i = MenuItem::new("退出", true, None);
    menu.append(&open_i)?;
    menu.append(&quit_i)?;

    let mut tray: Option<TrayIcon> = None;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            // 图标须在事件循环启动后创建（tray-icon#90）。
            Event::NewEvents(StartCause::Init) => {
                match TrayIconBuilder::new()
                    .with_menu(Box::new(menu.clone()))
                    .with_tooltip("PactMesh")
                    .with_icon(brand_icon())
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
            _ => {}
        }
    })
}

/// 32×32 纯品牌青绿（#0fb5a6）图标，免打包 .ico 资源。
fn brand_icon() -> tray_icon::Icon {
    const W: u32 = 32;
    const H: u32 = 32;
    let mut rgba = Vec::with_capacity((W * H * 4) as usize);
    for _ in 0..(W * H) {
        rgba.extend_from_slice(&[0x0f, 0xb5, 0xa6, 0xff]);
    }
    tray_icon::Icon::from_rgba(rgba, W, H).expect("valid brand icon")
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

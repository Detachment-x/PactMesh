//! JNI shim binding the PactMesh core into the Android app process.
//!
//! The app cannot drive PactMesh over RPC alone: handing the `VpnService` tun fd
//! to the core goes through `NetworkInstanceManager::set_tun_fd`, which has no RPC
//! surface. So the core is linked in-process and everything else (join, status,
//! config) still rides the existing HTTP `/api/*` controller on 127.0.0.1.

/// Link probe: pulls the core dependency graph into the shared object so the
/// aarch64 link is exercised for real, not just type-checked.
#[unsafe(no_mangle)]
pub extern "C" fn pactmesh_android_probe() -> i32 {
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(_) => return -1,
    };
    rt.block_on(async {
        let mgr = pactmesh::instance_manager::NetworkInstanceManager::new();
        mgr.list_network_instance_ids().len() as i32
    })
}

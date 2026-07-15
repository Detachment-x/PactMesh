package org.pactmesh.android

import android.app.Application
import org.pactmesh.android.vpn.VpnController

class PactMeshApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Prefs.init(this)
        Core.init(this)
        VpnController.init(this)
    }
}

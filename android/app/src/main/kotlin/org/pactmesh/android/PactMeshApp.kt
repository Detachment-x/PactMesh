package org.pactmesh.android

import android.app.Application

class PactMeshApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Core.init(this)
    }
}

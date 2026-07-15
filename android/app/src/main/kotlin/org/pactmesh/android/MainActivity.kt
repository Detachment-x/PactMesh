package org.pactmesh.android

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import org.pactmesh.android.ui.Root
import org.pactmesh.android.ui.theme.PactMeshTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            PactMeshTheme {
                val context = LocalContext.current
                val model: MainViewModel = viewModel()

                // Consent for the VPN slot is the system's dialog, and only an Activity
                // can raise it — hence the callback the screens fire rather than
                // switching mode themselves.
                val consent = rememberLauncherForActivityResult(
                    ActivityResultContracts.StartActivityForResult()
                ) { result ->
                    if (result.resultCode == Activity.RESULT_OK) model.setMode(RunMode.VPN)
                }
                val notifications = rememberLauncherForActivityResult(
                    ActivityResultContracts.RequestPermission()
                ) { /* The tunnel comes up either way; only the ongoing notice is at stake. */ }

                LaunchedEffect(Unit) {
                    if (Build.VERSION.SDK_INT >= 33 &&
                        ContextCompat.checkSelfPermission(
                            context,
                            Manifest.permission.POST_NOTIFICATIONS,
                        ) != PackageManager.PERMISSION_GRANTED
                    ) {
                        notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
                    }
                }

                Root(model) {
                    val intent = VpnService.prepare(context)
                    if (intent == null) model.setMode(RunMode.VPN) else consent.launch(intent)
                }
            }
        }
    }
}

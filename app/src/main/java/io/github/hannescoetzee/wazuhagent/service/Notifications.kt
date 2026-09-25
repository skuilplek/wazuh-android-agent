package io.github.hannescoetzee.wazuhagent.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import io.github.hannescoetzee.wazuhagent.R
import io.github.hannescoetzee.wazuhagent.ui.MainActivity

object Notifications {
    const val CHANNEL_AGENT = "agent"
    const val ID_AGENT = 1

    fun createChannels(context: Context) {
        val channel = NotificationChannel(CHANNEL_AGENT, "Agent status", NotificationManager.IMPORTANCE_LOW).apply {
            description = "Persistent notification while the Wazuh agent is running"
            setShowBadge(false)
        }
        context.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    fun agent(context: Context, status: AgentStatus): android.app.Notification {
        val open = PendingIntent.getActivity(
            context, 0, Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            context, 1, AgentForegroundService.stopIntent(context),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val text = when (status.state) {
            ConnectionState.CONNECTED -> "Connected"
            ConnectionState.CONNECTING -> "Connecting…"
            ConnectionState.WAITING_RETRY -> "Offline, retrying"
            ConnectionState.STOPPED -> "Stopped"
        }
        return NotificationCompat.Builder(context, CHANNEL_AGENT)
            .setSmallIcon(R.drawable.ic_stat_agent)
            .setContentTitle("Wazuh agent")
            .setContentText(if (status.detail.isEmpty()) text else "$text · ${status.detail}")
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(open)
            .addAction(0, "Stop", stop)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }
}

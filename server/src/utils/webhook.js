let cachedDb = null;
function getDb() {
    if (!cachedDb) {
        try {
            const mod = require('../database');
            cachedDb = (mod && mod.prepare) ? mod : (mod?.db || mod);
        } catch (_) {}
    }
    return cachedDb;
}

/**
 * Sends a rich Discord embed notification.
 * Supports per-app webhook URL from SQLite 'apps' table, fallback to process.env.DISCORD_WEBHOOK_URL.
 */
async function sendDiscordWebhook(arg1, arg2, arg3, arg4, arg5, arg6) {
    let opts = {};
    if (typeof arg1 === 'object' && arg1 !== null) {
        opts = arg1;
    } else {
        opts = {
            title: arg1,
            description: arg2,
            color: arg3 !== undefined ? arg3 : 0x38bdf8,
            fields: arg4 || [],
            webhookUrl: arg5 || null,
            appId: arg6 || null
        };
    }

    const {
        title = 'System Notification',
        description = '',
        color = 0x38bdf8,
        fields = [],
        appId = null,
        footer = 'KawaiiAuth Telemetry Gateway'
    } = opts;

    let targetWebhookUrl = (opts.webhookUrl || '').trim();

    // Look up per-app webhook URL if not provided directly
    if (!targetWebhookUrl && appId) {
        try {
            const db = getDb();
            if (db) {
                const appRow = db.prepare('SELECT name, webhook_url FROM apps WHERE id = ?').get(appId);
                if (appRow && appRow.webhook_url && appRow.webhook_url.trim()) {
                    targetWebhookUrl = appRow.webhook_url.trim();
                }
            }
        } catch (err) {
            // Database lookup error suppressed
        }
    }

    // Fall back to global environment webhook URL
    if (!targetWebhookUrl) {
        targetWebhookUrl = (process.env.DISCORD_WEBHOOK_URL || '').trim();
    }

    if (!targetWebhookUrl || !(targetWebhookUrl.startsWith('https://discord.com/api/webhooks/') || targetWebhookUrl.startsWith('https://discordapp.com/api/webhooks/'))) {
        return { success: false, message: 'No valid Discord webhook URL configured' };
    }

    const payload = JSON.stringify({
        embeds: [{
            title: `[KawaiiAuth] ${title}`,
            description,
            color: Number(color) || 0x38bdf8,
            fields: Array.isArray(fields) ? fields : [],
            footer: { text: footer },
            timestamp: new Date().toISOString()
        }]
    });

    try {
        const response = await fetch(targetWebhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: payload
        });

        if (!response.ok) {
            const errText = await response.text().catch(() => '');
            return { success: false, message: `Discord API returned ${response.status}: ${errText}` };
        }
        return { success: true, message: 'Webhook delivered' };
    } catch (err) {
        return { success: false, message: err.message || 'Network error delivering webhook' };
    }
}

module.exports = { sendDiscordWebhook };

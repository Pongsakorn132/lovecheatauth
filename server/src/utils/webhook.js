const https = require('node:https');

async function sendDiscordWebhook(title, description, color = 0xec4899, fields = []) {
    const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
    if (!webhookUrl || !webhookUrl.startsWith('https://discord.com/api/webhooks/')) {
        return;
    }

    const payload = JSON.stringify({
        embeds: [{
            title: `[KawaiiAuth] ${title}`,
            description,
            color,
            fields,
            footer: { text: "KawaiiAuth Telemetry Gateway" },
            timestamp: new Date().toISOString()
        }]
    });

    try {
        await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: payload
        });
    } catch (err) {
        // Silently fail webhook so it never blocks auth pipeline
    }
}

module.exports = { sendDiscordWebhook };

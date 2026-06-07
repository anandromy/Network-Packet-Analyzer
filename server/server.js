const express    = require('express');
const http       = require('http');
const { WebSocketServer } = require('ws');
const { spawn }  = require('child_process');
const path       = require('path');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });

app.use(express.static(path.join(__dirname, '..', 'client')));

let captureProcess = null;

function broadcast(obj) {
    const msg = JSON.stringify(obj);
    wss.clients.forEach(client => {
        if (client.readyState === 1) client.send(msg);
    });
}

wss.on('connection', (ws) => {
    console.log('Client connected');

    // Tell new client if capture is already running
    ws.send(JSON.stringify({
        type: 'status',
        msg: captureProcess ? 'Already capturing' : 'Ready'
    }));

    ws.on('message', (raw) => {
        let msg;
        try { msg = JSON.parse(raw); } catch { return; }

        // ── START ────────────────────────────────────────────────
        if (msg.action === 'start') {
            if (captureProcess) {
                ws.send(JSON.stringify({ type: 'status', msg: 'Already running' }));
                return;
            }

            const args = msg.device
                ? ['-i', msg.device]
                : ['-l'];

            // Adjust path to your compiled binary
            captureProcess = spawn('./parser', args, {
                cwd: path.join(__dirname, '..', 'engine', 'src')
            });

            captureProcess.stdout.on('data', (data) => {
                data.toString().split('\n').filter(Boolean).forEach(line => {
                    try {
                        const parsed = JSON.parse(line);
                        broadcast(parsed);
                    } catch (_) {}
                });
            });

            captureProcess.stderr.on('data', (data) => {
                broadcast({ type: 'status', msg: data.toString().trim() });
            });

            captureProcess.on('close', () => {
                captureProcess = null;
                broadcast({ type: 'stopped' });
                console.log('Capture process ended');
            });
        }

        // ── STOP ─────────────────────────────────────────────────
        if (msg.action === 'stop') {
            if (captureProcess) {
                captureProcess.kill('SIGINT');
            }
        }
    });

    ws.on('close', () => console.log('Client disconnected'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Netscope running → http://localhost:${PORT}`);
    console.log('Note: run with sudo if capturing live traffic');
});
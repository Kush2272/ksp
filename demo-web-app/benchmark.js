/**
 * Benchmark Module (benchmark.js)
 * Generates custom SVG charts, statistics, payload swapper, and loads interactive graphics.
 */

// Simulated metrics database matching KSP's performance targets
const BenchmarkDatabase = {
    "1KB": {
        latency: {
            ksp: { mean: 76.0, median: 75.8, ciMin: 75.4, ciMax: 76.5 },
            https: { mean: 45000, median: 44800, ciMin: 44200, ciMax: 45600 },
            http: { mean: 15000, median: 14950, ciMin: 14800, ciMax: 15200 }
        },
        throughput: {
            aes: 1213, // MB/s
            chacha: 505
        }
    },
    "64KB": {
        latency: {
            ksp: { mean: 180.2, median: 179.5, ciMin: 178.0, ciMax: 181.5 },
            https: { mean: 45200, median: 45000, ciMin: 44500, ciMax: 45900 },
            http: { mean: 15300, median: 15200, ciMin: 15000, ciMax: 15500 }
        },
        throughput: {
            aes: 1778,
            chacha: 1316
        }
    },
    "1MB": {
        latency: {
            ksp: { mean: 1087.0, median: 1062.9, ciMin: 1029.8, ciMax: 1144.0 },
            https: { mean: 46500, median: 46200, ciMin: 45800, ciMax: 47100 },
            http: { mean: 16400, median: 16200, ciMin: 15900, ciMax: 16800 }
        },
        throughput: {
            aes: 964,
            chacha: 840
        }
    }
};

class BenchmarkDashboard {
    constructor(latencyContainerId, throughputContainerId, statsContainerId) {
        this.latencyContainer = document.getElementById(latencyContainerId);
        this.throughputContainer = document.getElementById(throughputContainerId);
        this.statsContainer = document.getElementById(statsContainerId);
        this.activeSize = "64KB";
    }

    init() {
        this.drawCharts(this.activeSize);
    }

    // Main redrawing driver when payload sizes toggle
    drawCharts(size) {
        this.activeSize = size;
        const metrics = BenchmarkDatabase[size];

        this.drawLatencyChart(metrics.latency);
        this.drawThroughputChart(metrics.throughput);
        this.drawStatsSummary(metrics.latency.ksp);
    }

    // Render latency chart using custom glowing SVG columns
    drawLatencyChart(latency) {
        const maxVal = Math.max(latency.http.mean, latency.https.mean, latency.ksp.mean);
        const getScale = (val) => (val / maxVal) * 160;

        // Custom SVG bars for a clean visual representation of the latency ratios
        this.latencyContainer.innerHTML = `
            <svg viewBox="0 0 320 200" style="width: 100%; height: auto; background: #080a0f; border-radius: 6px; border: 1px solid rgba(255,255,255,0.02); padding: 10px;">
                <!-- Grid Lines -->
                <line x1="40" y1="40" x2="300" y2="40" stroke="#1c2030" stroke-dasharray="2" />
                <line x1="40" y1="100" x2="300" y2="100" stroke="#1c2030" stroke-dasharray="2" />
                <line x1="40" y1="160" x2="300" y2="160" stroke="#242c40" />

                <!-- HTTP Column -->
                <rect x="70" y="${160 - getScale(latency.http.mean)}" width="30" height="${getScale(latency.http.mean)}" fill="url(#purpleGrad)" rx="2" />
                <text x="85" y="180" fill="#8c9cb2" font-size="9" text-anchor="middle">HTTP</text>
                <text x="85" y="${150 - getScale(latency.http.mean)}" fill="#8c9cb2" font-size="9" font-weight="600" text-anchor="middle">${(latency.http.mean / 1000).toFixed(1)}ms</text>

                <!-- HTTPS Column -->
                <rect x="150" y="${160 - getScale(latency.https.mean)}" width="30" height="${getScale(latency.https.mean)}" fill="url(#purpleGrad)" rx="2" />
                <text x="165" y="180" fill="#8c9cb2" font-size="9" text-anchor="middle">HTTPS</text>
                <text x="165" y="${150 - getScale(latency.https.mean)}" fill="#8c9cb2" font-size="9" font-weight="600" text-anchor="middle">${(latency.https.mean / 1000).toFixed(1)}ms</text>

                <!-- KSP Column (glowing blue) -->
                <rect x="230" y="${160 - Math.max(getScale(latency.ksp.mean), 2)}" width="30" height="${Math.max(getScale(latency.ksp.mean), 2)}" fill="url(#blueGrad)" rx="2" style="filter: drop-shadow(0px 0px 4px rgba(0, 192, 255, 0.4));" />
                <text x="245" y="180" fill="#00c0ff" font-weight="600" font-size="9" text-anchor="middle">KSP</text>
                <text x="245" y="${150 - Math.max(getScale(latency.ksp.mean), 2)}" fill="#00c0ff" font-size="9" font-weight="700" text-anchor="middle">${latency.ksp.mean.toFixed(1)}µs</text>

                <!-- Defs for Gradients -->
                <defs>
                    <linearGradient id="purpleGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" stop-color="#bb00ff" />
                        <stop offset="100%" stop-color="#7700aa" />
                    </linearGradient>
                    <linearGradient id="blueGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" stop-color="#00c0ff" />
                        <stop offset="100%" stop-color="#0033aa" />
                    </linearGradient>
                </defs>
            </svg>
        `;
    }

    // Render throughput chart using custom glowing SVG horizontal progress bars
    drawThroughputChart(throughput) {
        const maxVal = Math.max(throughput.aes, throughput.chacha, 2000);
        const getPercent = (val) => (val / maxVal) * 100;

        this.throughputContainer.innerHTML = `
            <div class="bar-row">
                <div class="bar-label"><span>ChaCha20-Poly1305 (Software payload)</span> <span>${throughput.chacha} MB/s</span></div>
                <div class="bar-outer"><div class="bar-inner purple" style="width: ${getPercent(throughput.chacha).toFixed(2)}%;"></div></div>
            </div>
            
            <div class="bar-row" style="margin-top: 1rem;">
                <div class="bar-label"><span style="font-weight: 600; color: var(--accent-green);">AES-256-GCM (Hardware AES-NI)</span> <span style="font-weight: 600; color: var(--accent-green);">${throughput.aes} MB/s</span></div>
                <div class="bar-outer"><div class="bar-inner" style="width: ${getPercent(throughput.aes).toFixed(2)}%;"></div></div>
            </div>
        `;
    }

    // Render KSP stats summary
    drawStatsSummary(kspLatency) {
        this.statsContainer.innerHTML = `
            <div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 1rem; border-top: 1px solid var(--border-color); padding-top: 0.75rem;">
                <div style="display: grid; grid-template-columns: repeat(4, 1fr); text-align: center; gap: 0.25rem;">
                    <div>
                        <div style="font-size: 0.65rem; text-transform: uppercase;">Mean</div>
                        <div style="font-size: 0.9rem; font-weight: 600; color: var(--accent-blue);">${kspLatency.mean.toFixed(1)} µs</div>
                    </div>
                    <div>
                        <div style="font-size: 0.65rem; text-transform: uppercase;">Median</div>
                        <div style="font-size: 0.9rem; font-weight: 600; color: var(--text-primary);">${kspLatency.median.toFixed(1)} µs</div>
                    </div>
                    <div>
                        <div style="font-size: 0.65rem; text-transform: uppercase;">CI (95%) Min</div>
                        <div style="font-size: 0.9rem; font-weight: 500; color: var(--text-secondary);">${kspLatency.ciMin.toFixed(1)} µs</div>
                    </div>
                    <div>
                        <div style="font-size: 0.65rem; text-transform: uppercase;">CI (95%) Max</div>
                        <div style="font-size: 0.9rem; font-weight: 500; color: var(--text-secondary);">${kspLatency.ciMax.toFixed(1)} µs</div>
                    </div>
                </div>
            </div>
        `;
    }
}

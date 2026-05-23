const API_BASE = ['localhost', '127.0.0.1'].includes(window.location.hostname) || window.location.protocol === 'file:'
    ? 'http://127.0.0.1:8000'
    : window.location.origin;

const PRESETS = {
    Normal: {
        protocol_type: 'tcp',
        duration: 0.5,
        src_bytes: 450,
        dst_bytes: 1200,
        num_failed_logins: 0,
        count: 24,
        srv_count: 18,
        serror_rate: 0.05,
        rerror_rate: 0.02,
        same_srv_rate: 0.8,
        diff_srv_rate: 0.08,
        dst_host_count: 65,
        dst_host_srv_count: 45,
    },
    DoS: {
        protocol_type: 'tcp',
        duration: 0.1,
        src_bytes: 70,
        dst_bytes: 30,
        num_failed_logins: 0,
        count: 260,
        srv_count: 220,
        serror_rate: 0.91,
        rerror_rate: 0.15,
        same_srv_rate: 0.88,
        diff_srv_rate: 0.04,
        dst_host_count: 240,
        dst_host_srv_count: 220,
    },
    Exploit: {
        protocol_type: 'tcp',
        duration: 4.2,
        src_bytes: 9500,
        dst_bytes: 700,
        num_failed_logins: 2,
        count: 60,
        srv_count: 45,
        serror_rate: 0.55,
        rerror_rate: 0.42,
        same_srv_rate: 0.62,
        diff_srv_rate: 0.28,
        dst_host_count: 135,
        dst_host_srv_count: 80,
    },
    Reconnaissance: {
        protocol_type: 'icmp',
        duration: 0.3,
        src_bytes: 90,
        dst_bytes: 45,
        num_failed_logins: 0,
        count: 165,
        srv_count: 22,
        serror_rate: 0.18,
        rerror_rate: 0.72,
        same_srv_rate: 0.23,
        diff_srv_rate: 0.73,
        dst_host_count: 220,
        dst_host_srv_count: 35,
    },
    'Generic Attack': {
        protocol_type: 'udp',
        duration: 1.1,
        src_bytes: 4200,
        dst_bytes: 95,
        num_failed_logins: 0,
        count: 125,
        srv_count: 95,
        serror_rate: 0.63,
        rerror_rate: 0.45,
        same_srv_rate: 0.65,
        diff_srv_rate: 0.35,
        dst_host_count: 190,
        dst_host_srv_count: 160,
    },
    'Brute Force': {
        protocol_type: 'tcp',
        duration: 2.8,
        src_bytes: 350,
        dst_bytes: 180,
        num_failed_logins: 6,
        count: 85,
        srv_count: 60,
        serror_rate: 0.12,
        rerror_rate: 0.76,
        same_srv_rate: 0.72,
        diff_srv_rate: 0.15,
        dst_host_count: 95,
        dst_host_srv_count: 70,
    },
};

document.addEventListener('DOMContentLoaded', () => {
    const predictionForm = document.getElementById('prediction-form');
    const singleResult = document.getElementById('single-result');
    const presetStrip = document.getElementById('preset-strip');
    const expectedOutput = document.getElementById('expected-output');
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const loadingState = document.getElementById('loading-state');
    const metricsRow = document.getElementById('metrics-row');
    const analysisGrid = document.getElementById('analysis-grid');
    const resultsBody = document.getElementById('results-body');
    const attackChart = document.getElementById('attack-chart');
    const exportCsvButton = document.getElementById('export-csv');
    const exportJsonButton = document.getElementById('export-json');
    let latestResults = [];

    applyPreset('Normal');

    presetStrip.addEventListener('click', (event) => {
        const button = event.target.closest('.preset-button');
        if (!button) return;
        applyPreset(button.dataset.preset);
    });

    predictionForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const payload = formToPayload(new FormData(predictionForm));

        singleResult.innerHTML = resultShell('Analyzing record...');
        try {
            const response = await fetch(`${API_BASE}/predict-single`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await parseResponse(response);
            latestResults = data.data;
            renderSinglePrediction(data.data[0], data.model_info);
            renderMetrics(data);
        } catch (error) {
            renderError(singleResult, error.message);
        }
    });

    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', (event) => {
        event.preventDefault();
        dropZone.classList.add('dragover');
    });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', (event) => {
        event.preventDefault();
        dropZone.classList.remove('dragover');
        if (event.dataTransfer.files.length) {
            analyzeCsv(event.dataTransfer.files[0]);
        }
    });
    fileInput.addEventListener('change', (event) => {
        if (event.target.files.length) {
            analyzeCsv(event.target.files[0]);
        }
    });

    async function analyzeCsv(file) {
        if (!file.name.toLowerCase().endsWith('.csv')) {
            alert('Please choose a CSV file.');
            return;
        }

        loadingState.classList.remove('hidden');
        metricsRow.classList.add('hidden');
        analysisGrid.classList.add('hidden');

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch(`${API_BASE}/predict`, {
                method: 'POST',
                body: formData,
            });
            const data = await parseResponse(response);
            latestResults = data.data;
            renderBatchDashboard(data);
        } catch (error) {
            alert(error.message);
        } finally {
            loadingState.classList.add('hidden');
        }
    }

    exportCsvButton.addEventListener('click', () => exportResults('csv'));
    exportJsonButton.addEventListener('click', () => exportResults('json'));

    function applyPreset(name) {
        const preset = PRESETS[name];
        Object.entries(preset).forEach(([key, value]) => {
            const input = predictionForm.elements[key];
            if (input) input.value = value;
        });
        expectedOutput.innerHTML = `Expected class: <strong>${name}</strong>`;
        document.querySelectorAll('.preset-button').forEach((button) => {
            button.classList.toggle('active', button.dataset.preset === name);
        });
    }

    function formToPayload(formData) {
        const payload = {};
        formData.forEach((value, key) => {
            payload[key] = key === 'protocol_type' ? value : Number(value);
        });
        return payload;
    }

    async function parseResponse(response) {
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.detail || 'The API could not process the request.');
        }
        return data;
    }

    function renderSinglePrediction(row, modelInfo) {
        const statusClass = row.is_attack ? 'threat' : 'normal';
        singleResult.innerHTML = `
            <div class="section-heading">
                <p class="eyebrow">Model Output</p>
                <h2>Prediction Result</h2>
            </div>
            <div class="prediction-card ${statusClass}">
                <span class="risk-pill">${row.risk_level} Risk</span>
                <strong>${row.attack_type}</strong>
                <p>${row.confidence}% confidence using ${modelInfo.best_model || 'the trained model'}.</p>
            </div>
            <dl class="result-details">
                <div><dt>Protocol</dt><dd>${row.protocol}</dd></div>
                <div><dt>Source Bytes</dt><dd>${formatNumber(row.src_bytes)}</dd></div>
                <div><dt>Destination Bytes</dt><dd>${formatNumber(row.dst_bytes)}</dd></div>
            </dl>
        `;
    }

    function renderBatchDashboard(data) {
        renderMetrics(data);
        analysisGrid.classList.remove('hidden');
        renderAttackChart(data.attack_breakdown, data.total_analyzed);
        renderResultsTable(data.data);
    }

    function renderMetrics(data) {
        document.getElementById('total-records').textContent = formatNumber(data.total_analyzed);
        document.getElementById('threats-detected').textContent = formatNumber(data.threats_detected);
        document.getElementById('best-model').textContent = data.model_info.best_model || '--';
        const accuracy = Number(data.model_info.best_accuracy);
        document.getElementById('model-accuracy').textContent = Number.isFinite(accuracy)
            ? `${Math.round(accuracy * 10000) / 100}%`
            : 'Not loaded';

        metricsRow.classList.remove('hidden');
    }

    function renderAttackChart(breakdown, total) {
        const entries = Object.entries(breakdown).sort((a, b) => b[1] - a[1]);
        attackChart.innerHTML = entries.map(([label, value]) => {
            const percent = total ? Math.round((value / total) * 100) : 0;
            return `
                <div class="bar-row">
                    <div class="bar-meta">
                        <span>${label}</span>
                        <strong>${value}</strong>
                    </div>
                    <div class="bar-track">
                        <div class="bar-fill ${label === 'Normal' ? 'normal-fill' : 'threat-fill'}" style="width: ${percent}%"></div>
                    </div>
                </div>
            `;
        }).join('');
    }

    function renderResultsTable(rows) {
        const sortedRows = [...rows].sort((a, b) => {
            if (a.is_attack === b.is_attack) return b.confidence - a.confidence;
            return a.is_attack ? -1 : 1;
        });

        resultsBody.innerHTML = sortedRows.slice(0, 150).map((row) => `
            <tr>
                <td>#${row.id}</td>
                <td>${row.protocol}</td>
                <td>${formatNumber(row.src_bytes)} / ${formatNumber(row.dst_bytes)}</td>
                <td><span class="class-badge ${row.is_attack ? 'danger' : 'safe'}">${row.attack_type}</span></td>
                <td>${row.risk_level}</td>
                <td>${row.confidence}%</td>
            </tr>
        `).join('');
    }

    function exportResults(format) {
        if (!latestResults.length) {
            alert('Run a prediction or upload a CSV before exporting.');
            return;
        }

        if (format === 'json') {
            downloadFile(
                'aegissoc_predictions.json',
                JSON.stringify(latestResults, null, 2),
                'application/json'
            );
            return;
        }

        const columns = ['id', 'protocol', 'src_bytes', 'dst_bytes', 'attack_type', 'risk_level', 'confidence'];
        const rows = latestResults.map((row) => columns.map((column) => escapeCsv(row[column])).join(','));
        downloadFile('aegissoc_predictions.csv', [columns.join(','), ...rows].join('\n'), 'text/csv');
    }

    function escapeCsv(value) {
        const text = String(value ?? '');
        return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
    }

    function downloadFile(filename, content, type) {
        const blob = new Blob([content], { type });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        link.click();
        URL.revokeObjectURL(url);
    }

    function resultShell(message) {
        return `
            <div class="section-heading">
                <p class="eyebrow">Model Output</p>
                <h2>Prediction Result</h2>
            </div>
            <div class="empty-state">${message}</div>
        `;
    }

    function renderError(container, message) {
        container.innerHTML = resultShell(`Error: ${message}`);
    }

    function formatNumber(value) {
        return Number(value).toLocaleString(undefined, { maximumFractionDigits: 0 });
    }
});

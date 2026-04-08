/**
 * API Security Tester - Frontend JavaScript
 * Author: Samriddhi Poudel (23047345)
 * Date: December 2025
 */

const API_BASE_URL = 'http://127.0.0.1:8000';

let currentScanId = null;
let scanController = null;

document.addEventListener('DOMContentLoaded', function() {
    checkConnection();
    loadScanHistory();
    loadSavedEndpoints();
    setupEventListeners();
});

// ── Connection check ──────────────────────────────────────────────────────────

async function checkConnection() {
    const statusElement = document.getElementById('connectionStatus');
    try {
        const response = await fetch(API_BASE_URL + '/api/health');
        const data = await response.json();
        if (response.ok && data.status === 'healthy') {
            statusElement.innerHTML = '<span class="status-dot"></span> Connected';
            statusElement.classList.add('connected');
        } else {
            statusElement.innerHTML = '<span class="status-dot"></span> Partial';
        }
    } catch (error) {
        statusElement.innerHTML = '<span class="status-dot"></span> Disconnected';
        showNotification('Cannot connect to backend server', 'error');
    }
}

// ── Event listeners ───────────────────────────────────────────────────────────

function setupEventListeners() {
    const scanForm = document.getElementById('scanForm');
    if (scanForm) scanForm.addEventListener('submit', handleScan);

    const saveBtn = document.getElementById('saveBtn');
    if (saveBtn) saveBtn.addEventListener('click', handleSaveEndpoint);

    const clearBtn = document.getElementById('clearResults');
    if (clearBtn) clearBtn.addEventListener('click', clearResults);

    const refreshBtn = document.getElementById('refreshEndpoints');
    if (refreshBtn) refreshBtn.addEventListener('click', loadSavedEndpoints);
}

// ── Scan ──────────────────────────────────────────────────────────────────────

async function handleScan(event) {
    event.preventDefault();

    const apiUrl         = document.getElementById('apiUrl').value.trim();
    const apiName        = (document.getElementById('apiName') || {}).value || 'Quick Scan';
    const httpMethod     = document.getElementById('httpMethod').value;
    const apiDescription = (document.getElementById('apiDescription') || {}).value || '';

    if (!apiUrl) { showNotification('Please enter an API URL', 'error'); return; }
    if (!apiUrl.startsWith('http://') && !apiUrl.startsWith('https://')) {
        showNotification('URL must start with http:// or https://', 'error'); return;
    }

    scanController = new AbortController();
    showLoading();
    hideResults();
    document.getElementById('reportSection').style.display = 'none';

    try {
        const response = await fetch(API_BASE_URL + '/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                api_url:     apiUrl,
                api_name:    apiName,
                http_method: httpMethod,
                description: apiDescription
            }),
            signal: scanController.signal
        });

        const data = await response.json();

        if (response.ok && data.success) {
            // Backend returns: { success:true, scan_id, tests:[...], passed, failed, warnings }
            currentScanId = data.scan_id;
            window.currentScanId = data.scan_id;

            displayResults({ tests: data.tests });
            document.getElementById('reportSection').style.display = 'block';
            loadScanHistory();
            showNotification('Scan completed successfully!', 'success');
        } else {
            throw new Error(data.error || 'Scan failed');
        }
    } catch (error) {
        if (error.name === 'AbortError') {
            showNotification('Scan cancelled', 'info');
        } else {
            console.error('Scan error:', error);
            showNotification('Scan Error: ' + error.message, 'error');
        }
    } finally {
        hideLoading();
        scanController = null;
    }
}

// ── Save endpoint ─────────────────────────────────────────────────────────────

async function handleSaveEndpoint(event) {
    if (event) event.preventDefault();

    const apiUrl         = document.getElementById('apiUrl').value.trim();
    const apiName        = (document.getElementById('apiName') || {}).value || 'Unnamed API';
    const httpMethod     = document.getElementById('httpMethod').value;
    const apiDescription = (document.getElementById('apiDescription') || {}).value || '';

    if (!apiUrl) { showNotification('Please enter an API URL to save', 'error'); return; }

    try {
        const response = await fetch(API_BASE_URL + '/api/endpoints', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: apiName, url: apiUrl, method: httpMethod, description: apiDescription })
        });
        const data = await response.json();

        if (response.ok && data.success) {
            showNotification('Endpoint saved successfully!', 'success');
            loadSavedEndpoints();
        } else {
            throw new Error(data.error || 'Failed to save endpoint');
        }
    } catch (error) {
        showNotification('Error saving endpoint: ' + error.message, 'error');
    }
}

// ── Display results ───────────────────────────────────────────────────────────

function displayResults(results) {
    if (!results || !results.tests) { showNotification('No results to display', 'error'); return; }

    const totalTests = results.tests.length;
    const passed     = results.tests.filter(t => t.status === 'PASS').length;
    const failed     = results.tests.filter(t => t.status === 'FAIL').length;
    const warnings   = results.tests.filter(t => t.status === 'WARNING').length;

    document.getElementById('totalTests').textContent   = totalTests;
    document.getElementById('passedTests').textContent  = passed;
    document.getElementById('failedTests').textContent  = failed;
    document.getElementById('warningTests').textContent = warnings;

    document.getElementById('resultsDetails').innerHTML = results.tests.map(test => {
        let cls = 'pass', label = 'PASS';
        if (test.status === 'FAIL')    { cls = 'fail';    label = 'FAIL'; }
        if (test.status === 'WARNING') { cls = 'warning'; label = 'WARN'; }
        if (test.status === 'ERROR')   { cls = 'fail';    label = 'ERROR'; }
        return `<div class="result-item ${cls}">
            <div class="result-header">
                <span class="result-name">${escapeHtml(test.name)}</span>
                <span class="result-badge ${cls}">${label}</span>
            </div>
            <div class="result-details">${escapeHtml(test.details || '')}</div>
        </div>`;
    }).join('');

    showResults();
}

// ── Scan history ──────────────────────────────────────────────────────────────

async function loadScanHistory() {
    try {
        const response = await fetch(API_BASE_URL + '/api/scans');
        const data = await response.json();
        const container = document.getElementById('scanHistory');
        if (!container) return;

        if (data.success && data.scans && data.scans.length > 0) {
            container.innerHTML = data.scans.slice(0, 10).map(scan => `
                <div class="scan-item">
                    <div class="scan-info">
                        <h4>${escapeHtml(scan.api_name || 'Unknown API')}</h4>
                        <p class="scan-url">${escapeHtml(scan.api_url || '')}</p>
                        <p class="scan-date">${escapeHtml(scan.scan_timestamp || '')}</p>
                        <div class="scan-stats">
                            <span class="stat-badge stat-pass">${scan.passed || 0} Passed</span>
                            <span class="stat-badge stat-fail">${scan.failed || 0} Failed</span>
                            <span class="stat-badge">Total: ${scan.total_tests || 0}</span>
                        </div>
                    </div>
                    <div class="export-buttons-inline">
                        <button class="export-btn-small btn-pdf"  onclick="downloadScanReport(${scan.id},'pdf')">PDF</button>
                        <button class="export-btn-small btn-json" onclick="downloadScanReport(${scan.id},'json')">JSON</button>
                        <button class="export-btn-small btn-csv"  onclick="downloadScanReport(${scan.id},'csv')">CSV</button>
                    </div>
                </div>`).join('');
        } else {
            container.innerHTML = '<div class="empty-state"><p>No scan history yet. Run your first scan above!</p></div>';
        }
    } catch (error) {
        const container = document.getElementById('scanHistory');
        if (container) container.innerHTML = '<div class="empty-state error"><p>Failed to load scan history</p></div>';
    }
}

// ── Saved endpoints ───────────────────────────────────────────────────────────

async function loadSavedEndpoints() {
    try {
        const response = await fetch(API_BASE_URL + '/api/endpoints');
        const data = await response.json();
        const container = document.getElementById('savedEndpointsList');
        if (!container) return;

        if (data.success && data.endpoints && data.endpoints.length > 0) {
            container.innerHTML = data.endpoints.map(ep => `
                <div class="endpoint-item">
                    <div class="endpoint-info">
                        <h4>${escapeHtml(ep.name || '')}</h4>
                        <span class="endpoint-url">${escapeHtml(ep.url || '')}</span>
                        <span class="endpoint-method">${escapeHtml(ep.method || 'GET')}</span>
                    </div>
                    <button class="btn btn-small btn-secondary" onclick="loadEndpointToForm('${escapeHtml(ep.url)}','${escapeHtml(ep.name)}','${ep.method}')">Load</button>
                </div>`).join('');
        } else {
            container.innerHTML = '<p class="empty-state">No saved endpoints yet</p>';
        }
    } catch (error) {
        const container = document.getElementById('savedEndpointsList');
        if (container) container.innerHTML = '<p class="empty-state error">Failed to load endpoints</p>';
    }
}

// ── Load endpoint to form ─────────────────────────────────────────────────────

function loadEndpointToForm(url, name, method) {
    document.getElementById('apiUrl').value     = url;
    document.getElementById('apiName').value    = name;
    document.getElementById('httpMethod').value = method;
    document.getElementById('scanForm').scrollIntoView({ behavior: 'smooth' });
    showNotification('Endpoint loaded into form', 'success');
}

// ── Report download ───────────────────────────────────────────────────────────

function downloadReport(format) {
    if (!currentScanId) { showNotification('No scan results available to export', 'error'); return; }
    showNotification('Generating ' + format.toUpperCase() + ' report...', 'info');
    window.open(API_BASE_URL + '/api/reports/' + format + '/' + currentScanId, '_blank');
    setTimeout(() => showNotification(format.toUpperCase() + ' report download started!', 'success'), 500);
}

function downloadScanReport(scanId, format) {
    window.open(API_BASE_URL + '/api/reports/' + format + '/' + scanId, '_blank');
    showNotification('Report download started!', 'success');
}

// ── UI helpers ────────────────────────────────────────────────────────────────

function showLoading() {
    document.getElementById('loadingIndicator').style.display = 'block';
    const scanBtn = document.getElementById('scanBtn');
    const saveBtn = document.getElementById('saveBtn');
    if (scanBtn) scanBtn.disabled = true;
    if (saveBtn) saveBtn.disabled = true;
}

function cancelScan() {
    if (scanController) {
        scanController.abort();
        scanController = null;
    }
    hideLoading();
    showNotification('Scan cancelled.', 'info');
}

function hideLoading() {
    document.getElementById('loadingIndicator').style.display = 'none';
    const scanBtn = document.getElementById('scanBtn');
    const saveBtn = document.getElementById('saveBtn');
    if (scanBtn) scanBtn.disabled = false;
    if (saveBtn) saveBtn.disabled = false;
}

function showResults() {
    const s = document.getElementById('resultsSection');
    s.style.display = 'block';
    s.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function hideResults() {
    document.getElementById('resultsSection').style.display = 'none';
}

function clearResults() {
    hideResults();
    document.getElementById('reportSection').style.display = 'none';
    currentScanId = null;
    window.currentScanId = null;
    showNotification('Results cleared', 'success');
}

function showNotification(message, type = 'info') {
    const existing = document.querySelector('.notification');
    if (existing) existing.remove();
    const n = document.createElement('div');
    n.className = 'notification notification-' + type;
    n.textContent = message;
    document.body.appendChild(n);
    setTimeout(() => n.classList.add('show'), 100);
    setTimeout(() => { n.classList.remove('show'); setTimeout(() => n.remove(), 300); }, 3000);
}

function escapeHtml(text) {
    return String(text).replace(/[&<>"']/g, c =>
        ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#039;' })[c]
    );
}

window.downloadReport     = downloadReport;
window.downloadScanReport = downloadScanReport;
window.loadEndpointToForm = loadEndpointToForm;
/**
 * API Security Tester - Frontend JavaScript
 * Author: Samriddhi Poudel (23047345)
 * Date: December 13, 2025
 */

// Configuration
const API_BASE_URL = 'http://127.0.0.1:8000';

// DOM Elements
const scanForm = document.getElementById('scanForm');
const scanBtn = document.getElementById('scanBtn');
const saveBtn = document.getElementById('saveBtn');
const loadingIndicator = document.getElementById('loadingIndicator');
const resultsSection = document.getElementById('resultsSection');
const connectionStatus = document.getElementById('connectionStatus');
const clearResultsBtn = document.getElementById('clearResults');
const refreshEndpointsBtn = document.getElementById('refreshEndpoints');

// Initialize app when DOM loads
document.addEventListener('DOMContentLoaded', () => {
    console.log('🔒 API Security Tester Initialized');
    checkConnection();
    loadSavedEndpoints();
    setupEventListeners();
});

/**
 * Check backend connection
 */
async function checkConnection() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/health`);
        const data = await response.json();
        
        if (data.database === 'connected') {
            connectionStatus.innerHTML = '<span class="status-dot"></span> Connected';
            connectionStatus.classList.add('connected');
            showNotification('Connected to backend', 'success');
        } else {
            connectionStatus.innerHTML = '<span class="status-dot"></span> Database Error';
            showNotification('Database connection issue', 'error');
        }
    } catch (error) {
        connectionStatus.innerHTML = '<span class="status-dot"></span> Disconnected';
        showNotification('Cannot connect to backend', 'error');
        console.error('Connection error:', error);
    }
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Scan form submission
    scanForm.addEventListener('submit', handleScan);
    
    // Save endpoint button
    saveBtn.addEventListener('click', handleSaveEndpoint);
    
    // Clear results button
    clearResultsBtn.addEventListener('click', clearResults);
    
    // Refresh endpoints button
    refreshEndpointsBtn.addEventListener('click', loadSavedEndpoints);
}

/**
 * Handle API scan
 */
async function handleScan(e) {
    e.preventDefault();
    
    const apiUrl = document.getElementById('apiUrl').value;
    const apiName = document.getElementById('apiName').value || 'Quick Scan';
    const apiMethod = document.getElementById('apiMethod').value;
    
    // Validate URL
    if (!apiUrl.startsWith('http://') && !apiUrl.startsWith('https://')) {
        showNotification('Please enter a valid URL starting with http:// or https://', 'error');
        return;
    }
    
    // Show loading
    showLoading();
    hideResults();
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: apiUrl,
                name: apiName,
                method: apiMethod
            })
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            displayResults(data.results);
            showNotification('Scan completed successfully!', 'success');
            loadSavedEndpoints(); // Refresh the list
        } else {
            showNotification(data.error || 'Scan failed', 'error');
        }
    } catch (error) {
        console.error('Scan error:', error);
        showNotification('Failed to scan API. Check console for details.', 'error');
    } finally {
        hideLoading();
    }
}

/**
 * Handle save endpoint
 */
async function handleSaveEndpoint() {
    const apiUrl = document.getElementById('apiUrl').value;
    const apiName = document.getElementById('apiName').value || 'Unnamed API';
    const apiMethod = document.getElementById('apiMethod').value;
    const apiDescription = document.getElementById('apiDescription').value;
    
    if (!apiUrl) {
        showNotification('Please enter an API URL', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/endpoints`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: apiName,
                url: apiUrl,
                method: apiMethod,
                description: apiDescription
            })
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            showNotification('API endpoint saved successfully!', 'success');
            loadSavedEndpoints();
            // Don't clear form - user might want to scan it
        } else {
            showNotification(data.message || 'Failed to save endpoint', 'error');
        }
    } catch (error) {
        console.error('Save error:', error);
        showNotification('Failed to save endpoint', 'error');
    }
}

/**
 * Load saved endpoints
 */
async function loadSavedEndpoints() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/endpoints`);
        const data = await response.json();
        
        const listContainer = document.getElementById('savedEndpointsList');
        
        if (data.endpoints && data.endpoints.length > 0) {
            listContainer.innerHTML = data.endpoints.map(endpoint => `
                <div class="endpoint-item">
                    <div class="endpoint-info">
                        <h4>${endpoint.name}</h4>
                        <span class="endpoint-url">${endpoint.url}</span>
                        <span class="endpoint-method">${endpoint.method}</span>
                    </div>
                    <button class="btn btn-small" onclick="loadEndpointToForm('${endpoint.url}', '${endpoint.name}', '${endpoint.method}')">
                        Load
                    </button>
                </div>
            `).join('');
        } else {
            listContainer.innerHTML = '<p class="empty-state">No saved endpoints yet</p>';
        }
    } catch (error) {
        console.error('Load endpoints error:', error);
        showNotification('Failed to load saved endpoints', 'error');
    }
}

/**
 * Load endpoint data into form
 */
function loadEndpointToForm(url, name, method) {
    document.getElementById('apiUrl').value = url;
    document.getElementById('apiName').value = name;
    document.getElementById('apiMethod').value = method;
    
    // Scroll to form
    scanForm.scrollIntoView({ behavior: 'smooth' });
    showNotification('Endpoint loaded into form', 'success');
}

/**
 * Display scan results
 */
function displayResults(results) {
    // Update stats
    const totalTests = results.tests.length;
    const passedTests = results.tests.filter(t => t.status === 'PASS').length;
    const failedTests = results.tests.filter(t => t.status === 'FAIL').length;
    const warningTests = results.tests.filter(t => t.status === 'WARNING').length;
    
    document.getElementById('totalTests').textContent = totalTests;
    document.getElementById('passedTests').textContent = passedTests;
    document.getElementById('failedTests').textContent = failedTests;
    document.getElementById('warningTests').textContent = warningTests;
    
    // Display detailed results
    const resultsDetails = document.getElementById('resultsDetails');
    resultsDetails.innerHTML = results.tests.map(test => {
        const statusClass = test.status.toLowerCase();
        const statusText = test.status;
        
        return `
            <div class="result-item ${statusClass}">
                <div class="result-header">
                    <span class="result-name">${test.name}</span>
                    <span class="result-badge ${statusClass}">${statusText}</span>
                </div>
                <div class="result-details">${test.details}</div>
            </div>
        `;
    }).join('');
    
    // Show results section
    showResults();
}

/**
 * Clear results
 */
function clearResults() {
    hideResults();
    showNotification('Results cleared', 'success');
}

/**
 * Show/Hide UI elements
 */
function showLoading() {
    loadingIndicator.style.display = 'block';
    scanBtn.disabled = true;
    saveBtn.disabled = true;
}

function hideLoading() {
    loadingIndicator.style.display = 'none';
    scanBtn.disabled = false;
    saveBtn.disabled = false;
}

function showResults() {
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

function hideResults() {
    resultsSection.style.display = 'none';
}

/**
 * Show notification (simple implementation)
 */
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#3b82f6'};
        color: white;
        border-radius: 0.5rem;
        box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1);
        z-index: 1000;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Add CSS for notifications animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

console.log('✅ App.js loaded successfully');
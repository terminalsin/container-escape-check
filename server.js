const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Serve static files
app.use(express.static('public'));

// Helper function to categorize analysis files
function getCategoryForFile(filename) {
    const criticalFiles = ['harvested_credentials.txt', 'registry_credentials.txt', 'database_credentials.txt',
        'docker_api_analysis.txt', 'exfiltration_targets.txt', 'disruption_analysis.txt'
    ];
    const credentialFiles = ['capabilities.txt', 'docker_analysis.txt', 'procfs_analysis.txt', 'rootfs_analysis.txt'];
    const analysisFiles = ['internal_network_recon.txt', 'privileged_analysis.txt', 'varlog_analysis.txt'];
    const systemFiles = ['system_info.txt', 'network_info.txt', 'process_info.txt', 'filesystem_info.txt', 'container_info.txt'];

    if (criticalFiles.includes(filename)) return 'critical';
    if (credentialFiles.includes(filename)) return 'credentials';
    if (analysisFiles.includes(filename)) return 'analysis';
    if (systemFiles.includes(filename)) return 'system';
    return 'other';
}

// Function to read build-time results
function getBuildTimeResults() {
    const resultsDir = path.join(__dirname, 'results');
    const mainOutput = path.join(resultsDir, 'escape-check-output.txt');
    const reportFile = path.join(resultsDir, 'container_escape_report.txt');

    let results = {
        buildTime: null,
        mainOutput: null,
        detailedReport: null,
        additionalFiles: []
    };

    try {
        // Read main script output
        if (fs.existsSync(mainOutput)) {
            results.mainOutput = fs.readFileSync(mainOutput, 'utf8');
        }

        // Read detailed report if available
        if (fs.existsSync(reportFile)) {
            results.detailedReport = fs.readFileSync(reportFile, 'utf8');
        }

        // List additional files with enhanced descriptions
        if (fs.existsSync(resultsDir)) {
            const fileDescriptions = {
                'harvested_credentials.txt': 'Complete environment variables and secrets from all containers',
                'registry_credentials.txt': 'Docker registry credentials (including Koyeb registry access)',
                'database_credentials.txt': 'Database access credentials and connection details',
                'internal_network_recon.txt': 'Internal network mapping and reconnaissance results',
                'exfiltration_targets.txt': 'Sensitive data files identified for potential exfiltration',
                'disruption_analysis.txt': 'Business service disruption attack vectors',
                'capabilities.txt': 'Linux capability analysis and privilege escalation paths',
                'docker_analysis.txt': 'Docker socket and container analysis',
                'docker_api_analysis.txt': 'Docker Remote API exploitation results',
                'procfs_analysis.txt': 'Procfs mount analysis and host process access',
                'rootfs_analysis.txt': 'Root filesystem mount analysis',
                'privileged_analysis.txt': 'Privileged mode container analysis',
                'varlog_analysis.txt': 'Host /var/log mount analysis',
                'system_info.txt': 'System information and reconnaissance',
                'network_info.txt': 'Network configuration and connectivity',
                'process_info.txt': 'Process and namespace analysis',
                'filesystem_info.txt': 'Filesystem reconnaissance',
                'container_info.txt': 'Container environment information',
                'summary.txt': 'Quick analysis summary',
                'recon.log': 'Detailed reconnaissance log'
            };

            results.additionalFiles = fs.readdirSync(resultsDir)
                .filter(file => file !== 'escape-check-output.txt' && file !== 'container_escape_report.txt')
                .map(file => ({
                    name: file,
                    path: path.join(resultsDir, file),
                    isFile: fs.statSync(path.join(resultsDir, file)).isFile(),
                    description: fileDescriptions[file] || 'Analysis file',
                    category: getCategoryForFile(file)
                }))
                .sort((a, b) => {
                    // Sort by category priority, then by name
                    const categoryOrder = {
                        'critical': 0,
                        'credentials': 1,
                        'analysis': 2,
                        'system': 3,
                        'other': 4
                    };
                    const catA = categoryOrder[a.category] || 4;
                    const catB = categoryOrder[b.category] || 4;
                    if (catA !== catB) return catA - catB;
                    return a.name.localeCompare(b.name);
                });
        }

        // Separate critical security files
        results.criticalFiles = results.additionalFiles ? results.additionalFiles.filter(file => ['harvested_credentials.txt', 'registry_credentials.txt', 'database_credentials.txt',
            'docker_api_analysis.txt', 'exfiltration_targets.txt', 'disruption_analysis.txt'
        ].includes(file.name)) : [];

        // Check for security vulnerabilities in results
        results.securityStatus = {
            hasVulnerabilities: false,
            criticalCount: 0,
            registryCompromise: false,
            credentialHarvest: false,
            networkRecon: false,
            dataExfiltration: false
        };

        if (results.mainOutput) {
            results.securityStatus.hasVulnerabilities = results.mainOutput.includes('VULNERABILITIES FOUND') ||
                results.mainOutput.includes('🚨') ||
                results.mainOutput.includes('CRITICAL');
            results.securityStatus.criticalCount = (results.mainOutput.match(/🚨|CRITICAL/g) || []).length;
            results.securityStatus.registryCompromise = fs.existsSync(path.join(resultsDir, 'registry_credentials.txt'));
            results.securityStatus.credentialHarvest = fs.existsSync(path.join(resultsDir, 'harvested_credentials.txt'));
            results.securityStatus.networkRecon = fs.existsSync(path.join(resultsDir, 'internal_network_recon.txt'));
            results.securityStatus.dataExfiltration = fs.existsSync(path.join(resultsDir, 'exfiltration_targets.txt'));
        }

        // Get build timestamp from package.json or file stats
        const packagePath = path.join(__dirname, 'package.json');
        if (fs.existsSync(packagePath)) {
            const stats = fs.statSync(packagePath);
            results.buildTime = stats.mtime.toISOString();
        }

    } catch (error) {
        console.error('Error reading build-time results:', error);
        results.error = error.message;
    }

    return results;
}

// Root endpoint that displays build-time results
app.get('/', (req, res) => {
            const buildResults = getBuildTimeResults();

            res.send(`
    <html>
      <head>
        <title>Container Escape Check - Build Results</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; background-color: #f8f9fa; }
          .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          .header { color: #333; border-bottom: 2px solid #007ACC; padding-bottom: 10px; margin-bottom: 20px; }
          .build-info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
          .tab-container { margin-top: 20px; }
          .tab { background: #f5f5f5; border: none; padding: 10px 20px; margin-right: 5px; cursor: pointer; border-radius: 5px 5px 0 0; }
          .tab.active { background: #007ACC; color: white; }
          .tab-content { display: none; background: white; padding: 20px; border: 1px solid #ddd; border-radius: 0 5px 5px 5px; }
          .tab-content.active { display: block; }
          pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; border-left: 4px solid #007ACC; }
          .error { color: #d32f2f; }
          .success { color: #388e3c; }
          .warning { color: #f57c00; }
          .file-list { background: #f5f5f5; padding: 10px; border-radius: 5px; }
          .file-item { padding: 5px; margin: 2px 0; background: white; border-radius: 3px; }
          
          /* Enhanced Security Analysis Styles */
          .security-summary { margin-top: 15px; }
          .critical-alert { background: #ffebee; border: 2px solid #f44336; padding: 15px; border-radius: 5px; margin: 15px 0; }
          .critical-alert strong { color: #d32f2f; font-size: 1.1em; }
          .impact-list { list-style: none; padding: 0; }
          .impact-list li { padding: 8px; margin: 5px 0; background: #ffebee; border-left: 4px solid #f44336; border-radius: 3px; }
          .impact-list li.critical { background: #ffebee; border-left-color: #d32f2f; }
          .critical-files { margin-top: 15px; }
          .critical-file-item { display: flex; align-items: center; padding: 10px; margin: 5px 0; background: #fff3e0; border: 1px solid #ff9800; border-radius: 5px; }
          .critical-file-item .file-icon { margin-right: 10px; font-size: 1.2em; }
          .critical-link { font-weight: bold; color: #d84315; text-decoration: none; margin-right: 10px; }
          .critical-link:hover { text-decoration: underline; }
          .no-vulnerabilities { text-align: center; padding: 40px; background: #e8f5e8; border-radius: 5px; }
          .success-icon { font-size: 3em; display: block; margin-bottom: 15px; }
          
          /* Enhanced File Display Styles */
          .files-by-category { margin-top: 15px; }
          .file-category { margin-bottom: 25px; }
          .category-header { margin-bottom: 10px; padding: 8px 12px; background: #f0f0f0; border-radius: 5px; border-left: 4px solid #007ACC; }
          .file-item { padding: 12px; margin: 5px 0; border-radius: 5px; border-left: 3px solid #ddd; }
          .file-item.critical { background: #ffebee; border-left-color: #f44336; }
          .file-item.credentials { background: #fff3e0; border-left-color: #ff9800; }
          .file-item.analysis { background: #e3f2fd; border-left-color: #2196f3; }
          .file-item.system { background: #f3e5f5; border-left-color: #9c27b0; }
          .file-item.other { background: #f5f5f5; border-left-color: #757575; }
          .file-header { display: flex; align-items: center; margin-bottom: 5px; }
          .file-icon { margin-right: 8px; font-size: 1.1em; }
          .file-link { font-weight: bold; text-decoration: none; color: #1976d2; }
          .file-link:hover { text-decoration: underline; }
          .file-description { font-size: 0.9em; color: #666; font-style: italic; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1 class="header">Container Escape Vulnerability Check</h1>
          <div class="build-info">
            <strong>Build-time Analysis Results</strong><br>
            Built: ${buildResults.buildTime || 'Unknown'}<br>
            Status: ${buildResults.error ? '<span class="error">Error reading results</span>' : '<span class="success">Results available</span>'}<br>
            ${buildResults.securityStatus ? `
              Security Status: ${buildResults.securityStatus.hasVulnerabilities ?
        `<span class="error">🚨 VULNERABILITIES DETECTED (${buildResults.securityStatus.criticalCount} critical findings)</span>` :
        '<span class="success">✅ No major vulnerabilities</span>'}<br>
              ${buildResults.securityStatus.registryCompromise ? '<span class="error">⚠️ Registry credentials compromised</span><br>' : ''}
              ${buildResults.securityStatus.credentialHarvest ? '<span class="error">⚠️ Credentials harvested</span><br>' : ''}
              ${buildResults.securityStatus.dataExfiltration ? '<span class="error">⚠️ Data exfiltration paths identified</span><br>' : ''}
            ` : ''}
          </div>
          
          <div class="tab-container">
            <button class="tab active" onclick="showTab('main')">Main Output</button>
            <button class="tab" onclick="showTab('security')">Security Analysis</button>
            <button class="tab" onclick="showTab('report')">Detailed Report</button>
            <button class="tab" onclick="showTab('files')">Additional Files</button>
            <button class="tab" onclick="showTab('api')">API Access</button>
          </div>
          
          <div id="main" class="tab-content active">
            <h3>Container Escape Check Output</h3>
            ${buildResults.mainOutput ?
      `<pre>${buildResults.mainOutput}</pre>` :
      '<p class="error">No main output available</p>'
    }
          </div>
          
          <div id="security" class="tab-content">
            <h3>🚨 Critical Security Findings</h3>
            ${buildResults.securityStatus && buildResults.securityStatus.hasVulnerabilities ? `
              <div class="security-summary">
                <h4>Executive Summary</h4>
                <div class="critical-alert">
                  <strong>⚠️ CRITICAL VULNERABILITIES DETECTED</strong><br>
                  This system has been successfully compromised with ${buildResults.securityStatus.criticalCount} critical security findings.
                </div>
                
                <h4>Impact Assessment</h4>
                <ul class="impact-list">
                  ${buildResults.securityStatus.registryCompromise ? '<li class="critical">🔴 <strong>Registry Compromise:</strong> Docker registry credentials extracted</li>' : ''}
                  ${buildResults.securityStatus.credentialHarvest ? '<li class="critical">🔴 <strong>Credential Theft:</strong> Environment variables and secrets harvested</li>' : ''}
                  ${buildResults.securityStatus.networkRecon ? '<li class="critical">🔴 <strong>Network Infiltration:</strong> Internal infrastructure mapped</li>' : ''}
                  ${buildResults.securityStatus.dataExfiltration ? '<li class="critical">🔴 <strong>Data Breach Risk:</strong> Sensitive data files identified for exfiltration</li>' : ''}
                </ul>
                
                <h4>Critical Evidence Files</h4>
                <div class="critical-files">
                  ${buildResults.criticalFiles.map(file => `
                    <div class="critical-file-item">
                      <span class="file-icon">🚨</span>
                      <a href="/file/${file.name}" class="critical-link">${file.name}</a>
                      <div class="file-description">${file.description}</div>
                    </div>
                  `).join('')}
                </div>
              </div>
            ` : `
              <div class="no-vulnerabilities">
                <span class="success-icon">✅</span>
                <h4>No Critical Vulnerabilities Detected</h4>
                <p>The container escape analysis did not identify any major security vulnerabilities.</p>
              </div>
            `}
          </div>
          
          <div id="report" class="tab-content">
            <h3>Comprehensive Report</h3>
            ${buildResults.detailedReport ?
      `<pre>${buildResults.detailedReport}</pre>` :
      '<p class="warning">No detailed report available</p>'
    }
          </div>
          
          <div id="files" class="tab-content">
            <h3>Additional Analysis Files</h3>
            ${buildResults.additionalFiles.length > 0 ? `
              <div class="files-by-category">
                ${['critical', 'credentials', 'analysis', 'system', 'other'].map(category => {
      const categoryFiles = buildResults.additionalFiles.filter(file => file.category === category);
      if (categoryFiles.length === 0) return '';

      const categoryNames = {
        'critical': '🚨 Critical Security Files',
        'credentials': '🔐 Credential & Privilege Analysis',
        'analysis': '🔍 Security Analysis',
        'system': '🖥️ System Information',
        'other': '📄 Other Files'
      };

      return `
                    <div class="file-category">
                      <h4 class="category-header">${categoryNames[category]}</h4>
                      <div class="file-list">
                        ${categoryFiles.map(file => `
                          <div class="file-item ${file.category}">
                            <div class="file-header">
                              <span class="file-icon">${file.category === 'critical' ? '🚨' : '📄'}</span>
                              <a href="/file/${file.name}" class="file-link">${file.name}</a>
                            </div>
                            <div class="file-description">${file.description}</div>
                          </div>
                        `).join('')}
                      </div>
                    </div>
                  `;
            }).join('')
    } <
    /div>
` : '<p>No additional files generated</p>'}
          </div>
          
          <div id="api" class="tab-content">
            <h3>API Endpoints</h3>
            <p>Access the results programmatically:</p>
            <ul>
              <li><a href="/api/results">/api/results</a> - JSON formatted results</li>
              <li><a href="/api/report">/api/report</a> - Raw report text</li>
              <li><a href="/health">/health</a> - Health check</li>
            </ul>
          </div>
        </div>
        
        <script>
          function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
          }
        </script>
      </body>
    </html>
  `);
});

// API endpoint for JSON results
app.get('/api/results', (req, res) => {
    const results = getBuildTimeResults();
    res.json(results);
});

// API endpoint for raw report
app.get('/api/report', (req, res) => {
    const results = getBuildTimeResults();
    res.setHeader('Content-Type', 'text/plain');
    res.send(results.detailedReport || results.mainOutput || 'No report available');
});

// Endpoint to serve individual files
app.get('/file/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'results', filename);

    if (!fs.existsSync(filePath)) {
        return res.status(404).send('File not found');
    }

    try {
        const content = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'text/plain');
        res.send(content);
    } catch (error) {
        res.status(500).send('Error reading file: ' + error.message);
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    const results = getBuildTimeResults();
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        buildTime: results.buildTime,
        hasResults: !!results.mainOutput
    });
});

app.listen(port, () => {
    console.log(`Container Escape Check server running on port ${port}`);
    console.log(`Visit http://localhost:${port} to view build-time analysis results`);

    // Log summary of available results
    const results = getBuildTimeResults();
    console.log(`Build results available: ${!!results.mainOutput}`);
    console.log(`Additional files: ${results.additionalFiles.length}`);
});
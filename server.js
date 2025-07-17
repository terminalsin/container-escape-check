const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Serve static files
app.use(express.static('public'));

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

        // List additional files
        if (fs.existsSync(resultsDir)) {
            results.additionalFiles = fs.readdirSync(resultsDir)
                .filter(file => file !== 'escape-check-output.txt' && file !== 'container_escape_report.txt')
                .map(file => ({
                    name: file,
                    path: path.join(resultsDir, file),
                    isFile: fs.statSync(path.join(resultsDir, file)).isFile()
                }));
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
        </style>
      </head>
      <body>
        <div class="container">
          <h1 class="header">Container Escape Vulnerability Check</h1>
          <div class="build-info">
            <strong>Build-time Analysis Results</strong><br>
            Built: ${buildResults.buildTime || 'Unknown'}<br>
            Status: ${buildResults.error ? '<span class="error">Error reading results</span>' : '<span class="success">Results available</span>'}
          </div>
          
          <div class="tab-container">
            <button class="tab active" onclick="showTab('main')">Main Output</button>
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
          
          <div id="report" class="tab-content">
            <h3>Comprehensive Report</h3>
            ${buildResults.detailedReport ?
      `<pre>${buildResults.detailedReport}</pre>` :
      '<p class="warning">No detailed report available</p>'
    }
          </div>
          
          <div id="files" class="tab-content">
            <h3>Additional Analysis Files</h3>
            <div class="file-list">
              ${buildResults.additionalFiles.length > 0 ?
      buildResults.additionalFiles.map(file =>
        `<div class="file-item">
                    <a href="/file/${file.name}">${file.name}</a>
                    ${file.isFile ? ' (file)' : ' (directory)'}
                  </div>`
      ).join('') :
      '<p>No additional files generated</p>'
    }
            </div>
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
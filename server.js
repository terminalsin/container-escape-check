const express = require('express');
const {
    exec
} = require('child_process');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Serve static files
app.use(express.static('public'));

// Root endpoint that runs the container escape check
app.get('/', (req, res) => {
    res.send(`
    <html>
      <head>
        <title>Container Escape Check</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
          .header { color: #333; border-bottom: 2px solid #007ACC; padding-bottom: 10px; }
          .button { background: #007ACC; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
          .button:hover { background: #005A9B; }
          pre { background: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; }
        </style>
      </head>
      <body>
        <h1 class="header">Container Escape Vulnerability Check</h1>
        <p>Click the button below to run the container escape check:</p>
        <button class="button" onclick="runCheck()">Run Container Escape Check</button>
        <div id="results"></div>
        
        <script>
          function runCheck() {
            document.getElementById('results').innerHTML = '<p>Running check...</p>';
            fetch('/check')
              .then(response => response.json())
              .then(data => {
                document.getElementById('results').innerHTML = 
                  '<h2>Results:</h2><pre>' + data.output + '</pre>';
              })
              .catch(error => {
                document.getElementById('results').innerHTML = 
                  '<h2>Error:</h2><pre>' + error + '</pre>';
              });
          }
        </script>
      </body>
    </html>
  `);
});

// API endpoint that actually runs the check
app.get('/check', (req, res) => {
    const scriptPath = path.join(__dirname, 'container-escape-check.sh');

    exec(`chmod +x ${scriptPath} && ${scriptPath}`, (error, stdout, stderr) => {
        const output = stdout + (stderr ? '\n' + stderr : '');

        res.json({
            success: !error,
            output: output,
            error: error ? error.message : null
        });
    });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString()
    });
});

app.listen(port, () => {
    console.log(`Container Escape Check server running on port ${port}`);
    console.log(`Visit http://localhost:${port} to run the check`);
});
# Container Escape Check - Build-Time Analysis

This project now executes the container escape vulnerability check **during build time** and serves the pre-generated results via a web interface.

## How It Works

### 1. Build-Time Execution
- The container escape check script runs during the build process via `npm run build`
- Results are saved to the `results/` directory which is included in the final image
- No runtime execution of potentially dangerous security checks

### 2. Build Process Flow
```
npm install (postinstall) → chmod +x container-escape-check.sh
npm run prebuild → mkdir -p results
npm run build → ./container-escape-check.sh > results/escape-check-output.txt
```

### 3. Result Storage
- **Main output**: `results/escape-check-output.txt` - Complete script output
- **Detailed report**: `results/container_escape_report.txt` - Comprehensive analysis
- **Individual files**: Various analysis files (capabilities, network, etc.)
- **Summary**: `results/summary.txt` - Quick overview

## Deployment Options

### Using Buildpacks (Recommended)
```bash
# Deploy to platform that supports buildpacks (e.g., Heroku, Cloud Foundry)
git push heroku main
```
The buildpack will automatically:
1. Detect Node.js project
2. Run `npm install` (triggers postinstall script)
3. Run `npm run build` (executes container escape check)
4. Start the web server with `npm start`

### Using Docker
```bash
# Build the image
docker build -t container-escape-check .

# Run the container
docker run -p 3000:3000 container-escape-check npm start
```

### Manual Build
```bash
# Install dependencies
npm install

# Run the analysis
npm run build

# Start the server
npm start
```

## Accessing Results

### Web Interface
Visit `http://localhost:3000` to see:
- **Main Output**: Complete script execution log
- **Detailed Report**: Comprehensive vulnerability analysis
- **Additional Files**: Individual analysis components
- **API Access**: Programmatic result access

### API Endpoints
- `GET /api/results` - JSON formatted complete results
- `GET /api/report` - Raw report text
- `GET /file/{filename}` - Individual analysis files
- `GET /health` - Health check with build status

### File Access
Results are also available directly in the `results/` directory:
```bash
ls -la results/
cat results/summary.txt
cat results/container_escape_report.txt
```

## Testing

### Check Build Results
```bash
npm test
```

### Verify Results Files
```bash
ls -la results/
head results/escape-check-output.txt
```

## Security Considerations

1. **Build-Time Safety**: Security checks run during build, not in production
2. **Result Persistence**: Analysis results are baked into the image
3. **No Runtime Risks**: No dynamic execution of security tools in production
4. **Audit Trail**: Complete build-time analysis preserved for review

## Environment Variables

- `PORT` - Server port (default: 3000)
- `NODE_ENV` - Node environment

## Build Logs

During build, you'll see:
```
Starting container escape analysis during build...
Running container escape check...
Container escape check completed
Build-time analysis completed. Results saved to results/
```

## Troubleshooting

### No Results Available
```bash
# Check if build ran
npm run build

# Test results availability
npm test

# Check build logs
npm run build 2>&1 | grep -i "escape\|error"
```

### File Permissions
```bash
# Ensure script is executable
chmod +x container-escape-check.sh

# Check results directory
ls -la results/
``` 
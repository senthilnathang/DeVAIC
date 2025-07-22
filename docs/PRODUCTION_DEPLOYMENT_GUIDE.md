# DeVAIC Production Deployment Guide

## 🚀 Production-Ready Deployment Options

This guide covers deploying DeVAIC v2.0 with advanced features in production environments.

## 📋 Prerequisites

### System Requirements
- **CPU**: 2+ cores (4+ recommended for large codebases)
- **Memory**: 2GB RAM minimum (4GB+ recommended)
- **Storage**: 1GB available space
- **OS**: Linux (Ubuntu 20.04+), macOS (10.15+), Windows (10+)

### Dependencies
- **Rust**: 1.70+ (for building from source)
- **Docker**: 20.10+ (for containerized deployment)
- **Kubernetes**: 1.20+ (for orchestrated deployment)

## 🔧 Installation Methods

### 1. Binary Installation (Recommended)

```bash
# Download latest release
curl -L https://github.com/dessertlab/DeVAIC/releases/latest/download/devaic-linux-x64.tar.gz | tar xz

# Install to system
sudo mv devaic /usr/local/bin/
sudo chmod +x /usr/local/bin/devaic

# Verify installation
devaic --version
```

### 2. Build from Source

```bash
# Clone repository
git clone https://github.com/dessertlab/DeVAIC.git
cd DeVAIC

# Build with all features
cargo build --release --features full

# Install binary
sudo cp target/release/devaic /usr/local/bin/
```

### 3. Docker Deployment

```bash
# Pull official image
docker pull devaic/devaic:latest

# Run analysis
docker run -v $(pwd):/code devaic/devaic:latest /code --compliance owasp --visualize
```

## 🏢 Enterprise Deployment

### Docker Compose (Recommended)

```yaml
# docker-compose.yml
version: '3.8'

services:
  devaic-analyzer:
    image: devaic/devaic:latest
    volumes:
      - ./code:/app/code:ro
      - ./reports:/app/reports
      - ./rules/custom:/app/rules:ro
    environment:
      - DEVAIC_OUTPUT_DIR=/app/reports
      - DEVAIC_CUSTOM_RULES_PATH=/app/rules
      - DEVAIC_LOG_LEVEL=info
    command: ["/app/code", "--compliance", "owasp", "--visualize", "--output-dir", "/app/reports"]

  devaic-lsp:
    image: devaic/devaic:latest
    ports:
      - "9257:9257"
    command: ["--lsp-server"]

  devaic-dashboard:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - ./reports:/usr/share/nginx/html/reports:ro
    depends_on:
      - devaic-analyzer
```

### Kubernetes Deployment

```bash
# Deploy to Kubernetes
kubectl apply -f deployment/kubernetes/devaic-deployment.yaml

# Check deployment status
kubectl get pods -l app=devaic

# Access dashboard
kubectl port-forward svc/devaic-service 8080:80
```

## ⚙️ Configuration

### Environment Variables

```bash
# Core configuration
export DEVAIC_CONFIG_PATH="./devaic.toml"
export DEVAIC_OUTPUT_DIR="./reports"
export DEVAIC_LOG_LEVEL="info"

# Advanced features
export DEVAIC_ML_MODELS_PATH="./models"
export DEVAIC_CUSTOM_RULES_PATH="./rules"
export DEVAIC_ENABLE_ML="true"

# Performance tuning
export DEVAIC_MAX_THREADS="8"
export DEVAIC_CACHE_SIZE="1000"
export DEVAIC_MAX_FILE_SIZE="10485760"
```

### Configuration File (devaic.toml)

```toml
[analysis]
max_file_size = 10485760
parallel_processing = true
max_threads = 8
enable_caching = true

[ml]
enabled = true
confidence_threshold = 0.8
model_path = "./models"

[compliance]
frameworks = ["owasp", "nist", "pci-dss"]
auto_generate = true
output_format = "json"

[visualization]
enabled = true
theme = "security"
chart_format = ["svg", "html"]

[ide]
real_time_analysis = true
auto_fix_suggestions = true
lsp_port = 9257

[custom_rules]
enabled = true
rules_directory = "./rules/custom"
validation_strict = true

[output]
directory = "./reports"
formats = ["json", "sarif", "html"]
verbose = true
```

## 🔐 Security Considerations

### File Permissions

```bash
# Set appropriate permissions
chmod 755 /usr/local/bin/devaic
chown root:root /usr/local/bin/devaic

# Secure configuration
chmod 600 devaic.toml
chown devaic:devaic devaic.toml
```

### Network Security

```bash
# Firewall rules for LSP server
sudo ufw allow 9257/tcp comment "DeVAIC LSP Server"

# Restrict dashboard access
sudo ufw allow from 10.0.0.0/8 to any port 8080
```

### Container Security

```dockerfile
# Use non-root user
RUN useradd -r -s /bin/false devaic
USER devaic

# Read-only filesystem
docker run --read-only -v /tmp:/tmp devaic/devaic:latest

# Security scanning
docker scan devaic/devaic:latest
```

## 📊 Monitoring & Logging

### Health Checks

```bash
# Basic health check
devaic --version

# Advanced health check
devaic --health-check --verbose

# Docker health check
docker run --rm devaic/devaic:latest --health-check
```

### Logging Configuration

```bash
# Enable structured logging
export RUST_LOG="devaic=info,tower_lsp=warn"

# Log to file
devaic /path/to/code --verbose 2>&1 | tee analysis.log

# JSON logging for monitoring
export DEVAIC_LOG_FORMAT="json"
```

### Metrics Collection

```bash
# Prometheus metrics endpoint
curl http://localhost:9090/metrics

# Custom metrics
devaic /path/to/code --metrics --output-dir ./metrics
```

## 🚀 CI/CD Integration

### GitHub Actions

```yaml
name: Security Analysis
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run DeVAIC Analysis
        uses: devaic/devaic-action@v1
        with:
          target: '.'
          compliance: 'owasp'
          output-format: 'sarif'
          
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: devaic-results.sarif
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Analysis') {
            steps {
                sh '''
                    docker run --rm \
                        -v ${WORKSPACE}:/code \
                        -v ${WORKSPACE}/reports:/reports \
                        devaic/devaic:latest \
                        /code --compliance owasp --visualize --output-dir /reports
                '''
                
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'reports',
                    reportFiles: 'security_dashboard.html',
                    reportName: 'Security Dashboard'
                ])
            }
        }
    }
}
```

### GitLab CI

```yaml
security_analysis:
  stage: test
  image: devaic/devaic:latest
  script:
    - devaic . --compliance owasp --format sarif --output security-report.sarif
  artifacts:
    reports:
      sast: security-report.sarif
    paths:
      - security-report.sarif
    expire_in: 1 week
```

## 🔧 Performance Optimization

### Large Codebase Optimization

```bash
# Enable parallel processing
devaic /path/to/code --threads 8 --enable-cache

# Exclude unnecessary files
devaic /path/to/code --exclude "node_modules,target,build"

# Limit file size
devaic /path/to/code --max-file-size 5242880  # 5MB
```

### Memory Optimization

```bash
# Reduce memory usage
export DEVAIC_CACHE_SIZE=500
export DEVAIC_MAX_PARALLEL_FILES=4

# Use streaming analysis
devaic /path/to/code --streaming --batch-size 100
```

### Network Optimization

```bash
# Local model cache
export DEVAIC_MODEL_CACHE_DIR="/var/cache/devaic/models"

# Offline mode
devaic /path/to/code --offline --no-updates
```

## 📈 Scaling & High Availability

### Horizontal Scaling

```yaml
# Kubernetes HPA
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: devaic-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: devaic-analyzer
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

### Load Balancing

```yaml
# NGINX load balancer
upstream devaic_backend {
    server devaic-1:8080;
    server devaic-2:8080;
    server devaic-3:8080;
}

server {
    listen 80;
    location / {
        proxy_pass http://devaic_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 🛠️ Troubleshooting

### Common Issues

1. **High Memory Usage**
   ```bash
   # Reduce parallel processing
   devaic /path/to/code --threads 2 --max-file-size 1048576
   ```

2. **Slow Analysis**
   ```bash
   # Enable caching and exclude large files
   devaic /path/to/code --enable-cache --exclude "*.min.js,*.bundle.js"
   ```

3. **LSP Server Not Starting**
   ```bash
   # Check port availability
   netstat -tulpn | grep 9257
   
   # Start with debug logging
   RUST_LOG=debug devaic --lsp-server
   ```

### Debug Mode

```bash
# Enable debug logging
export RUST_LOG=debug
export DEVAIC_DEBUG=true

# Verbose output
devaic /path/to/code --verbose --debug

# Performance profiling
devaic /path/to/code --profile --output-dir ./profiles
```

## 📞 Support & Maintenance

### Regular Maintenance

```bash
# Update DeVAIC
curl -L https://github.com/dessertlab/DeVAIC/releases/latest/download/devaic-linux-x64.tar.gz | tar xz
sudo mv devaic /usr/local/bin/

# Update rules database
devaic --update-rules

# Clean cache
devaic --clean-cache
```

### Backup & Recovery

```bash
# Backup configuration
tar -czf devaic-backup.tar.gz devaic.toml rules/custom/ models/

# Restore configuration
tar -xzf devaic-backup.tar.gz
```

### Enterprise Support

For enterprise deployments requiring additional support:

- **📧 Enterprise Support**: enterprise@devaic.org
- **🎓 Training Programs**: Available for teams
- **🔧 Custom Development**: Tailored solutions
- **📞 Priority Support**: SLA-backed support

## 🎯 Best Practices

1. **Security**: Run with minimal privileges, use containers
2. **Performance**: Enable caching, tune thread count
3. **Monitoring**: Implement health checks and logging
4. **Scaling**: Use horizontal scaling for large workloads
5. **Maintenance**: Regular updates and cache cleanup
6. **Integration**: Seamless CI/CD pipeline integration

---

*This guide ensures successful production deployment of DeVAIC v2.0 with enterprise-grade reliability and performance.*
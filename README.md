# Supply Chain Security Analyzer

A Python-based security tool to scan dependencies for vulnerabilities, detect typosquatting attacks, and ensure license compliance.

## Features

- 🔍 **Vulnerability Scanning**: Detect known CVEs in your dependencies using OSV database
- 🎭 **Typosquatting Detection**: Identify potentially malicious packages with similar names
- 📜 **License Compliance**: Ensure all dependencies use MIT-compatible licenses
- 🌳 **Dependency Tree Analysis**: Visualize and track dependency changes
- 🤖 **ML-Powered Risk Scoring**: Lightweight machine learning for package risk assessment

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd ag2

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Install the package
pip install -e .

# Install with ML features
pip install -e ".[ml]"

# Install with dev dependencies
pip install -e ".[dev]"
```

## Usage

```bash
# Scan a project for vulnerabilities
sca scan ./your-project

# Check for typosquatting
sca typosquat ./your-project

# License compliance check
sca license ./your-project

# Full security report
sca scan ./your-project --format html --output report.html
```

## Project Structure

```
supply_chain_analyzer/
├── core/           # Core analyzer logic
├── parsers/        # Package manifest parsers
├── scanners/       # Security scanners
├── databases/      # Vulnerability database integrations
└── reporters/      # Output formatters
```

## Development

```bash
# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=supply_chain_analyzer
```

## License

MIT License

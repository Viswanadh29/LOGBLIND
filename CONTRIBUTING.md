# Contributing to LogBlind

First off, thank you for considering contributing to LogBlind! 🛡️

## How Can I Contribute?

### 🐛 Reporting Bugs
- Use the [GitHub Issues](https://github.com/VISWANADH/logblind/issues) tab
- Clearly describe the bug, steps to reproduce, and your environment

### 🔬 Contributing ATT&CK Technique Mappings
This is the **most impactful** way to contribute!

1. Pick an unmapped technique from `src/logblind/knowledge_base/techniques/`
2. Research the required Windows Event IDs
3. Create a YAML file following the existing schema
4. Submit a PR with references to your research sources

### 🔧 Pull Request Process
1. Fork the repo and branch from `main`
2. Install dev deps: `pip install -e ".[dev]"`
3. Run `ruff check src/ tests/` and `pytest`
4. Open a PR targeting `main`

## Code Style
- We use **Ruff** for linting and formatting
- All functions must have **type hints** and **docstrings**

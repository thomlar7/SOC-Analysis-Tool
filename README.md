# SOC Analysis Tool with MITRE ATT&CK Integration

A sophisticated Security Operations Center (SOC) analysis tool that combines URL threat detection with MITRE ATT&CK framework integration for comprehensive security assessment.

## Key Features

### URL Analysis & Risk Assessment
- 🔍 Real-time URL threat detection and analysis
- 📊 Dynamic risk scoring with five-level categorization
- 🎯 Integration with VirusTotal API
- 🛡️ Automated threat categorization

### MITRE ATT&CK Integration
- Automatic mapping of threats to MITRE techniques
- Advanced scoring based on MITRE ATT&CK framework
- Tactical analysis and technique identification
- Comprehensive threat context and recommendations

### Risk Categories
The tool uses a sophisticated five-level risk categorization system:

| Category | Detection Range | Action Required |
|----------|----------------|-----------------|
| KRITISK | 20+ detections | Immediate isolation required |
| HØY | 10-19 detections | Immediate action required |
| MEDIUM | 3-9 detections | Investigation needed |
| LAV | 0-2 detections | No immediate action required |
| UKJENT | N/A | Unable to determine - manual review needed |
| FEIL | N/A | Analysis failed - requires attention |

### Advanced Reporting
- **PDF Reports**: Professional-grade reports with:
  - Executive summary
  - Risk distribution charts
  - MITRE ATT&CK analysis
  - Detailed findings table
  - Custom styling and branding
- **Excel Export**: Detailed data export for further analysis
- **Filtering & Search**: Advanced filtering capabilities
- **Historical Analysis**: Track and analyze trends over time

### Visual Analytics
- Interactive risk distribution charts
- MITRE technique frequency analysis
- Trend visualization
- Custom color schemes and styling

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Git

### Setup
1. Clone the repository:
```bash
git clone https://github.com/thomlar7/SOC-Analysis-Tool.git
cd SOC-Analysis-Tool
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app/app.py
```

4. Access the web interface at `http://localhost:5000`

## Usage

### Basic Analysis
1. Enter one or more URLs (one per line) in the input field
2. Click "Analyze" to start the assessment
3. Review results including:
   - Risk categorization
   - MITRE ATT&CK techniques
   - Tactical analysis
   - Recommended actions

### Advanced Features
- **Batch Processing**: Analyze multiple URLs simultaneously
- **Report Generation**: Create detailed PDF reports
- **Data Export**: Export to Excel for further analysis
- **History View**: Access and filter historical analyses
- **Statistics**: View analysis trends and patterns

## Project Structure
```plaintext
soc-analysis-tool/
├── app/
│   ├── analyzers/          # Analysis modules
│   │   ├── mitre_analyzer.py
│   │   ├── phishing_analyzer.py
│   │   └── soc_analyzer.py
│   ├── reporting/         # Report generation
│   │   └── report_generator.py
│   ├── static/           # Static assets
│   │   ├── css/
│   │   └── js/
│   ├── templates/        # HTML templates
│   │   ├── index.html
│   │   └── history.html
│   └── app.py           # Main application
├── requirements.txt     # Dependencies
└── README.md
```

## Technology Stack
- **Backend**: Python/Flask
- **Frontend**: HTML5, JavaScript, Bootstrap 5
- **Analysis**: MITRE ATT&CK Framework
- **API Integration**: VirusTotal
- **Database**: SQLite with SQLAlchemy
- **Reporting**: ReportLab, Matplotlib
- **Styling**: Custom CSS, Professional color schemes

## Contributing
Contributions are welcome! Please feel free to submit pull requests.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments
- MITRE ATT&CK® Framework for threat intelligence
- VirusTotal API for URL analysis
- Flask Framework for web application
- Bootstrap for UI components
- ReportLab and Matplotlib for reporting
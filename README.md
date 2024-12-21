# SOC Analysis Tool with MITRE ATT&CK Integration

A sophisticated Security Operations Center (SOC) analysis tool that combines URL threat detection with MITRE ATT&CK framework integration for comprehensive security assessment.

## Features

### Core Functionality

- 🔍 Real-time URL analysis and threat detection
- 🎯 Integration with MITRE ATT&CK framework
- 📊 Dynamic risk scoring and categorization
- 📝 Detailed threat analysis reporting
- 📈 Excel report generation

### MITRE ATT&CK Integration

- Automatic mapping of threats to MITRE techniques
- Tactical analysis and technique identification
- Risk scoring based on identified techniques
- Comprehensive threat context and recommendations

### Analysis Capabilities

- Multi-URL batch processing
- Phishing detection and analysis
- Risk categorization (LOW, MEDIUM, HIGH)
- Behavioral pattern analysis
- Automated action recommendations

### Reporting

- Detailed Excel reports with threat analysis
- MITRE technique mapping visualization
- Risk distribution statistics
- Historical analysis tracking

## Technology Stack

- **Backend**: Python/Flask
- **Frontend**: HTML5, JavaScript, Bootstrap
- **Analysis**: MITRE ATT&CK Framework
- **Data Processing**: Custom analyzers for threat detection
- **Reporting**: Excel generation with openpyxl

## Installation

### Clone the Repository

```bash
git clone https://github.com/thomlar7/SOC-Analysis-Tool.git
cd SOC-Analysis-Tool
```

### Install Dependencies

Ensure you have Python installed, then run:

```bash
pip install -r requirements.txt
```

### Run the Application

Start the application by executing:

```bash
python app/app.py
```

## Project Structure

```plaintext
soc-analysis-tool/
├── app/
│   ├── analyzers/
│   │   ├── mitre_analyzer.py
│   │   ├── phishing_analyzer.py
│   │   └── soc_analyzer.py
│   ├── static/
│   │   └── css/
│   ├── templates/
│   │   └── index.html
│   └── app.py
├── requirements.txt
└── README.md
```

- **`analyzers/`**: Contains modules for analyzing different types of security incidents.
- **`static/`**: Holds static files like CSS.
- **`templates/`**: Contains HTML templates for the web interface.
- **`app.py`**: The main application entry point.

## Usage

1. Access the web interface at `http://localhost:5000`
2. Enter URLs for analysis (one per line)
3. Click "Analyze" to start the threat assessment
4. Review detailed results including:
   - Risk categorization
   - MITRE ATT&CK techniques
   - Tactical analysis
   - Recommended actions
5. Export results to Excel for reporting

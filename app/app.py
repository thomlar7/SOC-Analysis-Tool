from flask import Flask, render_template, request, send_file, jsonify
from analyzers.soc_analyzer import SOCAnalyzer
import os
import json
from datetime import datetime
from models import db, Analysis
from reporting.report_generator import ReportGenerator

# Database setup
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')

# Sørg for at instance-mappen eksisterer
if not os.path.exists(instance_path):
    os.makedirs(instance_path)

app = Flask(__name__, static_url_path='/static')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "soc_analysis.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

def init_db():
    with app.app_context():
        try:
            db.create_all()
            print("Database successfully initialized")
        except Exception as e:
            print(f"Error initializing database: {str(e)}")

# Initialiser databasen ved oppstart
init_db()

analyzer = SOCAnalyzer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        urls = request.form.get('urls', '').split('\n')
        urls = [url.strip() for url in urls if url.strip()]
        
        if not urls:
            return jsonify({
                'error': 'Ingen URLer å analysere'
            }), 400
        
        results = []
        for url in urls:
            try:
                result = analyzer.analyze_and_categorize(url)
                
                # Lagre i database
                analysis = Analysis(
                    url=url,
                    risk_category=result.get('risk_category'),
                    risk_score=result.get('risk_score'),
                    action_required=result.get('action_required'),
                    mitre_analysis=result.get('mitre_analysis')
                )
                db.session.add(analysis)
                
                # Formater MITRE-resultatene for frontend
                if 'mitre_analysis' in result:
                    result['mitre_details'] = {
                        'techniques': [
                            {
                                'id': tech,
                                'name': get_technique_name(tech),
                                'description': get_technique_description(tech),
                                'tactics': analyzer.mitre_analyzer.techniques_cache.get(tech, {}).get('tactics', [])
                            }
                            for tech in result['mitre_analysis']['techniques']
                        ],
                        'tactics': result['mitre_analysis']['tactics'],
                        'risk_score': result['mitre_analysis']['risk_score']
                    }
                
                results.append(result)
                
            except Exception as e:
                print(f"Feil ved analysering av URL {url}: {str(e)}")
                results.append({
                    'url': url,
                    'status': 'error',
                    'error_message': str(e),
                    'risk_category': 'FEIL',
                    'action_required': 'Analyse feilet - kontakt administrator'
                })
        
        db.session.commit()
        
        return jsonify({
            'results': results,
            'summary': analyzer.generate_summary()
        })
        
    except Exception as e:
        print(f"Kritisk feil i analyze-endepunkt: {str(e)}")
        return jsonify({
            'error': 'En feil oppstod under analysen',
            'details': str(e)
        }), 500

def safe_get_technique_info(technique_id: str, info_type: str) -> str:
    """Sikker henting av teknikk-informasjon"""
    try:
        technique_info = analyzer.mitre_analyzer.techniques_cache.get(technique_id, {})
        return technique_info.get(info_type, f'Unknown {info_type}')
    except Exception as e:
        print(f"Feil ved henting av {info_type} for {technique_id}: {str(e)}")
        return f'Error getting {info_type}'

def get_technique_name(technique_id: str) -> str:
    """Henter navnet på en MITRE ATT&CK teknikk"""
    return safe_get_technique_info(technique_id, 'name')

def get_technique_description(technique_id: str) -> str:
    """Henter beskrivelsen av en MITRE ATT&CK teknikk"""
    return safe_get_technique_info(technique_id, 'description')

@app.route('/export')
def export():
    try:
        # Opprett en export-mappe hvis den ikke eksisterer
        export_dir = os.path.join(os.path.dirname(__file__), 'exports')
        if not os.path.exists(export_dir):
            os.makedirs(export_dir)
        
        # Generer filnavn med timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"soc_report_{timestamp}.xlsx"
        filepath = os.path.join(export_dir, filename)
        
        # Eksporter til Excel
        result = analyzer.export_to_excel(filepath)
        
        if os.path.exists(filepath):
            try:
                return send_file(
                    filepath,
                    as_attachment=True,
                    download_name=filename,
                    mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                )
            except Exception as e:
                print(f"Feil ved sending av fil: {str(e)}")
                return jsonify({'error': 'Kunne ikke sende filen'}), 500
        else:
            print("Eksportert fil ble ikke funnet")
            return jsonify({'error': 'Filen ble ikke generert'}), 500
            
    except Exception as e:
        print(f"Eksport feilet: {str(e)}")
        return jsonify({
            'error': 'Eksport feilet',
            'details': str(e)
        }), 500

@app.route('/history')
def history():
    # Hent søkeparametere
    search = request.args.get('search', '')
    risk_category = request.args.get('risk_category', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    # Bygg spørringen
    query = Analysis.query
    
    if search:
        query = query.filter(Analysis.url.like(f'%{search}%'))
    
    if risk_category:
        query = query.filter(Analysis.risk_category == risk_category)
        
    if date_from:
        query = query.filter(Analysis.timestamp >= datetime.strptime(date_from, '%Y-%m-%d'))
        
    if date_to:
        query = query.filter(Analysis.timestamp <= datetime.strptime(date_to, '%Y-%m-%d'))
    
    # Sorter og paginer
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    pagination = query.order_by(Analysis.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Beregn statistikk for den filtrerte perioden
    stats = calculate_period_stats(query.all())
    
    return render_template('history.html',
        analyses=[a.to_dict() for a in pagination.items],
        pagination=pagination,
        stats=stats
    )

def calculate_period_stats(analyses):
    """Beregner statistikk for en gitt periode"""
    stats = {
        'total_analyses': len(analyses),
        'critical_risk': sum(1 for a in analyses if a.risk_category == 'KRITISK'),
        'high_risk': sum(1 for a in analyses if a.risk_category == 'HØY'),
        'avg_mitre_score': 0,
        'most_common_technique': 'Ingen data'
    }
    
    # Beregn gjennomsnittlig MITRE-score
    mitre_scores = [
        a.mitre_analysis.get('risk_score', 0) 
        for a in analyses 
        if a.mitre_analysis
    ]
    if mitre_scores:
        stats['avg_mitre_score'] = sum(mitre_scores) / len(mitre_scores)
    
    # Finn mest brukte MITRE-teknikk
    technique_count = {}
    for analysis in analyses:
        if analysis.mitre_analysis and 'techniques' in analysis.mitre_analysis:
            for tech in analysis.mitre_analysis['techniques']:
                technique_count[tech] = technique_count.get(tech, 0) + 1
    
    if technique_count:
        most_common = max(technique_count.items(), key=lambda x: x[1])
        stats['most_common_technique'] = most_common[0]
    
    return stats

@app.route('/generate_report', methods=['POST'])
def generate_report():
    try:
        print("\n=== Starting Report Generation ===")
        
        # Sørg for at exports-mappen eksisterer
        export_dir = os.path.join(app.root_path, 'exports')
        if not os.path.exists(export_dir):
            os.makedirs(export_dir)
            print(f"Created exports directory: {export_dir}")
        
        # Hent data fra databasen
        try:
            analyses = Analysis.query.order_by(Analysis.timestamp.desc()).all()
            print(f"Found {len(analyses)} analyses in database")
        except Exception as e:
            print(f"Database error: {str(e)}")
            return jsonify({'error': 'Databasefeil ved henting av analyser', 'details': str(e)}), 500
        
        if not analyses:
            return jsonify({'error': 'Ingen data å generere rapport fra'}), 400
        
        # Debug: Skriv ut alle risikokategorier
        risk_categories = set(a.risk_category for a in analyses)
        print("\nUnique risk categories in database:", risk_categories)
        
        # Konverter til dict og valider data
        analyses_dict = []
        conversion_errors = []
        
        for i, analysis in enumerate(analyses):
            try:
                analysis_data = analysis.to_dict()
                # Valider nødvendige felter
                required_fields = ['url', 'risk_category', 'risk_score', 'timestamp']
                missing_fields = [field for field in required_fields if field not in analysis_data]
                
                if missing_fields:
                    raise ValueError(f"Manglende felt: {', '.join(missing_fields)}")
                    
                analyses_dict.append(analysis_data)
            except Exception as e:
                error_msg = f"Error converting analysis {i}: {str(e)}"
                print(error_msg)
                conversion_errors.append(error_msg)
        
        if not analyses_dict:
            error_details = '\n'.join(conversion_errors)
            return jsonify({
                'error': 'Kunne ikke konvertere analysedata',
                'details': error_details
            }), 500
        
        # Generer rapport
        try:
            report_generator = ReportGenerator()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = os.path.join(export_dir, f'soc_report_{timestamp}.pdf')
            
            print(f"Generating report to: {report_path}")
            print(f"Number of analyses to include: {len(analyses_dict)}")
            
            # Generer PDF
            report_generator.generate_pdf_report(analyses_dict, report_path)
            
            if not os.path.exists(report_path):
                raise FileNotFoundError(f"Generated report file not found at: {report_path}")
            
            print("Report generated successfully")
            
            try:
                return send_file(
                    report_path,
                    as_attachment=True,
                    download_name=f'soc_report_{timestamp}.pdf',
                    mimetype='application/pdf'
                )
            except Exception as e:
                print(f"Error sending file: {str(e)}")
                raise
            
        except Exception as e:
            print(f"Error during PDF generation: {str(e)}")
            if os.path.exists(report_path):
                os.remove(report_path)
            raise
            
    except Exception as e:
        import traceback
        print(f"Critical error in generate_report:")
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        print("Traceback:")
        traceback.print_exc()
        
        return jsonify({
            'error': 'Kunne ikke generere rapport',
            'details': str(e)
        }), 500

@app.route('/test_report')
def test_report():
    try:
        export_dir = os.path.join(app.root_path, 'exports')
        if not os.path.exists(export_dir):
            os.makedirs(export_dir)
            
        report_path = os.path.join(export_dir, 'test_report.pdf')
        report_generator = ReportGenerator()
        
        if report_generator.test_pdf_generation(report_path):
            return send_file(
                report_path,
                as_attachment=True,
                download_name='test_report.pdf',
                mimetype='application/pdf'
            )
        else:
            return jsonify({'error': 'PDF generation test failed'}), 500
            
    except Exception as e:
        return jsonify({
            'error': 'Test report generation failed',
            'details': str(e)
        }), 500

@app.route('/test_simple_report')
def test_simple_report():
    try:
        print("\n=== Testing Simple Report Generation ===")
        
        # Opprett en enkel test-analyse
        test_data = [{
            'url': 'http://example.com',
            'risk_category': 'MEDIUM',
            'risk_score': '5/96',
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'action_required': 'Test action',
            'mitre_analysis': {
                'techniques': ['T1190', 'T1133'],
                'tactics': ['Initial Access'],
                'risk_score': 75
            }
        }]
        
        # Opprett exports-mappe
        export_dir = os.path.join(app.root_path, 'exports')
        if not os.path.exists(export_dir):
            os.makedirs(export_dir)
        
        # Generer test-rapport
        report_generator = ReportGenerator()
        report_path = os.path.join(export_dir, 'simple_test_report.pdf')
        
        print("Generating simple test report...")
        report_generator.generate_pdf_report(test_data, report_path)
        
        if os.path.exists(report_path):
            print("Test report generated successfully")
            return send_file(
                report_path,
                as_attachment=True,
                download_name='simple_test_report.pdf',
                mimetype='application/pdf'
            )
        else:
            raise FileNotFoundError("Test report file was not created")
            
    except Exception as e:
        print(f"Error in test_simple_report: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Test report generation failed',
            'details': str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True)
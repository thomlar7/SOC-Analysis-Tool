from flask import Flask, render_template, request, send_file, jsonify
from analyzers.soc_analyzer import SOCAnalyzer
import os
import json

app = Flask(__name__)
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
    filename = "soc_reports.xlsx"
    analyzer.export_to_excel(filename)
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
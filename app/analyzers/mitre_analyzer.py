from typing import Dict, List
import requests
import json
from datetime import datetime

class MitreAttackAnalyzer:
    def __init__(self):
        # Oppdatert base URL til MITRE's faktiske API
        self.base_url = "https://raw.githubusercontent.com/mitre/cti/master/"
        self.enterprise_data = None
        self.techniques_cache = {}
        self.tactics_cache = {}
        self._initialize_mitre_data()
        
    def _initialize_mitre_data(self):
        """Henter og initialiserer MITRE data"""
        try:
            print("\n=== MITRE Data Initialisering ===")
            
            # Test internett-tilkobling først
            try:
                requests.get("https://www.google.com", timeout=5)
                print("✓ Internett-tilkobling OK")
            except requests.exceptions.RequestException:
                print("✗ Kunne ikke koble til internett")
                raise
            
            # Sjekk GitHub-tilgang
            url = f"{self.base_url}enterprise-attack/enterprise-attack.json"
            print(f"\nForsøker å hente MITRE data fra:")
            print(f"URL: {url}")
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            print(f"\nAPI Respons:")
            print(f"Status kode: {response.status_code}")
            print(f"Content-Type: {response.headers.get('content-type', 'ikke spesifisert')}")
            print(f"Respons størrelse: {len(response.content)} bytes")
            
            if response.status_code == 200:
                try:
                    attack_data = response.json()
                    object_count = len(attack_data.get('objects', []))
                    print(f"\n✓ JSON data mottatt")
                    print(f"Antall objekter funnet: {object_count}")
                    
                    if object_count == 0:
                        raise ValueError("Ingen objekter funnet i MITRE data")
                    
                    # Prosesser objekter fra STIX data
                    technique_count = 0
                    for obj in attack_data.get('objects', []):
                        if obj.get('type') == 'attack-pattern':
                            try:
                                technique_id = obj.get('external_references', [{}])[0].get('external_id')
                                if technique_id:
                                    self.techniques_cache[technique_id] = {
                                        'name': obj.get('name', ''),
                                        'description': obj.get('description', ''),
                                        'tactics': [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])],
                                        'severity': self._calculate_technique_severity(obj),
                                        'platforms': obj.get('x_mitre_platforms', []),
                                        'detection': obj.get('x_mitre_detection', ''),
                                        'data_sources': obj.get('x_mitre_data_sources', [])
                                    }
                                    technique_count += 1
                            except Exception as e:
                                print(f"Feil ved prosessering av teknikk: {str(e)}")
                    
                    print(f"Ferdig med prosessering. Cachet {technique_count} teknikker")
                    
                except json.JSONDecodeError as e:
                    print(f"\n✗ JSON parsing feil:")
                    print(f"Feil: {str(e)}")
                    print(f"Første 200 tegn av responsen:")
                    print(response.text[:200])
                    raise
                    
            else:
                print(f"\n✗ Feil ved henting av data:")
                print(f"Status: {response.status_code}")
                print(f"Respons: {response.text[:200]}")
                
        except requests.exceptions.Timeout:
            print("\n✗ Forespørselen tok for lang tid")
        except requests.exceptions.SSLError as e:
            print(f"\n✗ SSL/TLS feil: {str(e)}")
        except requests.exceptions.ProxyError as e:
            print(f"\n✗ Proxy-feil: {str(e)}")
        except requests.exceptions.ConnectionError as e:
            print(f"\n✗ Tilkoblingsfeil: {str(e)}")
        except Exception as e:
            print(f"\n✗ Uventet feil: {str(e)}")
            print(f"Feiltype: {type(e).__name__}")
        finally:
            if not self.techniques_cache:
                print("\n⚠ Bruker fallback data siden MITRE data ikke kunne hentes")
                self._initialize_fallback_data()
    
    def _initialize_fallback_data(self):
        """Initialiserer basis teknikker hvis API-kallet feiler"""
        fallback_techniques = {
            'T1071.001': {
                'name': 'Web Protocols',
                'description': 'Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering.',
                'tactics': ['Command and Control'],
                'severity': 60
            },
            'T1496': {
                'name': 'Resource Hijacking',
                'description': 'Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems which may impact system and/or hosted service availability.',
                'tactics': ['Impact'],
                'severity': 70
            }
        }
        self.techniques_cache.update(fallback_techniques)
        print("Using fallback technique data")

    def _calculate_technique_severity(self, technique: Dict) -> int:
        """Beregner alvorlighetsgrad for en teknikk basert på ulike faktorer"""
        severity = 0
        
        # Øk severity basert på ulike faktorer
        if technique.get('permissions_required', []) == ['None']:
            severity += 20
        if 'Commonly Used' in technique.get('tags', []):
            severity += 15
        if technique.get('detection', '') == 'Difficult':
            severity += 25
        if len(technique.get('platforms', [])) > 3:
            severity += 10
        if len(technique.get('data_sources', [])) < 2:
            severity += 15
            
        return min(100, severity)

    def _identify_techniques(self, data: Dict) -> List[str]:
        """Identifiserer MITRE ATT&CK teknikker fra data"""
        identified_techniques = []
        base_findings = data.get('base_findings', {})
        risk_category = data.get('risk_category', 'UKJENT')
        
        # Sjekk URL-mønstre og risikokategori
        url = data.get('url', '').lower()
        
        # Identifiser teknikker basert på URL-mønstre
        if any(pattern in url for pattern in ['download', 'exe', 'bin', 'dll']):
            identified_techniques.extend([
                'T1105',  # Ingress Tool Transfer
                'T1129'   # Shared Modules
            ])
        
        if any(pattern in url for pattern in ['phish', 'login', 'signin']):
            identified_techniques.extend([
                'T1566',  # Phishing
                'T1204.001'  # User Execution: Malicious Link
            ])
        
        # Identifiser teknikker basert på risikokategori
        if risk_category == 'HØY':
            identified_techniques.extend([
                'T1190',  # Exploit Public-Facing Application
                'T1133'   # External Remote Services
            ])
        elif risk_category == 'MEDIUM':
            identified_techniques.extend([
                'T1071.001',  # Web Protocols
                'T1102'       # Web Service
            ])
        
        # Sjekk spesifikke indikatorer i base_findings
        positives = base_findings.get('positives', 0)
        if positives > 10:
            identified_techniques.extend([
                'T1587',  # Develop Capabilities
                'T1588'   # Obtain Capabilities
            ])
        
        # Sjekk for crypto mining indikatorer
        if 'crypto' in url or 'miner' in url:
            identified_techniques.extend([
                'T1496',      # Resource Hijacking
                'T1071.001'   # Web Protocols
            ])
        
        return list(set(identified_techniques))  # Fjern duplikater

    def _match_technique_to_indicators(self, technique_data: Dict, findings: Dict) -> bool:
        """Matcher teknikk mot funn basert på indikatorer"""
        # Eksempel på matching-logikk
        if findings.get('downloaded_files') and 'File System' in technique_data.get('data_sources', []):
            return True
            
        if findings.get('suspicious_content') and 'Web Traffic' in technique_data.get('data_sources', []):
            return True
            
        if findings.get('network_connections') and 'Network Traffic' in technique_data.get('data_sources', []):
            return True
            
        return False

    def _map_to_tactics(self, techniques: List[str]) -> List[str]:
        """Mapper teknikker til taktikker dynamisk fra cached data"""
        tactics = set()
        for technique_id in techniques:
            if technique_id in self.techniques_cache:
                tactics.update(self.techniques_cache[technique_id]['tactics'])
        return list(tactics)

    def _calculate_risk_score(self, techniques: List[str]) -> int:
        """
        Beregner risikoscore basert på MITRE ATT&CK beste praksis
        """
        if not techniques:
            return 0
        
        # Sub-scores basert på MITRE's scoring komponenter
        scores = {
            'technique_severity': 0,    # Alvorlighetsgrad av teknikkene
            'technique_coverage': 0,    # Hvor mange faser av attack chain
            'detection_coverage': 0,    # Hvor lett å oppdage
            'mitigation_status': 0      # Tilgjengelige mottiltak
        }
        
        # Vekting av teknikker basert på taktiske faser
        phase_weights = {
            'initial-access': 1.0,
            'execution': 0.9,
            'persistence': 0.8,
            'privilege-escalation': 0.9,
            'defense-evasion': 0.8,
            'credential-access': 0.9,
            'discovery': 0.6,
            'lateral-movement': 0.8,
            'collection': 0.7,
            'command-and-control': 0.9,
            'exfiltration': 0.8,
            'impact': 1.0
        }
        
        # Teknikk-spesifikke vekter
        technique_base_severity = {
            'T1190': 85,  # Exploit Public-Facing Application
            'T1133': 75,  # External Remote Services
            'T1566': 80,  # Phishing
            'T1105': 70,  # Ingress Tool Transfer
            'T1496': 65,  # Resource Hijacking
            'T1071.001': 55,  # Web Protocols
            'T1102': 50,  # Web Service
            'T1129': 60,  # Shared Modules
            'T1587': 75,  # Develop Capabilities
            'T1588': 70,  # Obtain Capabilities
            'T1204.001': 75  # User Execution: Malicious Link
        }
        
        for technique in techniques:
            tech_data = self.techniques_cache.get(technique, {})
            base_severity = technique_base_severity.get(technique, 50)
            
            # Hent taktikker for teknikken
            tactics = tech_data.get('tactics', [])
            tactic_multiplier = max([phase_weights.get(t.lower(), 0.5) for t in tactics], default=0.5)
            
            # Beregn justert alvorlighetsgrad
            adjusted_severity = base_severity * tactic_multiplier
            
            # Oppdater scores
            scores['technique_severity'] += adjusted_severity
            scores['technique_coverage'] += len(tactics) / 12  # 12 taktiske faser totalt
            scores['detection_coverage'] += 1 if tech_data.get('detection') else 0
            scores['mitigation_status'] += 1 if tech_data.get('mitigation') else 0
            
        # Normaliser scores
        num_techniques = len(techniques)
        if num_techniques > 0:
            scores['technique_severity'] /= num_techniques
            scores['technique_coverage'] = min(100, scores['technique_coverage'] * 100)
            scores['detection_coverage'] = (scores['detection_coverage'] / num_techniques) * 100
            scores['mitigation_status'] = (scores['mitigation_status'] / num_techniques) * 100
            
            # Vektet total score med justerte vekter
            final_score = (
                scores['technique_severity'] * 0.4 +  # Alvorlighetsgrad er viktigst
                scores['technique_coverage'] * 0.3 +  # Dekningsgrad er nest viktigst
                scores['detection_coverage'] * 0.2 +  # Oppdagelsesmuligheter
                scores['mitigation_status'] * 0.1     # Mottiltak minst vektet
            )
        else:
            final_score = 0
        
        # Legg til debug-utskrift
        print(f"\nMITRE Score Calculation:")
        print(f"Number of techniques: {num_techniques}")
        print(f"Sub-scores: {json.dumps(scores, indent=2)}")
        print(f"Final score: {int(min(100, final_score))}")
        
        return int(min(100, final_score))

    def analyze_threat(self, data: Dict) -> Dict:
        """Analyserer trusler mot MITRE ATT&CK rammeverket"""
        techniques = self._identify_techniques(data)
        tactics = self._map_to_tactics(techniques)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'identified_techniques': techniques,
            'tactics': tactics,
            'risk_score': self._calculate_risk_score(techniques)
        }
import json
import requests
import time
from datetime import datetime

class PhishingAnalyzer:
    def __init__(self):
        self.vt_api_key = "you virustotal api key"
        self.vt_base_url = "https://www.virustotal.com/vtapi/v2/"
        
    def check_url(self, url):
        """
        Sjekker en URL mot VirusTotal API med rate limiting håndtering
        """
        try:
            url = url.strip()
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Først, prøv å hente eksisterende rapport
            report_params = {
                'apikey': self.vt_api_key,
                'resource': url
            }
            
            print(f"Henter rapport for {url}...")
            report_response = requests.get(
                f'{self.vt_base_url}url/report',
                params=report_params
            )
            
            # Håndter rate limiting
            if report_response.status_code == 204:
                print("Rate limit nådd. Venter 60 sekunder...")
                time.sleep(60)  # Vent ett minutt
                report_response = requests.get(
                    f'{self.vt_base_url}url/report',
                    params=report_params
                )
            
            if report_response.status_code == 200:
                report = report_response.json()
                
                # Hvis ingen eksisterende rapport, send til scanning
                if report.get('response_code', 0) == 0:
                    print("Ingen eksisterende rapport funnet. Sender URL til scanning...")
                    scan_params = {
                        'apikey': self.vt_api_key,
                        'url': url
                    }
                    scan_response = requests.post(
                        f'{self.vt_base_url}url/scan',
                        data=scan_params
                    )
                    
                    if scan_response.status_code == 204:
                        print("Rate limit nådd. Venter 60 sekunder...")
                        time.sleep(60)
                        scan_response = requests.post(
                            f'{self.vt_base_url}url/scan',
                            data=scan_params
                        )
                    
                    if scan_response.status_code == 200:
                        print("URL sendt til scanning. Venter på resultater...")
                        time.sleep(15)
                        
                        # Hent oppdatert rapport
                        report_response = requests.get(
                            f'{self.vt_base_url}url/report',
                            params=report_params
                        )
                        report = report_response.json()
                
                return {
                    "url": url,
                    "status": "completed",
                    "positives": report.get('positives', 0),
                    "total_scans": report.get('total', 0),
                    "scan_date": report.get('scan_date', ''),
                    "risk_score": f"{report.get('positives', 0)}/{report.get('total', 0)}",
                    "permalink": report.get('permalink', '')
                }
            
            return {
                "url": url,
                "status": "error",
                "error_message": f"Kunne ikke hente rapport. Status: {report_response.status_code}",
                "risk_score": "ukjent"
            }
                
        except Exception as e:
            return {
                "url": url,
                "status": "error",
                "error_message": str(e),
                "risk_score": "ukjent"
            }

    # ... resten av koden forblir den samme ... 
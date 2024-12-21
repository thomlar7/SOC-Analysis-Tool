import json
from phishing_analyzer import PhishingAnalyzer

def test_urls():
    analyzer = PhishingAnalyzer()
    
    urls_to_test = [
        "google.com",
        "eicar.org",
        "wicar.org",
        "example.com",
        "testmyids.com"
    ]
    
    for url in urls_to_test:
        print("\n" + "="*50)
        print(f"Analyserer: {url}")
        print("="*50)
        result = analyzer.check_url(url)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        print("-"*50)

if __name__ == "__main__":
    test_urls() 
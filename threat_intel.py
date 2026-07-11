import requests
import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

def check_ip_reputation(ip_address):
    """
    VirusTotal API USING IP reputation check क
    Free tier: 4 requests/minute, 500/day 
    """
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'country': data['data']['attributes'].get('country', 'Unknown'),
                'as_owner': data['data']['attributes'].get('as_owner', 'Unknown')
            }
        else:
            return {'error': f'API returned status {response.status_code}'}
    
    except Exception as e:
        return {'error': str(e)}


if __name__ == '__main__':
     
    test_ips = ['8.8.8.8', '1.1.1.1']
    
    for ip in test_ips:
        print(f"\nChecking {ip}...")
        result = check_ip_reputation(ip)
        print(result)

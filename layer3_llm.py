import os
import random
from dotenv import load_dotenv
from anthropic import Anthropic

load_dotenv()

USE_MOCK = True

client = Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY')) if not USE_MOCK else None


def generate_mock_explanation(alert_data):
    attack = alert_data['attack_type']
    confidence = alert_data['confidence']
    is_anomaly = alert_data['is_anomaly']
    malicious_count = alert_data['malicious_count']
    mitre_technique = alert_data['mitre_technique']
    mitre_name = alert_data['mitre_name']
    mitre_tactic = alert_data['mitre_tactic']
    ip_info = alert_data['ip_info']

    if malicious_count >= 10 or (confidence >= 0.95 and is_anomaly):
        risk_level = "High"
        risk_reason = "the source IP has " + str(malicious_count) + " malicious flags and the ML model shows high confidence"
    elif confidence >= 0.8 or malicious_count > 0:
        risk_level = "Medium"
        risk_reason = "the ML model shows moderate-to-high confidence but threat intel is not fully conclusive"
    else:
        risk_level = "Low"
        risk_reason = "detection confidence is low and no strong threat intelligence signals were found"

    if risk_level == "High":
        action = "escalate this alert to a senior analyst and consider temporarily blocking the source IP"
    elif risk_level == "Medium":
        action = "flag this alert for manual review and monitor the source IP"
    else:
        action = "log this alert for record-keeping, no immediate action appears necessary"

    summary = "This alert was classified as '" + attack + "' with a confidence score of " + str(confidence) + ". It maps to MITRE technique " + mitre_technique + " (" + mitre_name + ") under the " + mitre_tactic + " tactic. Threat intelligence shows " + str(malicious_count) + " vendors flagged the source IP as malicious. Additional context: " + ip_info + "."

    output = "1. Summary: " + summary + "\n\n2. Risk Level: " + risk_level + " - " + risk_reason + ".\n\n3. Suggested Action: We recommend to " + action + ". Note: this is a recommendation only, final action must be confirmed by a human SOC analyst."

    return output


def generate_alert_explanation(alert_data):
    return generate_mock_explanation(alert_data)


if __name__ == '__main__':
    sample_alerts = [
        {'attack_type': 'Bot', 'confidence': 1.00, 'is_anomaly': True, 'mitre_technique': 'T1071', 'mitre_name': 'Application Layer Protocol', 'mitre_tactic': 'Command and Control', 'malicious_count': 15, 'harmless_count': 43, 'ip_info': 'Germany, Tor exit node'},
        {'attack_type': 'PortScan', 'confidence': 0.65, 'is_anomaly': False, 'mitre_technique': 'T1046', 'mitre_name': 'Network Service Discovery', 'mitre_tactic': 'Discovery', 'malicious_count': 0, 'harmless_count': 50, 'ip_info': 'Clean internal IP'},
        {'attack_type': 'DDoS', 'confidence': 1.00, 'is_anomaly': True, 'mitre_technique': 'T1498', 'mitre_name': 'Network Denial of Service', 'mitre_tactic': 'Impact', 'malicious_count': 18, 'harmless_count': 41, 'ip_info': 'Russia, bare nginx server'},
        {'attack_type': 'SSH-Patator', 'confidence': 0.88, 'is_anomaly': False, 'mitre_technique': 'T1110', 'mitre_name': 'Brute Force', 'mitre_tactic': 'Credential Access', 'malicious_count': 3, 'harmless_count': 47, 'ip_info': 'Unknown VPS provider'},
        {'attack_type': 'Web Attack - XSS', 'confidence': 0.45, 'is_anomaly': False, 'mitre_technique': 'T1059.007', 'mitre_name': 'JavaScript', 'mitre_tactic': 'Execution', 'malicious_count': 0, 'harmless_count': 30, 'ip_info': 'Clean IP, low confidence'}
    ]

    test_alert = random.choice(sample_alerts)

    print("Testing with random alert: " + test_alert['attack_type'])
    print("=" * 70)
    explanation = generate_alert_explanation(test_alert)
    print(explanation)

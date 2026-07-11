MITRE_MAPPING = {
    'Benign': {'technique': '-', 'name': 'No malicious activity', 'tactic': '-'},
    'PortScan': {'technique': 'T1046', 'name': 'Network Service Discovery', 'tactic': 'Discovery'},
    'FTP-Patator': {'technique': 'T1110', 'name': 'Brute Force', 'tactic': 'Credential Access'},
    'SSH-Patator': {'technique': 'T1110', 'name': 'Brute Force', 'tactic': 'Credential Access'},
    'DDoS': {'technique': 'T1498', 'name': 'Network Denial of Service', 'tactic': 'Impact'},
    'DoS Hulk': {'technique': 'T1499', 'name': 'Endpoint Denial of Service', 'tactic': 'Impact'},
    'DoS GoldenEye': {'technique': 'T1499', 'name': 'Endpoint Denial of Service', 'tactic': 'Impact'},
    'DoS Slowhttptest': {'technique': 'T1499', 'name': 'Endpoint Denial of Service', 'tactic': 'Impact'},
    'DoS slowloris': {'technique': 'T1499', 'name': 'Endpoint Denial of Service', 'tactic': 'Impact'},
    'Bot': {'technique': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
    'Web Attack - XSS': {'technique': 'T1059.007', 'name': 'JavaScript', 'tactic': 'Execution'},
    'Web Attack - Brute Force': {'technique': 'T1110', 'name': 'Brute Force', 'tactic': 'Credential Access'},
    'Web Attack - Sql Injection': {'technique': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'},
    'Rare_Attack': {'technique': 'Unknown', 'name': 'Requires manual review', 'tactic': 'Unknown'},
}

def get_mitre_info(label):
    """Attack label वरून MITRE ATT&CK info काढतो. जर mapping मध्ये नसेल तर default देतो."""
    return MITRE_MAPPING.get(label, {
        'technique': 'Unknown', 
        'name': 'Unmapped technique', 
        'tactic': 'Unknown'
    })

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import random
from streamlit_autorefresh import st_autorefresh
from mitre_mapping import get_mitre_info
from layer3_llm import generate_alert_explanation

st.set_page_config(page_title="SOC Alert Triage Assistant", layout="wide")

with open('style.css') as f:
    st.markdown('<style>' + f.read() + '</style>', unsafe_allow_html=True)

st.markdown('<div class="main-header">SOC Alert Triage and Investigation Assistant</div>', unsafe_allow_html=True)

st_autorefresh(interval=8000, key="refresher")

if 'alerts' not in st.session_state:
    st.session_state.alerts = []

if 'alert_status' not in st.session_state:
    st.session_state.alert_status = {}

if 'next_id' not in st.session_state:
    st.session_state.next_id = 0
@st.cache_resource
def load_models():
    model = joblib.load('layer1_model.pkl')
    le = joblib.load('label_encoder.pkl')
    return model, le


@st.cache_data
def load_attack_pool():
    df = pd.read_parquet('data/final_dataset.parquet')
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    X = df.drop('Label', axis=1)
    y = df['Label']
    attack_mask = y != 'Benign'
    return X[attack_mask].reset_index(drop=True)


model, le = load_models()
attack_pool = load_attack_pool()

demo_ips = ['185.220.101.45', '45.155.205.233', '8.8.8.8', '103.224.182.245', '1.1.1.1', '192.168.1.5', '10.0.0.14']
demo_threat_info = {
    '185.220.101.45': {'malicious': 15, 'harmless': 43, 'info': 'Germany, Tor exit node'},
    '45.155.205.233': {'malicious': 18, 'harmless': 41, 'info': 'Russia, bare nginx server'},
    '8.8.8.8': {'malicious': 0, 'harmless': 54, 'info': 'US, Google LLC'},
    '103.224.182.245': {'malicious': 0, 'harmless': 57, 'info': 'US, Trellian Pty Limited'},
    '1.1.1.1': {'malicious': 0, 'harmless': 56, 'info': 'Cloudflare Inc'},
    '192.168.1.5': {'malicious': 0, 'harmless': 20, 'info': 'Internal network IP'},
    '10.0.0.14': {'malicious': 2, 'harmless': 30, 'info': 'Unknown external relay'}
}


def generate_new_alert():
    row = attack_pool.sample(1)
    prediction = model.predict(row)
    probability = model.predict_proba(row).max()
    label = le.inverse_transform(prediction)[0]

    ip = random.choice(demo_ips)
    threat = demo_threat_info[ip]
    mitre = get_mitre_info(label)

    if threat['malicious'] >= 10:
        severity = 'high'
    elif threat['malicious'] >= 1:
        severity = 'medium'
    else:
        severity = 'medium' if probability >= 0.9 else 'low'

    new_id = st.session_state.next_id
    st.session_state.next_id += 1

    alert = {
        'id': new_id,
        'attack_type': label,
        'confidence': round(float(probability), 2),
        'ip': ip,
        'severity': severity,
        'mitre_technique': mitre['technique'],
        'mitre_name': mitre['name'],
        'mitre_tactic': mitre['tactic'],
        'malicious_count': threat['malicious'],
        'harmless_count': threat['harmless'],
        'ip_info': threat['info'],
        'is_anomaly': random.choice([True, False])
    }
    return alert


if len(st.session_state.alerts) == 0:
    for _ in range(5):
        st.session_state.alerts.insert(0, generate_new_alert())
else:
    st.session_state.alerts.insert(0, generate_new_alert())
    if len(st.session_state.alerts) > 15:
        st.session_state.alerts = st.session_state.alerts[:15]
high_count = sum(1 for a in st.session_state.alerts if a['severity'] == 'high')
medium_count = sum(1 for a in st.session_state.alerts if a['severity'] == 'medium')
low_count = sum(1 for a in st.session_state.alerts if a['severity'] == 'low')
total = len(st.session_state.alerts)
high_pct = round((high_count / total * 100)) if total > 0 else 0

col1, col2, col3, col4 = st.columns(4)

with col1:
    html = '<div class="metric-card">'
    html += '<div class="metric-icon">&#128274;</div>'
    html += '<div class="metric-value">' + str(total) + '</div>'
    html += '<div class="metric-label">Total alerts</div>'
    html += '<div class="metric-badge badge-neutral">' + str(high_pct) + '% high severity</div>'
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)

with col2:
    html = '<div class="metric-card">'
    html += '<div class="metric-icon">&#9888;</div>'
    html += '<div class="metric-value">' + str(high_count) + '</div>'
    html += '<div class="metric-label">High severity</div>'
    html += '<div class="metric-badge badge-red">needs review</div>'
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)

with col3:
    html = '<div class="metric-card">'
    html += '<div class="metric-icon">&#9202;</div>'
    html += '<div class="metric-value">' + str(medium_count) + '</div>'
    html += '<div class="metric-label">Medium severity</div>'
    html += '<div class="metric-badge badge-blue">monitoring</div>'
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)

with col4:
    html = '<div class="metric-card">'
    html += '<div class="metric-icon">&#9989;</div>'
    html += '<div class="metric-value">' + str(low_count) + '</div>'
    html += '<div class="metric-label">Low severity</div>'
    html += '<div class="metric-badge badge-green">stable</div>'
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)

st.write("")

left_col, right_col = st.columns([1.1, 1])

with left_col:
    st.subheader("Live alert feed")
    for a in st.session_state.alerts:
        badge_class = 'badge-' + a['severity']
        card_class = 'alert-card ' + a['severity']
        status = st.session_state.alert_status.get(a['id'])

        card_html = '<div class="' + card_class + '">'
        card_html += '<div class="alert-title">' + a['attack_type'] + '</div>'
        card_html += '<div class="alert-meta">IP ' + a['ip'] + ' | confidence ' + str(a['confidence']) + '</div>'
        card_html += '<span class="badge ' + badge_class + '">' + a['severity'] + '</span>'

        if status == 'blocked':
            card_html += ' <span class="badge badge-red">&#128274; IP blocked by SOC</span>'
        elif status == 'escalated':
            card_html += ' <span class="badge badge-blue">&#9650; Escalated</span>'
        elif status == 'ignored':
            card_html += ' <span class="badge badge-neutral">Ignored</span>'
        elif status == 'false_positive':
            card_html += ' <span class="badge badge-green">Marked false positive</span>'

        card_html += '</div>'
        st.markdown(card_html, unsafe_allow_html=True)
        if st.button('View details', key='btn_' + str(a['id'])):
            st.session_state['selected_alert'] = a['id']

with right_col:
    st.subheader("Alert detail")
    if 'selected_alert' in st.session_state:
        selected = None
        for a in st.session_state.alerts:
            if a['id'] == st.session_state['selected_alert']:
                selected = a
                break

        if selected is not None:
            detail_html = '<div class="detail-panel">'
            detail_html += '<div class="alert-title">' + selected['attack_type'] + ' detected</div>'
            detail_html += '<div class="section-label">Source IP</div>' + selected['ip']
            detail_html += '<div class="section-label">Confidence</div>' + str(selected['confidence'])
            detail_html += '<div class="section-label">MITRE ATT&CK</div>' + selected['mitre_technique'] + ' - ' + selected['mitre_name'] + ' (' + selected['mitre_tactic'] + ')'
            detail_html += '<div class="section-label">Threat intelligence</div>' + str(selected['malicious_count']) + ' vendors flagged malicious, ' + str(selected['harmless_count']) + ' flagged clean. ' + selected['ip_info']
            detail_html += '</div>'
            st.markdown(detail_html, unsafe_allow_html=True)

            st.markdown('<div class="section-label">AI explanation</div>', unsafe_allow_html=True)
            explanation = generate_alert_explanation(selected)
            st.markdown('<div class="llm-box">' + explanation + '</div>', unsafe_allow_html=True)

            current_status = st.session_state.alert_status.get(selected['id'])
            if current_status:
                st.info('Current status: ' + current_status)

            b1, b2, b3, b4 = st.columns(4)
            with b1:
                if st.button('Escalate'):
                    st.session_state.alert_status[selected['id']] = 'escalated'
                    st.rerun()
            with b2:
                if st.button('Block IP'):
                    st.session_state.alert_status[selected['id']] = 'blocked'
                    st.rerun()
            with b3:
                if st.button('Ignore'):
                    st.session_state.alert_status[selected['id']] = 'ignored'
                    st.rerun()
            with b4:
                if st.button('False Positive'):
                    st.session_state.alert_status[selected['id']] = 'false_positive'
                    st.rerun()
    else:
        st.write("Select an alert from the list to see details.")

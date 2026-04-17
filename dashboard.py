"""
ComplianceGPT - AI-Powered Vulnerability Analysis Dashboard
"""

import streamlit as st
import pandas as pd
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.integrations.csv_parser import VulnerabilityParser
from src.analyzers.vulnerability_analyzer import VulnerabilityAnalyzer


# Page config
st.set_page_config(
    page_title="ComplianceGPT - AI Vulnerability Analyst",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3.5rem;
        font-weight: 800;
        text-align: center;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.5rem;
    }
    
    .subtitle {
        text-align: center;
        color: #666;
        font-size: 1.3rem;
        margin-bottom: 2rem;
    }
    
    .ai-badge {
        display: inline-block;
        background: linear-gradient(135deg, #667eea, #764ba2);
        color: white;
        padding: 0.3rem 1rem;
        border-radius: 20px;
        font-size: 0.9rem;
        font-weight: 600;
    }
    
    .feature-box {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        margin: 1rem 0;
        border-left: 4px solid #667eea;
    }
    
    .how-it-works {
        background: #f8f9fa;
        padding: 1.5rem;
        border-radius: 10px;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)


def main():
    """Main dashboard"""
    
    # Header
    st.markdown('<div class="main-header">🤖 ComplianceGPT</div>', unsafe_allow_html=True)
    st.markdown('<div class="subtitle">AI-Powered Vulnerability & Risk Intelligence Platform</div>', unsafe_allow_html=True)
    st.markdown('<div style="text-align: center;"><span class="ai-badge">⚡ Powered by Claude AI</span></div>', unsafe_allow_html=True)
    
    # Sidebar
    st.sidebar.title("⚙️ Configuration")
    
    uploaded_file = st.sidebar.file_uploader(
        "📁 Upload Vulnerability Scan",
        type=['csv'],
        help="Upload Nessus, OpenVAS, or custom CSV"
    )
    
    use_ai = st.sidebar.checkbox("🤖 Use AI Analysis", value=True, help="Claude AI analyzes each vulnerability")
    
    with st.sidebar.expander("🏢 Business Context", expanded=False):
        env_type = st.selectbox("Environment", ["Production", "Staging", "Development", "Test"])
        data_class = st.selectbox("Data Classification", ["Public", "Internal", "Confidential", "PII", "Payment Data"])
        compliance = st.multiselect("Compliance", ["PCI-DSS", "SOC 2", "ISO 27001", "NIST CSF"], default=["PCI-DSS", "SOC 2"])
    
    st.sidebar.markdown("---")
    st.sidebar.info("💡 ComplianceGPT uses AI to analyze vulnerabilities with business context, providing actionable insights beyond CVSS scores.")
    
    # Main content
    if not uploaded_file and 'use_sample' not in st.session_state:
        show_landing_page()
    else:
        # Process file
        if 'use_sample' in st.session_state and st.session_state.use_sample:
            process_sample_data(env_type, data_class, compliance, use_ai)
        elif uploaded_file:
            process_uploaded_file(uploaded_file, env_type, data_class, compliance, use_ai)
        
        # Display if analyzed
        if 'analyzed_vulns' in st.session_state:
            display_results(st.session_state.analyzed_vulns, use_ai)


def show_landing_page():
    """Landing page with information"""
    
    # What it does section
    st.markdown("## 🎯 What ComplianceGPT Does")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="feature-box">
            <h3>🧠 AI Risk Analysis</h3>
            <p>Goes beyond CVSS scores. AI analyzes vulnerabilities in the context of YOUR business environment, 
            data classification, and compliance requirements to provide intelligent prioritization.</p>
        </div>
        
        <div class="feature-box">
            <h3>💼 Business Impact Assessment</h3>
            <p>Explains real-world consequences in plain English. Understand what's actually at risk - 
            not just technical jargon about buffer overflows.</p>
        </div>
        
        <div class="feature-box">
            <h3>📋 Compliance Mapping</h3>
            <p>Automatically maps vulnerabilities to specific controls in PCI-DSS, SOC 2, ISO 27001, 
            and NIST Cybersecurity Framework.</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="feature-box">
            <h3>⚡ Exploitation Intelligence</h3>
            <p>AI assesses exploitation likelihood based on public exploits, active campaigns, 
            and attack difficulty - helping you focus on what attackers will actually use.</p>
        </div>
        
        <div class="feature-box">
            <h3>🔧 Smart Remediation</h3>
            <p>Provides actionable, prioritized fix recommendations with immediate workarounds, 
            proper fixes, and long-term prevention strategies.</p>
        </div>
        
        <div class="feature-box">
            <h3>📊 Executive Reports</h3>
            <p>Generates plain-English summaries suitable for leadership. Export CSV reports 
            for documentation and tracking.</p>
        </div>
        """, unsafe_allow_html=True)
    
    # How it works
    st.markdown("---")
    st.markdown("## 🔄 How It Works")
    
    st.markdown("""
    <div class="how-it-works">
        <h4>1️⃣ Upload Your Scan</h4>
        <p>Import vulnerability scans from Nessus, OpenVAS, or any CSV with vulnerability data.</p>
        
        <h4>2️⃣ Add Business Context</h4>
        <p>Tell us about your environment (Production/Staging), data classification, and compliance needs.</p>
        
        <h4>3️⃣ AI Analysis (1-2 minutes)</h4>
        <p>Claude AI analyzes each vulnerability considering your specific context, assessing business impact, 
        exploitation likelihood, and compliance implications.</p>
        
        <h4>4️⃣ Get Actionable Intelligence</h4>
        <p>Receive prioritized findings with clear remediation guidance and export reports for your team.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Supported formats
    st.markdown("---")
    st.markdown("## 📊 Supported Formats")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.info("""
        **Import vulnerability scans from:**
        - 🔹 Nessus (CSV export)
        - 🔹 OpenVAS (CSV/XML export)
        - 🔹 Custom CSV format
        
        **Required columns:** `cve_id`, `cvss_score`, `severity`, `name`, `description`, `solution`, `host`, `port`, `protocol`
        """)
    
    with col2:
        st.markdown("### 🚀 Quick Start")
        if st.button("📊 Try with Sample Data", use_container_width=True, type="primary"):
            st.session_state.use_sample = True
            st.rerun()
        
        st.markdown("**or**")
        st.markdown("👆 Upload your scan in the sidebar")


def process_sample_data(env_type, data_class, compliance, use_ai):
    """Process sample data"""
    sample_path = 'data/sample_vulnerabilities.csv'
    
    if not os.path.exists(sample_path):
        st.error(f"Sample file not found: {sample_path}")
        return
    
    parser = VulnerabilityParser()
    vulns = parser.parse_csv(sample_path)
    
    if not vulns:
        st.error("Could not load sample data")
        return
    
    st.success(f"✅ Loaded {len(vulns)} sample vulnerabilities")
    
    context = {
        'environment_type': env_type.lower(),
        'data_classification': data_class,
        'compliance_requirements': compliance
    }
    
    analyze_vulns(vulns, context, use_ai)


def process_uploaded_file(uploaded_file, env_type, data_class, compliance, use_ai):
    """Process uploaded file"""
    parser = VulnerabilityParser()
    
    try:
        temp_path = f"data/uploads/temp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        os.makedirs(os.path.dirname(temp_path), exist_ok=True)
        
        with open(temp_path, 'wb') as f:
            f.write(uploaded_file.getbuffer())
        
        vulns = parser.parse_csv(temp_path)
        
        if not vulns:
            st.error("No vulnerabilities found")
            return
        
        st.success(f"✅ Loaded {len(vulns)} vulnerabilities")
        
        context = {
            'environment_type': env_type.lower(),
            'data_classification': data_class,
            'compliance_requirements': compliance
        }
        
        analyze_vulns(vulns, context, use_ai)
        
    except Exception as e:
        st.error(f"Error: {e}")


def analyze_vulns(vulns, context, use_ai):
    """Analyze vulnerabilities"""
    with st.spinner(f"🤖 AI analyzing {len(vulns)} vulnerabilities... (~30 seconds)"):
        analyzer = VulnerabilityAnalyzer(use_ai=use_ai)
        analyzed = analyzer.analyze_batch(vulns, context, show_progress=False)
        
        st.session_state.analyzed_vulns = analyzed
        st.session_state.scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def display_results(vulnerabilities, use_ai):
    """Display results"""
    st.success(f"✅ AI Analysis completed at {st.session_state.scan_time}")
    
    # Stats
    total = len(vulnerabilities)
    critical = sum(1 for v in vulnerabilities if v.get('ai_priority', 3) == 5)
    high = sum(1 for v in vulnerabilities if v.get('ai_priority', 3) == 4)
    medium = sum(1 for v in vulnerabilities if v.get('ai_priority', 3) == 3)
    low = sum(1 for v in vulnerabilities if v.get('ai_priority', 3) <= 2)
    
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("📊 Total", total)
    col2.metric("🔴 Critical", critical)
    col3.metric("🟠 High", high)
    col4.metric("🟡 Medium", medium)
    col5.metric("🟢 Low", low)
    
    st.markdown("---")
    st.markdown("## 🔍 AI-Powered Vulnerability Analysis")
    
    # Display vulns
    for vuln in sorted(vulnerabilities, key=lambda x: x.get('ai_priority', 3), reverse=True):
        priority = vuln.get('ai_priority', 3)
        ai = vuln.get('ai_analysis', {})
        
        emoji = {5: "🔴", 4: "🟠", 3: "🟡", 2: "🟢", 1: "⚪"}
        
        with st.expander(f"{emoji.get(priority)} **AI Priority {priority}/5** - {vuln['name']}", expanded=(priority>=4)):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"**CVE:** `{vuln.get('cve_id')}`")
                st.markdown(f"**CVSS Score:** {vuln.get('cvss_score')} ({vuln.get('severity')})")
                st.markdown(f"**Affected Host:** {vuln.get('host')}:{vuln.get('port')}")
            
            with col2:
                st.markdown(f"**Exploitation:** {ai.get('exploitation_rating', 'Unknown')}")
                if use_ai:
                    st.markdown(f"**AI Tokens:** {ai.get('tokens_used', 0)}")
            
            if use_ai and ai.get('model') != 'fallback':
                st.markdown("### 💼 Business Impact Analysis")
                st.info(ai.get('business_impact', 'N/A'))
                
                st.markdown("### ⚠️ Exploitation Assessment")
                st.warning(ai.get('exploitation_likelihood', 'N/A'))
                
                st.markdown("### 📋 Compliance Impact")
                st.write(ai.get('compliance_impact', 'N/A'))
                
                st.markdown("### 🔧 AI-Generated Remediation Plan")
                st.success(ai.get('remediation', 'N/A'))
    
    # Export
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📥 Export")
    
    export_data = [{
        'CVE': v.get('cve_id'),
        'Name': v.get('name'),
        'AI_Priority': v.get('ai_priority'),
        'CVSS': v.get('cvss_score'),
        'Exploitation': v.get('ai_analysis', {}).get('exploitation_rating'),
        'Business_Impact': v.get('ai_analysis', {}).get('business_impact', '')[:200]
    } for v in vulnerabilities]
    
    df = pd.DataFrame(export_data)
    csv = df.to_csv(index=False)
    
    st.sidebar.download_button(
        "📄 Download AI Report",
        csv,
        f"compliancegpt_report_{datetime.now().strftime('%Y%m%d')}.csv",
        "text/csv",
        use_container_width=True
    )


if __name__ == "__main__":
    main()

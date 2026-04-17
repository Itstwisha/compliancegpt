"""
Claude AI Client for vulnerability analysis
"""

import os
from anthropic import Anthropic
from decouple import config
from typing import Dict, Any, Optional
import re


class ClaudeClient:
    """Client for interacting with Claude AI API"""
    
    def __init__(self):
        """Initialize Claude client"""
        self.api_key = config('ANTHROPIC_API_KEY')
        self.model = config('AI_MODEL', default='claude-sonnet-4-6')
        self.max_tokens = int(config('AI_MAX_TOKENS', default=4000))
        self.temperature = float(config('AI_TEMPERATURE', default=0.3))
        
        self.client = Anthropic(api_key=self.api_key)
    
    def analyze_vulnerability(
        self, 
        vulnerability: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze a vulnerability using Claude AI
        
        Args:
            vulnerability: Vulnerability data (CVE, CVSS, description, etc.)
            context: Optional context (business environment, compliance needs)
            
        Returns:
            AI analysis with prioritization, impact, and recommendations
        """
        # Build the prompt
        prompt = self._build_vulnerability_prompt(vulnerability, context)
        
        try:
            # Call Claude API
            message = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            
            # Extract response
            response_text = message.content[0].text
            
            # Parse response into structured format
            analysis = self._parse_ai_response(response_text, vulnerability)
            
            # Add metadata
            analysis['tokens_used'] = int(message.usage.input_tokens) + int(message.usage.output_tokens)
            analysis['model'] = message.model
            
            return analysis
            
        except Exception as e:
            print(f"❌ AI Analysis Error: {e}")
            return self._fallback_analysis(vulnerability)
    
    def _build_vulnerability_prompt(
        self, 
        vulnerability: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build prompt for vulnerability analysis"""
        
        # Extract vulnerability details
        cve_id = vulnerability.get('cve_id', 'N/A')
        cvss_score = vulnerability.get('cvss_score', 'N/A')
        severity = vulnerability.get('severity', 'N/A')
        description = vulnerability.get('description', 'No description available')
        affected_hosts = vulnerability.get('affected_hosts', [])
        plugin_name = vulnerability.get('plugin_name', vulnerability.get('name', 'N/A'))
        
        # Build context section
        context_str = ""
        if context:
            env_type = context.get('environment_type', 'production')
            data_classification = context.get('data_classification', 'sensitive')
            compliance_reqs = context.get('compliance_requirements', [])
            
            context_str = f"""
ENVIRONMENT CONTEXT:
- Environment Type: {env_type}
- Data Classification: {data_classification}
- Compliance Requirements: {', '.join(compliance_reqs) if compliance_reqs else 'General security best practices'}
"""
        
        prompt = f"""You are a cybersecurity analyst performing risk assessment on a vulnerability.

VULNERABILITY DETAILS:
- CVE ID: {cve_id}
- CVSS Score: {cvss_score}
- Severity: {severity}
- Plugin/Check: {plugin_name}
- Description: {description}
- Affected Systems: {len(affected_hosts) if isinstance(affected_hosts, list) else 1} host(s)
{context_str}

Analyze this vulnerability and provide:

1. BUSINESS_IMPACT (2-3 sentences):
   - Explain the real-world business risk in plain English
   - What could actually happen if exploited?
   - Estimate potential cost impact if available

2. EXPLOITATION_LIKELIHOOD (1 paragraph):
   - Is this actively exploited in the wild?
   - Are there public exploits available?
   - How difficult is it to exploit?
   - Rate: VERY HIGH, HIGH, MEDIUM, LOW, VERY LOW

3. COMPLIANCE_IMPACT (bullet points):
   - Which compliance frameworks does this affect?
   - Consider: PCI-DSS, SOC 2, ISO 27001, NIST CSF
   - Identify specific control numbers if applicable

4. PRIORITY (IMPORTANT - Start with just the number):
   Start your response with ONLY a number 1-5, then explain:
   - 5 = CRITICAL - Fix immediately (within 24 hours)
   - 4 = HIGH - Fix within 1 week
   - 3 = MEDIUM - Fix within 1 month
   - 2 = LOW - Fix when convenient
   - 1 = INFORMATIONAL - Monitor only

5. REMEDIATION (numbered list):
   - Immediate actions (stop-gap measures)
   - Short-term fixes (proper remediation)
   - Long-term prevention (systemic improvements)

Format EXACTLY as:

BUSINESS_IMPACT:
[Your analysis]

EXPLOITATION_LIKELIHOOD:
[Your analysis and rating]

COMPLIANCE_IMPACT:
[Bullet points]

PRIORITY:
[Start with just a number 1-5, then explain]

REMEDIATION:
[Numbered list]
"""
        return prompt
    
    def _parse_ai_response(
        self, 
        response_text: str, 
        vulnerability: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Parse Claude's response into structured format"""
        
        sections = {
            'business_impact': '',
            'exploitation_likelihood': '',
            'exploitation_rating': 'UNKNOWN',
            'compliance_impact': '',
            'priority': 3,
            'priority_justification': '',
            'remediation': '',
            'full_analysis': response_text
        }
        
        try:
            # Split by section headers
            parts = response_text.split('\n\n')
            
            current_section = None
            for part in parts:
                part = part.strip()
                
                if part.startswith('BUSINESS_IMPACT:'):
                    current_section = 'business_impact'
                    sections[current_section] = part.replace('BUSINESS_IMPACT:', '').strip()
                    
                elif part.startswith('EXPLOITATION_LIKELIHOOD:'):
                    current_section = 'exploitation_likelihood'
                    text = part.replace('EXPLOITATION_LIKELIHOOD:', '').strip()
                    sections[current_section] = text
                    
                    # Extract rating
                    text_upper = text.upper()
                    if 'VERY HIGH' in text_upper:
                        sections['exploitation_rating'] = 'VERY HIGH'
                    elif 'VERY LOW' in text_upper:
                        sections['exploitation_rating'] = 'VERY LOW'
                    elif 'HIGH' in text_upper:
                        sections['exploitation_rating'] = 'HIGH'
                    elif 'MEDIUM' in text_upper:
                        sections['exploitation_rating'] = 'MEDIUM'
                    elif 'LOW' in text_upper:
                        sections['exploitation_rating'] = 'LOW'
                        
                elif part.startswith('COMPLIANCE_IMPACT:'):
                    current_section = 'compliance_impact'
                    sections[current_section] = part.replace('COMPLIANCE_IMPACT:', '').strip()
                    
                elif part.startswith('PRIORITY:'):
                    current_section = 'priority'
                    text = part.replace('PRIORITY:', '').strip()
                    
                    # Extract priority number - look for digit at start
                    priority_match = re.search(r'^(\d)', text)
                    if priority_match:
                        sections['priority'] = int(priority_match.group(1))
                    else:
                        # Fallback - search anywhere in first line
                        first_line = text.split('\n')[0]
                        for num in ['5', '4', '3', '2', '1']:
                            if num in first_line:
                                sections['priority'] = int(num)
                                break
                    
                    sections['priority_justification'] = text
                    
                elif part.startswith('REMEDIATION:'):
                    current_section = 'remediation'
                    sections[current_section] = part.replace('REMEDIATION:', '').strip()
                    
                elif current_section:
                    # Continue previous section
                    sections[current_section] += '\n\n' + part
            
        except Exception as e:
            print(f"⚠️  Warning: Could not fully parse AI response: {e}")
        
        return sections
    
    def _fallback_analysis(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback analysis if AI fails"""
        cvss = vulnerability.get('cvss_score', 0)
        
        # Simple CVSS-based priority
        if cvss >= 9.0:
            priority = 5
            priority_text = "CRITICAL - CVSS 9.0+"
        elif cvss >= 7.0:
            priority = 4
            priority_text = "HIGH - CVSS 7.0-8.9"
        elif cvss >= 4.0:
            priority = 3
            priority_text = "MEDIUM - CVSS 4.0-6.9"
        else:
            priority = 2
            priority_text = "LOW - CVSS < 4.0"
        
        return {
            'business_impact': 'AI analysis unavailable - using CVSS-based assessment',
            'exploitation_likelihood': 'Unknown - AI analysis unavailable',
            'exploitation_rating': 'UNKNOWN',
            'compliance_impact': 'Manual review required',
            'priority': priority,
            'priority_justification': priority_text,
            'remediation': 'Refer to vendor security advisories',
            'full_analysis': 'Fallback analysis used - AI service unavailable',
            'tokens_used': 0,
            'model': 'fallback'
        }
    
    def generate_executive_summary(
        self, 
        vulnerabilities: list,
        scan_metadata: Dict[str, Any]
    ) -> str:
        """
        Generate executive summary of vulnerability scan
        
        Args:
            vulnerabilities: List of vulnerabilities with AI analysis
            scan_metadata: Scan date, scope, etc.
            
        Returns:
            Executive summary text
        """
        
        # Count by priority
        critical = sum(1 for v in vulnerabilities if v.get('ai_analysis', {}).get('priority') == 5)
        high = sum(1 for v in vulnerabilities if v.get('ai_analysis', {}).get('priority') == 4)
        medium = sum(1 for v in vulnerabilities if v.get('ai_analysis', {}).get('priority') == 3)
        low = sum(1 for v in vulnerabilities if v.get('ai_analysis', {}).get('priority') <= 2)
        
        prompt = f"""Generate an executive summary for a vulnerability scan report.

SCAN DETAILS:
- Date: {scan_metadata.get('scan_date', 'Unknown')}
- Systems Scanned: {scan_metadata.get('hosts_scanned', 'Unknown')}
- Total Vulnerabilities: {len(vulnerabilities)}

FINDINGS BY PRIORITY:
- Critical (Priority 5): {critical}
- High (Priority 4): {high}
- Medium (Priority 3): {medium}
- Low (Priority 1-2): {low}

Write a 3-paragraph executive summary suitable for C-level executives:

1. First paragraph: Overall security posture assessment
2. Second paragraph: Key risks and business impact
3. Third paragraph: Recommended actions and timeline

Use business language, not technical jargon. Focus on risk and impact.
Keep it concise (200-300 words total).
"""
        
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=1000,
                temperature=0.5,
                messages=[{"role": "user", "content": prompt}]
            )
            
            return message.content[0].text
            
        except Exception as e:
            print(f"❌ Error generating summary: {e}")
            return "Executive summary generation failed. Please review detailed findings below."

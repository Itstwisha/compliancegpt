"""
Parse vulnerability scan CSV files
"""

import pandas as pd
from typing import List, Dict, Any


class VulnerabilityParser:
    """Parse vulnerability scan results from CSV"""
    
    def parse_csv(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Parse CSV file containing vulnerability scan results
        
        Args:
            filepath: Path to CSV file
            
        Returns:
            List of vulnerability dictionaries
        """
        try:
            df = pd.read_csv(filepath)
            
            vulnerabilities = []
            
            for _, row in df.iterrows():
                vuln = {
                    'plugin_id': row.get('plugin_id', 'N/A'),
                    'cve_id': row.get('cve_id', 'N/A'),
                    'cvss_score': float(row.get('cvss_score', 0)),
                    'severity': row.get('severity', 'Unknown'),
                    'name': row.get('name', 'Unnamed Vulnerability'),
                    'description': row.get('description', 'No description'),
                    'solution': row.get('solution', 'No solution provided'),
                    'host': row.get('host', 'Unknown'),
                    'port': row.get('port', 'N/A'),
                    'protocol': row.get('protocol', 'N/A')
                }
                vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            print(f"❌ Error parsing CSV: {e}")
            return []
    
    def get_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get summary statistics"""
        
        total = len(vulnerabilities)
        
        critical = sum(1 for v in vulnerabilities if v['severity'].lower() == 'critical')
        high = sum(1 for v in vulnerabilities if v['severity'].lower() == 'high')
        medium = sum(1 for v in vulnerabilities if v['severity'].lower() == 'medium')
        low = sum(1 for v in vulnerabilities if v['severity'].lower() == 'low')
        
        unique_hosts = len(set(v['host'] for v in vulnerabilities))
        
        avg_cvss = sum(v['cvss_score'] for v in vulnerabilities) / total if total > 0 else 0
        
        return {
            'total': total,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'unique_hosts': unique_hosts,
            'average_cvss': round(avg_cvss, 2)
        }

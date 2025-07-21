import splunklib.client as client
import splunklib.results as results
from datetime import datetime, timedelta
import asyncio
import json
import logging
from typing import Dict, List, Optional, Any
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

from ..models.hunt import ThreatHunt, HuntType


logger = logging.getLogger(__name__)


class SplunkHuntingEngine:
    """Executes threat hunting queries in Splunk"""
    
    def __init__(self, host: str, port: int, splunk_token: str):
        self.service = client.connect(
            host=host,
            port=port,
            splunkToken=splunk_token,
            autologin=True
        )
        self.hunt_queries = self._load_hunt_queries()
        
    async def execute_hypothesis_hunt(self, hunt: ThreatHunt) -> Dict:
        """Executes queries for hypothesis-driven hunting"""
        results = {}
        
        for query in hunt.queries:
            try:
                bounded_query = self._add_time_bounds(query, days=30)
                
                job = self.service.jobs.create(
                    bounded_query,
                    search_mode="normal",
                    max_count=10000
                )
                
                # Wait for completion
                while not job.is_ready():
                    await asyncio.sleep(1)
                
                result_reader = results.ResultsReader(job.results())
                hunt_results = []
                
                for result in result_reader:
                    if isinstance(result, dict):
                        hunt_results.append(result)
                
                results[query] = {
                    'count': len(hunt_results),
                    'data': hunt_results[:100],
                    'statistics': self._calculate_statistics(hunt_results)
                }
                
                logger.info(f"Query executed: {len(hunt_results)} results for hunt {hunt.hunt_id}")
                
            except Exception as e:
                logger.error(f"Error executing query: {str(e)}")
                results[query] = {
                    'error': str(e),
                    'count': 0,
                    'data': []
                }
        
        return results
    
    async def execute_baseline_hunt(self, metric: str, environment: str) -> Dict:
        """Establishes baselines for normal behavior"""
        baseline_query = f"""
        index={environment} earliest=-30d@d latest=now
        | bucket _time span=1h
        | stats avg({metric}) as avg_value, 
                stdev({metric}) as stdev_value,
                p95({metric}) as p95_value by _time
        | eventstats avg(avg_value) as baseline_avg,
                     stdev(avg_value) as baseline_stdev
        """
        
        try:
            job = self.service.jobs.create(baseline_query)
            
            while not job.is_ready():
                await asyncio.sleep(1)
            
            result_reader = results.ResultsReader(job.results())
            baseline_data = []
            
            for result in result_reader:
                if isinstance(result, dict):
                    baseline_data.append(result)
            
            # Calculate baseline statistics
            if baseline_data:
                baseline_stats = self._calculate_baseline_stats(baseline_data)
                logger.info(f"Baseline established for {metric} in {environment}")
                return baseline_stats
            else:
                logger.warning(f"No data found for baseline calculation: {metric}")
                return {'error': 'No baseline data available'}
                
        except Exception as e:
            logger.error(f"Error executing baseline hunt: {str(e)}")
            return {'error': str(e)}
    
    async def execute_math_hunt(self, algorithm: str, data: List[Dict]) -> Dict:
        """Executes Model-Assisted Threat Hunting"""
        try:
            if algorithm == "isolation_forest":
                return await self._run_isolation_forest(data)
            elif algorithm == "clustering":
                return await self._run_clustering_analysis(data)
            elif algorithm == "time_series_anomaly":
                return await self._run_time_series_analysis(data)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
                
        except Exception as e:
            logger.error(f"Error in ML analysis: {str(e)}")
            return {'error': str(e), 'anomalies': []}
    
    async def get_data_for_ml(self, data_source: str, days: int = 7) -> List[Dict]:
        """Retrieves data for ML analysis"""
        query = f"""
        index={data_source} earliest=-{days}d@d latest=now
        | fields _time, *
        | head 10000
        """
        
        try:
            job = self.service.jobs.create(query)
            
            while not job.is_ready():
                await asyncio.sleep(1)
            
            result_reader = results.ResultsReader(job.results())
            data = []
            
            for result in result_reader:
                if isinstance(result, dict):
                    data.append(result)
            
            logger.info(f"Retrieved {len(data)} records from {data_source} for ML analysis")
            return data
            
        except Exception as e:
            logger.error(f"Error retrieving ML data: {str(e)}")
            return []
    
    async def create_saved_search(self, detection: Dict) -> Optional[str]:
        """Creates a saved search (alert) in Splunk"""
        try:
            search_name = f"ThreatHunt_{detection['name'].replace(' ', '_')}"
            
            saved_search = self.service.saved_searches.create(
                name=search_name,
                search=detection['query'],
                description=detection.get('description', ''),
                dispatch_earliest='-1h',
                dispatch_latest='now'
            )
            
            # Enable alerting if threshold specified
            if 'threshold' in detection:
                saved_search.update(**{
                    'alert.track': '1',
                    'alert.comparator': 'greater than',
                    'alert.threshold': str(detection['threshold']),
                    'alert.severity': detection.get('severity', '3')
                })
            
            logger.info(f"Created saved search: {search_name}")
            return search_name
            
        except Exception as e:
            logger.error(f"Error creating saved search: {str(e)}")
            return None
    
    def get_hunt_queries_by_technique(self, technique_id: str) -> List[str]:
        """Returns pre-built queries for specific MITRE techniques"""
        technique_queries = {
            "T1055": [  # Process Injection
                """
                index=endpoint process_name=* 
                | eval suspicious_injection=if(
                    (process_name="svchost.exe" AND parent_process!="services.exe") OR
                    (process_name="rundll32.exe" AND cmdline="*,#*"), 1, 0)
                | where suspicious_injection=1
                """,
                """
                index=sysmon EventCode=8 
                | stats count by SourceImage, TargetImage 
                | where SourceImage!=TargetImage
                """
            ],
            "T1003": [  # Credential Dumping
                """
                index=endpoint (process_name="lsass.exe" AND action="read") OR
                (cmdline="*sekurlsa*" OR cmdline="*mimikatz*")
                """,
                """
                index=windows EventCode=4656 Object_Name="*\\lsass.exe"
                | stats count by Account_Name, Computer_Name
                """
            ],
            "T1021": [  # Remote Services
                """
                index=windows EventCode=4624 Logon_Type=3
                | stats count by Account_Name, Source_Network_Address, Computer_Name
                | where count > 10
                """,
                """
                index=network dest_port IN (22, 3389, 5985, 5986)
                | stats count by src_ip, dest_ip, dest_port
                | where count > 50
                """
            ],
            "T1083": [  # File and Directory Discovery
                """
                index=endpoint (process_name="dir.exe" OR process_name="ls" OR cmdline="*dir *")
                | stats count by user, process_name, cmdline
                | where count > 20
                """,
                """
                index=sysmon EventCode=1 
                (CommandLine="*dir *" OR CommandLine="*ls *" OR CommandLine="*find *")
                | stats count by User, CommandLine
                """
            ]
        }
        return technique_queries.get(technique_id, [])
    
    def _add_time_bounds(self, query: str, days: int = 30) -> str:
        """Adds time bounds to query for efficiency"""
        if 'earliest=' not in query.lower():
            return f"earliest=-{days}d@d latest=now {query}"
        return query
    
    def _calculate_statistics(self, data: List[Dict]) -> Dict:
        """Calculates basic statistics for hunt results"""
        if not data:
            return {}
        
        stats = {
            'total_events': len(data),
            'unique_fields': {},
            'time_distribution': {}
        }
        
        # Calculate unique values for common fields
        common_fields = ['user', 'src_ip', 'dest_ip', 'process_name', 'account_name']
        for field in common_fields:
            values = [item.get(field) for item in data if item.get(field)]
            if values:
                stats['unique_fields'][field] = len(set(values))
        
        return stats
    
    def _calculate_baseline_stats(self, baseline_data: List[Dict]) -> Dict:
        """Calculates baseline statistics"""
        if not baseline_data:
            return {}
        
        # Extract numeric values for statistics
        values = []
        for record in baseline_data:
            for key, value in record.items():
                if key in ['avg_value', 'baseline_avg', 'p95_value']:
                    try:
                        values.append(float(value))
                    except (ValueError, TypeError):
                        continue
        
        if values:
            return {
                'baseline_avg': np.mean(values),
                'baseline_stdev': np.std(values),
                'p95_value': np.percentile(values, 95),
                'min_value': np.min(values),
                'max_value': np.max(values),
                'sample_size': len(baseline_data)
            }
        
        return {'error': 'No numeric data for baseline calculation'}
    
    async def _run_isolation_forest(self, data: List[Dict]) -> Dict:
        """Runs Isolation Forest algorithm for anomaly detection"""
        if not data:
            return {'anomalies': [], 'anomaly_score': 0.0}
        
        # Prepare data for ML
        df = pd.DataFrame(data)
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        
        if len(numeric_columns) == 0:
            return {'anomalies': [], 'error': 'No numeric features for analysis'}
        
        # Handle missing values
        df_numeric = df[numeric_columns].fillna(0)
        
        # Scale features
        scaler = StandardScaler()
        scaled_data = scaler.fit_transform(df_numeric)
        
        # Run Isolation Forest
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        anomaly_labels = iso_forest.fit_predict(scaled_data)
        anomaly_scores = iso_forest.decision_function(scaled_data)
        
        # Identify anomalies
        anomalies = []
        for i, label in enumerate(anomaly_labels):
            if label == -1:  # Anomaly
                anomalies.append({
                    'index': i,
                    'score': float(anomaly_scores[i]),
                    'data': data[i],
                    'confidence': abs(float(anomaly_scores[i]))
                })
        
        # Sort by confidence
        anomalies.sort(key=lambda x: x['confidence'], reverse=True)
        
        return {
            'anomalies': anomalies[:20],  # Top 20 anomalies
            'anomaly_score': float(np.mean(np.abs(anomaly_scores))),
            'total_anomalies': len(anomalies),
            'algorithm': 'isolation_forest'
        }
    
    async def _run_clustering_analysis(self, data: List[Dict]) -> Dict:
        """Runs clustering analysis for pattern detection"""
        if not data:
            return {'anomalies': [], 'anomaly_score': 0.0}
        
        df = pd.DataFrame(data)
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        
        if len(numeric_columns) == 0:
            return {'anomalies': [], 'error': 'No numeric features for clustering'}
        
        df_numeric = df[numeric_columns].fillna(0)
        scaler = StandardScaler()
        scaled_data = scaler.fit_transform(df_numeric)
        
        # Run DBSCAN clustering
        dbscan = DBSCAN(eps=0.5, min_samples=5)
        cluster_labels = dbscan.fit_predict(scaled_data)
        
        # Identify outliers (cluster label -1)
        anomalies = []
        for i, label in enumerate(cluster_labels):
            if label == -1:  # Outlier
                anomalies.append({
                    'index': i,
                    'cluster': int(label),
                    'data': data[i],
                    'confidence': 0.8  # Fixed confidence for outliers
                })
        
        return {
            'anomalies': anomalies,
            'anomaly_score': len(anomalies) / len(data) if data else 0.0,
            'total_clusters': len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0),
            'algorithm': 'dbscan_clustering'
        }
    
    async def _run_time_series_analysis(self, data: List[Dict]) -> Dict:
        """Runs time series anomaly detection"""
        if not data:
            return {'anomalies': [], 'anomaly_score': 0.0}
        
        # Convert to time series DataFrame
        df = pd.DataFrame(data)
        
        if '_time' not in df.columns:
            return {'anomalies': [], 'error': 'No timestamp field for time series analysis'}
        
        try:
            df['_time'] = pd.to_datetime(df['_time'])
            df = df.set_index('_time').sort_index()
            
            # Find numeric columns for analysis
            numeric_columns = df.select_dtypes(include=[np.number]).columns
            if len(numeric_columns) == 0:
                return {'anomalies': [], 'error': 'No numeric features for time series analysis'}
            
            anomalies = []
            for column in numeric_columns:
                series = df[column].fillna(0)
                
                # Simple anomaly detection using rolling statistics
                rolling_mean = series.rolling(window=24, min_periods=1).mean()
                rolling_std = series.rolling(window=24, min_periods=1).std()
                
                # Identify outliers (beyond 3 standard deviations)
                threshold = 3
                outliers = abs(series - rolling_mean) > (threshold * rolling_std)
                
                for timestamp, is_outlier in outliers.items():
                    if is_outlier:
                        anomalies.append({
                            'timestamp': timestamp.isoformat(),
                            'metric': column,
                            'value': float(series.loc[timestamp]),
                            'expected': float(rolling_mean.loc[timestamp]),
                            'confidence': 0.7
                        })
            
            return {
                'anomalies': anomalies[:50],  # Limit results
                'anomaly_score': len(anomalies) / len(df) if len(df) > 0 else 0.0,
                'algorithm': 'time_series'
            }
            
        except Exception as e:
            return {'anomalies': [], 'error': f'Time series analysis failed: {str(e)}'}
    
    def _load_hunt_queries(self) -> Dict:
        """Loads predefined hunt query templates"""
        return {
            'lateral_movement': {
                'rdp_brute_force': '''
                index=windows EventCode=4625 Logon_Type=10
                | stats count by Source_Network_Address, Account_Name, Computer_Name
                | where count > 10
                ''',
                'smb_lateral_movement': '''
                index=windows EventCode=5140 Share_Name!="*$"
                | stats count by Source_Address, Account_Name, Share_Name
                | where count > 5
                '''
            },
            'persistence': {
                'scheduled_tasks': '''
                index=windows EventCode=4698
                | stats count by Account_Name, Task_Name, Computer_Name
                ''',
                'registry_run_keys': '''
                index=sysmon EventCode=13 TargetObject="*\\Run\\*"
                | stats count by Image, TargetObject, Details
                '''
            },
            'credential_access': {
                'lsass_access': '''
                index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
                | stats count by SourceImage, SourceUser, Computer_Name
                ''',
                'kerberoasting': '''
                index=windows EventCode=4769 Ticket_Encryption_Type=0x17
                | stats count by Account_Name, Service_Name, Client_Address
                | where count > 5
                '''
            }
        }
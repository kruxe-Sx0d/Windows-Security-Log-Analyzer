"""
Windows Security Log Analyzer
Author: Cyber Security Analyst
Description: Analyzes Windows security logs for failed logins and suspicious patterns
Dependencies: pandas, re, matplotlib, glob, numpy, datetime
"""

import pandas as pd
import re
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import glob
import numpy as np
from datetime import datetime, timedelta
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

# Set style for better visualizations
plt.style.use('ggplot')

class WindowsLogAnalyzer:
    """
    A comprehensive Windows security log analyzer for detecting suspicious activities
    """
    
    def __init__(self, log_directory='./logs/', log_pattern='*.log'):
        """
        Initialize the log analyzer
        
        Args:
            log_directory (str): Directory containing log files
            log_pattern (str): Pattern for log files (e.g., '*.log', 'Security*.csv')
        """
        self.log_directory = log_directory
        self.log_pattern = log_pattern
        self.logs_df = pd.DataFrame()
        self.failed_logins_df = pd.DataFrame()
        self.suspicious_activities = pd.DataFrame()
        
    def load_logs(self):
        """
        Load and combine all log files from the directory
        """
        try:
            log_files = glob.glob(f"{self.log_directory}/{self.log_pattern}")
            
            if not log_files:
                print(f"No log files found in {self.log_directory} with pattern {self.log_pattern}")
                return False
            
            print(f"Found {len(log_files)} log file(s)")
            
            all_logs = []
            for file in log_files:
                print(f"Processing: {file}")
                
                # Try different reading strategies based on file type
                if file.endswith('.csv'):
                    df = pd.read_csv(file, low_memory=False)
                else:
                    # For text logs, read with flexible parsing
                    try:
                        df = pd.read_csv(file, sep='\t', engine='python', 
                                       on_bad_lines='skip', low_memory=False)
                    except:
                        try:
                            # Try comma separated
                            df = pd.read_csv(file, engine='python', 
                                           on_bad_lines='skip', low_memory=False)
                        except:
                            # If all else fails, read as fixed width
                            with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                                lines = f.readlines()
                            df = pd.DataFrame({'raw_log': lines})
                
                # Standardize column names
                if not df.empty:
                    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
                    all_logs.append(df)
            
            # Combine all logs if any were loaded
            if all_logs:
                self.logs_df = pd.concat(all_logs, ignore_index=True)
                print(f"Total log entries loaded: {len(self.logs_df)}")
                return True
            else:
                print("No valid log data found in files")
                return False
            
        except Exception as e:
            print(f"Error loading logs: {str(e)}")
            return False
    
    def _is_text_column(self, column_series):
        """
        Safely check if a column contains text data
        
        Args:
            column_series: pandas Series to check
            
        Returns:
            bool: True if column contains text data
        """
        if column_series.empty:
            return False
        
        # Sample some values from the column (not just first row)
        sample_size = min(100, len(column_series))
        sample = column_series.dropna().sample(n=sample_size, random_state=42) if len(column_series.dropna()) > 0 else column_series.dropna()
        
        if sample.empty:
            return False
        
        # Check if any value in sample looks like text (contains letters)
        text_pattern = re.compile(r'[a-zA-Z]')
        for val in sample:
            if isinstance(val, str) and text_pattern.search(val):
                return True
        
        return False
    
    def _get_text_columns(self, df):
        """
        Get all columns that contain text data
        
        Args:
            df: DataFrame to analyze
            
        Returns:
            list: List of column names with text data
        """
        if df.empty:
            return []
        
        text_columns = []
        for col in df.columns:
            if self._is_text_column(df[col]):
                text_columns.append(col)
        
        return text_columns
    
    def parse_log_entries(self):
        """
        Parse and standardize log entries with common Windows event patterns
        """
        if self.logs_df.empty:
            print("No logs loaded. Please load logs first.")
            return
        
        # Create a copy for parsing
        parsed_logs = self.logs_df.copy()
        
        # Standardize timestamp if exists
        timestamp_columns = ['timestamp', 'datetime', 'date', 'time', 'created', 'logontime']
        for col in timestamp_columns:
            if col in parsed_logs.columns:
                try:
                    parsed_logs['parsed_timestamp'] = pd.to_datetime(
                        parsed_logs[col], errors='coerce'
                    )
                    # Check if we successfully parsed any timestamps
                    if parsed_logs['parsed_timestamp'].notna().any():
                        print(f"Using '{col}' column for timestamps")
                        break
                except Exception as e:
                    print(f"Could not parse '{col}' as timestamp: {str(e)}")
        
        # If no timestamp column found, try to extract from text
        if 'parsed_timestamp' not in parsed_logs.columns or parsed_logs['parsed_timestamp'].isna().all():
            print("No timestamp column found, attempting to extract from text...")
            parsed_logs['parsed_timestamp'] = self._extract_timestamps_from_text(parsed_logs)
        
        # Extract IP addresses using regex
        parsed_logs['extracted_ip'] = parsed_logs.apply(
            lambda row: self._extract_ip_from_row(row), axis=1
        )
        
        # Extract usernames
        username_columns = ['username', 'user', 'account_name', 'subject_user_name', 
                           'targetusername', 'newtargetusername']
        for col in username_columns:
            if col in parsed_logs.columns:
                # Convert to string and clean
                parsed_logs['extracted_username'] = parsed_logs[col].astype(str).str.strip()
                if parsed_logs['extracted_username'].notna().any():
                    print(f"Using '{col}' column for usernames")
                    break
        
        # Extract event IDs
        event_id_columns = ['event_id', 'eventid', 'eventcode', 'id']
        for col in event_id_columns:
            if col in parsed_logs.columns:
                try:
                    parsed_logs['event_id_numeric'] = pd.to_numeric(parsed_logs[col], errors='coerce')
                    if parsed_logs['event_id_numeric'].notna().any():
                        print(f"Using '{col}' column for event IDs")
                        break
                except:
                    continue
        
        self.logs_df = parsed_logs
        print(f"Log parsing completed. Timestamps found: {parsed_logs['parsed_timestamp'].notna().sum()}")
    
    def _extract_timestamps_from_text(self, df):
        """
        Attempt to extract timestamps from text columns
        
        Args:
            df: DataFrame with log entries
            
        Returns:
            Series: Parsed timestamps
        """
        # Common timestamp patterns
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}',  # ISO format
            r'\d{2}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}',     # US date format
            r'\d{2}-\d{2}-\d{4}\s\d{2}:\d{2}:\d{2}',     # EU date format
        ]
        
        timestamps = pd.Series([pd.NaT] * len(df))
        
        text_cols = self._get_text_columns(df)
        for col in text_cols:
            for pattern in timestamp_patterns:
                matches = df[col].str.extract(f'({pattern})', expand=False)
                if matches.notna().any():
                    try:
                        parsed = pd.to_datetime(matches, errors='coerce')
                        # Fill only NA values
                        timestamps = timestamps.fillna(parsed)
                    except:
                        continue
        
        return timestamps
    
    def _extract_ip_from_row(self, row):
        """
        Extract IP addresses from a row using multiple strategies
        """
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        # Check common IP columns first
        ip_columns = ['ip_address', 'source_ip', 'ip', 'client_ip', 'remote_ip', 
                     'sourceaddress', 'destinationip']
        for col in ip_columns:
            if col in row.index and pd.notna(row[col]):
                if isinstance(row[col], str):
                    match = re.search(ip_pattern, row[col])
                    if match:
                        return match.group()
                else:
                    # Try converting to string
                    try:
                        match = re.search(ip_pattern, str(row[col]))
                        if match:
                            return match.group()
                    except:
                        continue
        
        # Search in all string columns
        for col, value in row.items():
            if isinstance(value, str) and pd.notna(value):
                match = re.search(ip_pattern, value)
                if match:
                    return match.group()
        
        return None
    
    def detect_failed_logins(self):
        """
        Detect failed login attempts using common Windows event IDs and patterns
        """
        if self.logs_df.empty:
            print("No logs to analyze")
            return
        
        # Common Windows Event IDs for failed logins
        failed_login_event_ids = [4625, 4771, 4776, 529, 530, 531, 532, 533, 534, 535, 536, 537, 539]
        
        # Initialize failed logins dataframe
        failed_logins = pd.DataFrame()
        
        # Method 1: Check by Event ID
        if 'event_id_numeric' in self.logs_df.columns:
            event_failed = self.logs_df[
                self.logs_df['event_id_numeric'].isin(failed_login_event_ids)
            ].copy()
            if not event_failed.empty:
                event_failed['detection_method'] = 'event_id'
                failed_logins = pd.concat([failed_logins, event_failed], ignore_index=True)
        
        # Method 2: Check by keywords in message/description
        keyword_patterns = [
            r'logon failure',
            r'failed logon',
            r'authentication failed',
            r'incorrect password',
            r'bad password',
            r'account locked',
            r'account logon was rejected',
            r'wrong password',
            r'access denied',
            r'status: 0xc000006d',  # NT_STATUS_LOGON_FAILURE
            r'status: 0xc0000072',  # NT_STATUS_ACCOUNT_DISABLED
            r'status: 0xc0000234',  # NT_STATUS_ACCOUNT_LOCKED_OUT
        ]
        
        text_columns = self._get_text_columns(self.logs_df)
        
        for col in text_columns:
            for pattern in keyword_patterns:
                try:
                    mask = self.logs_df[col].astype(str).str.contains(pattern, case=False, na=False)
                    keyword_failed = self.logs_df[mask].copy()
                    if not keyword_failed.empty:
                        keyword_failed['detection_method'] = f'keyword_{pattern}'
                        failed_logins = pd.concat([failed_logins, keyword_failed], ignore_index=True)
                except Exception as e:
                    print(f"Error processing pattern '{pattern}' in column '{col}': {str(e)}")
                    continue
        
        # Remove duplicates
        if not failed_logins.empty:
            # Create a hash for each row to identify duplicates
            failed_logins['row_hash'] = failed_logins.apply(
                lambda row: hash(tuple(row.astype(str).values)), axis=1
            )
            failed_logins = failed_logins.drop_duplicates(subset='row_hash')
            failed_logins = failed_logins.drop(columns=['row_hash'])
            
            failed_logins['detection_time'] = datetime.now()
            
            # Categorize failure types
            failed_logins['failure_category'] = failed_logins.apply(
                self._categorize_failure, axis=1
            )
        
        self.failed_logins_df = failed_logins
        
        if not failed_logins.empty:
            print(f"Detected {len(failed_logins)} failed login attempts")
            if 'failure_category' in failed_logins.columns:
                print("\nFailure Categories:")
                print(failed_logins['failure_category'].value_counts())
        else:
            print("No failed login attempts detected")
    
    def _categorize_failure(self, row):
        """
        Categorize failure types based on log content
        """
        # Convert entire row to string for searching
        row_str = ' '.join([str(v) for v in row.values if pd.notna(v)]).lower()
        
        if any(term in row_str for term in ['account locked', 'locked out', '0xc0000234']):
            return 'Account Lockout'
        elif any(term in row_str for term in ['incorrect password', 'wrong password', 'bad password', '0xc000006d']):
            return 'Wrong Password'
        elif any(term in row_str for term in ['account disabled', '0xc0000072']):
            return 'Disabled Account'
        elif 'expired' in row_str:
            return 'Expired Password'
        elif 'time restriction' in row_str:
            return 'Time Restriction'
        elif 'workstation restriction' in row_str:
            return 'Workstation Restriction'
        elif 'logon type: 3' in row_str:
            return 'Network Logon Failure'
        elif 'logon type: 2' in row_str:
            return 'Interactive Logon Failure'
        elif 'kerberos' in row_str:
            return 'Kerberos Failure'
        elif 'ntlm' in row_str:
            return 'NTLM Failure'
        elif any(status in row_str for status in ['0xc000006a', '0xc0000064', '0xc0000070']):
            return 'Other NT Status Failure'
        else:
            return 'General Failure'
    
    def detect_suspicious_patterns(self):
        """
        Detect various suspicious patterns in the logs
        """
        if self.logs_df.empty:
            print("No logs to analyze")
            return
        
        suspicious_activities = []
        
        # 1. Brute Force Detection
        print("\n[+] Checking for brute force patterns...")
        brute_force = self._detect_brute_force()
        if not brute_force.empty:
            suspicious_activities.append(('Brute Force Attempts', brute_force))
        
        # 2. Multiple Failed Logins from Same IP
        print("[+] Checking for multiple failed logins from same IP...")
        ip_failures = self._detect_ip_failures()
        if not ip_failures.empty:
            suspicious_activities.append(('IP Failure Patterns', ip_failures))
        
        # 3. Off-hours Activity
        print("[+] Checking for off-hours activity...")
        off_hours = self._detect_off_hours_activity()
        if not off_hours.empty:
            suspicious_activities.append(('Off-hours Activity', off_hours))
        
        # 4. Account Enumeration
        print("[+] Checking for account enumeration...")
        enumeration = self._detect_account_enumeration()
        if not enumeration.empty:
            suspicious_activities.append(('Account Enumeration', enumeration))
        
        # 5. Geographical anomalies (if IP data available)
        print("[+] Checking for geographical anomalies...")
        geo_anomalies = self._detect_geographical_anomalies()
        if not geo_anomalies.empty:
            suspicious_activities.append(('Geographical Anomalies', geo_anomalies))
        
        # Combine all suspicious activities
        if suspicious_activities:
            all_suspicious = pd.concat(
                [df for _, df in suspicious_activities], 
                keys=[name for name, _ in suspicious_activities]
            )
            self.suspicious_activities = all_suspicious
            print(f"\n[!] Total suspicious activities detected: {len(all_suspicious)}")
            
            # Print summary of findings
            for pattern_name, pattern_df in suspicious_activities:
                print(f"   - {pattern_name}: {len(pattern_df)} instances")
        else:
            print("\n[+] No suspicious patterns detected")
    
    def _detect_brute_force(self):
        """
        Detect brute force attack patterns
        """
        if self.failed_logins_df.empty:
            print("   No failed logins for brute force detection")
            return pd.DataFrame()
        
        # Check if required columns exist
        required_cols = ['parsed_timestamp', 'extracted_ip']
        missing_cols = [col for col in required_cols if col not in self.failed_logins_df.columns]
        
        if missing_cols:
            print(f"   Missing columns for brute force detection: {missing_cols}")
            return pd.DataFrame()
        
        try:
            # Group by IP and time window (5-minute intervals)
            self.failed_logins_df['time_window'] = self.failed_logins_df['parsed_timestamp'].dt.floor('5min')
            
            # Count failures per IP per time window
            brute_force = self.failed_logins_df.groupby(
                ['extracted_ip', 'time_window']
            ).size().reset_index(name='failure_count')
            
            # Threshold: more than 5 failures in 5 minutes
            brute_force = brute_force[brute_force['failure_count'] > 5]
            
            if not brute_force.empty:
                print(f"   Detected {len(brute_force)} potential brute force patterns")
            
            return brute_force
            
        except Exception as e:
            print(f"   Error in brute force detection: {str(e)}")
            return pd.DataFrame()
    
    def _detect_ip_failures(self):
        """
        Detect multiple failed logins from same IP to different accounts
        """
        if self.failed_logins_df.empty:
            return pd.DataFrame()
        
        # Check if we have IP and username data
        has_ip = 'extracted_ip' in self.failed_logins_df.columns
        has_user = 'extracted_username' in self.failed_logins_df.columns
        
        if not has_ip:
            return pd.DataFrame()
        
        try:
            # Group by IP and count unique users and total attempts
            if has_user:
                # Calculate unique users per IP
                unique_users = self.failed_logins_df.groupby('extracted_ip')['extracted_username'].nunique()
                total_attempts = self.failed_logins_df.groupby('extracted_ip').size()
                
                ip_stats = pd.DataFrame({
                    'unique_users': unique_users,
                    'total_attempts': total_attempts
                }).reset_index()
                
                # Suspicious: multiple users from same IP OR many attempts
                suspicious_ips = ip_stats[
                    (ip_stats['unique_users'] > 3) | 
                    (ip_stats['total_attempts'] > 10)
                ]
            else:
                # If no username, just check total attempts
                total_attempts = self.failed_logins_df.groupby('extracted_ip').size()
                ip_stats = pd.DataFrame({
                    'total_attempts': total_attempts
                }).reset_index()
                
                suspicious_ips = ip_stats[ip_stats['total_attempts'] > 10]
            
            if not suspicious_ips.empty:
                print(f"   Found {len(suspicious_ips)} suspicious IP patterns")
            
            return suspicious_ips
            
        except Exception as e:
            print(f"   Error in IP failure detection: {str(e)}")
            return pd.DataFrame()
    
    def _detect_off_hours_activity(self):
        """
        Detect activity outside normal business hours
        """
        if 'parsed_timestamp' not in self.logs_df.columns:
            return pd.DataFrame()
        
        try:
            # Extract hour from timestamp
            self.logs_df['hour'] = self.logs_df['parsed_timestamp'].dt.hour
            
            # Define business hours (9 AM to 6 PM)
            off_hours_mask = (self.logs_df['hour'] < 9) | (self.logs_df['hour'] > 18)
            off_hours_activity = self.logs_df[off_hours_mask].copy()
            
            if off_hours_activity.empty:
                return pd.DataFrame()
            
            # Filter for security-related events
            security_keywords = ['logon', 'login', 'authentication', 'access', 
                               'failed', 'success', 'password', 'account']
            
            # Get text columns
            text_columns = self._get_text_columns(off_hours_activity)
            
            security_events = pd.DataFrame()
            for col in text_columns:
                col_data = off_hours_activity[col].astype(str).str.lower()
                for keyword in security_keywords:
                    mask = col_data.str.contains(keyword, na=False)
                    if mask.any():
                        events = off_hours_activity[mask].copy()
                        events['detected_keyword'] = keyword
                        security_events = pd.concat([security_events, events], ignore_index=True)
            
            # Remove duplicates
            if not security_events.empty:
                security_events = security_events.drop_duplicates()
                print(f"   Found {len(security_events)} off-hours security events")
            
            return security_events
            
        except Exception as e:
            print(f"   Error in off-hours detection: {str(e)}")
            return pd.DataFrame()
    
    def _detect_account_enumeration(self):
        """
        Detect possible account enumeration attacks
        """
        if self.failed_logins_df.empty:
            return pd.DataFrame()
        
        # Look for patterns of non-existent users
        enumeration_keywords = [
            r'user name not recognized',
            r'account not found',
            r'no such user',
            r'unknown user',
            r'user unknown',
            r'there is no such user',
            r'the specified account does not exist'
        ]
        
        text_columns = self._get_text_columns(self.failed_logins_df)
        
        enumeration_events = pd.DataFrame()
        for col in text_columns:
            col_data = self.failed_logins_df[col].astype(str).str.lower()
            for pattern in enumeration_keywords:
                try:
                    mask = col_data.str.contains(pattern, na=False)
                    events = self.failed_logins_df[mask].copy()
                    if not events.empty:
                        events['enumeration_pattern'] = pattern
                        enumeration_events = pd.concat([enumeration_events, events], ignore_index=True)
                except:
                    continue
        
        if not enumeration_events.empty:
            enumeration_events = enumeration_events.drop_duplicates()
            print(f"   Found {len(enumeration_events)} possible account enumeration attempts")
        
        return enumeration_events
    
    def _detect_geographical_anomalies(self):
        """
        Simple geographical anomaly detection based on IP patterns
        """
        if 'extracted_ip' not in self.logs_df.columns:
            return pd.DataFrame()
        
        try:
            # Extract first octet for basic "geographical" grouping
            def get_ip_class(ip):
                if pd.isna(ip) or not isinstance(ip, str):
                    return 'Unknown'
                
                parts = str(ip).split('.')
                if len(parts) >= 1:
                    try:
                        first_octet = int(parts[0])
                        if first_octet == 10:
                            return 'Private (10.x.x.x)'
                        elif first_octet == 172 and len(parts) > 1:
                            second_octet = int(parts[1])
                            if 16 <= second_octet <= 31:
                                return 'Private (172.16-31.x.x)'
                        elif first_octet == 192 and len(parts) > 1 and parts[1] == '168':
                            return 'Private (192.168.x.x)'
                        elif first_octet <= 126:
                            return 'Class A Public'
                        elif first_octet <= 191:
                            return 'Class B Public'
                        else:
                            return 'Class C Public'
                    except ValueError:
                        return 'Invalid'
                return 'Unknown'
            
            self.logs_df['ip_class'] = self.logs_df['extracted_ip'].apply(get_ip_class)
            
            # Count activities per IP class
            ip_class_counts = self.logs_df['ip_class'].value_counts().reset_index()
            ip_class_counts.columns = ['ip_class', 'count']
            
            # Look for anomalies: high percentage of private IPs in failed logins
            if not self.failed_logins_df.empty and 'extracted_ip' in self.failed_logins_df.columns:
                failed_ip_classes = self.failed_logins_df['extracted_ip'].apply(get_ip_class)
                failed_counts = failed_ip_classes.value_counts()
                
                print(f"   IP class distribution in failed logins:")
                for ip_class, count in failed_counts.head().items():
                    print(f"     {ip_class}: {count}")
            
            return ip_class_counts
            
        except Exception as e:
            print(f"   Error in geographical detection: {str(e)}")
            return pd.DataFrame()
    
    def generate_report(self):
        """
        Generate comprehensive security report
        """
        print("\n" + "="*60)
        print("WINDOWS SECURITY LOG ANALYSIS REPORT")
        print("="*60)
        
        print(f"\n1. LOG OVERVIEW")
        print(f"   Total log entries: {len(self.logs_df)}")
        
        if not self.logs_df.empty and 'parsed_timestamp' in self.logs_df.columns:
            time_min = self.logs_df['parsed_timestamp'].min()
            time_max = self.logs_df['parsed_timestamp'].max()
            if pd.notna(time_min) and pd.notna(time_max):
                print(f"   Time range: {time_min} to {time_max}")
        
        print(f"\n2. FAILED LOGIN SUMMARY")
        print(f"   Total failed login attempts: {len(self.failed_logins_df)}")
        
        if not self.failed_logins_df.empty:
            if 'extracted_ip' in self.failed_logins_df.columns:
                unique_ips = self.failed_logins_df['extracted_ip'].nunique()
                print(f"   Unique IPs with failures: {unique_ips}")
            
            if 'extracted_username' in self.failed_logins_df.columns:
                unique_users = self.failed_logins_df['extracted_username'].nunique()
                print(f"   Unique usernames with failures: {unique_users}")
        
        print(f"\n3. SUSPICIOUS PATTERNS DETECTED")
        if not self.suspicious_activities.empty:
            if hasattr(self.suspicious_activities.index, 'levels'):
                suspicious_counts = self.suspicious_activities.index.get_level_values(0).value_counts()
                for pattern, count in suspicious_counts.items():
                    print(f"   {pattern}: {count} instances")
        else:
            print("   No suspicious patterns detected")
        
        print(f"\n4. TOP THREAT INDICATORS")
        
        # Top attacking IPs
        if not self.failed_logins_df.empty and 'extracted_ip' in self.failed_logins_df.columns:
            top_ips = self.failed_logins_df['extracted_ip'].value_counts().head(5)
            if not top_ips.empty:
                print(f"\n   Top 5 IPs with failed logins:")
                for ip, count in top_ips.items():
                    if pd.notna(ip):
                        print(f"     {ip}: {count} attempts")
        
        # Most targeted accounts
        if not self.failed_logins_df.empty and 'extracted_username' in self.failed_logins_df.columns:
            top_accounts = self.failed_logins_df['extracted_username'].value_counts().head(5)
            if not top_accounts.empty:
                print(f"\n   Top 5 targeted accounts:")
                for account, count in top_accounts.items():
                    if pd.notna(account) and account != 'nan':
                        print(f"     {account}: {count} failures")
        
        print("\n" + "="*60)
        print("REPORT END")
        print("="*60)
    
    def visualize_findings(self, save_figures=False):
        """
        Create visualizations for the analysis findings
        """
        if self.logs_df.empty:
            print("No data to visualize")
            return
        
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        axes = axes.ravel()
        
        plot_counter = 0
        
        # Plot 1: Failed logins over time
        if (not self.failed_logins_df.empty and 
            'parsed_timestamp' in self.failed_logins_df.columns and
            self.failed_logins_df['parsed_timestamp'].notna().any()):
            
            try:
                ax1 = axes[plot_counter]
                # Resample to hourly frequency
                failed_copy = self.failed_logins_df.copy()
                failed_copy.set_index('parsed_timestamp', inplace=True)
                daily_failures = failed_copy.resample('H').size()
                
                if not daily_failures.empty:
                    ax1.plot(daily_failures.index, daily_failures.values, 
                            color='red', linewidth=2, marker='o', markersize=3)
                    ax1.set_title('Failed Logins Over Time', fontsize=12, fontweight='bold')
                    ax1.set_xlabel('Time')
                    ax1.set_ylabel('Failed Logins')
                    ax1.tick_params(axis='x', rotation=45)
                    ax1.grid(True, alpha=0.3)
                    plot_counter += 1
            except Exception as e:
                print(f"Error creating timeline plot: {str(e)}")
        
        # Plot 2: Failure categories
        if (not self.failed_logins_df.empty and 
            'failure_category' in self.failed_logins_df.columns):
            
            try:
                ax2 = axes[plot_counter]
                category_counts = self.failed_logins_df['failure_category'].value_counts()
                
                if not category_counts.empty:
                    colors = plt.cm.Set3(np.linspace(0, 1, len(category_counts)))
                    wedges, texts, autotexts = ax2.pie(
                        category_counts.values, 
                        labels=category_counts.index, 
                        autopct=lambda p: f'{p:.1f}%\n({int(p*sum(category_counts.values)/100)})',
                        colors=colors, 
                        startangle=90,
                        textprops={'fontsize': 9}
                    )
                    ax2.set_title('Failure Categories Distribution', fontsize=12, fontweight='bold')
                    plot_counter += 1
            except Exception as e:
                print(f"Error creating pie chart: {str(e)}")
        
        # Plot 3: Top IPs with failures
        if (not self.failed_logins_df.empty and 
            'extracted_ip' in self.failed_logins_df.columns):
            
            try:
                ax3 = axes[plot_counter]
                # Filter out NaN IPs
                valid_ips = self.failed_logins_df[self.failed_logins_df['extracted_ip'].notna()]
                top_ips = valid_ips['extracted_ip'].value_counts().head(10)
                
                if not top_ips.empty:
                    y_pos = np.arange(len(top_ips))
                    bars = ax3.barh(y_pos, top_ips.values, color='coral')
                    ax3.set_yticks(y_pos)
                    ax3.set_yticklabels(top_ips.index)
                    ax3.set_title('Top 10 IPs with Failed Logins', fontsize=12, fontweight='bold')
                    ax3.set_xlabel('Number of Failures')
                    
                    # Add value labels
                    for i, bar in enumerate(bars):
                        width = bar.get_width()
                        ax3.text(width + 0.1, bar.get_y() + bar.get_height()/2,
                                str(int(width)), va='center', fontsize=9)
                    
                    plot_counter += 1
            except Exception as e:
                print(f"Error creating bar chart: {str(e)}")
        
        # Plot 4: Hourly distribution of activities
        if ('parsed_timestamp' in self.logs_df.columns and 
            self.logs_df['parsed_timestamp'].notna().any()):
            
            try:
                ax4 = axes[plot_counter]
                # Extract hour and count
                self.logs_df['hour'] = self.logs_df['parsed_timestamp'].dt.hour
                hourly_counts = self.logs_df['hour'].value_counts().sort_index()
                
                if not hourly_counts.empty:
                    ax4.bar(hourly_counts.index, hourly_counts.values, 
                           alpha=0.7, color='steelblue', width=0.8)
                    ax4.set_title('Hourly Activity Distribution', fontsize=12, fontweight='bold')
                    ax4.set_xlabel('Hour of Day')
                    ax4.set_ylabel('Number of Events')
                    ax4.set_xticks(range(0, 24, 2))
                    ax4.grid(True, alpha=0.3, axis='y')
                    plot_counter += 1
            except Exception as e:
                print(f"Error creating hourly distribution: {str(e)}")
        
        # Plot 5: IP class distribution
        if 'ip_class' in self.logs_df.columns:
            try:
                ax5 = axes[plot_counter]
                ip_class_dist = self.logs_df['ip_class'].value_counts()
                
                if not ip_class_dist.empty:
                    bars = ax5.bar(range(len(ip_class_dist)), ip_class_dist.values, 
                                  color='lightgreen')
                    ax5.set_title('IP Address Class Distribution', fontsize=12, fontweight='bold')
                    ax5.set_xlabel('IP Class')
                    ax5.set_ylabel('Count')
                    ax5.set_xticks(range(len(ip_class_dist)))
                    ax5.set_xticklabels(ip_class_dist.index, rotation=45, ha='right')
                    
                    # Add value labels on top of bars
                    for bar in bars:
                        height = bar.get_height()
                        ax5.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                                f'{int(height)}', ha='center', va='bottom', fontsize=9)
                    
                    plot_counter += 1
            except Exception as e:
                print(f"Error creating IP class distribution: {str(e)}")
        
        # Plot 6: Suspicious patterns
        if not self.suspicious_activities.empty:
            try:
                ax6 = axes[plot_counter]
                # Extract pattern names from multi-index
                if hasattr(self.suspicious_activities.index, 'levels'):
                    pattern_counts = self.suspicious_activities.index.get_level_values(0).value_counts()
                    
                    if not pattern_counts.empty:
                        bars = ax6.bar(range(len(pattern_counts)), pattern_counts.values, 
                                      color='orange')
                        ax6.set_title('Detected Suspicious Patterns', fontsize=12, fontweight='bold')
                        ax6.set_xlabel('Pattern Type')
                        ax6.set_ylabel('Count')
                        ax6.set_xticks(range(len(pattern_counts)))
                        ax6.set_xticklabels(pattern_counts.index, rotation=45, ha='right')
                        
                        # Add value labels
                        for bar in bars:
                            height = bar.get_height()
                            ax6.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                                    f'{int(height)}', ha='center', va='bottom', fontsize=9)
                        
                        plot_counter += 1
            except Exception as e:
                print(f"Error creating suspicious patterns chart: {str(e)}")
        
        # Hide empty subplots
        for i in range(plot_counter, 6):
            axes[i].axis('off')
        
        plt.suptitle('Windows Security Log Analysis Dashboard', fontsize=16, fontweight='bold', y=1.02)
        plt.tight_layout()
        
        if save_figures:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            plt.savefig(f'security_analysis_{timestamp}.png', dpi=300, bbox_inches='tight')
            print(f"Visualization saved as 'security_analysis_{timestamp}.png'")
        
        plt.show()
    
    def export_results(self, format='csv'):
        """
        Export analysis results to file
        
        Args:
            format (str): Export format ('csv', 'excel', 'json')
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            if format == 'csv':
                if not self.failed_logins_df.empty:
                    self.failed_logins_df.to_csv(f'failed_logins_{timestamp}.csv', index=False)
                    print(f"Failed logins exported to 'failed_logins_{timestamp}.csv'")
                else:
                    print("No failed login data to export")
                
                if not self.suspicious_activities.empty:
                    self.suspicious_activities.to_csv(f'suspicious_activities_{timestamp}.csv')
                    print(f"Suspicious activities exported to 'suspicious_activities_{timestamp}.csv'")
                else:
                    print("No suspicious activities to export")
            
            elif format == 'excel':
                with pd.ExcelWriter(f'security_analysis_{timestamp}.xlsx', engine='openpyxl') as writer:
                    # Write summary sheet
                    summary_data = {
                        'Metric': ['Total Log Entries', 'Failed Logins', 'Suspicious Patterns'],
                        'Count': [len(self.logs_df), len(self.failed_logins_df), len(self.suspicious_activities)]
                    }
                    pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)
                    
                    # Write detailed data
                    if not self.failed_logins_df.empty:
                        self.failed_logins_df.to_excel(writer, sheet_name='Failed_Logins', index=False)
                    
                    if not self.suspicious_activities.empty:
                        self.suspicious_activities.to_excel(writer, sheet_name='Suspicious_Activities')
                    
                    if not self.logs_df.empty:
                        # Write sample of raw logs
                        self.logs_df.head(1000).to_excel(writer, sheet_name='Raw_Logs_Sample', index=False)
                
                print(f"Full analysis exported to 'security_analysis_{timestamp}.xlsx'")
            
            elif format == 'json':
                if not self.failed_logins_df.empty:
                    self.failed_logins_df.to_json(f'failed_logins_{timestamp}.json', orient='records')
                    print(f"Failed logins exported to 'failed_logins_{timestamp}.json'")
                else:
                    print("No failed login data to export")
            
            else:
                print(f"Unsupported format: {format}. Use 'csv', 'excel', or 'json'.")
                
        except Exception as e:
            print(f"Error exporting results: {str(e)}")

# Example usage function
def analyze_windows_logs(log_dir='./logs/', log_pattern='*.log'):
    """
    Main function to run the log analyzer
    
    Args:
        log_dir (str): Directory containing log files
        log_pattern (str): Pattern for log files
    """
    print("="*60)
    print("Windows Security Log Analyzer")
    print("="*60)
    
    # Initialize analyzer
    analyzer = WindowsLogAnalyzer(log_directory=log_dir, log_pattern=log_pattern)
    
    # Step 1: Load logs
    print("\n[1/5] Loading log files...")
    if not analyzer.load_logs():
        print("Failed to load logs. Exiting.")
        return analyzer
    
    # Step 2: Parse log entries
    print("\n[2/5] Parsing log entries...")
    analyzer.parse_log_entries()
    
    # Step 3: Detect failed logins
    print("\n[3/5] Detecting failed logins...")
    analyzer.detect_failed_logins()
    
    # Step 4: Detect suspicious patterns
    print("\n[4/5] Detecting suspicious patterns...")
    analyzer.detect_suspicious_patterns()
    
    # Step 5: Generate report
    print("\n[5/5] Generating report...")
    analyzer.generate_report()
    
    return analyzer

# Create sample log data for testing
def create_sample_logs(output_dir='./logs/', num_entries=500):
    """
    Create sample Windows security logs for testing
    
    Args:
        output_dir (str): Directory to save sample logs
        num_entries (int): Number of log entries to generate
    """
    import os
    import random
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Sample data
    event_types = ['Success', 'Failure']
    usernames = ['Administrator', 'John.Doe', 'Jane.Smith', 'ServiceAccount', 'Guest', 
                'BackupAdmin', 'SQLService', 'IIS_User', 'AD_Admin', 'Support']
    ips = ['192.168.1.{}'.format(i) for i in range(1, 51)] + \
          ['10.0.0.{}'.format(i) for i in range(1, 21)] + \
          ['172.16.0.{}'.format(i) for i in range(1, 11)]
    
    reasons = [
        'Wrong password',
        'Account locked out',
        'User not found',
        'Logon type not allowed',
        'Time restriction',
        'Workstation restriction',
        'Account disabled',
        'Password expired'
    ]
    
    # Generate logs
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    
    for i in range(num_entries):
        timestamp = base_time + timedelta(minutes=random.randint(0, 10080))
        event_type = random.choices(event_types, weights=[0.7, 0.3])[0]
        username = random.choice(usernames)
        ip = random.choice(ips)
        
        if event_type == 'Failure':
            reason = random.choice(reasons)
            event_id = random.choice([4625, 4771, 529, 530])
            log_entry = {
                'Timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'EventID': event_id,
                'EventType': 'Failure',
                'Username': username,
                'IPAddress': ip,
                'Description': f'Logon Failure: {reason}',
                'Reason': reason
            }
        else:
            event_id = 4624
            log_entry = {
                'Timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'EventID': event_id,
                'EventType': 'Success',
                'Username': username,
                'IPAddress': ip,
                'Description': 'Successful logon',
                'Reason': 'None'
            }
        
        logs.append(log_entry)
    
    # Create DataFrame and save
    df = pd.DataFrame(logs)
    output_file = os.path.join(output_dir, 'sample_security_logs.csv')
    df.to_csv(output_file, index=False)
    
    print(f"Created {num_entries} sample log entries in '{output_file}'")
    return output_file

if __name__ == "__main__":
    # Uncomment to create sample data for testing
    # create_sample_logs('./security_logs/', 1000)
    
    # Run the analyzer
    analyzer = analyze_windows_logs('./security_logs/', '*.csv')
    
    # Generate visualizations
    if not analyzer.logs_df.empty:
        analyzer.visualize_findings(save_figures=True)
    
    # Export results
    analyzer.export_results(format='excel')
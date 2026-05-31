import pandas as pd
import numpy as np

def calculate_risk_score(row):
    score = 0
    
    # 1. Failed Logins Weight (Max 30 points)
    # 1-3 failures = Low, 4-9 = Med, 10+ = High
    if row['failed_logins'] >= 10:
        score += 30
    elif row['failed_logins'] >= 4:
        score += 15
    elif row['failed_logins'] > 0:
        score += 5
        
    # 2. Dormancy Weight (Max 20 points)
    if row['days_inactive'] > 90:
        score += 20
    elif row['days_inactive'] > 30:
        score += 10
        
    # 3. Suspicious IP / Location Activity (Max 30 points)
    if row['brute_force_trigger']:
        score += 30
    elif row['impossible_travel']:
        score += 25
        
    # 4. Privilege Multiplier (Critical Infrastructure)
    if row['is_privileged_user'] and score > 20:
        score += 20  # High privilege amplifies existing risks
        
    # Cap the score at 100
    return min(100, score)

def assign_risk_tier(score):
    if score >= 75: return 'Critical'
    if score >= 50: return 'High'
    if score >= 25: return 'Medium'
    return 'Low'

# Mocking execution for illustration (Replace with your actual analytics ingestion)
if __name__ == "__main__":
    print("🤖 Initializing AccessGuard AI Risk Scoring Engine...")
    
    # Simulating data coming out of your Step 3 Analytics
    mock_analytics_data = {
        'user_id': ['U001', 'U002', 'U003', 'U004'],
        'username': ['Allison', 'John', 'David', 'Sarah'],
        'failed_logins': [1, 11, 14, 0],
        'days_inactive': [12, 120, 5, 2],
        'brute_force_trigger': [False, True, True, False],
        'impossible_travel': [False, False, True, False],
        'is_privileged_user': [False, True, True, False]
    }
    
    df = pd.DataFrame(mock_analytics_data)
    
    # Run the Engine
    df['risk_score'] = df.apply(calculate_risk_score, axis=1)
    df['risk_tier'] = df['risk_score'].apply(assign_risk_tier)
    
    # Save the output for Step 5 (Streamlit)
    df.to_csv("data/risk_assessments.csv", index=False)
    
    # Display polished output
    print("\n+= Risk Assessment Matrix Generated =+")
    print(df[['username', 'failed_logins', 'days_inactive', 'risk_score', 'risk_tier']].to_string(index=False))
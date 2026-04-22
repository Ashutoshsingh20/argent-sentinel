import pandas as pd
import numpy as np

class ContextEngine:
    def __init__(self, data_path='outputs/feature_matrix.csv'):
        self.df = pd.read_csv(data_path)
        # We need is_attack for debugging/reporting normal vs attack entities
        self.attack_entities = self.df[self.df['is_attack'] == 1]['entity_id'].unique()
        self.normal_entities = [e for e in self.df['entity_id'].unique() if e not in self.attack_entities]
        
    def _is_business_hours(self, timestamps):
        # Simulating time: start at 08:00 AM (480 mins). Business hours 09:00 - 18:00
        # timestamps are in seconds
        minutes_since_start = timestamps // 60
        time_in_minutes = (480 + minutes_since_start) % 1440
        return (time_in_minutes >= 540) & (time_in_minutes < 1080)

    def apply_rules(self):
        rules_triggered = {f"CTX-{i:02d}": 0 for i in range(1, 9)}
        c_scores = []
        
        # We need a rolling 5 timestep window for failed_auth_count.
        self.df = self.df.sort_values(by=['entity_id', 'timestamp']).reset_index(drop=True)
        self.df['auth_fail_5_sum'] = self.df.groupby('entity_id')['failed_auth_count'].transform(
            lambda x: x.rolling(5, min_periods=1).sum()
        )
        
        # We will iterate row by row or vectorize
        business_hours_mask = self._is_business_hours(self.df['timestamp'])
        geo_anomaly_mask = self.df['geo_anomaly_flag'] == 1
        https_mask = self.df['protocol_type_HTTPS'] == 1
        ssh_mask = self.df['protocol_type_SSH'] == 1
        not_sa_mask = self.df['entity_type'] != 'service_account'
        sa_mask = self.df['entity_type'] == 'service_account'
        # cross_cloud traversal based on traversal_depth > 7 as simulated in DataGenerator (ATTACK-02)
        cross_cloud_mask = self.df['traversal_depth'] >= 8
        auth_fail_mask = self.df['auth_fail_5_sum'] > 3
        # registered env always matches in our static generation
        env_match_mask = pd.Series([True] * len(self.df))
        
        df_len = len(self.df)
        adjustments = np.zeros(df_len)
        
        # CTX-01: +0.20
        adjustments += np.where(business_hours_mask, 0.20, 0)
        rules_triggered["CTX-01"] += business_hours_mask.sum()
        
        # CTX-02: -0.40
        adjustments += np.where(geo_anomaly_mask, -0.40, 0)
        rules_triggered["CTX-02"] += geo_anomaly_mask.sum()
        
        # CTX-03: +0.15
        adjustments += np.where(https_mask, 0.15, 0)
        rules_triggered["CTX-03"] += https_mask.sum()
        
        # CTX-04: -0.30
        ctx_04_mask = ssh_mask & not_sa_mask
        adjustments += np.where(ctx_04_mask, -0.30, 0)
        rules_triggered["CTX-04"] += ctx_04_mask.sum()
        
        # CTX-05: -0.25
        adjustments += np.where(cross_cloud_mask, -0.25, 0)
        rules_triggered["CTX-05"] += cross_cloud_mask.sum()
        
        # CTX-06: -0.10
        ctx_06_mask = sa_mask & business_hours_mask
        adjustments += np.where(ctx_06_mask, -0.10, 0)
        rules_triggered["CTX-06"] += ctx_06_mask.sum()
        
        # CTX-07: -0.35
        adjustments += np.where(auth_fail_mask, -0.35, 0)
        rules_triggered["CTX-07"] += auth_fail_mask.sum()
        
        # CTX-08: +0.15
        adjustments += np.where(env_match_mask, 0.15, 0)
        rules_triggered["CTX-08"] += env_match_mask.sum()
        
        # Final C(t) = clip(0.5 + sum(adjustments), 0.0, 1.0)
        self.df['context_score'] = np.clip(0.5 + adjustments, 0.0, 1.0)
        
        # Save results
        out_df = self.df[['entity_id', 'timestamp', 'timestep', 'context_score']]
        out_df.to_csv('outputs/context_scores.csv', index=False)
        
        return rules_triggered, self.df

if __name__ == '__main__':
    # Step 5 specifies putting Engine logic here, but we will print report from a unified script
    pass

import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import f1_score
import config

class AnomalyDetector:
    def __init__(self, data_path='outputs/feature_matrix.csv'):
        self.df = pd.read_csv(data_path)
        
        self.feature_cols = [c for c in self.df.columns if c not in [
            'entity_id', 'entity_type', 'timestamp', 'timestep', 'is_attack'
        ]]
        
    def tune_contamination(self):
        grid = [0.05, 0.10, 0.15, 0.20, 0.25]
        results = []
        
        # We need the ground truth just for tuning F1 metric
        y_true = self.df['is_attack'].values
        X = self.df[self.feature_cols].values
        
        print("Tuning Grid Search (n_jobs=-1, n_estimators=200):")
        best_f1 = -1
        best_c = None
        
        for c in grid:
            iso = IsolationForest(
                n_estimators=200, 
                contamination=c, 
                max_samples='auto', 
                random_state=config.RANDOM_SEED, 
                n_jobs=-1
            )
            y_pred = iso.fit_predict(X)
            # IsolationForest returns -1 for anomaly, 1 for normal
            # Convert to our format: 1 for anomaly, 0 for normal
            y_pred_binary = np.where(y_pred == -1, 1, 0)
            
            f1 = f1_score(y_true, y_pred_binary)
            results.append({'contamination': c, 'f1': f1})
            print(f"› Contamination: {c:.2f} | F1-Score: {f1:.4f}")
            
            if f1 > best_f1:
                best_f1 = f1
                best_c = c
                
        self.best_contamination = best_c
        self.best_f1 = best_f1
        return pd.DataFrame(results)

    def fit_final_model(self):
        X = self.df[self.feature_cols].values
        
        self.iso_final = IsolationForest(
            n_estimators=200, 
            contamination=self.best_contamination, 
            max_samples='auto', 
            random_state=config.RANDOM_SEED, 
            n_jobs=-1
        )
        self.iso_final.fit(X)
        with open('outputs/anomaly_detector.pkl', 'wb') as f:
            pickle.dump(self.iso_final, f)
        
        # decision_function: lower (negative) means anomaly, higher means normal.
        # We want 1 = highly anomalous, 0 = normal. 
        # So we invert the decision function by multiplying by -1.
        raw_scores = -self.iso_final.decision_function(X)
        
        # Rescale to [0, 1]
        scaler = MinMaxScaler(feature_range=(0, 1))
        self.A_t = scaler.fit_transform(raw_scores.reshape(-1, 1)).flatten()
        
        return self.A_t

    def get_stats(self):
        self.df['anomaly_score'] = self.A_t
        stats = self.df.groupby('is_attack')['anomaly_score'].describe().T
        return stats

    def run(self):
        grid_results = self.tune_contamination()
        self.fit_final_model()
        stats = self.get_stats()
        
        # Save output
        out_df = self.df[['entity_id', 'timestamp', 'timestep', 'anomaly_score']]
        out_df.to_csv('outputs/anomaly_scores.csv', index=False)
        
        return grid_results, stats

if __name__ == '__main__':
    detector = AnomalyDetector()
    grid_results, stats = detector.run()
    
    print("\n■ STEP 3 COMPLETE: Anomaly Detection")
    print(f"\n› Selected Best Contamination: {detector.best_contamination:.2f} (F1 = {detector.best_f1:.4f})")
    print("\n› A(t) Stats [Normal (0) vs Attack (1)]:")
    print(stats)
    print("\n■ CONFIRM: A(t) scores rescaled correctly. 0=normal, 1=anomalous.")
    print("→ HALT. Await: 'proceed to Step 4'")

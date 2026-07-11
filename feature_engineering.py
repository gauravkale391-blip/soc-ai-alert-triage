import pandas as pd
import numpy as np

print("Loading data...")
df = pd.read_parquet('data/final_dataset.parquet')
df = df.replace([np.inf, -np.inf], np.nan).dropna()


df['packets_per_byte'] = df['Total Fwd Packets'] / (df['Fwd Packets Length Total'] + 1)
df['iat_variability'] = df['Flow IAT Std'] / (df['Flow IAT Mean'] + 1)  
df['syn_to_total_ratio'] = df['SYN Flag Count'] / (df['Total Fwd Packets'] + df['Total Backward Packets'] + 1)
df['fwd_bwd_packet_ratio'] = df['Total Fwd Packets'] / (df['Total Backward Packets'] + 1)  
print("New features created:")
print(df[['packets_per_byte', 'iat_variability', 'syn_to_total_ratio', 'fwd_bwd_packet_ratio']].describe())


df.to_parquet('data/enhanced_dataset.parquet', index=False)
print("\nSaved enhanced dataset!")

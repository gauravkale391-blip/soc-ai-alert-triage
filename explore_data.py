import pandas as pd


df_benign = pd.read_parquet('data/Benign-Monday-no-metadata.parquet')
print("Benign shape:", df_benign.shape)
print("\nColumns:\n", df_benign.columns.tolist())
print("\nFirst few rows:\n", df_benign.head())

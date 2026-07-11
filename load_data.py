import pandas as pd
import glob

files = glob.glob('data/*.parquet')
print("Found files:", files)


dfs = []
for f in files:
    df = pd.read_parquet(f)
    dfs.append(df)
    print(f"{f}: {df.shape[0]} rows, Label values: {df['Label'].unique()}")


combined_df = pd.concat(dfs, ignore_index=True)
print("\nCombined shape:", combined_df.shape)
print("\nLabel distribution:\n", combined_df['Label'].value_counts())

combined_df.to_parquet('data/combined_dataset.parquet', index=False)
print("\nSaved combined dataset!")

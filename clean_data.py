import pandas as pd

df = pd.read_parquet('data/combined_dataset.parquet')


df['Label'] = df['Label'].astype(str).str.replace('�', '-', regex=False)

print("Cleaned label distribution:\n", df['Label'].value_counts())


print("\nMissing values:", df.isnull().sum().sum())
print("Infinite values:", (df.select_dtypes(include=['float64', 'int64']) 
                            .apply(lambda x: (x == float('inf')).sum())).sum())


df.to_parquet('data/cleaned_dataset.parquet', index=False)
print("\nSaved cleaned dataset!")

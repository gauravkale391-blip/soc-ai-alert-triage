import pandas as pd

df = pd.read_parquet('data/cleaned_dataset.parquet')


rare_classes = ['Heartbleed', 'Web Attack - Sql Injection', 'Infiltration']
df['Label'] = df['Label'].apply(lambda x: 'Rare_Attack' if x in rare_classes else x)

print("Final label distribution:\n", df['Label'].value_counts())

df.to_parquet('data/final_dataset.parquet', index=False)
print("\nSaved final dataset!")

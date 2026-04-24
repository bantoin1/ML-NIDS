import pandas as pd


def combine_datasets(input_files, output_file):
    dfs = []

    for file_path in input_files:
        df = pd.read_csv(file_path)
        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)
    combined = combined.sample(frac=1.0, random_state=42).reset_index(drop=True)
    combined.to_csv(output_file, index=False)

    print(f"Combined dataset saved to {output_file}")
    print(combined["label"].value_counts())


if __name__ == "__main__":
    combine_datasets(
        input_files=[
            "datasets/processed/public_features.csv",
            "datasets/processed/project_alert_features.csv",
            "datasets/processed/benign_features.csv",
        ],
        output_file="datasets/processed/final_combined_dataset.csv"
    )
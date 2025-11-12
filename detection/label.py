# label_data.py
import pandas as pd

# --- Timestamps based on your notes ---
NORMAL_START_TIME = 1758473973
NORMAL_END_TIME   = 1758474654

SYN_FLOOD_START_TIME = 1758474655  # Assumed to start right after normal traffic
SYN_FLOOD_END_TIME   = 1758474744

ICMP_FLOOD_START_TIME = 1758475466
ICMP_FLOOD_END_TIME   = 1758475812

# --- Define the labels ---
LABEL_BENIGN = 0
LABEL_SYN_FLOOD = 1
LABEL_ICMP_FLOOD = 2

def get_label(timestamp):
    """Assigns a label based on the timestamp of the flow."""
    if NORMAL_START_TIME <= timestamp <= NORMAL_END_TIME:
        return LABEL_BENIGN
    elif SYN_FLOOD_START_TIME <= timestamp <= SYN_FLOOD_END_TIME:
        return LABEL_SYN_FLOOD
    elif ICMP_FLOOD_START_TIME <= timestamp <= ICMP_FLOOD_END_TIME:
        return LABEL_ICMP_FLOOD
    else:
        return -1 # Mark as unlabeled/unclassified

# --- Main script logic ---
if __name__ == "__main__":
    input_csv = 'flow_data.csv'
    output_csv = 'labeled_flow_data.csv'

    print(f"Reading raw data from '{input_csv}'...")
    df = pd.read_csv(input_csv)
    
    # Apply the labeling function to create the new 'label' column
    print("Applying labels based on your timestamps...")
    df['label'] = df['timestamp'].apply(get_label)

    # Filter out any unlabeled data
    labeled_df = df[df['label'] != -1].copy()

    print("\nLabeling complete. Here are the counts for each label:")
    print(labeled_df['label'].value_counts())
    print(f"({LABEL_BENIGN}=Benign, {LABEL_SYN_FLOOD}=SYN Flood, {LABEL_ICMP_FLOOD}=ICMP Flood)")

    # Save the new DataFrame to a new file
    labeled_df.to_csv(output_csv, index=False)
    print(f"\n✅ Labeled data saved successfully to '{output_csv}'")
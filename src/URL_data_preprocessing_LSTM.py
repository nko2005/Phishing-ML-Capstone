
import dill
import re
import string
import pandas as pd
from urllib.parse import urlparse
import pickle
from URL_data_preprocessing import process_dataset

print("######################## Preparing Data for LSTM###############")

#Loading  Dill File
dill_file = 'phishing_links.dill' 
with open(dill_file, 'rb') as f:
    pickleData = dill.load(f)
    train_x, train_y = pickleData["train_x"], pickleData["train_y"]
    val_x, val_y = pickleData["val_x"], pickleData["val_y"]
    test_x, test_y = pickleData["test_x"], pickleData["test_y"]
    char_to_int = pickleData["char_to_int"]
    
# Reverse Mapping
int_to_char = {v: k for k, v in char_to_int.items()}
#Process Datasets
train_features = process_dataset(train_x)
val_features = process_dataset(val_x)
test_features = process_dataset(test_x)

# # Convert to DataFrame 
train_df = pd.DataFrame(train_features)
val_df = pd.DataFrame(val_features)
test_df = pd.DataFrame(test_features)

# # Add labels to the DataFrame
train_df['label'] = train_y
val_df['label'] = val_y
test_df['label'] = test_y

X_train=train_df.drop(columns=['label'])
y_train=train_df['label']

X_val=val_df.drop(columns=['label'])
y_val=val_df['label']

X_test=test_df.drop(columns=['label'])
y_test=test_df['label']


# Identify other categorical columns
categorical_columns = ['tld']  
# One-hot encode other categorical columns
X_train = pd.get_dummies(X_train, columns=categorical_columns)
X_val = pd.get_dummies(X_val, columns=categorical_columns)
X_test = pd.get_dummies(X_test, columns=categorical_columns)

# Align the columns of validation and test sets with the training set
X_val = X_val.reindex(columns=X_train.columns, fill_value=0)
X_test = X_test.reindex(columns=X_train.columns, fill_value=0)

# Save the preprocessed data
with open('processed_data/processed_data_LSTM.pkl', 'wb') as f:
    pickle.dump((X_train, y_train, X_val, y_val, X_test, y_test), f)

print("Preprocessed data saved to 'processed_data/processed_data_LSTM.pkl'")

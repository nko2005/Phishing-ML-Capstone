from sklearn.preprocessing import OneHotEncoder
import whois
import requests
from datetime import datetime
from urllib.parse import urlparse
import re
import string
import dill 
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.preprocessing import OneHotEncoder
from sklearn.utils import shuffle
import joblib

# Example
url = 'http://example.com'
#print(get_domain_age(url))def get_domain_age(url):
#     domain = urlparse(url).netloc
#     try:
#         whois_info = whois.whois(domain)
#         creation_date = whois_info.creation_date

#         if isinstance(creation_date, list):
#             creation_date = creation_date[0]

#         if creation_date is None:
#             return -1  # Unknown age

#         domain_age = (datetime.now() - creation_date).days
#         return domain_age
    
#     except Exception as e:
#         print(f"Error fetching WHOIS data for {domain}: {e}")
#         return -1  # Handle other errors by returning a default value



def get_tld(url):
    domain = urlparse(url).netloc
    # Check if it's an IP address
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        return 'IP Address'  # or return a placeholder like 'IP Address'
    
    # Remove 'www.' if present
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Split the domain by '.' and get the last part as TLD
    tld = domain.split('.')[-1]
    return tld




def check_domain_reputation(url):
    domain = urlparse(url).netloc
    # Use an API like VirusTotal or PhishTank
    # Example with VirusTotal (Note: Requires API key)
    api_key = 'YOUR_API_KEY'
    response = requests.get(f'https://www.virustotal.com/vtapi/v2/url/report?apikey={api_key}&resource={domain}')
    result = response.json()
    # Check the reputation score or categories
    reputation = result.get('positives', 0)  # Example field
    return reputation


def get_subdomain_count(url):
    domain = urlparse(url).netloc
    subdomains = domain.split('.')[:-2]
    return len(subdomains)


def uses_ip_address(url):
    domain = urlparse(url).netloc
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    return bool(ip_pattern.fullmatch(domain))



def get_parameter_count(url):
    query = urlparse(url).query
    return len(query.split('&')) if query else 0

def count_special_characters(url):
    special_chars = set(string.punctuation)
    return sum(1 for char in url if char in special_chars)
def has_https(url):
    return urlparse(url).scheme == 'https'
def has_query(url):
    return bool(urlparse(url).query)
def get_path_length(url):
    return len(urlparse(url).path)
def has_ip_address(url):
    return bool(re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', urlparse(url).netloc))
def has_at_symbol(url):
    return '@' in urlparse(url).netloc
def has_double_slash(url):
    return '//' in urlparse(url).path
def has_http(url):
    return 'http' in urlparse(url).scheme
def num_dots(url):
    return urlparse(url).netloc.count('.')



# Step 1: Loading  Dill File
dill_file = 'phishing_links.dill' 
with open(dill_file, 'rb') as f:
    pickleData = dill.load(f)
    train_x, train_y = pickleData["train_x"], pickleData["train_y"]
    val_x, val_y = pickleData["val_x"], pickleData["val_y"]
    test_x, test_y = pickleData["test_x"], pickleData["test_y"]
    char_to_int = pickleData["char_to_int"]

# Step 2: Inspect Data Shapes
print("Feature Shapes:\n")
print("Train set: {}".format(train_x.shape), 
      " Validation set: {}".format(val_x.shape),
      " Test set: {}".format(test_x.shape))

# Step 3: Reverse Mapping
int_to_char = {v: k for k, v in char_to_int.items()}

def int_seq_to_str(seq):
    return ''.join(int_to_char[i] for i in seq if i in int_to_char)

def extract_features(url):
    features = {}
    padding_char = '补'
    url=url.strip(padding_char)
    features['url'] = url
    features['length'] = len(url)
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_special_chars'] = count_special_characters(url)
    features['has_ip'] = int(uses_ip_address(url))
    #features['domain_age'] = get_domain_age(url)
    features['tld'] = get_tld(url)  #  store this as a one-hot encoding later
    #features['reputation'] = check_domain_reputation(url)  # Make sure to handle API usage correctly
    features['num_subdomains'] = get_subdomain_count(url)
    features['path_length'] = len(urlparse(url).path)
    features['has_query'] = int(bool(urlparse(url).query))
    features['has_https'] = int(urlparse(url).scheme == 'https')
    features['has_at_symbol'] = int('@' in urlparse(url).netloc)
    
    
    return features

def process_dataset(dataset_x):
    return [extract_features(int_seq_to_str(seq)) for seq in dataset_x]

# Step 4: Process Datasets
train_features = process_dataset(train_x)
val_features = process_dataset(val_x)
test_features = process_dataset(test_x)

# Convert to DataFrame 
train_df = pd.DataFrame(train_features)
val_df = pd.DataFrame(val_features)
test_df = pd.DataFrame(test_features)

# Add labels to the DataFrame
train_df['label'] = train_y
val_df['label'] = val_y
test_df['label'] = test_y


# print("First few rows of the training set:")
# print(train_df.head())

# print("First few rows of the validation set:")
# print(val_df.head())

# print("First few rows of the test set:")
# print(test_df.head())

# print("Feature names:")
# print(train_df.columns)

# print("Sample training data:")
# print(train_df.sample(5))
# df_cleaned = train_df

# print("########################Checking infos########################")
# print(train_df.info())
# print(val_df.info())
# print(test_df.info())
# print("########################Checking placeholders########################")
# # Check for entries that look like placeholders
# # Check for entries that contain '补' anywhere in the string
# placeholder_entries = train_df[train_df['url'].str.contains('补', na=False)]

# # Count and display the number of placeholder entries
# number_of_placeholders = len(placeholder_entries)
# print(f"Number of entries containing '补': {number_of_placeholders}")
# print(placeholder_entries)
# print("########################Checking int sequence########################")
# # Print the first few integer sequences
# print("Sample integer sequences from train_x:")
# print(train_x[:5])  # Adjust the index to show more or fewer entries as needed
# print("saving sample data")
# sample_df = train_df.sample(frac=0.01)  # Adjust the fraction as needed
# sample_df.to_csv('train_data_sample.csv', index=False)
print("########################Training model ########################")
X_train=train_df.drop(columns=['label','url'])
y_train=train_df['label']

X_val=val_df.drop(columns=['label','url'])
y_val=val_df['label']

X_test=test_df.drop(columns=['label','url'])
y_test=test_df['label']


# Identify other categorical columns
categorical_columns = ['tld']  # Replace with your actual categorical columns

# One-hot encode other categorical columns
X_train = pd.get_dummies(X_train, columns=categorical_columns)
X_val = pd.get_dummies(X_val, columns=categorical_columns)
X_test = pd.get_dummies(X_test, columns=categorical_columns)

# Align the columns of validation and test sets with the training set
X_val = X_val.reindex(columns=X_train.columns, fill_value=0)
X_test = X_test.reindex(columns=X_train.columns, fill_value=0)

# print("Training data shape after one-hot encoding:")
# print(X_train.info())
# print(X_val.info())
# print(X_test.info())

# Initialize the model
rf_model = RandomForestClassifier(n_estimators=100, random_state=42, warm_start=True)

# Define batch size
batch_size = 100000

# Shuffle the training data
X_train, y_train = shuffle(X_train, y_train, random_state=42)

# Train the model in batches
for start in range(0, X_train.shape[0], batch_size):
    end = min(start + batch_size, X_train.shape[0])
    rf_model.n_estimators += 10  # Increment the number of estimators
    rf_model.fit(X_train[start:end], y_train[start:end])
    print(f"Trained on batch {start} to {end}")


# Validate the model
rf_val_pred = rf_model.predict(X_val)
rf_val_accuracy = accuracy_score(y_val, rf_val_pred)
print(f"Random Forest Validation Accuracy: {rf_val_accuracy}")

# Test the model
rf_test_pred = rf_model.predict(X_test)
rf_test_accuracy = accuracy_score(y_test, rf_test_pred)
print(f"Random Forest Test Accuracy: {rf_test_accuracy}")

# Print confusion matrix
rf_conf_matrix = confusion_matrix(y_test, rf_test_pred)
print("Random Forest Confusion Matrix:")
print(rf_conf_matrix)

# Print classification report
rf_class_report = classification_report(y_test, rf_test_pred)
print("Random Forest Classification Report:")
print(rf_class_report)

# Save the trained model
model_filename = 'random_forest_model.joblib'
joblib.dump(rf_model, model_filename)
print(f"Model saved to {model_filename}")
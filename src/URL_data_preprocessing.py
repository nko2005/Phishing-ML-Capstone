import dill
import re
import string
import pandas as pd
from urllib.parse import urlparse
import pickle

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

 #Process Datasets
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


print("First few rows of the training set:")
print(train_df.head())

print("First few rows of the validation set:")
print(val_df.head())

print("First few rows of the test set:")
print(test_df.head())

print("Feature names:")
print(train_df.columns)

print("Sample training data:")
print(train_df.sample(5))
df_cleaned = train_df

#prepare data for ml model

X_train=train_df.drop(columns=['label','url'])
y_train=train_df['label']

X_val=val_df.drop(columns=['label','url'])
y_val=val_df['label']

X_test=test_df.drop(columns=['label','url'])
y_test=test_df['label']
categorical_columns = ['tld'] 
 
# One-hot encode other categorical columns
X_train = pd.get_dummies(X_train, columns=categorical_columns)
X_val = pd.get_dummies(X_val, columns=categorical_columns)
X_test = pd.get_dummies(X_test, columns=categorical_columns)

# Align the columns of validation and test sets with the training set
X_val = X_val.reindex(columns=X_train.columns, fill_value=0)
X_test = X_test.reindex(columns=X_train.columns, fill_value=0)

# Save the preprocessed data
with open('processed_data/preprocessed_data.pkl', 'wb') as f:
    pickle.dump((X_train, y_train, X_val, y_val, X_test, y_test), f)

print("Preprocessed data saved to 'processed_data/preprocessed_data.pkl'")
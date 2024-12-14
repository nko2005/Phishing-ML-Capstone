import pandas as pd
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from bs4 import BeautifulSoup



# Download stopwords if not already downloaded
try:
    nltk.download('stopwords')
    nltk.download('punkt')
except Exception as e:
    print("Error downloading NLTK resources:", e)
print("#####Data set processing###")
# Load dataset
df = pd.read_csv('Email_datasets/Enron.csv')

# Remove duplicates
df = df.drop_duplicates(subset='body')

# Remove NaN values
df = df.dropna(subset=['body'])

# Function to remove HTML tags
def remove_html_tags(text):
    return BeautifulSoup(text, "html.parser").get_text()

df['body'] = df['body'].apply(remove_html_tags)

# Remove stop words
stop_words = set(stopwords.words('english'))

def remove_stop_words(text):
    word_tokens = word_tokenize(text)
    filtered_text = [word for word in word_tokens if word.lower() not in stop_words]
    return ' '.join(filtered_text)

df['body'] = df['body'].apply(remove_stop_words)

# Function to remove HTML tags
def remove_html_tags(text):
    if '<' in text and '>' in text:
        return BeautifulSoup(text, "html.parser").get_text()
    return text

# Apply the function to remove HTML tags
df['body'] = df['body'].apply(remove_html_tags)

print("Number of emails:", len(df))
print("Number of unique emails:", len(df['body'].unique()))
print("Number of duplicates:", len(df) - len(df['body'].unique()))
print("Number of phishing emails:", len(df[df['label'] == 1]))
print("Number of non-phishing emails:", len(df[df['label'] == 0]))
print("Number of missing values:", df.isnull().sum().sum())
print("Number of empty emails:", len(df[df['body'] == '']))
print("Number of emails with one word:", len(df[df['body'].str.split().str.len() == 1]))
print("Number of emails with two words:", len(df[df['body'].str.split().str.len() == 2]))

# Remove missing values
df = df.dropna(subset=['body'])  # Drops rows where 'body' is NaN

# Remove empty emails
df = df[df['body'].str.strip() != '']  # Keep only non-empty emails

# Filter out emails with one or two words
df = df[df['body'].str.split().str.len() > 2]  # Keep only emails with more than 2 words

# Check final counts
print(f"Total emails after cleaning: {len(df)}")
print(f"Total phishing emails after cleaning: {len(df[df['label'] == 1])}")
print(f"Total non-phishing emails after cleaning: {len(df[df['label'] == 0])}")

# Calculate average length of emails
average_length = df['body'].str.split().str.len().mean()
print(f"Average length of emails: {average_length}")


# Save the cleaned dataframe to a new CSV file
df.to_csv('processed_data/Cleaned_Enron.csv', index=False)
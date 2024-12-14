from flask import Flask, request, jsonify
import torch
import torch.nn as nn
import torch.nn.functional as F  # For softmax
from transformers import BertTokenizer, BertForSequenceClassification
from flask_cors import CORS
app = Flask(__name__)
CORS(app)
# Define LSTM model architecture
class MyLSTMModel(nn.Module):
    def __init__(self, vocab_size=60, embedding_dim=128, hidden_dim=128, output_dim=2):
        super(MyLSTMModel, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim)
        self.lstm = nn.LSTM(embedding_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, output_dim)

    def forward(self, x):
        embedded = self.embedding(x)
        _, (hidden, _) = self.lstm(embedded)
        output = self.fc(hidden.squeeze(0))
        return output

# Load LSTM model and tokenizer
lstm_model = MyLSTMModel(vocab_size=59)  # Adjust vocab_size based on your training
lstm_model.load_state_dict(torch.load('Trained_models/saved_model_lstm.pth', weights_only=True))
lstm_model.eval()

# Device setup (GPU if available)
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
lstm_model.to(device)

# Tokenize URLs or text
characters = 'abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&\'()*+,;='
char_to_idx = {char: idx + 1 for idx, char in enumerate(characters)}
char_to_idx['<PAD>'] = 0  # Padding token

# Tokenize URLs
def tokenize_urls(urls, char_to_idx):
    tokenized_urls = []
    for url in urls:
        tokenized_url = [char_to_idx.get(char, 0) for char in url.lower()]  # Use 0 for unknown characters
        tokenized_urls.append(tokenized_url)
    return tokenized_urls

# Pad sequences to ensure consistent input length
def pad_sequences(sequences, maxlen=100, padding='post'):
    padded_sequences = []
    for seq in sequences:
        if len(seq) < maxlen:
            if padding == 'post':
                seq = seq + [0] * (maxlen - len(seq))
            else:
                seq = [0] * (maxlen - len(seq)) + seq
        else:
            seq = seq[:maxlen]
        padded_sequences.append(seq)
    return padded_sequences

@app.route('/predict_url', methods=['POST'])
def predict_url():
    data = request.json
    url = data.get('url')

    # Preprocess the URL
    url_tokenized = tokenize_urls([url], char_to_idx)
    url_padded = pad_sequences(url_tokenized, maxlen=100)

    # Convert the input to a tensor and move it to the right device
    url_tensor = torch.tensor(url_padded, dtype=torch.long).to(device)

    # Make a prediction using the LSTM model
    with torch.no_grad():
        output = lstm_model(url_tensor)
        
        # Apply softmax to convert logits to probabilities
        probabilities = F.softmax(output, dim=1)
        
        # Get the predicted class (index of the highest probability)
        predicted_class = torch.argmax(probabilities, dim=1).item()

    # Map the predicted class to the label
    prediction = 'safe' if predicted_class == 0 else 'phishing'

    # Return the prediction
    return jsonify({'url_prediction': prediction})

# Load the trained BERT model and tokenizer
model_path = 'Trained_models/saved_model_BERT'  # Adjust path to your saved model directory
tokenizer = BertTokenizer.from_pretrained(model_path)
bert_model = BertForSequenceClassification.from_pretrained(model_path)
bert_model.eval()  # Set the model to evaluation mode
bert_model.to(device)  # Move the BERT model to the same device

@app.route('/predict_text', methods=['POST'])
def predict_text():
    data = request.json
    text = data.get('text')

    # Tokenize the input text
    encodings = tokenizer([text], truncation=True, padding=True, max_length=512, return_tensors='pt')

    # Move encodings to the same device as the model
    encodings = {key: val.to(device) for key, val in encodings.items()}

    # Get model predictions
    with torch.no_grad():
        outputs = bert_model(**encodings)
        logits = outputs.logits
        predicted_class = torch.argmax(logits, dim=1).item()  # Get the class with highest probability

    # Return the prediction (1 for phishing, 0 for non-phishing)
    prediction = 'Phishing' if predicted_class == 1 else 'Non-Phishing'
    return jsonify({'text_prediction': prediction})

if __name__ == '__main__':
    app.run(debug=True)

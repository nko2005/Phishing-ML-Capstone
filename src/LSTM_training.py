
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report
import pickle
import matplotlib.pyplot as plt
from torch.utils.tensorboard import SummaryWriter
import seaborn as sns
import random
import numpy as np
# Set random seeds for reproducibility
def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False

set_seed(42)  # Set the seed to a fixed value
# Load the preprocessed data
with open('processed_data_LSTM.pkl', 'rb') as f:
    X_train, y_train, X_val, y_val, X_test, y_test = pickle.load(f)

# Check if GPU is available
device = torch.device('cuda' )
print(f"Using device: {device}")

# Define a character dictionary
characters = 'abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&\'()*+,;='
char_to_idx = {char: idx + 1 for idx, char in enumerate(characters)}
char_to_idx['<PAD>'] = 0  # Padding token

# Tokenize the URLs
def tokenize_urls(urls, char_to_idx):
    tokenized_urls = []
    for url in urls:
        tokenized_url = [char_to_idx.get(char, 0) for char in url.lower()]  # Use 0 for unknown characters
        tokenized_urls.append(tokenized_url)
    return tokenized_urls

X_train_sequences = tokenize_urls(X_train['url'], char_to_idx)
X_val_sequences = tokenize_urls(X_val['url'], char_to_idx)
X_test_sequences = tokenize_urls(X_test['url'], char_to_idx)

# Pad sequences to ensure consistent input length
max_sequence_length = 100  
def pad_sequences(sequences, maxlen, padding='post'):
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

X_train_padded = pad_sequences(X_train_sequences, max_sequence_length)
X_val_padded = pad_sequences(X_val_sequences, max_sequence_length)
X_test_padded = pad_sequences(X_test_sequences, max_sequence_length)

print("Padded sequences shape:")
print(len(X_train_padded), len(X_val_padded), len(X_test_padded))

# Define a custom Dataset
class URLDataset(Dataset):
    def __init__(self, sequences, labels):
        self.sequences = sequences
        self.labels = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        sequence = torch.tensor(self.sequences[idx], dtype=torch.long)
        label = torch.tensor(self.labels[idx], dtype=torch.long)
        return sequence, label

# Create DataLoader
train_dataset = URLDataset(X_train_padded, y_train)
val_dataset = URLDataset(X_val_padded, y_val)
test_dataset = URLDataset(X_test_padded, y_test)

train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)
test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)

# Define model 
class URLClassifier(nn.Module):
    def __init__(self, vocab_size, embedding_dim, hidden_dim, output_dim, dropout_prob=0.5):
        super(URLClassifier, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim)
        self.lstm = nn.LSTM(embedding_dim, hidden_dim, batch_first=True)
        self.dropout = nn.Dropout(dropout_prob)
        self.fc = nn.Linear(hidden_dim, output_dim)

    def forward(self, x):
        embedded = self.embedding(x)
        lstm_out, (hidden, _) = self.lstm(embedded)
        hidden = self.dropout(hidden.squeeze(0))
        output = self.fc(hidden)
        return output
    
# Hyperparameters
vocab_size = len(char_to_idx)
embedding_dim = 128
hidden_dim = 128
output_dim = 2  # Binary classification
dropout_prob = 0.5
learning_rate = 0.001
weight_decay = 1e-5  # Weight decay for regularization
num_epochs = 30  # Increased number of epochs

# Initialize the model
model = URLClassifier(vocab_size, embedding_dim, hidden_dim, output_dim, dropout_prob)
model.to(device)


# Define loss and optimizer
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=learning_rate, weight_decay=weight_decay)


# Define loss and optimizer
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)

# Initialize TensorBoard writer
writer = SummaryWriter(log_dir='./runs/lstm_training')

# Initialize lists to store metrics for custom plotting
train_losses = []
val_accuracies = []

# Training loop with logging
for epoch in range(num_epochs):
    model.train()
    running_loss = 0.0
    for sequences, labels in train_loader:
        sequences, labels = sequences.to(device), labels.to(device)
        optimizer.zero_grad()
        outputs = model(sequences)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()
        running_loss += loss.item()
    
    # Record training loss to TensorBoard
    train_loss = running_loss / len(train_loader)
    train_losses.append(train_loss)
    writer.add_scalar('Loss/train', train_loss, epoch)

    # Validation phase
    model.eval()
    all_preds = []
    all_labels = []
    with torch.no_grad():
        for sequences, labels in val_loader:
            sequences, labels = sequences.to(device), labels.to(device)
            outputs = model(sequences)
            _, preds = torch.max(outputs, 1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())

    # Calculate metrics and record to TensorBoard
    accuracy = accuracy_score(all_labels, all_preds)
    precision, recall, f1, _ = precision_recall_fscore_support(all_labels, all_preds, average='binary')

    val_accuracies.append(accuracy)
    writer.add_scalar('Accuracy/val', accuracy, epoch)
    writer.add_scalar('Precision/val', precision, epoch)
    writer.add_scalar('Recall/val', recall, epoch)
    writer.add_scalar('F1-score/val', f1, epoch)

    # Print the stats for each epoch
    print(f"Epoch {epoch+1}/{num_epochs}, Loss: {train_loss}, Accuracy: {accuracy}, Precision: {precision}, Recall: {recall}, F1: {f1}")

# After training, close the writer
writer.close()

# Plot metrics using matplotlib (optional)
plt.figure(figsize=(10, 6))

# Training loss plot
plt.subplot(2, 1, 1)
plt.plot(range(num_epochs), train_losses, label='Training Loss')
plt.title('Training Loss')
plt.xlabel('Epoch')
plt.ylabel('Loss')

# Validation accuracy plot
plt.subplot(2, 1, 2)
plt.plot(range(num_epochs), val_accuracies, label='Validation Accuracy', color='orange')
plt.title('Validation Accuracy')
plt.xlabel('Epoch')
plt.ylabel('Accuracy')

plt.tight_layout()
plt.show()

# Evaluate final model
model.eval()
all_preds = []
all_labels = []
with torch.no_grad():
    for sequences, labels in test_loader:
        sequences, labels = sequences.to(device), labels.to(device)
        outputs = model(sequences)
        _, preds = torch.max(outputs, 1)
        all_preds.extend(preds.cpu().numpy())
        all_labels.extend(labels.cpu().numpy())

# Calculate and print metrics
accuracy = accuracy_score(all_labels, all_preds)
precision, recall, f1, _ = precision_recall_fscore_support(all_labels, all_preds, average='binary')
print(f"Test Accuracy: {accuracy}")
print(f"Test Precision: {precision}")
print(f"Test Recall: {recall}")
print(f"Test F1-score: {f1}")

# Classification report
print(classification_report(all_labels, all_preds, target_names=['Non-Phishing', 'Phishing']))

# Confusion matrix plot
cm = confusion_matrix(all_labels, all_preds)
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Non-Phishing', 'Phishing'], yticklabels=['Non-Phishing', 'Phishing'])
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix')
plt.show()

# Save the model
model_save_path = 'Trained_models/saved_model_lstm.pth'
torch.save(model.state_dict(), model_save_path)
print(f"Model saved to {model_save_path}")

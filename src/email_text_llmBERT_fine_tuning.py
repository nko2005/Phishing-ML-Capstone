import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import torch
from transformers import BertTokenizer, BertForSequenceClassification, Trainer, TrainingArguments, TrainerCallback
from bs4 import BeautifulSoup
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import nltk
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns
import shutil
import json


print("#######LLM training######")
print(torch.cuda.is_available())
class MetricsLogger(TrainerCallback):
    def __init__(self):
        self.train_losses = []
        self.eval_losses = []
        self.train_accuracies = []
        self.eval_accuracies = []

    def on_log(self, args, state, control, logs=None, **kwargs):
        if logs is not None:
            if 'loss' in logs:
                self.train_losses.append(logs['loss'])
            if 'eval_loss' in logs:
                self.eval_losses.append(logs['eval_loss'])
            if 'eval_accuracy' in logs:
                self.eval_accuracies.append(logs['eval_accuracy'])
            if 'accuracy' in logs:
                 self.train_accuracies.append(logs['accuracy'])

# Initialize the metrics logger
metrics_logger = MetricsLogger()
# Load the cleaned dataset
df = pd.read_csv('processed_data/Cleaned_Enron.csv')
# # Encode labels
label_encoder = LabelEncoder()
df['label'] = label_encoder.fit_transform(df['label'])

# Split the data
train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)

# Tokenize the data
tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')

train_encodings = tokenizer(train_df['body'].tolist(), truncation=True, padding=True, max_length=512)
test_encodings = tokenizer(test_df['body'].tolist(), truncation=True, padding=True, max_length=512)

class EmailDataset(torch.utils.data.Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item['labels'] = torch.tensor(self.labels[idx])
        return item

    def __len__(self):
        return len(self.labels)
train_dataset = EmailDataset(train_encodings, train_df['label'].tolist())
test_dataset = EmailDataset(test_encodings, test_df['label'].tolist())
# Check if GPU is available
device = torch.device('cuda') if torch.cuda.is_available() else torch.device('cpu')
print(f"Using device: {device}")

#  # Load BERT model
model = BertForSequenceClassification.from_pretrained('bert-base-uncased', num_labels=2)
# model.to(device)# Move model to GPU if available

# Create a valid logging directory in the home directory
home_dir = os.path.expanduser('~')
log_dir = os.path.join(home_dir, '/training_logs/')
# Print debug information
print(f"Log directory path: {log_dir}")

# Create the logging directory
os.makedirs(log_dir, exist_ok=True)

# Ensure the directory is not read-only
os.chmod(log_dir, 0o777)
# Print debug information
print(f"Directory created: {os.path.isdir(log_dir)}")
print(f"Directory contents: {os.listdir(os.path.dirname(log_dir))}")


# Training arguments with mixed precision and gradient accumulation
training_args = TrainingArguments(
    output_dir='./results',
    num_train_epochs=3,
    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,
    warmup_steps=500,
    weight_decay=0.01,
    logging_dir=log_dir,  # Correctly specify the logging directory
    logging_steps=10,
    eval_strategy="epoch",  # Use evaluation_strategy instead of eval_strategy
    fp16=True,  # Enable mixed precision training
    gradient_accumulation_steps=4,  # Accumulate gradients over 4 steps
)

# Initialize the Trainer
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset,
    compute_metrics=lambda p: {
        'accuracy': accuracy_score(p.label_ids, p.predictions.argmax(-1)),
        'precision': precision_recall_fscore_support(p.label_ids, p.predictions.argmax(-1), average='binary')[0],
        'recall': precision_recall_fscore_support(p.label_ids, p.predictions.argmax(-1), average='binary')[1],
        'f1': precision_recall_fscore_support(p.label_ids, p.predictions.argmax(-1), average='binary')[2],
    },
    callbacks=[metrics_logger]
)

# Train the model
trainer.train()
# Save metrics to a JSON file
metrics = {
    'train_losses': metrics_logger.train_losses,
    'eval_losses': metrics_logger.eval_losses,
    'train_accuracies': metrics_logger.train_accuracies,
    'eval_accuracies': metrics_logger.eval_accuracies
}
# Evaluate the model
eval_results = trainer.evaluate()

# Print evaluation results
print("Evaluation Results:", eval_results)

# Predict on the test set
predictions = trainer.predict(test_dataset)
preds = predictions.predictions.argmax(-1)

# Calculate accuracy, precision, recall, and F1-score
accuracy = accuracy_score(test_df['label'], preds)
precision, recall, f1, _ = precision_recall_fscore_support(test_df['label'], preds, average='binary')

print(f"Accuracy: {accuracy}")
print(f"Precision: {precision}")
print(f"Recall: {recall}")
print(f"F1-score: {f1}")

# Classification report
print(classification_report(test_df['label'], preds, target_names=['Non-Phishing', 'Phishing']))
# Save all data to a JSON file
all_data = {
    'train_losses': metrics_logger.train_losses,
    'eval_losses': metrics_logger.eval_losses,
    'train_accuracies': metrics_logger.train_accuracies,
    'eval_accuracies': metrics_logger.eval_accuracies,
    'eval_results': eval_results,
    'predictions': preds.tolist(),
    'accuracy': accuracy,
    'precision': precision,
    'recall': recall,
    'f1': f1
}

with open('all_data_llm_finetuning.json', 'w') as f:
    json.dump(all_data, f)

# Confusion matrix
cm = confusion_matrix(test_df['label'], preds)
print(cm)
# Plot confusion matrix
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Non-Phishing', 'Phishing'], yticklabels=['Non-Phishing', 'Phishing'])
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix')
plt.show()





# with open('metrics.json', 'w') as f:
#     json.dump(metrics, f)


 #Load metrics from the JSON file
with open('all_data.json', 'r') as f:
    all_data = json.load(f)

train_losses = all_data['train_losses']
eval_losses = all_data['eval_losses']
train_accuracies = all_data['train_accuracies']
eval_accuracies = all_data['eval_accuracies']

# Adjust the length of the epochs array to match the length of the metric arrays
epochs = range(1, len(eval_losses) + 1)

# Plot training and evaluation metrics
plt.figure(figsize=(12, 6))

plt.subplot(1, 2, 1)
plt.plot(epochs, train_losses[:len(epochs)], label='Training Loss')
plt.plot(epochs, eval_losses, label='Evaluation Loss')
plt.xlabel('Epochs')
plt.ylabel('Loss')
plt.title('Training and Evaluation Loss')
plt.legend()

plt.subplot(1, 2, 2)
if train_accuracies:
    plt.plot(epochs, train_accuracies[:len(epochs)], label='Training Accuracy')
if eval_accuracies:
    plt.plot(epochs, eval_accuracies, label='Evaluation Accuracy')
plt.xlabel('Epochs')
plt.ylabel('Accuracy')
plt.title('Training and Evaluation Accuracy')
plt.legend()

plt.tight_layout()
plt.show()





# # Example prediction
# def predict(text, label_encoder):
#     encodings = tokenizer([text], truncation=True, padding=True, max_length=512)
#     dataset = EmailDataset(encodings, [0])  # Dummy label
#     predictions = trainer.predict(dataset)
#     predicted_label = predictions.predictions.argmax(-1).item()
#     return label_encoder.inverse_transform([predicted_label])[0]

# # Test the prediction function
# sample_text = "Congratulations! You've won a free iPhone. Click here to claim your prize."
# print(f"Prediction: {predict(sample_text, label_encoder)}")

# Output final stats
print(f"Total emails after cleaning: {len(df)}")
print(f"Total phishing emails after cleaning: {len(df[df['label'] == 1])}")
print(f"Total non-phishing emails after cleaning: {len(df[df['label'] == 0])}")

# Save the model and tokenizer
model_save_path = './saved_model'
os.makedirs(model_save_path, exist_ok=True)
model.save_pretrained(model_save_path)
tokenizer.save_pretrained(model_save_path)

import os
from matplotlib import pyplot as plt
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import torch
from transformers import RobertaTokenizer, RobertaForSequenceClassification, Trainer, TrainingArguments
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support, classification_report
import seaborn as sns
import json

# Load the cleaned dataset
df = pd.read_csv('processed_data/Cleaned_Enron.csv')

# Encode labels
label_encoder = LabelEncoder()
df['label'] = label_encoder.fit_transform(df['label'])

# Split the data
train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)

# Load the RoBERTa tokenizer and model
tokenizer = RobertaTokenizer.from_pretrained('roberta-base')
train_encodings = tokenizer(train_df['body'].tolist(), truncation=True, padding=True, max_length=512)
test_encodings = tokenizer(test_df['body'].tolist(), truncation=True, padding=True, max_length=512)

# Dataset class
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

# Load RoBERTa model
model = RobertaForSequenceClassification.from_pretrained('roberta-base', num_labels=2)
model.to(device)  # Ensure the model is on the correct device

# Training arguments
training_args = TrainingArguments(
    output_dir='./results',
    num_train_epochs=3,
    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,
    warmup_steps=500,
    weight_decay=0.01,
    logging_dir='./training_logs',
    logging_steps=10,
    eval_strategy="epoch",
    fp16=True,
    gradient_accumulation_steps=4,
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
    }
)

# Train the model
trainer.train()

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
# Confusion matrix
cm = confusion_matrix(test_df['label'], preds)

# Plot confusion matrix
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Non-Phishing', 'Phishing'], yticklabels=['Non-Phishing', 'Phishing'])
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix')
plt.show()
# Save the model and tokenizer
model_save_path = 'Trained_models/saved_model_ROBERTA'
os.makedirs(model_save_path, exist_ok=True)
model.save_pretrained(model_save_path)
tokenizer.save_pretrained(model_save_path)

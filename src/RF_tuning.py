import os
import pickle
import tempfile
import gc
import shutil
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from scipy.stats import randint

import numpy as np
import pandas as pd
#double check compatibility
print(np.__version__)
print(pd.__version__)
print("######################## Hyperparameter tuning RandomForest ########################")

# Load the preprocessed data
with open('processed_data/preprocessed_data.pkl', 'rb') as f:
    X_train, y_train, X_val, y_val, X_test, y_test = pickle.load(f)

print("Preprocessed data loaded from 'preprocessed_data.pkl'")

# Drop 'tld' columns from the datasets
X_train = X_train.drop(columns=[col for col in X_train.columns if 'tld' in col])
X_val = X_val.drop(columns=[col for col in X_val.columns if 'tld' in col])
X_test = X_test.drop(columns=[col for col in X_test.columns if 'tld' in col])
# Create a temporary directory
temp_dir = tempfile.mkdtemp(dir='D:\\Temp')
print(f"Temporary directory created at: {temp_dir}")

# Ensure the directory exists
if not os.path.exists(temp_dir):
    os.makedirs(temp_dir)
    print(f"Temporary directory created manually at: {temp_dir}")

# Configure joblib to use the temporary directory
joblib.parallel_backend('loky', temp_folder=temp_dir)
print(f"Configured joblib to use temporary directory: {temp_dir}")

# Use a larger subset of the training data for hyperparameter tuning
X_train_subset = X_train.sample(frac=0.4, random_state=42)  
y_train_subset = y_train[X_train_subset.index]

# Define the parameter distribution
# Define the refined parameter distribution based on previous results
# param_dist = {
#     'n_estimators': randint(400, 450),  # Narrowed range around the best n_estimators
#     'max_depth': [40, 45, 50, 55, 60],  # Narrowed range around the best max_depth
#     'min_samples_split': randint(8, 11),  # Narrowed range around the best min_samples_split
#     'min_samples_leaf': randint(2, 5),  # Narrowed range around the best min_samples_leaf
#     'bootstrap': [False]  # Keeping bootstrap as False based on best result
# }
param_dist = {
    'n_estimators': randint(350, 450),  # Slightly tighter range for n_estimators
    'max_depth': [10, 20, 30, 40],  # Reduced max_depth range
    'min_samples_split': randint(10, 20),  # Increased min_samples_split
    'min_samples_leaf': randint(3, 5),  # Increased min_samples_leaf
    'bootstrap': [False],
    'max_features': ['sqrt', 'log2']  # Limiting features to reduce overfitting
}


# Initialize the Random Forest model
rf = RandomForestClassifier(random_state=42)

# Use StratifiedKFold for better cross-validation
cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)  # Increased splits to 10

# Initialize Randomized Search
random_search = RandomizedSearchCV(estimator=rf, param_distributions=param_dist,
                                   n_iter=200, cv=cv, n_jobs=-1, verbose=2, scoring='accuracy')  # Increased n_iter

# Fit the model (this will take care of the hyperparameter tuning)
random_search.fit(X_train_subset, y_train_subset)

# Get the best parameters and best score
best_params = random_search.best_params_
best_score = random_search.best_score_

print(f"Best parameters: {best_params}")
print(f"Best cross-validation score: {best_score}")

# Evaluate the model on the validation set
y_val_pred = random_search.predict(X_val)
val_accuracy = accuracy_score(y_val, y_val_pred)
print(f"Validation Accuracy: {val_accuracy}")

# Evaluate the model on the test set
y_test_pred = random_search.predict(X_test)
test_accuracy = accuracy_score(y_test, y_test_pred)
print(f"Test Accuracy: {test_accuracy}")

# Print confusion matrix and classification report
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_test_pred))
print("Classification Report:")
print(classification_report(y_test, y_test_pred))

# Save the model
model_filename = 'random_forest_model_tuned.joblib'
joblib.dump(random_search.best_estimator_, model_filename)
print(f"Model saved to {model_filename}")

# Explicitly free memory
del X_train, y_train, X_train_subset, y_train_subset, random_search
gc.collect()

# Clean up the temporary directory
shutil.rmtree(temp_dir)
print(f"Temporary directory {temp_dir} removed.")
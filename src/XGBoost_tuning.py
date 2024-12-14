import os
import pickle
import tempfile
import gc
import shutil
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from hyperopt import fmin, tpe, hp, Trials
from xgboost import XGBClassifier
import numpy as np
import pandas as pd

print("######################## Hyperparameter tuning XGBoost with Hyperopt ########################")

# Load the preprocessed data
with open('processed_data/preprocessed_data.pkl', 'rb') as f:
    X_train, y_train, X_val, y_val, X_test, y_test = pickle.load(f)

print("Preprocessed data loaded from 'preprocessed_data.pkl'")

# Drop 'tld' columns from the datasets
X_train = X_train.drop(columns=[col for col in X_train.columns if 'tld' in col])
X_val = X_val.drop(columns=[col for col in X_val.columns if 'tld' in col])
X_test = X_test.drop(columns=[col for col in X_test.columns if 'tld' in col])

# Use a larger subset of the training data for hyperparameter tuning
X_train_subset = X_train.sample(frac=0.4, random_state=42)  
y_train_subset = y_train[X_train_subset.index]



# Create a temporary directory
temp_dir = tempfile.mkdtemp()
print(f"Temporary directory created at: {temp_dir}")

# Set random seeds for reproducibility
def set_seed(seed):
    np.random.seed(seed)
    joblib.parallel_backend('loky', temp_folder=temp_dir)
    print(f"Configured joblib to use temporary directory: {temp_dir}")

set_seed(42)

# Define the objective function
def objective(params):
    model = XGBClassifier(
        n_estimators=int(params['n_estimators']),
        max_depth=int(params['max_depth']),
        learning_rate=params['learning_rate'],
        subsample=params['subsample'],
        colsample_bytree=params['colsample_bytree'],
        gamma=params['gamma'],
        min_child_weight=int(params['min_child_weight']),
        use_label_encoder=False,
        eval_metric='logloss'
    )
    
    # Train the model
    model.fit(X_train_subset, y_train_subset)
    
    # Predict on the validation set
    y_pred = model.predict(X_val)
    
    # Calculate accuracy score
    accuracy = accuracy_score(y_val, y_pred)
    
    # Return negative accuracy since fmin minimizes the objective
    return -accuracy

# Define the search space for the hyperparameters
space = {
    'n_estimators': hp.quniform('n_estimators', 100, 1000, 50),
    'max_depth': hp.quniform('max_depth', 3, 10, 1),
    'learning_rate': hp.uniform('learning_rate', 0.01, 0.2),
    'subsample': hp.uniform('subsample', 0.6, 1.0),
    'colsample_bytree': hp.uniform('colsample_bytree', 0.6, 1.0),
    'gamma': hp.uniform('gamma', 0, 0.3),
    'min_child_weight': hp.quniform('min_child_weight', 1, 10, 1)
}

# Create a trials object to store results
trials = Trials()

# Run the optimization
best = fmin(fn=objective,                # The objective function to minimize
            space=space,                  # The search space
            algo=tpe.suggest,             # The optimization algorithm (TPE)
            max_evals=50,                 # Number of trials
            trials=trials)                # The trials object

print(f"Best hyperparameters found: {best}")

# Retrieve the best hyperparameters from the optimization process
best_params = best
best_model = XGBClassifier(
    n_estimators=int(best_params['n_estimators']),
    max_depth=int(best_params['max_depth']),
    learning_rate=best_params['learning_rate'],
    subsample=best_params['subsample'],
    colsample_bytree=best_params['colsample_bytree'],
    gamma=best_params['gamma'],
    min_child_weight=int(best_params['min_child_weight']),
    use_label_encoder=False,
    eval_metric='logloss'
)

# Train the best model on the full training data
best_model.fit(X_train, y_train)

# Evaluate the model on the validation set
y_val_pred = best_model.predict(X_val)
print(f"Validation Accuracy: {accuracy_score(y_val, y_val_pred)}")
print(f"Confusion Matrix:\n{confusion_matrix(y_val, y_val_pred)}")
print(f"Classification Report:\n{classification_report(y_val, y_val_pred)}")

# Evaluate the model on the test set
y_test_pred = best_model.predict(X_test)
print(f"Test Accuracy: {accuracy_score(y_test, y_test_pred)}")
print(f"Confusion Matrix:\n{confusion_matrix(y_test, y_test_pred)}")
print(f"Classification Report:\n{classification_report(y_test, y_test_pred)}")

# Save the best model
best_model_path = 'Trained_models/best_xgb_model_hyperopt.pkl'
joblib.dump(best_model, best_model_path)
print(f"Best model saved to {best_model_path}")

# Clean up the temporary directory
shutil.rmtree(temp_dir)
print(f"Temporary directory {temp_dir} removed")

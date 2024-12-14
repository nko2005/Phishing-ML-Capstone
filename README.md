# Phishing-ML-Capstone

## Overview

This project aims to develop a chrome extension to detect phishing Email Text and links. Phishing is a type of cyber attack where attackers disguise themselves as trustworthy entities to steal sensitive information such as usernames, passwords, and credit card details. 

## Features

- Data preprocessing and feature extraction
- Model training and evaluation
- Deployment of the model for real-time phishing detection

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/Phishing-ML-Capstone.git
    ```
2. Navigate to the project directory:
    ```bash
    cd Phishing-ML-Capstone
    ```
3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```


## Chrome Extension Setup

1. Navigate to `chrome://extensions/` in your Chrome browser.
2. Enable "Developer mode" by toggling the switch in the top right corner.
3. Click on the "Load unpacked" button.
4. Select the `chrome_extension` directory from the cloned repository.
5. The extension should now be loaded and visible in your extensions list.

## Training Pipeline
1. Run the preprocessing scripts:
    ```bash
    python URL_data_preprocessing_LSTM.py
    ```
    ```bash
    python URL_data_preprocessing.py
    ```
    ```bash
    python Text_data_preprocessing.py.py
    ```

2. Train and evaluate and save the models:
    ```bash
    python LSTM_training.py
    ```
    ```bash
    python RF_tuning.py
    ```
     ```bash
    python RF_tuning.py
    ```


## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the Creative Commons Attribution 4.0 International License. 

## Acknowledgements

- Thanks to the contributors of the datasets used in this project:

- Special thanks to my supervisor, professors, friends & family and  to the open-source community for providing valuable tools and libraries.




// Handle URL detection
document.getElementById('check-url').addEventListener('click', function() {
  const url = document.getElementById('url').value;
  
  if (!url) {
    document.getElementById('url-result').innerText = 'Please enter a URL!';
    return;
  }

  // Sending the URL to the Flask server for phishing detection
  fetch('http://127.0.0.1:5000/predict_url', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ url: url })
  })
  .then(response => response.json())
  .then(data => {
    // Display URL prediction result
    let resultMessage = `URL Prediction: ${data.url_prediction}`;
    document.getElementById('url-result').innerText = resultMessage;
    if (data.url_prediction === 'safe') {
      document.getElementById('url-result').style.color = 'green';
    } else {
      document.getElementById('url-result').style.color = 'red';
    }
  })
  .catch(error => {
    console.error('Error:', error);
    document.getElementById('url-result').innerText = 'Error occurred while checking the URL.';
  });
});

// Handle Text (Email Body) detection
document.getElementById('check-text').addEventListener('click', function() {
  const emailBody = document.getElementById('emailBody').value;
  
  if (!emailBody) {
    document.getElementById('text-result').innerText = 'Please enter the email body!';
    return;
  }

  // Sending the email body to the Flask server for phishing detection
  fetch('http://127.0.0.1:5000/predict_text', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ text: emailBody })
  })
  .then(response => response.json())
  .then(data => {
    // Display email body prediction result
    let resultMessage = `Text Prediction: ${data.text_prediction}`;
    document.getElementById('text-result').innerText = resultMessage;
  })
  .catch(error => {
    console.error('Error:', error);
    document.getElementById('text-result').innerText = 'Error occurred while checking the email body.';
  });
});

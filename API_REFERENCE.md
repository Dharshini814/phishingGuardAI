# 📡 PhishGuard AI - API Reference

Base URL: `http://localhost:8000`

Interactive Documentation: `http://localhost:8000/docs`

---

## Authentication
No authentication required for local development.

## Response Format
All responses are JSON. Errors include a `detail` field with the error message.

---

## Endpoints

### 1. Health Check
**GET** `/api/health`

Check if the API and ML model are ready.

**Response:**
```json
{
  "status": "ok",                    // "ok" | "degraded"
  "model_ready": true,               // boolean
  "model_name": "Logistic Regression", // string
  "timestamp": "2024-01-01T00:00:00Z",
  "service": "PhishGuard AI",
  "version": "1.0.0"
}
```

---

### 2. Predict URL
**POST** `/api/predict`

Analyze a URL for phishing indicators using ML.

**Request Body:**
```json
{
  "url": "https://example.com/login"
}
```

**Response:**
```json
{
  "prediction": "PHISHING",         // "PHISHING" | "LEGITIMATE"
  "confidence": 0.947,              // float [0, 1]
  "risk_score": 87,                 // int [0, 100]
  "risk_level": "HIGH",             // "LOW" | "MEDIUM" | "HIGH"
  "indicators": [                   // array of warning strings
    "Suspicious keyword detected",
    "Long URL"
  ],
  "positive_signals": [             // array of positive signals
    "HTTPS protocol detected",
    "Normal domain structure"
  ],
  "explanation": "The ML model classified...", // string
  "model_used": "Logistic Regression",
  "url_analyzed": "https://example.com/login"
}
```

**Error Responses:**
- `422 Unprocessable Entity` - Invalid URL format
- `503 Service Unavailable` - Model not available

---

### 3. Dashboard Statistics
**GET** `/api/dashboard`

Get aggregated statistics for the dashboard.

**Response:**
```json
{
  "total_analyzed": 42,
  "phishing_detected": 15,
  "legitimate_detected": 27,
  "model_accuracy": 0.9959,        // null if no metrics
  "best_model": "Logistic Regression",
  "recent_activity": [              // last 10 scans
    {
      "timestamp": "2024-01-01T10:30:00Z",
      "prediction": "PHISHING",
      "risk_score": 87
    }
  ]
}
```

---

### 4. Scan History
**GET** `/api/history`

Get all scan history records (newest first).

**Response:**
```json
{
  "history": [
    {
      "id": "uuid-string",
      "url": "https://example.com",
      "prediction": "LEGITIMATE",
      "confidence": 0.8234,
      "risk_score": 25,
      "risk_level": "LOW",
      "timestamp": "2024-01-01T10:30:00Z"
    }
  ],
  "total": 1
}
```

---

### 5. Clear History
**DELETE** `/api/history`

Clear all scan history for the current session.

**Response:**
```json
{
  "message": "History cleared. 5 records removed.",
  "cleared_count": 5
}
```

---

### 6. Model Metrics
**GET** `/api/model/metrics`

Get model training metrics and performance data.

**Response:**
```json
{
  "dataset_size": 1227,
  "train_size": 981,
  "test_size": 246,
  "feature_count": 19,
  "feature_names": ["url_length", "domain_length", ...],
  "best_model": "Logistic Regression",
  "models": [
    {
      "model_name": "Logistic Regression",
      "accuracy": 0.9959,
      "precision": 1.0000,
      "recall": 0.9917,
      "f1_score": 0.9958,
      "confusion_matrix": {
        "true_negative": 126,
        "false_positive": 0,
        "false_negative": 1,
        "true_positive": 119
      }
    },
    // ... other models
  ]
}
```

**Error Response:**
- `404 Not Found` - Model metrics not available (run training first)

---

### 7. Feature List
**GET** `/api/model/features`

Get list of ML features with descriptions.

**Response:**
```json
{
  "feature_count": 19,
  "features": [
    {
      "index": 0,
      "name": "url_length",
      "description": "Total character count of the URL"
    },
    // ... other features
  ]
}
```

---

## Risk Score Levels

| Score Range | Risk Level | Description |
|-------------|------------|-------------|
| 0–30        | LOW        | Minimal phishing risk |
| 31–60       | MEDIUM     | Moderate risk indicators |
| 61–100      | HIGH       | Strong phishing indicators |

---

## Feature Extraction

The system extracts 19 URL structural features:

1. **url_length** - Total character count
2. **domain_length** - Domain/hostname length
3. **path_length** - URL path length
4. **num_dots** - Count of '.' characters
5. **num_hyphens** - Count of '-' characters
6. **num_underscores** - Count of '_' characters
7. **num_slashes** - Count of '/' characters
8. **num_question_marks** - Count of '?' characters
9. **num_equals** - Count of '=' characters
10. **num_ampersands** - Count of '&' characters
11. **num_special_chars** - Non-alphanumeric, non-dot characters
12. **num_digits** - Numeric digit count
13. **has_at_symbol** - 1 if '@' present, else 0
14. **has_ip_address** - 1 if hostname is IP address
15. **has_https** - 1 if HTTPS scheme
16. **num_subdomains** - Subdomain count
17. **num_query_params** - Query parameter count
18. **has_suspicious_keyword** - 1 if phishing keywords detected
19. **is_url_shortener** - 1 if URL shortener domain

---

## Example Usage

### Python (requests)
```python
import requests

# Health check
response = requests.get("http://localhost:8000/api/health")
print(response.json())

# Predict URL
response = requests.post(
    "http://localhost:8000/api/predict",
    json={"url": "https://www.google.com"}
)
result = response.json()
print(f"Prediction: {result['prediction']}")
print(f"Confidence: {result['confidence']:.2%}")
```

### JavaScript (fetch)
```javascript
// Health check
const health = await fetch('http://localhost:8000/api/health');
const healthData = await health.json();
console.log(healthData);

// Predict URL
const response = await fetch('http://localhost:8000/api/predict', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ url: 'https://www.google.com' })
});
const result = await response.json();
console.log(`Prediction: ${result.prediction}`);
```

### cURL
```bash
# Health check
curl -X GET "http://localhost:8000/api/health"

# Predict URL
curl -X POST "http://localhost:8000/api/predict" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'
```

---

## CORS Configuration

The API allows requests from these origins:
- `http://localhost:5173` (Vite development server)
- `http://127.0.0.1:5173`
- `http://localhost:3000` (Alternative frontend port)

For production, update `ALLOWED_ORIGINS` in `backend/config.py`.

---

## Error Codes

| HTTP Code | Description |
|-----------|-------------|
| 200 | Success |
| 404 | Resource not found (metrics, model) |
| 422 | Validation error (invalid URL) |
| 500 | Internal server error |
| 503 | Service unavailable (model not loaded) |

---

## Rate Limiting
No rate limiting is currently implemented for local development. For production deployment, consider adding rate limiting middleware.

---

## Security Notes

1. **No URL Fetching**: The API never visits or downloads content from submitted URLs
2. **String Analysis Only**: Only URL structure and parsing is performed
3. **No Sensitive Data**: No credentials, cookies, or personal data are stored
4. **Input Validation**: All URLs are validated before processing
5. **Error Sanitization**: Python stack traces are not exposed to clients
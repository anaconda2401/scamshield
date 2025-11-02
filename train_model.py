# train_model.py
# This script is NOW FIXED to use your 'body' and 'label' columns.

import pandas as pd
import re
import joblib
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import time

# --- 1. CHECK NLTK DATA ---
print("Checking NLTK data (stopwords, wordnet)...")
try:
    nltk.data.find('corpora/stopwords')
    nltk.data.find('corpora/wordnet')
    print("NLTK data is ready.")
except LookupError:
    print("Downloading NLTK data...")
    nltk.download('stopwords')
    nltk.download('wordnet')

# --- 2. PREPROCESSING LOGIC ---
lemmatizer = WordNetLemmatizer()
stop_words = set(stopwords.words('english'))

def preprocess(message):
    message = str(message).lower() # Ensure it's a string and lowercase
    message = re.sub(r'http[s]?://\S+', '_URL_', message) # Mask URLs
    message = re.sub(r'\d+', '_NUM_', message) # Mask numbers
    message = re.sub(r'[^a-z\s_]', '', message) # Remove punctuation (keep underscores)
    tokens = message.split()
    tokens = [lemmatizer.lemmatize(w) for w in tokens if w not in stop_words]
    return ' '.join(tokens)

# --- 3. LOAD AND TRAIN MODEL ---
print("Starting model training...")
start_time = time.time()

# Load dataset
try:
    # Use error_bad_lines=False to skip problematic rows in some CSVs
    df = pd.read_csv('SpamAssasin.csv', on_bad_lines='skip')
except FileNotFoundError:
    print("\n--- ERROR ---")
    print("SpamAssasin.csv not found in this folder.")
    print("Please download it and place it here.")
    exit()
except Exception as e:
    print(f"Error loading CSV: {e}")
    exit()

print(f"CSV Columns Found: {df.columns.tolist()}\n")

# --- THIS IS THE FIX ---
# We are using 'body' and 'label' based on your CSV sample
TEXT_COLUMN_NAME = 'body'
LABEL_COLUMN_NAME = 'label'
# ---------------------

# Prepare data
try:
    df = df[[TEXT_COLUMN_NAME, LABEL_COLUMN_NAME]]
    df.columns = ['text', 'label'] # Rename them to 'text' and 'label'
except KeyError as e:
    print(f"--- KEY ERROR! ---")
    print(f"Column not found: {e}")
    print("Your CSV is missing one of the required columns: 'body' or 'label'")
    exit()

# Drop any rows with missing text
df = df.dropna(subset=['text'])

# Convert labels (assuming 1=Spam, 0=Not Scam)
df['label'] = df['label'].astype(int)
print(f"Loaded {len(df)} emails.")

# Preprocess the text
print("Preprocessing all email text... (This is the long step)")
df['processed_text'] = df['text'].apply(preprocess)
print("Preprocessing complete.")

# Define features (X) and target (y)
X = df['processed_text']
y = df['label']

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# --- 4. CREATE AND TRAIN MODELS ---
print("Training TfidfVectorizer (vectorizer.pkl)...")
vectorizer = TfidfVectorizer(max_features=5000) # Limit to top 5000 words
X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

print("Training Logistic Regression model (model.pkl)...")
ml_model = LogisticRegression(max_iter=1000)
ml_model.fit(X_train_tfidf, y_train)

print("Training complete.")
end_time = time.time()

# --- 5. EVALUATE THE MODEL ---
print("\n--- Model Evaluation (On Test Set) ---")
y_pred = ml_model.predict(X_test_tfidf)
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Not Scam (0)', 'Scam (1)']))

# --- 6. SAVE YOUR MODELS ---
joblib.dump(vectorizer, 'vectorizer.pkl')
joblib.dump(ml_model, 'model.pkl')

print("\n--- SUCCESS! ---")
print(f"Total training time: {end_time - start_time:.2f} seconds.")
print("Models saved as 'vectorizer.pkl' and 'model.pkl'.")
print("You can now upload your project to PythonAnywhere.")
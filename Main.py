import numpy as np
import pandas as pd
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.layers import Input, Embedding, Conv1D, MaxPooling1D, GlobalMaxPooling1D, Dense, Dropout
from tensorflow.keras.models import Model
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import logging

# Setup logging
logging.basicConfig(filename='debug.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s')

try:
    data = pd.read_csv('urlset.csv', encoding='latin1', usecols=['domain', 'label'], low_memory=False)
except UnicodeDecodeError:
    data = pd.read_csv('urlset.csv', encoding='ISO-8859-1', usecols=['domain', 'label'], low_memory=False)

data['domain'] = data['domain'].astype(str).fillna('')
data['label'] = pd.to_numeric(data['label'], errors='coerce').fillna(0).astype(int)
data = data[data['label'].isin([0, 1])]

shuffled_data = data.sample(frac=1).reset_index(drop=True)  # Shuffle the DataFrame
first_100_values = shuffled_data  # Get the first 100 rows
#first_100_values = shuffled_data.head(100)

urls = first_100_values['domain'].values
labels = first_100_values['label'].values

tokenizer = Tokenizer(num_words=5000)
tokenizer.fit_on_texts(urls)
sequences = tokenizer.texts_to_sequences(urls)
maxlen = 100
padded_sequences = pad_sequences(sequences, maxlen=maxlen)

input_layer = Input(shape=(maxlen,))
embedding_layer = Embedding(input_dim=5000, output_dim=128)(input_layer)
conv_layer = Conv1D(filters=64, kernel_size=5, activation='relu')(embedding_layer)
pool_layer = MaxPooling1D(pool_size=2)(conv_layer)
conv_layer2 = Conv1D(filters=128, kernel_size=5, activation='relu')(pool_layer)
global_pool_layer = GlobalMaxPooling1D()(conv_layer2)
dropout_layer = Dropout(0.5)(global_pool_layer)
dense_layer = Dense(128, activation='relu')(dropout_layer)
output_layer = Dense(1, activation='sigmoid')(dense_layer)

cnn_model = Model(inputs=input_layer, outputs=output_layer)
cnn_model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
cnn_model.fit(padded_sequences, labels, epochs=10, batch_size=32, validation_split=0.2)
cnn_model.summary()

feature_extractor = Model(inputs=cnn_model.input, outputs=cnn_model.layers[-2].output)
features = feature_extractor.predict(padded_sequences)

X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)
svm_classifier = SVC(kernel='linear')
svm_classifier.fit(X_train, y_train)
y_pred = svm_classifier.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"SVM Accuracy: {accuracy}")

def predict_malicious_url(url):
    sequence = tokenizer.texts_to_sequences([url])
    padded_sequence = pad_sequences(sequence, maxlen=maxlen)
    feature = feature_extractor.predict(padded_sequence)
    prediction = svm_classifier.predict(feature)
    return prediction[0]

# Example test URLs
test_urls = [
    "www.dghjdgf.com/paypal.co.uk/cycgi-bin/webscrcmd=_home-customer&nav=1/loading.php",
    "code.google.com/p/pysqlite/"
]
for url in test_urls:
    result = predict_malicious_url(url)
    print(f"URL: {url} - Malicious: {result}")
    logging.info(f"URL: {url} - Malicious: {result}")

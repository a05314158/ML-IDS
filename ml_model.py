import numpy as np
import joblib
import os
import tensorflow as tf
from abc import ABC, abstractmethod
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from tf_autoencoder import create_autoencoder
from config import NUM_FEATURES, NN_HIDDEN_LAYER_SIZE, NN_EPOCHS, NN_LEARNING_RATE, NN_BATCH_SIZE, CONTAMINATION


class BaseDetector(ABC):
    def __init__(self):
        self.scaler = StandardScaler()
        self.initial_threshold = 0.0

    def save(self, model_path, model_obj):
        joblib.dump(self.scaler, f"{model_path}_scaler.joblib")
        joblib.dump(self.initial_threshold, f"{model_path}_threshold.joblib")
        self._save_model_file(model_path, model_obj)

    def load(self, model_path):
        scaler_path = f"{model_path}_scaler.joblib"
        threshold_path = f"{model_path}_threshold.joblib"
        if all(os.path.exists(p) for p in [scaler_path, threshold_path]):
            self.scaler = joblib.load(scaler_path)
            self.initial_threshold = joblib.load(threshold_path)
            return self._load_model_file(model_path)
        return False

    @abstractmethod
    def _save_model_file(self, path, obj): pass

    @abstractmethod
    def _load_model_file(self, path): pass

    @abstractmethod
    def train_and_save_model(self, X_train, model_path): pass

    @abstractmethod
    def predict(self, X_new): pass


class IsolationForestDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        self.model = IsolationForest(contamination=CONTAMINATION, random_state=42)

    def _save_model_file(self, path, obj): joblib.dump(obj, f"{path}.joblib")

    def _load_model_file(self, path):
        self.model = joblib.load(f"{path}.joblib")
        return True

    def train_and_save_model(self, X_train, model_path):
        X_scaled = self.scaler.fit_transform(X_train)
        self.model.fit(X_scaled)
        self.initial_threshold = np.percentile(self.model.decision_function(X_scaled), 5.0)
        self.save(model_path, self.model)

    def predict(self, X_new):
        return self.model.decision_function(self.scaler.transform(X_new))[0]


class TFAutoencoderDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        self.model = None

    def _save_model_file(self, path, obj): obj.save(f"{path}.keras")

    def _load_model_file(self, path):
        self.model = tf.keras.models.load_model(f"{path}.keras")
        return True

    def train_and_save_model(self, X_train, model_path):
        X_scaled = self.scaler.fit_transform(X_train)
        self.model = create_autoencoder(X_train.shape[1], 8, 0.005)

        monitor = tf.keras.callbacks.EarlyStopping(
            monitor='val_loss', min_delta=0.0001, patience=10, restore_best_weights=True, verbose=0
        )
        self.model.fit(
            X_scaled, X_scaled, epochs=NN_EPOCHS, batch_size=NN_BATCH_SIZE,
            validation_split=0.2, callbacks=[monitor], verbose=0, shuffle=True
        )

        reconstructed = self.model.predict(X_scaled, verbose=0)
        errors = np.mean(np.abs(X_scaled - reconstructed), axis=1)
        self.initial_threshold = np.percentile(errors, 95.0)
        self.save(model_path, self.model)

    def predict(self, X_new):
        X_scaled = self.scaler.transform(X_new)
        reconstructed = self.model.predict(X_scaled, verbose=0)
        return float(np.mean(np.square(X_scaled - reconstructed)))
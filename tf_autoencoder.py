import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, Dropout


def create_autoencoder(input_size: int, hidden_size: int, learning_rate: float) -> Model:
    input_layer = Input(shape=(input_size,), name="input")

    encoded = Dense(hidden_size, activation='relu')(input_layer)
    encoded = Dropout(0.1)(encoded)  # Борется с переобучением (ML tuning)

    decoded = Dense(input_size, activation='linear')(encoded)

    autoencoder = Model(inputs=input_layer, outputs=decoded, name="SmartAutoencoder")
    autoencoder.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate), loss='mae')

    return autoencoder
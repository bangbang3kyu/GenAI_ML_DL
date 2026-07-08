from tensorflow.keras.models import load_model
import numpy as np

# 모델 로드
loaded_model = load_model('classification_model.keras')
print("Model loaded successfully.")

# 새로운 데이터에 대한 예측
sample_data = np.random.rand(1, 10) # 1개의 샘플 데이터
prediction = loaded_model.predict(sample_data)
print(f"Prediction for {sample_data}: {prediction}")
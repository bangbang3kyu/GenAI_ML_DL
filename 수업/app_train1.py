# 파이썬에서 병렬 처리(Parallel Processing)와 대용량 데이터 객체 직렬화(Object Serialization)를 빠르고 쉽게 구현할 수 있도록 돕는 라이브러리입니다. 
# 특히 머신러닝 모델이나 대규모 데이터셋을 다룰 때 연산 속도를 크게 향상시킵니다
from sklearn.linear_model import LinearRegression
from sklearn.datasets import make_regression
import joblib

# 샘플 데이터 생성 및 모델 학습
X, y = make_regression(n_samples=100, n_features=1, noise=0.1)
model = LinearRegression()
model.fit(X,y)

# 모델 -> 파일로 저장
joblib.dump(model, 'linear_model.pkl')
print("Model saved successfully")


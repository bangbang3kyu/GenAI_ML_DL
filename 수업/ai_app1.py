from sklearn.datasets import make_regression
import joblib

X , y = make_regression(n_samples=10, n_features=1, noise=0.1)

# 모델 파일 로드
loaded_model = joblib.load('linear_model.pkl')
print("Load Ok!!")

y_pred = loaded_model.predict(X)
print(y_pred)
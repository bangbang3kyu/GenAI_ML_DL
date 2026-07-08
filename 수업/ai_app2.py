from sklearn.datasets import make_regression
import pickle

X , y = make_regression(n_samples=10, n_features=1, noise=0.1)

# 모델 파일 로드
with open('linear_model2.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
    print("모델 로드 성공!")

# 모델 사용
y_pred = loaded_model.predict(X)

print(y_pred)

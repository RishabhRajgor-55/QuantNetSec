import joblib

model = joblib.load("intrusion_model.pkl")

from sklearn.pipeline import Pipeline

if isinstance(model, Pipeline):
    for step_name, step in model.named_steps.items():
        print(f"Checking step: {step_name}")
        if hasattr(step, "feature_names_in_"):
            print(step.feature_names_in_)
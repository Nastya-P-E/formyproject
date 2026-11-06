import pandas as pd

df = pd.read_csv("data.csv")
features = [c for c in df.columns if c not in ("id", "ocenka")]
grouped = df.groupby(features)["ocenka"].agg(["count", "sum"])
# count — сколько строк в группе, sum — сколько единиц
# максимум из (sum, count - sum)
correct = grouped.apply(lambda r: max(r["sum"], r["count"] - r["sum"]), axis=1).sum()
accuracy = correct / len(df)
print(round(accuracy, 4))
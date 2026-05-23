import os

import numpy as np
import pandas as pd


FEATURES = [
    "duration",
    "protocol_type",
    "src_bytes",
    "dst_bytes",
    "num_failed_logins",
    "count",
    "srv_count",
    "serror_rate",
    "rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "dst_host_count",
    "dst_host_srv_count",
]

ATTACK_PROFILES = {
    "Normal": {
        "duration": (1.4, 1.2),
        "protocol": [0.72, 0.22, 0.06],
        "src_bytes": (5.2, 1.0),
        "dst_bytes": (6.0, 1.1),
        "failed_logins": 0.08,
        "count": (8, 45),
        "srv_count": (6, 40),
        "serror": (0.6, 8.0),
        "rerror": (0.5, 10.0),
        "same_srv": (7.5, 1.4),
        "diff_srv": (0.8, 7.0),
        "dst_host_count": (20, 110),
        "dst_host_srv_count": (15, 95),
    },
    "DoS": {
        "duration": (0.18, 0.18),
        "protocol": [0.82, 0.08, 0.10],
        "src_bytes": (4.6, 0.9),
        "dst_bytes": (3.2, 0.8),
        "failed_logins": 0.03,
        "count": (160, 360),
        "srv_count": (120, 300),
        "serror": (7.5, 1.2),
        "rerror": (2.6, 3.2),
        "same_srv": (7.0, 1.3),
        "diff_srv": (1.2, 6.0),
        "dst_host_count": (180, 255),
        "dst_host_srv_count": (145, 255),
    },
    "Exploit": {
        "duration": (3.0, 2.0),
        "protocol": [0.88, 0.10, 0.02],
        "src_bytes": (8.4, 1.3),
        "dst_bytes": (5.2, 1.4),
        "failed_logins": 1.2,
        "count": (18, 95),
        "srv_count": (12, 80),
        "serror": (3.6, 2.5),
        "rerror": (2.8, 3.0),
        "same_srv": (4.2, 3.0),
        "diff_srv": (2.5, 3.8),
        "dst_host_count": (45, 180),
        "dst_host_srv_count": (18, 130),
    },
    "Reconnaissance": {
        "duration": (0.55, 0.55),
        "protocol": [0.35, 0.18, 0.47],
        "src_bytes": (4.1, 0.9),
        "dst_bytes": (3.6, 0.8),
        "failed_logins": 0.15,
        "count": (75, 210),
        "srv_count": (5, 55),
        "serror": (1.8, 4.5),
        "rerror": (4.8, 2.0),
        "same_srv": (2.0, 4.8),
        "diff_srv": (5.8, 2.0),
        "dst_host_count": (120, 255),
        "dst_host_srv_count": (8, 70),
    },
    "Generic Attack": {
        "duration": (1.1, 0.9),
        "protocol": [0.45, 0.48, 0.07],
        "src_bytes": (7.5, 1.2),
        "dst_bytes": (4.4, 1.0),
        "failed_logins": 0.3,
        "count": (55, 185),
        "srv_count": (40, 155),
        "serror": (4.6, 2.8),
        "rerror": (3.6, 3.2),
        "same_srv": (5.2, 2.6),
        "diff_srv": (3.2, 3.4),
        "dst_host_count": (80, 230),
        "dst_host_srv_count": (70, 220),
    },
    "Brute Force": {
        "duration": (2.2, 1.4),
        "protocol": [0.94, 0.05, 0.01],
        "src_bytes": (5.7, 0.9),
        "dst_bytes": (4.9, 0.9),
        "failed_logins": 4.5,
        "count": (30, 130),
        "srv_count": (20, 105),
        "serror": (1.4, 5.4),
        "rerror": (5.0, 2.2),
        "same_srv": (6.2, 2.0),
        "diff_srv": (1.8, 5.0),
        "dst_host_count": (35, 150),
        "dst_host_srv_count": (20, 125),
    },
}


def beta_sample(rng, params, size):
    return rng.beta(params[0], params[1], size=size).round(3)


def build_class_frame(rng, label, n_rows):
    profile = ATTACK_PROFILES[label]
    min_count, max_count = profile["count"]
    min_srv, max_srv = profile["srv_count"]
    min_host, max_host = profile["dst_host_count"]
    min_host_srv, max_host_srv = profile["dst_host_srv_count"]

    frame = pd.DataFrame(
        {
            "duration": rng.exponential(profile["duration"][0], n_rows)
            + rng.normal(0, profile["duration"][1] * 0.05, n_rows),
            "protocol_type": rng.choice([0, 1, 2], n_rows, p=profile["protocol"]),
            "src_bytes": rng.lognormal(profile["src_bytes"][0], profile["src_bytes"][1], n_rows),
            "dst_bytes": rng.lognormal(profile["dst_bytes"][0], profile["dst_bytes"][1], n_rows),
            "num_failed_logins": rng.poisson(profile["failed_logins"], n_rows),
            "count": rng.integers(min_count, max_count + 1, n_rows),
            "srv_count": rng.integers(min_srv, max_srv + 1, n_rows),
            "serror_rate": beta_sample(rng, profile["serror"], n_rows),
            "rerror_rate": beta_sample(rng, profile["rerror"], n_rows),
            "same_srv_rate": beta_sample(rng, profile["same_srv"], n_rows),
            "diff_srv_rate": beta_sample(rng, profile["diff_srv"], n_rows),
            "dst_host_count": rng.integers(min_host, max_host + 1, n_rows),
            "dst_host_srv_count": rng.integers(min_host_srv, max_host_srv + 1, n_rows),
            "label": label,
        }
    )

    frame["duration"] = frame["duration"].clip(lower=0).round(3)
    frame["src_bytes"] = frame["src_bytes"].clip(0, 250000).round(0).astype(int)
    frame["dst_bytes"] = frame["dst_bytes"].clip(0, 250000).round(0).astype(int)
    return frame


def generate_synthetic_network_data(num_samples=12000):
    rng = np.random.default_rng(42)
    class_weights = {
        "Normal": 0.36,
        "DoS": 0.17,
        "Exploit": 0.14,
        "Reconnaissance": 0.13,
        "Generic Attack": 0.12,
        "Brute Force": 0.08,
    }

    frames = []
    allocated = 0
    for label, weight in class_weights.items():
        n_rows = int(num_samples * weight)
        allocated += n_rows
        frames.append(build_class_frame(rng, label, n_rows))

    if allocated < num_samples:
        frames.append(build_class_frame(rng, "Normal", num_samples - allocated))

    df = pd.concat(frames, ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    os.makedirs("data", exist_ok=True)
    df.to_csv("data/network_traffic.csv", index=False)
    df.head(60).to_csv("data/sample_network_logs.csv", index=False)

    print("Generated multi-class IDS dataset:")
    print(df["label"].value_counts())
    print("\nFiles created:")
    print("- data/network_traffic.csv")
    print("- data/sample_network_logs.csv")


if __name__ == "__main__":
    generate_synthetic_network_data()

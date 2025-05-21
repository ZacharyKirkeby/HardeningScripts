import os
import re
import sys
import string
from collections import defaultdict
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

JUNK_REGEX = [
    r"^~", r".*\.tmp$", r".*\.bak$", r".*\.log$",
    r"^desktop\.ini$", r"^thumbs\.db$"
]
FILLER_WORDS = {"copy", "new", "final", "temp", "tmp", "backup", "old"}

def is_junk(filename):
    name, _ = os.path.splitext(filename.lower())
    if any(re.match(pattern, filename) for pattern in JUNK_REGEX):
        return True
    if len(name) <= 2:
        return True
    alpha_ratio = sum(c.isalpha() for c in name) / max(len(name), 1)
    if alpha_ratio < 0.4:
        return True
    tokens = re.split(r"[\W_]+", name)
    if any(token in FILLER_WORDS for token in tokens):
        return True
    return False

def clean_filename(filename):
    name, _ = os.path.splitext(filename)
    return re.sub(rf"[{re.escape(string.punctuation)}\d]+", " ", name.lower())

def analyze_directory(path, n_clusters=5):
    if not os.path.isdir(path):
        raise ValueError(f"Invalid directory: {path}")
    files = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
    if not files:
        return {"groupings": {}, "junk": []}
    junk_files = [f for f in files if is_junk(f)]
    candidate_files = [f for f in files if f not in junk_files]
    if not candidate_files:
        return {"groupings": {}, "junk": junk_files}
    cleaned = [clean_filename(f) for f in candidate_files]
    vectorizer = TfidfVectorizer(token_pattern=r"(?u)\b\w+\b")
    tfidf = vectorizer.fit_transform(cleaned)
    n_clusters = min(n_clusters, len(candidate_files))
    model = KMeans(n_clusters=n_clusters, random_state=42, n_init="auto")
    labels = model.fit_predict(tfidf)
    groupings = defaultdict(list)
    for file, label in zip(candidate_files, labels):
        groupings[int(label)].append(file)
    return {"groupings": dict(groupings), "junk": junk_files}

def output_results(result, output_path):
    lines = []
    lines.append("[File Groupings]")
    for group_id, files in result["groupings"].items():
        lines.append(f"Group {group_id}:")
        lines.extend(f"  {f}" for f in files)
    lines.append("\n[Junk Files]")
    lines.extend(f"  {f}" for f in result["junk"])
    content = "\n".join(lines)
    print(content)
    with open(os.path.join(output_path, "file_groupings.txt"), "w", encoding="utf-8") as f:
        f.write(content)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python file_analyzer.py <directory_path>")
        sys.exit(1)
    directory = sys.argv[1]
    try:
        result = analyze_directory(directory)
        output_results(result, directory)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

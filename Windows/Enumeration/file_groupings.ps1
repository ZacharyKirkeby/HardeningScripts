param (
    [Parameter(Mandatory = $true)]
    [string]$Directory
)

if (-not (Test-Path $Directory -PathType Container)) {
    Write-Error "Invalid directory: $Directory"
    exit 1
}

$TempPython = [System.IO.Path]::Combine($env:TEMP, "analyze_temp.py")
$OutputFile = Join-Path $Directory "file_groupings.txt"

@'
import os, re, string, sys
from collections import defaultdict
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

junk_regex = [
    r"^~", r".*\\.tmp$", r".*\\.bak$", r".*\\.log$", r"^desktop\\.ini$", r"^thumbs\\.db$"
]
filler = {"copy", "new", "final", "temp", "tmp", "backup", "old"}

def is_junk(fn):
    base = os.path.splitext(fn.lower())[0]
    if any(re.match(p, fn.lower()) for p in junk_regex): return True
    if len(base) <= 2: return True
    alpha = sum(c.isalpha() for c in base) / max(1, len(base))
    if alpha < 0.4: return True
    if any(t in filler for t in re.split(r"[\\W_]+", base)): return True
    return False

def clean(fn):
    return re.sub(f"[{re.escape(string.punctuation)}\\d]+", " ", os.path.splitext(fn)[0].lower())

def analyze(path):
    files = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
    junk = [f for f in files if is_junk(f)]
    rest = [f for f in files if f not in junk]
    if not rest:
        return {}, junk

    cleaned_map = [(f, clean(f)) for f in rest]
    cleaned_map = [(f, c) for f, c in cleaned_map if c.strip()]
    if not cleaned_map:
        return {}, junk

    rest, cleaned = zip(*cleaned_map)
    vec = TfidfVectorizer(token_pattern=r"(?u)\b\w+\b")
    mat = vec.fit_transform(cleaned)
    k = min(len(rest), 5)
    model = KMeans(n_clusters=k, random_state=42, n_init="auto")
    labels = model.fit_predict(mat)
    groups = defaultdict(list)
    for f, l in zip(rest, labels):
        groups[int(l)].append(f)
    return groups, junk

if __name__ == "__main__":
    dir_path = sys.argv[1]
    result, junk = analyze(dir_path)
    with open(os.path.join(dir_path, "file_groupings.txt"), "w", encoding="utf-8") as f:
        f.write("[File Groupings]\\n")
        for k in sorted(result):
            f.write(f"Group {k}:\\n")
            for file in result[k]:
                f.write(f"  {file}\\n")
        f.write("\\n[Junk Files]\\n")
        for j in junk:
            f.write(f"  {j}\\n")
'@ | Set-Content -Path $TempPython -Encoding UTF8
python $TempPython $Directory
Remove-Item $TempPython -Force
Write-Output "`nOutput saved to: $OutputFile"

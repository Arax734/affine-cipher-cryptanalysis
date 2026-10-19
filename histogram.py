import matplotlib.pyplot as plt

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def letter_counts(ciphertext):
    text = ciphertext.upper()
    return {c: text.count(c) for c in ALPHABET}

def plot_histogram(ciphertext, filename="histogram.png", show=True):
    counts = letter_counts(ciphertext)
    total = sum(counts.values())

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(list(counts.keys()), list(counts.values()), color="steelblue")
    ax.bar_label(bars, labels=[f"{n}\n{100 * n / total:.1f}%" if n else "" for n in counts.values()], fontsize=7)
    ax.set_title(f"Ciphertext letter frequency histogram (total letters: {total})")
    ax.set_xlabel("Letter")
    ax.set_ylabel("Occurrences")
    fig.tight_layout()

    fig.savefig(filename, dpi=150)
    if show:
        plt.show()
    plt.close(fig)
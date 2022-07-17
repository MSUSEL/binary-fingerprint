import pickle
import networkx as nx
import matplotlib.pyplot as plt

with open("c2/graph.pkl", "rb") as f:
    g = pickle.load(f)

nx.draw(g, with_labels=False)
plt.show()

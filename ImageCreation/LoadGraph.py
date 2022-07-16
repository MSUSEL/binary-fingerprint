import pickle
import networkx as nx
import matplotlib as plt

with open("clusters/graph.pkl", "rb") as f:
    g = pickle.load(f)

nx.graph(g)
plt.show()

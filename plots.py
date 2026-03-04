import numpy as np
import pandas as pd
from scipy.spatial.distance import squareform, pdist
from scipy.cluster.hierarchy import linkage, dendrogram, fcluster
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import LabelEncoder
from scipy.cluster.hierarchy import linkage, dendrogram
from sklearn.preprocessing import MinMaxScaler
import re
from copy import deepcopy
import networkx as nx
import random
import plotly.graph_objects as go



def create_plot(df,addresses,usernames):

    df['EndDate'] = pd.to_datetime(df['EndDate'])
    df['Day'] = df['EndDate'].dt.day
    df['Time'] = df['EndDate'].dt.hour + df['EndDate'].dt.minute / 60

    # Combine day and time as a decimal representation
    df['EndDate'] = round(df['Day'] + df['Time'] / 24, 2)
    df.drop(['Day', 'Time'], axis=1, inplace=True)

    df = df.reset_index()

    nodes = df[['index', 'MalwareIntelAttackType', 'pred_cluster','EndDate']].rename(columns={'MalwareIntelAttackType': 'name'})

    edges = []
    for pred_cluster in df['pred_cluster'].unique():
        pred_cluster_data = df[df['pred_cluster'] == pred_cluster].sort_values('EndDate')
        for i in range(len(pred_cluster_data) - 1):
            current_row = pred_cluster_data.iloc[i]
            next_row = pred_cluster_data.iloc[i + 1]

            # Directed edge between consecutive timestamps
            edges.append([current_row['index'], next_row['index'], {'type': 'directed'}])

            # Undirected edge for common information within the pred_cluster
            for j in range(i+1,len(pred_cluster_data)):
                next_row = pred_cluster_data.iloc[j]
                common_info = set(current_row.values) & set(next_row.values)
                common_info_addresses = set(current_row[addresses]) & \
                                                set(next_row[addresses])
                common_info_usernames = set(current_row[usernames]) & \
                                                    set(next_row[usernames])

                common_info = common_info_addresses.union(common_info_usernames)
                common_info.discard("NIL")
                common_info.discard(np.nan)


                if len(common_info) > 2:  # Only consider common info other than index and EndDate
                    edges.append([current_row['index'], next_row['index'], {'type': 'undirected', 'common_info': list(common_info)}])

    print("Nodes List:")
    print(nodes)
    print("\nEdges List:")
    print(edges)


    # Create a directed graph
    G = nx.DiGraph()

    # Add nodes to the graph with pred_cluster information
    for _, node in nodes.iterrows():
        G.add_node(node['index'], name=node['name'], pred_cluster=node['pred_cluster'], date = node['EndDate'])

    # Add edges to the graph
    G.add_edges_from(edges)

    # Generate color map for pred_clusters
    unique_pred_clusters = df['pred_cluster'].unique()
    pred_cluster_color_map = {pred_cluster: "#{:06x}".format(random.randint(0, 0xFFFFFF)) for pred_cluster in unique_pred_clusters}

    # Retrieve colors for nodes based on their pred_clusters
    node_colors = [pred_cluster_color_map.get(G.nodes[node]['pred_cluster'], 'gray') for node in G.nodes()]

    # Create Plotly figure
    fig = go.Figure()
    pos = {}



    # Add nodes to Plotly figure
    for idx, (node, color) in enumerate(zip(G.nodes(), node_colors)):
        node_info = f"Index: {node}<br>Name: {G.nodes[node]['name']}<br>pred_cluster: {G.nodes[node]['pred_cluster']}"
        x_pos,y_pos = G.nodes[node]['date'], G.nodes[node]['pred_cluster']
        x_pos += idx * 0.1
        pos[node] = (x_pos,y_pos)
        fig.add_trace(go.Scatter(x=[x_pos], y=[y_pos], mode='markers', marker=dict(size=20, color=color), text=node_info, hoverinfo='text'))

    # Add edges to Plotly figure

    for edge in edges:
        try:
            edge_label = f"Type: {edge[2]['common_info']}"
        except (KeyError, IndexError):
            edge_label = f"Type: {edge[2]['type']}"
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]

        if edge[2]['type'] == 'directed':
            fig.add_trace(go.Scatter(x=[x0, x1, None], y=[y0, y1, None], mode='lines', line=dict(color='yellow', dash='solid'),hovertext=edge_label, hoverinfo='text'))
        elif edge[2]['type'] == 'undirected':
            fig.add_trace(go.Scatter(x=[x0, x1, None], y=[y0, y1, None], mode='lines', line=dict(color='gray', dash='dash'),hovertext=edge_label, hoverinfo='text'))
        else:
            print("here")
            fig.add_trace(go.Scatter(x=[x0, x1, None], y=[y0, y1, None], mode='lines', line=dict(color='black', dash='solid'),hovertext=edge_label, hoverinfo='text'))

        x_label = (x0 + x1) / 2
        y_label = (y0 + y1) / 2

        # fig.add_annotation(x=x_label, y=y_label, text=edge_label, showarrow=False)

    # Show Plotly figure
    fig.update_layout(title='Attach Chains based on pred_clusters', showlegend=False)
    fig.show()

    fig.write_html("Plots/interactive_graph.html")


def main(uri = "Data/Cleaned/Test_test_dataset.csv", addresses = None,usernames = None):
    if addresses and usernames:
        df = pd.read_csv(uri)
        print(df)
        create_plot(df,addresses,usernames)
    else:
        addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
        usernames = ["SourceHostName","DeviceHostName","DestinationHostName"]
        df = pd.read_csv(uri)
        create_plot(df,addresses,usernames)



###                                          RUN PROGRAM 
if __name__ == "__main__":
    main()
import time
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
from pathlib import Path
from copy import deepcopy
from sklearn.impute import KNNImputer
import networkx as nx
from kneed import KneeLocator
from scipy.spatial.distance import cdist
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from core import postprocessing




##                                           PRE-PROCESSING FUNCTIONS:

def get_data(path):
    data = pd.read_csv(path)
    init_data = deepcopy(data)
    return init_data

def stem(array):
  ## checks and extract domain of email in usernames
  # eg --> stem(["a@b","arnav@gmail.com","rahul@gmail.com"]) --> [b,gmail.com,gmail.com]
  
  email_Regex = r"\S+@\S+\.\S+"
  for i in range(len(array)):
    a = array[i]

    if a and a != "NIL" and a != np.nan:
      if re.match(email_Regex,a):
        a = a[a.index('@') + 1 : ]
      array[i] = a
  return array


def label_with_nulls_included(dataframe):

    # label_encoder = LabelEncoder()
    encoded_df = dataframe.copy()
    row_label_dict = {}
    l = []
    for index, row in dataframe.iterrows():

        # Create a dictionary to store label mappings for this row
        row_values = dataframe.iloc[index].values.tolist()
        for col in range(len(row_values)):
            value = row_values[col]
            if (value in row_label_dict) and (value != 0) :
                label = row_label_dict[value]
            else:
                label = index
                row_label_dict[value] = label
            l.append(label)

        encoded_df.iloc[index] = l
        l = []
    return encoded_df


def label_impute_usernames(df):
    df = label_with_nulls_included(df)
    df = df.replace('NIL', np.nan)
    imputer = KNNImputer(n_neighbors=2)
    df = pd.DataFrame(imputer.fit_transform(df), columns=df.columns)
    df = df.rename(columns={0:'SourceUserName', 1: 'SourceHostName',2: 'DeviceHostName',3:'DestinationHostName', 4:'SourceUserID',5:'DestinationUserID',6:'Destination User Name'})
    return df



################

##                                          CLUSTERING METHODS AND HELPERS:

def scale_data(input_df):
    scaler = StandardScaler()
    scaler.fit(input_df)
    input_df = scaler.transform(input_df)
    return input_df
     
def get_optimal_k(X):
    distortions = []
    inertias = []
    mapping1 = {}
    mapping2 = {}
    K = range(1,23)
    for k in K:
        kmeanModel = KMeans(n_clusters=k).fit(X)
        kmeanModel.fit(X)
        distortions.append(sum(np.min(cdist(X, kmeanModel.cluster_centers_,'euclidean'),axis=1)) / X.shape[0])
        inertias.append(kmeanModel.inertia_)
        mapping1[k] = sum(np.min(cdist(X, kmeanModel.cluster_centers_,'euclidean'),axis=1)) / X.shape[0]
        mapping2[k] = kmeanModel.inertia_
    y = [i for i in mapping1.values()]
    x = range(1, len(y)+1)
    kn = KneeLocator(x, y, direction='decreasing')
    optimal_k = kn.knee
    return optimal_k

def create_heatmap(input_df):
    
    corr = pd.DataFrame(input_df)
    corr = corr.corr()
    sns.heatmap(corr,cmap="Blues",annot=True)
    plt.savefig("Plots/heatmap")

# Network graphs 

def Network_graph_clusters(input_df,post_process):
    
    network = deepcopy(input_df)
    s = network.filter(items = network.columns).values
    G = nx.from_numpy_array((s == s[:,None]).any(axis=-1))
    cluster = dict(enumerate(nx.connected_components(G)))
    clusters = [None for i in range(len(network))]

    for i in range(len(network)):
      for c,l in cluster.items():
        if i in l:
          clusters[i] = c
          break

    post_process['cluster'] = clusters
    return post_process


# K-Means clusters:

def k_means(input_df,post_process):
    kmeans = KMeans(random_state=1234,tol = 0.001,init ='k-means++')
    kmeans.fit(input_df)
    labels = kmeans.labels_
    cluster_info = pd.DataFrame(labels)
    # original_data = pd.read_csv("/content/INFINA_df.csv" , encoding="windows-1254")
    # post_process = pd.DataFrame(post_process)
    post_process["cluster"] = cluster_info
    return post_process


################          


def main (path):

  t = time.localtime()
  current_time = time.strftime("%H:%M:%S", t)
  print("Preproceesing started at : " + str(current_time))

  file_name = Path(path).name
  addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
  usernames = ["SourceHostName","DeviceHostName","DestinationHostName"]
  data = get_data(path)

  data = data.drop_duplicates(
    subset = addresses,
    keep = 'first').reset_index()

  data.dropna(subset= addresses, how='all', inplace=True)
  # data.dropna(subset=['SourceUserName','SourceHostName','DeviceHostName','DestinationUserName','DestinationHostName'], how='all', inplace=True)
  data.dropna(subset=usernames, how='all', inplace=True)
  data = data.reset_index()

  data = data.replace(np.nan, 0)
  for col in usernames:
    data[col] = stem(list(data[col]))

  post_process = deepcopy(data)

  data  = data[addresses+usernames]

  print(data.columns)
  data = data.replace('NIL', 0)
  data = data.replace(np.nan, 0)
  df = data[usernames]

  for col in df.columns:
    df[col] = stem(list(df[col]))

  df = label_impute_usernames(df)
  labeled_data = label_with_nulls_included(data[addresses])
  merged_df = labeled_data.join(df)
  input_df = merged_df
  col = input_df.columns

  network_clusters = Network_graph_clusters(input_df, post_process)
  file_path = str(Path('Data/Preprocessed') / f'network_{file_name}')
  network_clusters.to_csv(file_path, index=False)
  postprocessing.main(file_path)

  input_df = scale_data(input_df)
  create_heatmap(input_df)
  
  # optimal_k = get_optimal_k(input_df)
  post_process = k_means(input_df, post_process)
  file_path = str(Path('Data/Preprocessed') / f'Kmeans_{file_name}')
  post_process.to_csv(file_path, index=False)
  postprocessing.main(file_path)


## RUN FILE
 

# t = time.localtime()
# current_time = time.strftime("%H:%M:%S", t)
# print("Preproceesing started at : " + str(current_time))

if __name__ == "__main__":
    main("Data/Raw_data/test_dataset.csv")

    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)
    print("Preproceesing finished at : " + str(current_time))
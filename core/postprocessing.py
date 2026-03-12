import random
import time
import pandas as pd
import numpy as np
from collections import defaultdict
from pathlib import Path


def correlation(data, usernames, addresses, require_both: bool = False):

    cols = data.columns
    result = pd.DataFrame(columns = cols)
    clusters = data.groupby('cluster')
    cluster_counts = [x for x in data['cluster'].value_counts()]
    max_clust = max(cluster_counts) + 1 # keep track of max cluster value to assign unique cluster
    for c_no, cluster in clusters:
        cluster_no = defaultdict(lambda: False)
        scores_clusters = [(0,None) for i in range(len(clusters))] # (score,chain)

        for i in range(len(cluster)):
            max_chain = None
            threshold_corr = 0.3
            clust_dict = defaultdict(lambda: False)
            score = [0 for index in range(len(cluster))]
            cluster_rows = [None for i in range(len(cluster))]
            # if clust_dict[i]:
            #   continue

            for j in range(i+1, len(cluster)):
                # if clust_dict[j]:
                #     continue
                row_i = cluster.iloc[i]
                row_j = cluster.iloc[j]
                common_info_addresses = set(row_i[addresses]) & \
                                       set(row_j[addresses])
                common_info_usernames = set(row_i[usernames]) & \
                                         set(row_j[usernames])
                common_info_addresses.discard("NIL")
                common_info_addresses.discard(np.nan)
                common_info_usernames.discard("NIL")
                common_info_usernames.discard(np.nan)

                # Correlation scoring: 'require_both=False' (OR semantics) means either
                # a shared username OR a shared IP address is sufficient to correlate.
                # 'require_both=True' (AND semantics) requires BOTH to match — stricter.
                if require_both:
                    corr = min(len(common_info_usernames), len(common_info_addresses)) > 0
                    corr = int(corr) * (len(common_info_usernames) + len(common_info_addresses))
                else:
                    corr = len(common_info_usernames) + len(common_info_addresses)
                if corr > 0:
                  if cluster_rows[i]:
                    score[i] += (corr) + (0.8 * (len(cluster_rows[i])) )
                    # score[i] += (corr / (len(cluster_rows[i]) + 1)) + (0.8 * (len(cluster_rows[i])+1) )
                    cluster_rows[i].append(row_j[cols])
                  else:
                    score[i] = corr / 2
                    cluster_rows[i] = [row_i[cols],row_j[cols]]

            max_score = max(score)
            if max_score > threshold_corr:
                ind = score.index(max_score)
                max_chain = pd.DataFrame(cluster_rows[ind])
                scores_clusters.append((max_score,max_chain))
                
        for score_,chain in scores_clusters:
          if score_ and chain is not None:
            df = chain
            if cluster_no[c_no]:
              df['cluster'] = df['cluster'].replace(to_replace=list(df['cluster'])[0], value = max_clust)
              cluster_no[max_clust] = True
              max_clust +=1
            else:
              cluster_no[c_no] = True
            df['correlation_score'] = score_
            result = pd.concat([result, df], ignore_index=True)

          else:
            continue

    return result

# def correlation(data,usernames,addresses):
   
#     clusters = {}
#     for ind in range(len(data)):
#       clusters[ind] = None
#     clusters[0] = 0
    
#     score = {} 
#     for ind in range(len(data)):
#       score[ind] = [0 for i in range(len(data))]
#       score[ind][ind] = 0.5
   
      
#     for i in range(len(data)):
#       for j in range(len(data)):
#         if i == j:
#            continue
#         row_i = data.iloc[i]
#         row_j = data.iloc[j]
#         common_info_addresses = set(row_i[addresses]) & \
#                                        set(row_j[addresses])
#         common_info_usernames = set(row_i[usernames]) & \
#                                          set(row_j[usernames])
#         common_info_addresses.discard("NIL")
#         common_info_addresses.discard(np.nan)
#         common_info_usernames.discard("NIL")
#         common_info_usernames.discard(np.nan)
#         corr = len(common_info_usernames) + len(common_info_addresses)
#         score[i][j] = corr
#         score[j][i] = corr

#         if corr > max(score[i]) and corr > max(score[j]):
#            clusters[j] = clusters[i]
#         elif corr >  max(score[j]):
#            clusters[j] = clusters[i]
#         elif corr >  max(score[i]): 
#            clusters[i] = clusters[j]
#         else:
#            if not clusters[j]:
#               clusters[j] = random.randint(1,100)
#            continue

    
#     for row, c_no in clusters.keys():
#        data.iloc[row]['pred_cluster'] = c_no
    
#     return data

# username
# source user_id and destination user_id

def clean_clusters(res, min_cluster_size: int = 2, require_multi_attack: bool = True):
  import logging as _log
  _logger = _log.getLogger("mitre-core.postprocessing")
  res = res.sort_values('correlation_score', ascending=False).drop_duplicates('index').sort_index()
  cluster_counts = res['cluster'].value_counts()
  clusters_to_remove = set()

  # Drop clusters below minimum size
  small_clusters = cluster_counts[cluster_counts <= min_cluster_size].index
  clusters_to_remove.update(small_clusters)
  if len(small_clusters):
      _logger.info(f"clean_clusters: removing {len(small_clusters)} clusters with <= {min_cluster_size} events")

  # Optionally drop single-attack-type clusters
  if require_multi_attack and 'AttackType' in res.columns:
      cluster_attack_types = res.groupby('cluster')['AttackType'].nunique()
      single_type = cluster_attack_types[cluster_attack_types == 1].index
      clusters_to_remove.update(single_type)
      if len(single_type):
          _logger.info(f"clean_clusters: removing {len(single_type)} single-attack-type clusters")

  before = len(res)
  res = res[~res['cluster'].isin(clusters_to_remove)]
  _logger.info(f"clean_clusters: {before} → {len(res)} rows after filtering")
  return res


def find_columns_for_row_values(dataframe, values):
    matching_columns = {}
    for row_index in range(len(dataframe)):
        row_values = dataframe.iloc[row_index]
        for column in dataframe.columns:
            if any(value == row_values[column] for value in values):
                matching_columns[column] = True

    return list(matching_columns.keys())


def get_feature_chains(data,usernames,addresses):
  column_names = {} # key : cluster_no, value: features
  clusters = data.groupby('cluster')
  for c_no, cluster in clusters:
    values = set()
    for i in range(len(cluster)):
      for j in range(i+1, len(cluster)):
        row_i = cluster.iloc[i]
        row_j = cluster.iloc[j]
        common_info_addresses = set(row_i[addresses]) & \
                                          set(row_j[addresses])
        common_info_usernames = set(row_i[usernames]) & \
                                            set(row_j[usernames])
        common_info_addresses.discard("NIL")
        common_info_addresses.discard(np.nan)
        common_info_usernames.discard("NIL")
        common_info_usernames.discard(np.nan)
        values = values.union(common_info_addresses.union(common_info_usernames))
    try:
        column_names[c_no] = find_columns_for_row_values(cluster,values)
    except Exception as e:
        print(f"Cannot get column names for cluster {c_no}: {e}")

  return column_names


def get_unique_values(list_of_lists):
    unique_values = {}
    for sublist in list_of_lists:
        for col in sublist:
          if col in unique_values:
            continue
          else:
            unique_values[col] = True

    return list(unique_values.keys())


def main(uri = 'Data/Preprocessed/Canara15WidgetExport_clustered.csv'):
  

  file_name = Path(uri).name

  df = pd.read_csv(uri)
  addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
  usernames = ["SourceHostName","DeviceHostName","DestinationHostName"]

  # df["DestinationAddress"] = df["DestinationAddress"].apply(lambda x: '.'.join(str(x).split('.')[:3]))
  # df["SourceAddress"] = df["SourceAddress"].apply(lambda x: '.'.join(str(x).split('.')[:3]))

  df = df.drop_duplicates(keep ="first", ignore_index = True)
  res = correlation(df, usernames,addresses)
  # res = clean_clusters(res)
  path = str(Path('Data/Cleaned') / file_name)
  res.to_csv(path, index=False)


####                                         RUN PROGRAM


if False:
  main()

  t = time.localtime()
  current_time = time.strftime("%H:%M:%S", t)
  print("Postproceesing complete at : " + str(current_time))


####

"""FEATURE CHAINS"""

# pd.set_option('display.max_columns', 500)
# df = pd.read_csv('/content/drive/My Drive/Results/test_moded_data.csv')


# df = df.drop_duplicates(keep ="first", ignore_index = True)

# # change tto drop on address similarity's also
# cluster_counts = df.groupby('cluster').size()
# cluster_counts = df['cluster'].value_counts()
# cluster_attack_types = df.groupby('cluster')['AttackType'].nunique()
# # print(cluster_counts[cluster_counts <= 2].index)
# single_instance_clusters = cluster_counts[cluster_counts <= 2].index
# single_attack_type_clusters = cluster_attack_types[cluster_attack_types == 1].index
# clusters_to_remove = set(single_instance_clusters).union(single_attack_type_clusters)
# df = df[~df['cluster'].isin(clusters_to_remove)]
# # df['Correlation_features'] = None
# result = correlation(df)

# coloumn = get_feature_chains(result)
# print((coloumn.items()))

# cluster_counts = result.groupby('cluster').size()
# cluster_counts = result['cluster'].value_counts()
# single_instance_clusters = cluster_counts[cluster_counts <= 2].index
# df = result[~result['cluster'].isin(set(single_instance_clusters))]

# df.to_csv('/content/drive/My Drive/Results/test_moded_data_1.csv', index=False)

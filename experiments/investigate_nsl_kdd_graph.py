import logging
import time
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import adjusted_rand_score
from datasets.loaders.nsl_kdd_loader import NSLKDDTemporalLoader
from core.correlation_pipeline import CorrelationPipeline

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mitre-core.investigate_nsl_kdd")

def main():
    logger.info("Loading NSL-KDD dataset...")
    loader = NSLKDDTemporalLoader(dataset_dir="datasets/raw/NSL-KDD")
    df = loader.load_and_preprocess()
    
    # Just take a sample to speed things up for this script
    df_sample = df.head(5000).copy()
    
    logger.info(f"Loaded {len(df_sample)} events from NSL-KDD")
    
    # Build graph to check edges
    from hgnn.hgnn_training import AlertToGraphConverter
    converter = AlertToGraphConverter()
    try:
        data = converter.convert(df_sample)
        logger.info("Graph Metadata:")
        print(data.metadata())
        
        logger.info("Edge Counts:")
        for edge_type in data.edge_types:
            num_edges = data[edge_type].edge_index.shape[1]
            print(f"  {edge_type}: {num_edges}")
            if num_edges == 0:
                logger.warning(f"  WARNING: 0 edges for {edge_type} - graph is disconnected!")
                
    except Exception as e:
        logger.error(f"Failed to build graph: {e}")
        
    # Run Feature-Only Baseline (GBM)
    logger.info("Running Feature-Only Baseline (GBM)...")
    
    # Extract numerical features
    numeric_cols = df_sample.select_dtypes(include=['number']).columns.tolist()
    # Remove obvious non-features if present
    numeric_cols = [c for c in numeric_cols if c not in ['pred_cluster', 'CampaignID', 'label']]
    
    if len(numeric_cols) == 0:
        logger.error("No numeric features found for GBM.")
        return
        
    X = df_sample[numeric_cols].fillna(0).values
    
    # Ground truth labels
    if 'AttackType' in df_sample.columns:
        y_true = df_sample['AttackType'].astype('category').cat.codes.values
    else:
        # Fallback to whatever categorical we can find, or just random for structural test
        y_true = df_sample.iloc[:, 0].astype('category').cat.codes.values
        
    # Fit GBM (unsupervised proxy via pseudo-labels or just run it as a classifier to see if features have signal)
    # We'll use KMeans as the unsupervised baseline on raw features since ARI needs clusters
    from sklearn.cluster import KMeans
    kmeans = KMeans(n_clusters=len(set(y_true)), random_state=42)
    y_pred_baseline = kmeans.fit_predict(X)
    
    ari_baseline = adjusted_rand_score(y_true, y_pred_baseline)
    logger.info(f"Feature-only (KMeans) ARI: {ari_baseline:.4f}")
    
    # Run HGNN (if model available)
    logger.info("Running HGNN Correlation...")
    try:
        # Assuming nsl_kdd_best.pt exists
        model_path = "hgnn_checkpoints/nsl_kdd_best.pt"
        pipeline = CorrelationPipeline(method='hgnn', model_path=model_path)
        
        # NSL-KDD doesn't have standard usernames/addresses, so we pass empty lists
        # The engine will fallback to whatever features it can
        result = pipeline.correlate(df_sample, usernames=[], addresses=[])
        
        y_pred_hgnn = result.data['pred_cluster'].values
        ari_hgnn = adjusted_rand_score(y_true, y_pred_hgnn)
        logger.info(f"HGNN ARI: {ari_hgnn:.4f}")
        
    except Exception as e:
        logger.error(f"HGNN run failed: {e}")
        ari_hgnn = "N/A"
        
    print("\n--- RESULTS COMPARISON ---")
    print(f"Feature-Only Baseline ARI: {ari_baseline:.4f}")
    print(f"HGNN ARI:                  {ari_hgnn}")
    
    if isinstance(ari_hgnn, float) and ari_baseline >= ari_hgnn:
        print("\nCONCLUSION: Feature-only baseline >= HGNN. The graph adds no value for NSL-KDD.")

if __name__ == "__main__":
    main()
